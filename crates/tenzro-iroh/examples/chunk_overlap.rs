//! How much of one file or tree is already held in another, under
//! content-defined chunking.
//!
//! A blob is addressed by the hash of the whole file, so two files that
//! differ a little share nothing on the wire or on disk. This cuts both
//! inputs into chunks whose boundaries follow the content (a Gear rolling
//! hash, 8 KiB to 128 KiB, 64 KiB on average: the parameters of the Xet
//! chunking draft), names every chunk by its BLAKE3 hash, and reports how
//! many bytes of the second input sit in chunks the first already has.
//! That is what a chunk index would save when moving or storing the second
//! after the first.
//!
//! The Gear table here is derived from a fixed label, not the draft's
//! table, so boundaries differ from a Xet client's while the share of
//! repeated content they find is the same.
//!
//! An input is a file, or a directory whose files are read in path order
//! and cut one by one. Memory is one map entry per distinct chunk.
//!
//! Usage:
//!   cargo run --release -p tenzro-iroh --example chunk_overlap -- <held> <incoming>

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// No chunk is cut shorter than this, except the last of a file.
const MIN_CHUNK: usize = 8 * 1024;
/// A chunk that found no boundary is cut here.
const MAX_CHUNK: usize = 128 * 1024;
/// A boundary falls where these bits of the rolling hash are all zero: 16
/// bits, one position in 65,536.
const BOUNDARY_MASK: u64 = 0xFFFF_0000_0000_0000;
/// Bytes the rolling hash remembers: each step shifts one bit out.
const GEAR_WINDOW: usize = 64;

/// A chunk's name: the first 16 bytes of its BLAKE3 hash.
type ChunkId = [u8; 16];

fn gear_table() -> [u64; 256] {
    let mut bytes = [0u8; 256 * 8];
    blake3::Hasher::new_derive_key("tenzro chunk_overlap gear table")
        .finalize_xof()
        .fill(&mut bytes);
    let mut table = [0u64; 256];
    let (words, _) = bytes.as_chunks::<8>();
    for (entry, word) in table.iter_mut().zip(words) {
        *entry = u64::from_le_bytes(*word);
    }
    table
}

/// Cuts a byte stream into content-defined chunks. The cuts depend only on
/// the bytes, never on how the stream was split across `push` calls.
struct Chunker {
    table: [u64; 256],
    rolling: u64,
    len: usize,
    hasher: blake3::Hasher,
}

impl Chunker {
    fn new() -> Self {
        Self {
            table: gear_table(),
            rolling: 0,
            len: 0,
            hasher: blake3::Hasher::new(),
        }
    }

    fn push(&mut self, data: &[u8], emit: &mut impl FnMut(ChunkId, usize)) {
        let mut start = 0;
        for (i, &byte) in data.iter().enumerate() {
            self.len += 1;
            // The hash only matters from the shortest chunk on, and only
            // remembers its window, so the bytes before that are skipped.
            if self.len + GEAR_WINDOW > MIN_CHUNK {
                self.rolling = (self.rolling << 1).wrapping_add(self.table[byte as usize]);
            }
            let boundary = self.len >= MIN_CHUNK && self.rolling & BOUNDARY_MASK == 0;
            if boundary || self.len == MAX_CHUNK {
                self.hasher.update(&data[start..=i]);
                start = i + 1;
                self.cut(emit);
            }
        }
        self.hasher.update(&data[start..]);
    }

    /// End the stream: what is left is its last chunk.
    fn finish(&mut self, emit: &mut impl FnMut(ChunkId, usize)) {
        self.cut(emit);
    }

    fn cut(&mut self, emit: &mut impl FnMut(ChunkId, usize)) {
        if self.len == 0 {
            return;
        }
        let mut id = ChunkId::default();
        id.copy_from_slice(&self.hasher.finalize().as_bytes()[..16]);
        emit(id, self.len);
        self.hasher.reset();
        self.rolling = 0;
        self.len = 0;
    }
}

/// The distinct chunks of one input and its size.
#[derive(Default)]
struct Index {
    chunks: HashMap<ChunkId, usize>,
    bytes: u64,
    count: u64,
}

impl Index {
    fn add(&mut self, id: ChunkId, len: usize) {
        self.chunks.insert(id, len);
        self.bytes += len as u64;
        self.count += 1;
    }

    fn add_stream(&mut self, mut reader: impl Read) -> std::io::Result<()> {
        let mut chunker = Chunker::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            chunker.push(&buf[..n], &mut |id, len| self.add(id, len));
        }
        chunker.finish(&mut |id, len| self.add(id, len));
        Ok(())
    }

    /// Bytes in distinct chunks: what the input costs to hold once.
    fn unique_bytes(&self) -> u64 {
        self.chunks.values().map(|&len| len as u64).sum()
    }

    /// Bytes of this input's distinct chunks that `held` does not have.
    fn bytes_missing_from(&self, held: &Index) -> u64 {
        self.chunks
            .iter()
            .filter(|(id, _)| !held.chunks.contains_key(*id))
            .map(|(_, &len)| len as u64)
            .sum()
    }
}

fn files_under(path: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)?
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<_>>()?;
        entries.sort();
        for entry in entries {
            files_under(&entry, out)?;
        }
    } else {
        out.push(path.to_path_buf());
    }
    Ok(())
}

fn index_of(path: &Path) -> std::io::Result<Index> {
    let mut files = Vec::new();
    files_under(path, &mut files)?;
    let mut index = Index::default();
    for file in files {
        index.add_stream(File::open(file)?)?;
    }
    Ok(index)
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

fn describe(name: &str, index: &Index) {
    let unique = index.unique_bytes();
    println!(
        "{name}: {} bytes in {} chunks; {} bytes in distinct chunks ({:.2}% repeats itself)",
        index.bytes,
        index.count,
        unique,
        percent(index.bytes - unique, index.bytes),
    );
}

fn main() -> std::io::Result<()> {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [held_path, incoming_path] = args.as_slice() else {
        eprintln!("usage: chunk_overlap <held file or directory> <incoming file or directory>");
        std::process::exit(2);
    };
    let held = index_of(held_path)?;
    let incoming = index_of(incoming_path)?;
    describe("held", &held);
    describe("incoming", &incoming);
    let unique = incoming.unique_bytes();
    let missing = incoming.bytes_missing_from(&held);
    println!(
        "incoming after held: {missing} bytes to move of {} ({:.2}% of its distinct chunks already held)",
        incoming.bytes,
        percent(unique - missing, unique),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(label: &str, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        blake3::Hasher::new_derive_key(label)
            .finalize_xof()
            .fill(&mut out);
        out
    }

    fn index(data: &[u8]) -> Index {
        let mut index = Index::default();
        index.add_stream(data).expect("read");
        index
    }

    #[test]
    fn chunks_cover_the_input_within_the_size_bounds() {
        let data = noise("cover", 3 * 1024 * 1024 + 123);
        let mut sizes = Vec::new();
        let mut chunker = Chunker::new();
        chunker.push(&data, &mut |_, len| sizes.push(len));
        chunker.finish(&mut |_, len| sizes.push(len));
        assert_eq!(sizes.iter().sum::<usize>(), data.len());
        let (last, rest) = sizes.split_last().expect("chunks");
        assert!(rest.iter().all(|&s| (MIN_CHUNK..=MAX_CHUNK).contains(&s)));
        assert!(*last <= MAX_CHUNK);
        // Boundaries one position in 65,536 after the shortest chunk.
        let mean = data.len() / sizes.len();
        assert!((32 * 1024..=96 * 1024).contains(&mean), "mean chunk {mean}");
    }

    #[test]
    fn cuts_do_not_depend_on_how_the_stream_is_read() {
        let data = noise("split", 1024 * 1024);
        let mut whole = Vec::new();
        let mut chunker = Chunker::new();
        chunker.push(&data, &mut |id, len| whole.push((id, len)));
        chunker.finish(&mut |id, len| whole.push((id, len)));

        let mut pieces = Vec::new();
        let mut chunker = Chunker::new();
        for piece in data.chunks(7919) {
            chunker.push(piece, &mut |id, len| pieces.push((id, len)));
        }
        chunker.finish(&mut |id, len| pieces.push((id, len)));
        assert_eq!(whole, pieces);
    }

    #[test]
    fn an_insertion_costs_the_chunks_around_it_and_no_more() {
        let original = noise("insert", 4 * 1024 * 1024);
        let mut edited = original[..100_000].to_vec();
        edited.extend_from_slice(b"forty-two bytes that were not there before");
        edited.extend_from_slice(&original[100_000..]);

        let held = index(&original);
        let incoming = index(&edited);
        let missing = incoming.bytes_missing_from(&held);
        assert!(missing > 0);
        assert!(
            missing <= 3 * MAX_CHUNK as u64,
            "{missing} bytes to move for a 42-byte insertion"
        );
    }

    #[test]
    fn the_same_content_has_nothing_to_move_and_other_content_everything() {
        let data = noise("same", 1024 * 1024);
        let held = index(&data);
        assert_eq!(index(&data).bytes_missing_from(&held), 0);

        let other = index(&noise("other", 1024 * 1024));
        assert_eq!(other.bytes_missing_from(&held), other.unique_bytes());
    }

    #[test]
    fn content_repeated_inside_one_input_is_counted_once() {
        let block = noise("repeat", 512 * 1024);
        let mut twice = block.clone();
        twice.extend_from_slice(&block);
        let index = index(&twice);
        assert_eq!(index.bytes, 1024 * 1024);
        // The second copy realigns to the first copy's cuts within a few
        // chunks.
        assert!(index.unique_bytes() <= 512 * 1024 + 3 * MAX_CHUNK as u64);
    }
}
