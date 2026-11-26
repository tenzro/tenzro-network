//! What a volume can offer, measured on the machine that holds it.
//!
//! [`measure`] writes a scratch file on the volume, reads it back once in
//! order and many times at random offsets, and reads the volume's free
//! space. [`propose`] turns that into the storage classes the volume
//! qualifies for: a validator's possession probe reads a few random chunks
//! of every object a claim holds, so a class's deadline bounds how many
//! objects the volume can answer for in time. The measurement only proposes;
//! what the network believes is what the probes measure.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;

use rand::{Rng, RngCore};
use serde::Serialize;

use crate::error::{Result, StorageProviderError};
use crate::pdp::CHUNK_SIZE;

/// Name of the scratch file, removed when the measurement ends.
const SCRATCH: &str = ".tenzro-volume-probe";
/// A proposal keeps the estimated answer time to this fraction of the
/// deadline: the rest is the probe's gossip both ways, the proof's
/// verification and a volume busier than when it was measured.
pub const PROPOSAL_MARGIN: u64 = 4;
/// Bytes of a Merkle path per proven chunk, for a shard of up to 2^20 chunks.
const PATH_BYTES: u64 = 20 * 32;

/// One measurement of a volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VolumeMeasure {
    /// Median time of one random chunk read, microseconds.
    pub random_read_p50_us: u64,
    /// 99th percentile time of one random chunk read, microseconds.
    pub random_read_p99_us: u64,
    /// Rate of one sequential read of the scratch file, bytes per second.
    pub sequential_read_bytes_per_s: u64,
    /// Space the volume has free for this user, bytes.
    pub free_bytes: u64,
}

/// One storage class and what the measured volume can do for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClassFit {
    /// The class, as the chain names it (`hot`, `warm`, `cold`).
    pub class: String,
    /// The class's governed probe deadline, ms.
    pub deadline_ms: u64,
    /// Estimated time to answer a probe for one object, microseconds.
    pub per_object_us: u64,
    /// Objects the volume can answer a probe for inside the deadline with
    /// [`PROPOSAL_MARGIN`]; 0 means the volume does not qualify.
    pub max_objects: u64,
}

fn io(e: std::io::Error) -> StorageProviderError {
    StorageProviderError::Volume(e.to_string())
}

/// Measures the volume holding `dir` with a scratch file of `sample_bytes`
/// and `reads` random chunk reads. The file is removed afterwards.
pub fn measure(dir: &Path, sample_bytes: u64, reads: usize) -> Result<VolumeMeasure> {
    if sample_bytes < CHUNK_SIZE as u64 || reads == 0 {
        return Err(StorageProviderError::Volume(
            "a measurement needs at least one chunk and one read".into(),
        ));
    }
    let path = dir.join(SCRATCH);
    let result = measure_file(&path, sample_bytes, reads);
    let _ = std::fs::remove_file(&path);
    let (random, sequential) = result?;
    let free_bytes = fs4::statvfs(dir).map_err(io)?.available_space();
    Ok(VolumeMeasure {
        random_read_p50_us: percentile(&random, 50),
        random_read_p99_us: percentile(&random, 99),
        sequential_read_bytes_per_s: sequential,
        free_bytes,
    })
}

fn measure_file(path: &Path, sample_bytes: u64, reads: usize) -> Result<(Vec<u64>, u64)> {
    let mut rng = rand::thread_rng();
    {
        let mut file = std::fs::File::create(path).map_err(io)?;
        let mut block = vec![0u8; 1 << 20];
        let mut left = sample_bytes;
        while left > 0 {
            let n = left.min(block.len() as u64) as usize;
            rng.fill_bytes(&mut block[..n]);
            file.write_all(&block[..n]).map_err(io)?;
            left -= n as u64;
        }
        file.sync_all().map_err(io)?;
        drop_cache(&file);
    }
    let mut file = std::fs::File::open(path).map_err(io)?;
    let started = Instant::now();
    let mut block = vec![0u8; 1 << 20];
    let mut read = 0u64;
    loop {
        let n = file.read(&mut block).map_err(io)?;
        if n == 0 {
            break;
        }
        read += n as u64;
    }
    let elapsed = started.elapsed().as_micros().max(1) as u64;
    let sequential = read.saturating_mul(1_000_000) / elapsed;
    drop_cache(&file);
    let chunks = sample_bytes / CHUNK_SIZE as u64;
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut times = Vec::with_capacity(reads);
    for _ in 0..reads {
        let at = rng.gen_range(0..chunks) * CHUNK_SIZE as u64;
        let started = Instant::now();
        file.seek(SeekFrom::Start(at)).map_err(io)?;
        file.read_exact(&mut chunk).map_err(io)?;
        times.push(started.elapsed().as_micros() as u64);
    }
    Ok((times, sequential))
}

/// Asks the kernel to forget the file's cached pages, so reads reach the
/// volume. Elsewhere the reads may be served from memory and the figures are
/// a lower bound.
#[cfg(target_os = "linux")]
fn drop_cache(file: &std::fs::File) {
    use std::os::fd::AsRawFd;
    // SAFETY: posix_fadvise only reads the descriptor, which `file` keeps open.
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
    }
}

#[cfg(not(target_os = "linux"))]
fn drop_cache(_file: &std::fs::File) {}

fn percentile(times: &[u64], p: usize) -> u64 {
    let mut sorted = times.to_vec();
    sorted.sort_unstable();
    let rank = (sorted.len() * p).div_ceil(100).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

/// The classes `measured` qualifies for. A probe proves `samples` chunks of
/// each object it covers, each a random read and, with its Merkle path, sent
/// over an uplink of `uplink_bytes_per_s`. `classes` are the chain's classes
/// with their governed deadlines.
pub fn propose(
    measured: &VolumeMeasure,
    uplink_bytes_per_s: u64,
    samples: u32,
    classes: &[(String, u64)],
) -> Vec<ClassFit> {
    let proof_bytes = u64::from(samples) * (CHUNK_SIZE as u64 + PATH_BYTES);
    let send_us = proof_bytes.saturating_mul(1_000_000) / uplink_bytes_per_s.max(1);
    let per_object_us = (u64::from(samples) * measured.random_read_p99_us + send_us).max(1);
    classes
        .iter()
        .map(|(class, deadline_ms)| ClassFit {
            class: class.clone(),
            deadline_ms: *deadline_ms,
            per_object_us,
            max_objects: deadline_ms.saturating_mul(1_000) / PROPOSAL_MARGIN / per_object_us,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(p99_us: u64) -> VolumeMeasure {
        VolumeMeasure {
            random_read_p50_us: p99_us / 2,
            random_read_p99_us: p99_us,
            sequential_read_bytes_per_s: 100 << 20,
            free_bytes: 1 << 40,
        }
    }

    fn classes() -> Vec<(String, u64)> {
        vec![
            ("hot".into(), 10_000),
            ("warm".into(), 20_000),
            ("cold".into(), 30_000),
        ]
    }

    #[test]
    fn a_slower_volume_answers_for_fewer_objects_and_a_longer_deadline_for_more() {
        let fast = propose(&volume(100), 10 << 20, 8, &classes());
        let slow = propose(&volume(10_000), 10 << 20, 8, &classes());
        for (f, s) in fast.iter().zip(&slow) {
            assert!(f.max_objects > s.max_objects, "{}", f.class);
        }
        assert!(fast[0].max_objects < fast[1].max_objects);
        assert!(fast[1].max_objects < fast[2].max_objects);
    }

    #[test]
    fn the_margin_keeps_the_estimate_to_a_quarter_of_the_deadline() {
        // 8 reads of 1 ms and a proof sent at 13,312,000 bytes a second, 1 ms: 9 ms per object.
        let fit = &propose(
            &volume(1_000),
            8 * (CHUNK_SIZE as u64 + PATH_BYTES) * 1_000,
            8,
            &classes(),
        )[0];
        assert_eq!(fit.per_object_us, 9_000);
        assert_eq!(fit.max_objects, 10_000 * 1_000 / PROPOSAL_MARGIN / 9_000);
        assert!(fit.max_objects * fit.per_object_us * PROPOSAL_MARGIN <= fit.deadline_ms * 1_000);
    }

    #[test]
    fn a_volume_too_slow_for_a_class_does_not_qualify() {
        let fit = propose(&volume(1_000_000), 1, 8, &classes());
        assert!(fit.iter().all(|f| f.max_objects == 0));
    }

    #[test]
    fn a_measurement_reads_back_its_scratch_file_and_removes_it() {
        let dir = std::env::temp_dir().join(format!("tenzro-volume-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let m = measure(&dir, 4 << 20, 64).unwrap();
        assert!(m.random_read_p50_us <= m.random_read_p99_us);
        assert!(m.sequential_read_bytes_per_s > 0);
        assert!(m.free_bytes > 0);
        assert!(!dir.join(SCRATCH).exists());
        assert!(measure(&dir, 1, 1).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
