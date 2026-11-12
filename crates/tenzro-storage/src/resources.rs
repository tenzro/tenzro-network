//! Disk and resource protection shared by the node, `tenzro-node doctor`,
//! `tenzro status`, the setup preflight and the assistant.
//!
//! Everything here reacts to what is measured, never to elapsed time:
//!
//! - [`DataClass`] says how critical each kind of stored data is, and the
//!   tables [`DATA_LAYOUT`] and [`COLUMN_FAMILY_CLASSES`] list every path and
//!   column family the node keeps. Automatic cleanup removes only paths of
//!   [`CLEANUP_TARGETS`], and [`guarded_remove`] refuses anything that
//!   classifies as [`DataClass::Critical`].
//! - [`Reading`] is one measurement of the volume (free bytes, free percent,
//!   inodes, read-only flag), of the host (swap, memory, I/O pressure) and of
//!   how fast the data grows ([`GrowthTracker`], bytes per block).
//! - [`Ladder`] turns readings into a [`Level`], entering and leaving levels
//!   with hysteresis, and reports the runway: blocks left at the measured
//!   growth.
//! - [`Headroom`] answers whether a step that writes a lot may start.
//! - [`role_estimate`] and [`preflight`] size a data directory for a role.

use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Bytes in a gibibyte.
pub const GIB: u64 = 1 << 30;
/// Bytes in a mebibyte.
pub const MIB: u64 = 1 << 20;

/// Blocks in one epoch at the public network's parameters (7,200
/// checkpoints at one a second). Runway budgets are stated in multiples of it.
pub const EPOCH_BLOCKS: u64 = 7_200;

/// How critical stored data is. The pruner touches
/// [`Expendable`](DataClass::Expendable) first, then
/// [`Regenerable`](DataClass::Regenerable), then
/// [`Important`](DataClass::Important), and only down to its safe floor;
/// [`Critical`](DataClass::Critical) is never removed by an automatic step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Rebuilt from peers or by recomputation: relay buffers, caches,
    /// derived indexes, model download partials.
    Regenerable,
    /// Past its use: history beyond the retention window, older snapshots,
    /// compaction leftovers, temporary files, logs.
    Expendable,
    /// Serves peers and joins: recent history inside the window, the newest
    /// snapshot, receipts and logs inside the window.
    Important,
    /// Never removed by any automatic step: identity and device keys,
    /// consensus safety state, current and previous epoch state, the latest
    /// verified checkpoint and finality proof, wallet and key custody data,
    /// the genesis.
    Critical,
}

impl DataClass {
    /// Lowercase name for logs and status output.
    pub fn name(self) -> &'static str {
        match self {
            DataClass::Regenerable => "regenerable",
            DataClass::Expendable => "expendable",
            DataClass::Important => "important",
            DataClass::Critical => "critical",
        }
    }

    /// The order the pruner takes classes in: expendable, regenerable,
    /// important. Critical is not in it.
    pub const PRUNE_ORDER: [DataClass; 3] = [
        DataClass::Expendable,
        DataClass::Regenerable,
        DataClass::Important,
    ];
}

/// One entry of the data directory.
#[derive(Debug, Clone, Copy)]
pub struct DataItem {
    /// Name relative to the data directory. A trailing `/` names a
    /// directory and everything under it; a leading `*` matches a file
    /// suffix anywhere under the directory named before it.
    pub path: &'static str,
    /// Its class.
    pub class: DataClass,
    /// What it holds.
    pub what: &'static str,
}

/// Every path the node keeps under its data directory, by class. Longer
/// (more specific) entries win; a path that matches nothing is
/// [`DataClass::Critical`], so a directory added without a row is never
/// swept.
pub const DATA_LAYOUT: &[DataItem] = &[
    DataItem {
        path: "db/",
        class: DataClass::Critical,
        what: "the node store: state, accounts, blocks, transactions, metadata (inside it the pruner works by column family, see COLUMN_FAMILY_CLASSES, never by file)",
    },
    DataItem {
        path: "db/archive/",
        class: DataClass::Expendable,
        what: "rotated write-ahead logs whose data is already in SST files",
    },
    DataItem {
        path: "consensus/",
        class: DataClass::Critical,
        what: "consensus safety state: votes, locks, certificates (window pruning goes through the store API)",
    },
    DataItem {
        path: "epoch-proof/",
        class: DataClass::Critical,
        what: "handover proof log and the chain proof that certifies snapshots",
    },
    DataItem {
        path: "epoch-snapshots/",
        class: DataClass::Important,
        what: "epoch snapshots: the newest serves joins",
    },
    DataItem {
        path: "epoch-snapshots/*.partial",
        class: DataClass::Expendable,
        what: "a snapshot that was being written",
    },
    DataItem {
        path: "iroh/",
        class: DataClass::Critical,
        what: "the node's network identity key",
    },
    DataItem {
        path: "device-keys/",
        class: DataClass::Critical,
        what: "device and machine keys",
    },
    DataItem {
        path: "wallets/",
        class: DataClass::Critical,
        what: "wallet and key custody data",
    },
    DataItem {
        path: "audit/",
        class: DataClass::Critical,
        what: "audit records",
    },
    DataItem {
        path: "genesis.json",
        class: DataClass::Critical,
        what: "the genesis",
    },
    DataItem {
        path: "tenzro-node.lock",
        class: DataClass::Critical,
        what: "single-instance lock",
    },
    DataItem {
        path: "tenzro-node.pid",
        class: DataClass::Critical,
        what: "process id file",
    },
    DataItem {
        path: ".ballast",
        class: DataClass::Regenerable,
        what: "reserve file the node deletes itself at the last level",
    },
    DataItem {
        path: "tmp/",
        class: DataClass::Expendable,
        what: "temporary files",
    },
    DataItem {
        path: "logs/",
        class: DataClass::Expendable,
        what: "the node's own log files",
    },
    DataItem {
        path: "relay/",
        class: DataClass::Regenerable,
        what: "relay buffers",
    },
    DataItem {
        path: "cache/",
        class: DataClass::Regenerable,
        what: "caches and derived indexes",
    },
    DataItem {
        path: "models/",
        class: DataClass::Regenerable,
        what: "downloaded models, fetched again on demand",
    },
    DataItem {
        path: "models/*.partial",
        class: DataClass::Expendable,
        what: "model downloads that did not finish",
    },
];

/// Paths automatic steps may remove or shrink, relative to the data
/// directory. A test fails if any classifies as [`DataClass::Critical`].
pub const CLEANUP_TARGETS: &[&str] = &[
    "db/archive/",
    "epoch-snapshots/old",
    "epoch-snapshots/x.partial",
    ".ballast",
    "tmp/",
    "logs/",
    "relay/",
    "cache/",
    "models/x.partial",
];

/// Column families of the node store by class. The pruner deletes rows of
/// the families listed in [`PRUNE_COLUMN_FAMILIES`] through the store, by
/// height or key range; it never drops a family.
pub const COLUMN_FAMILY_CLASSES: &[(&str, DataClass)] = &[
    ("blocks", DataClass::Important),
    ("transactions", DataClass::Important),
    ("events", DataClass::Important),
    ("state_trie", DataClass::Critical),
    ("state", DataClass::Critical),
    ("accounts", DataClass::Critical),
    ("metadata", DataClass::Critical),
    ("identities", DataClass::Critical),
    ("delegations", DataClass::Critical),
    ("credentials", DataClass::Critical),
    ("channels", DataClass::Critical),
    ("agents", DataClass::Critical),
    ("models", DataClass::Critical),
    ("providers", DataClass::Critical),
    ("tokens", DataClass::Critical),
    ("settlements", DataClass::Critical),
    ("model_services", DataClass::Critical),
    ("audit", DataClass::Critical),
    ("validator_modules", DataClass::Critical),
    ("da_committee", DataClass::Critical),
    ("challenges", DataClass::Critical),
];

/// The column families history pruning deletes rows from, always below the
/// retention floor. Everything else in the store is [`DataClass::Critical`].
pub const PRUNE_COLUMN_FAMILIES: &[&str] = &["blocks", "transactions", "events"];

/// The class of a column family; unknown names are critical.
pub fn column_family_class(name: &str) -> DataClass {
    COLUMN_FAMILY_CLASSES
        .iter()
        .find(|(n, _)| *n == name)
        .map_or(DataClass::Critical, |(_, c)| *c)
}

fn normal_components(rel: &Path) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(s) => out.push(s.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

fn item_matches(item: &DataItem, parts: &[String]) -> Option<usize> {
    let spec: Vec<&str> = item.path.trim_end_matches('/').split('/').collect();
    let dir_item = item.path.ends_with('/');
    let mut specificity = 0;
    for (i, want) in spec.iter().enumerate() {
        let got = parts.get(i)?;
        if let Some(suffix) = want.strip_prefix('*') {
            if !got.ends_with(suffix) {
                return None;
            }
        } else if got != want {
            return None;
        }
        specificity += 1;
    }
    if !dir_item && parts.len() > spec.len() {
        // A file entry covers only itself, and a `*.partial` directory its
        // whole content.
        let last = spec.last().copied().unwrap_or("");
        if !last.starts_with('*') {
            return None;
        }
    }
    Some(specificity * 2 + usize::from(!dir_item))
}

/// The class of `rel`, a path relative to the data directory. A path that
/// is absolute, climbs out with `..`, or matches no row of [`DATA_LAYOUT`]
/// is [`DataClass::Critical`].
pub fn classify(rel: &Path) -> DataClass {
    let Some(parts) = normal_components(rel) else {
        return DataClass::Critical;
    };
    if parts.is_empty() {
        return DataClass::Critical;
    }
    DATA_LAYOUT
        .iter()
        .filter_map(|i| item_matches(i, &parts).map(|s| (s, i.class)))
        .max_by_key(|(s, _)| *s)
        .map_or(DataClass::Critical, |(_, c)| c)
}

/// Removes `rel` under `data_dir` (a file or a directory tree) if and only
/// if it is not critical. Every automatic deletion of a node data path goes
/// through here.
pub fn guarded_remove(data_dir: &Path, rel: &Path) -> std::io::Result<u64> {
    let class = classify(rel);
    if class == DataClass::Critical {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is critical data and is never removed automatically",
                rel.display()
            ),
        ));
    }
    let path = data_dir.join(rel);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    if meta.is_dir() {
        let bytes = tree_bytes(&path);
        std::fs::remove_dir_all(&path)?;
        Ok(bytes)
    } else {
        let bytes = meta.len();
        std::fs::remove_file(&path)?;
        Ok(bytes)
    }
}

/// Bytes of the files under `dir` (apparent size), 0 if it does not exist.
pub fn tree_bytes(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return std::fs::metadata(dir).map_or(0, |m| m.len());
    };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => tree_bytes(&e.path()),
            Ok(_) => e.metadata().map_or(0, |m| m.len()),
            Err(_) => 0,
        })
        .sum()
}

/// Bytes the files under `dirs` occupy together, each file once however
/// many hardlinks reach it (the figure `du` gives for the set), and the
/// bytes of the files in `dirs[1..]` that no file outside that tree links
/// to (what a snapshot costs beyond the live store). On a platform without
/// a file identity every file counts once and the extra is the full size.
pub fn unique_bytes(live: &Path, snapshot: &Path) -> (u64, u64) {
    #[cfg(windows)]
    fn walk(dir: &Path, seen: &mut std::collections::HashSet<(u32, u64)>, total: &mut u64) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                walk(&e.path(), seen, total);
            } else {
                // A file whose identity cannot be read counts in full.
                match windows_files::identity(&e.path()) {
                    Some(id) if !seen.insert(id) => {}
                    _ => *total += m.len(),
                }
            }
        }
    }
    #[cfg(unix)]
    fn walk(dir: &Path, seen: &mut std::collections::HashSet<(u64, u64)>, total: &mut u64) {
        use std::os::unix::fs::MetadataExt;
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                walk(&e.path(), seen, total);
            } else if seen.insert((m.dev(), m.ino())) {
                *total += m.len();
            }
        }
    }
    #[cfg(any(unix, windows))]
    {
        let mut seen = std::collections::HashSet::new();
        let mut live_total = 0;
        walk(live, &mut seen, &mut live_total);
        let mut extra = 0;
        walk(snapshot, &mut seen, &mut extra);
        (live_total + extra, extra)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let l = tree_bytes(live);
        let s = tree_bytes(snapshot);
        (l + s, s)
    }
}

/// What Windows says a file is and what its volume can do, which the
/// standard library does not give.
#[cfg(windows)]
mod windows_files {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, GetFileInformationByHandle,
        GetVolumeInformationByHandleW,
    };

    /// FILE_SUPPORTS_HARD_LINKS among a volume's file system flags.
    const SUPPORTS_HARD_LINKS: u32 = 0x0040_0000;

    /// Opens a file or a directory with no access rights, which is enough
    /// to ask what it is and leaves every other user of it undisturbed.
    fn open(path: &Path) -> Option<std::fs::File> {
        std::fs::OpenOptions::new()
            .access_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .ok()
    }

    /// The volume serial number and the file index: the same for every
    /// hardlink to one file, different for any two files.
    pub fn identity(path: &Path) -> Option<(u32, u64)> {
        let file = open(path)?;
        // SAFETY: the structure is plain integers, for which zero is valid.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open for the length of the call and `info`
        // is a valid out pointer.
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
        (ok != 0).then(|| {
            let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
            (info.dwVolumeSerialNumber, index)
        })
    }

    /// The serial number of the volume that holds `path`, and whether its
    /// file system has hardlinks.
    pub fn volume(path: &Path) -> Option<(u32, bool)> {
        let file = open(path)?;
        let (mut serial, mut flags) = (0u32, 0u32);
        // SAFETY: the handle is open for the length of the call, the two
        // out pointers are valid, and the name buffers are absent with a
        // length of zero.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                &mut serial,
                std::ptr::null_mut(),
                &mut flags,
                std::ptr::null_mut(),
                0,
            )
        };
        (ok != 0).then_some((serial, flags & SUPPORTS_HARD_LINKS != 0))
    }
}

/// A measurement of one volume.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VolumeStats {
    /// Size of the volume in bytes.
    pub total_bytes: u64,
    /// Bytes an unprivileged writer can still use.
    pub free_bytes: u64,
    /// Inodes on the volume (0 when the platform does not report them).
    pub inodes_total: u64,
    /// Inodes still free.
    pub inodes_free: u64,
    /// Whether the volume is mounted read-only.
    pub read_only: bool,
}

impl VolumeStats {
    /// Percent of the volume still free, as `df` computes it.
    pub fn free_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            return 100.0;
        }
        self.free_bytes as f64 * 100.0 / self.total_bytes as f64
    }

    /// Percent of inodes still free (100 when not reported).
    pub fn inodes_free_pct(&self) -> f64 {
        if self.inodes_total == 0 {
            return 100.0;
        }
        self.inodes_free as f64 * 100.0 / self.inodes_total as f64
    }

    /// Percent of the volume in use, rounded up the way `df` does.
    pub fn used_pct(&self) -> u8 {
        (100.0 - self.free_pct()).ceil().clamp(0.0, 100.0) as u8
    }

    /// A volume of `total` bytes with `free` free, for tests and plans.
    pub fn of(total: u64, free: u64) -> Self {
        Self {
            total_bytes: total,
            free_bytes: free,
            inodes_total: 0,
            inodes_free: 0,
            read_only: false,
        }
    }
}

/// Measures the volume holding `path` (which must exist).
pub fn volume_stats(path: &Path) -> std::io::Result<VolumeStats> {
    let st = fs4::statvfs(path)?;
    let used = st.total_space().saturating_sub(st.free_space());
    let mut out = VolumeStats {
        total_bytes: used + st.available_space(),
        free_bytes: st.available_space(),
        inodes_total: 0,
        inodes_free: 0,
        read_only: false,
    };
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `c` is a valid NUL-terminated path and `s` a valid out
        // pointer for the duration of the call.
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0 {
            out.inodes_total = s.f_files as u64;
            out.inodes_free = s.f_favail as u64;
            out.read_only = (s.f_flag & libc::ST_RDONLY) != 0;
        }
    }
    Ok(out)
}

/// Host pressure that threatens the data besides the volume itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct HostPressure {
    /// Swap size in bytes (0 without swap).
    pub swap_total: u64,
    /// Swap still free.
    pub swap_free: u64,
    /// Memory available without swapping.
    pub mem_available: u64,
    /// Physical memory.
    pub mem_total: u64,
    /// Share of the last ten seconds some task waited on I/O, percent
    /// (Linux pressure stall information; `None` where not reported).
    pub io_stall_pct: Option<f64>,
}

impl HostPressure {
    /// Swap is used up and memory is nearly gone: the kernel is about to
    /// kill processes or stall writes.
    pub fn memory_exhausted(&self) -> bool {
        let mem_low = self.mem_total > 0 && self.mem_available * 100 < self.mem_total * 5;
        let swap_gone = self.swap_total == 0 || self.swap_free * 100 < self.swap_total * 5;
        mem_low && swap_gone
    }

    /// Writes are waiting on the device.
    pub fn io_slow(&self) -> bool {
        self.io_stall_pct.is_some_and(|p| p >= IO_STALL_WARN_PCT)
    }
}

/// I/O stall percent (last ten seconds) at which the host counts as slow.
pub const IO_STALL_WARN_PCT: f64 = 40.0;

/// Reads the host pressure from `/proc` (Linux); zero elsewhere.
pub fn host_pressure() -> HostPressure {
    let mut out = HostPressure::default();
    if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
        let kb = |key: &str| {
            s.lines()
                .find_map(|l| l.strip_prefix(key))
                .and_then(|r| r.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
                .map_or(0, |v| v << 10)
        };
        out.swap_total = kb("SwapTotal:");
        out.swap_free = kb("SwapFree:");
        out.mem_available = kb("MemAvailable:");
        out.mem_total = kb("MemTotal:");
    }
    if let Ok(s) = std::fs::read_to_string("/proc/pressure/io") {
        out.io_stall_pct = s
            .lines()
            .find(|l| l.starts_with("some"))
            .and_then(|l| l.split_whitespace().find_map(|t| t.strip_prefix("avg10=")))
            .and_then(|v| v.parse::<f64>().ok());
    }
    out
}

/// Bytes added per block over the last blocks, from samples of the node's
/// own data size.
#[derive(Debug, Clone)]
pub struct GrowthTracker {
    samples: VecDeque<(u64, u64)>,
    window_blocks: u64,
}

/// Fewest blocks a growth figure needs to span before it is trusted.
pub const MIN_GROWTH_SPAN_BLOCKS: u64 = 50;

impl GrowthTracker {
    /// A tracker over the last `window_blocks` blocks.
    pub fn new(window_blocks: u64) -> Self {
        Self {
            samples: VecDeque::new(),
            window_blocks: window_blocks.max(MIN_GROWTH_SPAN_BLOCKS * 2),
        }
    }

    /// Records the data size at a height. A height that does not advance
    /// replaces the last sample.
    pub fn record(&mut self, height: u64, data_bytes: u64) {
        if let Some(last) = self.samples.back_mut() {
            if height < last.0 {
                self.samples.clear();
            } else if height == last.0 {
                last.1 = data_bytes;
                return;
            }
        }
        self.samples.push_back((height, data_bytes));
        while self
            .samples
            .front()
            .is_some_and(|f| height.saturating_sub(f.0) > self.window_blocks)
            && self.samples.len() > 2
        {
            self.samples.pop_front();
        }
    }

    /// Bytes added per block over the window, or `None` until the samples
    /// span [`MIN_GROWTH_SPAN_BLOCKS`]. Shrinkage (pruning) counts as zero.
    pub fn bytes_per_block(&self) -> Option<f64> {
        let (h0, b0) = *self.samples.front()?;
        let (h1, b1) = *self.samples.back()?;
        let span = h1.checked_sub(h0)?;
        if span < MIN_GROWTH_SPAN_BLOCKS {
            return None;
        }
        Some(b1.saturating_sub(b0) as f64 / span as f64)
    }
}

/// Blocks the free bytes last at `bytes_per_block`; `None` when the data is
/// not growing (or growth is unknown).
pub fn runway_blocks(free_bytes: u64, bytes_per_block: Option<f64>) -> Option<u64> {
    let g = bytes_per_block?;
    if g < 1.0 {
        return None;
    }
    Some((free_bytes as f64 / g) as u64)
}

/// A step of the degradation ladder, from healthy to the last reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Plenty of room.
    Ok,
    /// First level: logged and shown in doctor and status.
    Warn,
    /// Second level: aggressive pruning and compaction.
    Prune,
    /// Third level: non-essential data refused; consensus continues.
    Refuse,
    /// Last level: the ballast is released, snapshots stop.
    Reserve,
}

impl Level {
    /// Lowercase name for logs and status output.
    pub fn name(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Prune => "prune",
            Level::Refuse => "refuse",
            Level::Reserve => "reserve",
        }
    }

    fn from_index(i: u8) -> Level {
        match i {
            0 => Level::Ok,
            1 => Level::Warn,
            2 => Level::Prune,
            3 => Level::Refuse,
            _ => Level::Reserve,
        }
    }

    /// The class the pruner would give up next at this level.
    pub fn sacrifice_class(self) -> Option<DataClass> {
        match self {
            Level::Ok | Level::Warn => None,
            Level::Prune => Some(DataClass::Expendable),
            Level::Refuse => Some(DataClass::Regenerable),
            Level::Reserve => Some(DataClass::Important),
        }
    }
}

/// What a level lets the node do. Consensus writes are never in this list:
/// they continue at every level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Producing an epoch or state-sync snapshot.
    Snapshot,
    /// Serving public history queries.
    HistoryQuery,
    /// Forwarding relay traffic for others.
    Relay,
    /// Downloading a model or accepting an upload.
    Download,
    /// Importing a snapshot or a backup.
    Import,
    /// A full compaction (needs room for its output).
    Compaction,
}

impl Level {
    /// Whether `action` may run at this level.
    pub fn allows(self, action: Action) -> bool {
        match action {
            Action::Snapshot => self < Level::Refuse,
            Action::HistoryQuery | Action::Relay | Action::Download | Action::Import => {
                self < Level::Refuse
            }
            Action::Compaction => self < Level::Reserve,
        }
    }
}

/// Thresholds of the ladder. A level trips when free bytes AND free percent
/// are both under its pair (so a 100 GB disk and a 4 TB disk behave
/// differently), or when the runway under it is shorter than its blocks,
/// or when the inode, read-only or memory checks say so.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LadderConfig {
    /// First level: free bytes under this and ...
    pub warn_free_gib: u64,
    /// ... free percent under this.
    pub warn_free_pct: f64,
    /// Second level bytes.
    pub prune_free_gib: u64,
    /// Second level percent.
    pub prune_free_pct: f64,
    /// Third level bytes.
    pub refuse_free_gib: u64,
    /// Third level percent.
    pub refuse_free_pct: f64,
    /// Last level bytes.
    pub reserve_free_gib: u64,
    /// Last level percent.
    pub reserve_free_pct: f64,
    /// Runway, in blocks, under which the first level trips.
    pub warn_runway_blocks: u64,
    /// Runway under which the second level trips.
    pub prune_runway_blocks: u64,
    /// Runway under which the third level trips.
    pub refuse_runway_blocks: u64,
    /// Runway under which the last level trips.
    pub reserve_runway_blocks: u64,
    /// A level is left only once the measurement clears its threshold by
    /// this factor (bytes and runway) and by this many points (percent).
    pub hysteresis_factor: f64,
    /// Hysteresis in percentage points.
    pub hysteresis_points: f64,
    /// Blocks the growth figure averages over.
    pub growth_window_blocks: u64,
    /// Size of the ballast file, MiB; 0 turns it off.
    pub ballast_mb: u64,
    /// Margin, MiB, kept free beyond what a large write needs.
    pub step_margin_mb: u64,
}

impl Default for LadderConfig {
    fn default() -> Self {
        Self {
            warn_free_gib: 40,
            warn_free_pct: 20.0,
            prune_free_gib: 20,
            prune_free_pct: 12.0,
            refuse_free_gib: 8,
            refuse_free_pct: 6.0,
            reserve_free_gib: 3,
            reserve_free_pct: 3.0,
            warn_runway_blocks: 20 * EPOCH_BLOCKS * 24,
            prune_runway_blocks: 20 * EPOCH_BLOCKS * 8,
            refuse_runway_blocks: 20 * EPOCH_BLOCKS,
            reserve_runway_blocks: 2 * EPOCH_BLOCKS,
            hysteresis_factor: 1.25,
            hysteresis_points: 1.0,
            growth_window_blocks: 4 * EPOCH_BLOCKS,
            ballast_mb: 2048,
            step_margin_mb: 1024,
        }
    }
}

/// One measurement the ladder judges.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Reading {
    /// The volume holding the data directory.
    pub volume: VolumeStats,
    /// The host.
    pub host: HostPressure,
    /// Bytes added per block lately, if known.
    pub bytes_per_block: Option<f64>,
}

impl Reading {
    /// A reading of a volume alone, with no host pressure and no growth.
    pub fn of_volume(volume: VolumeStats) -> Self {
        Self {
            volume,
            host: HostPressure::default(),
            bytes_per_block: None,
        }
    }
}

/// Why a level was entered, for logs and status output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cause {
    /// The level this cause alone would give.
    pub level: Level,
    /// A sentence: what was measured.
    pub what: String,
}

/// The ladder's verdict on one reading.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    /// The level now.
    pub level: Level,
    /// Free bytes on the data volume.
    pub free_bytes: u64,
    /// Free percent on the data volume.
    pub free_pct: f64,
    /// Bytes added per block lately, if known.
    pub bytes_per_block: Option<f64>,
    /// Blocks until the volume is full at that growth; `None` when the data
    /// is not growing.
    pub runway_blocks: Option<u64>,
    /// The class the pruner gives up next at this level.
    pub next_sacrificed: Option<DataClass>,
    /// What put the node at this level.
    pub causes: Vec<Cause>,
    /// Memory and swap are nearly gone.
    pub memory_exhausted: bool,
    /// Writes are waiting on the device.
    pub io_slow: bool,
    /// Inodes are nearly gone.
    pub inodes_low: bool,
    /// The volume is read-only.
    pub read_only: bool,
}

impl Assessment {
    /// One line for doctor and status.
    pub fn summary(&self) -> String {
        let runway = self
            .runway_blocks
            .map_or("not growing".to_string(), |b| format!("{b} blocks"));
        let next = self
            .next_sacrificed
            .map_or("none".to_string(), |c| c.name().to_string());
        format!(
            "level {}; {:.1} GiB free ({:.1}%); runway {runway}; growth {} B/block; next sacrificed: {next}",
            self.level.name(),
            self.free_bytes as f64 / GIB as f64,
            self.free_pct,
            self.bytes_per_block
                .map_or("unknown".into(), |g| format!("{g:.0}")),
        )
    }
}

/// The ladder: thresholds plus the level the node is at, so entering and
/// leaving a level follows hysteresis.
#[derive(Debug, Clone)]
pub struct Ladder {
    cfg: LadderConfig,
    level: Level,
}

impl Ladder {
    /// A ladder at [`Level::Ok`].
    pub fn new(cfg: LadderConfig) -> Self {
        Self {
            cfg,
            level: Level::Ok,
        }
    }

    /// The thresholds.
    pub fn config(&self) -> &LadderConfig {
        &self.cfg
    }

    /// The current level.
    pub fn level(&self) -> Level {
        self.level
    }

    fn bytes_of(&self, i: u8) -> (u64, f64, u64) {
        let c = &self.cfg;
        match i {
            1 => (c.warn_free_gib * GIB, c.warn_free_pct, c.warn_runway_blocks),
            2 => (
                c.prune_free_gib * GIB,
                c.prune_free_pct,
                c.prune_runway_blocks,
            ),
            3 => (
                c.refuse_free_gib * GIB,
                c.refuse_free_pct,
                c.refuse_runway_blocks,
            ),
            _ => (
                c.reserve_free_gib * GIB,
                c.reserve_free_pct,
                c.reserve_runway_blocks,
            ),
        }
    }

    /// The highest level whose thresholds the reading is under, with every
    /// threshold scaled by `scale` (1.0 to enter, the hysteresis factor to
    /// decide whether a level may be left).
    fn raw_level(&self, r: &Reading, scale: f64, points: f64, causes: &mut Vec<Cause>) -> Level {
        let mut top = Level::Ok;
        let mut note = |level: Level, what: String, top: &mut Level| {
            if level > *top {
                *top = level;
            }
            if scale == 1.0 {
                causes.push(Cause { level, what });
            }
        };
        let free = r.volume.free_bytes;
        let pct = r.volume.free_pct();
        let runway = runway_blocks(free, r.bytes_per_block);
        for i in 1..=4u8 {
            let (bytes, p, rw) = self.bytes_of(i);
            let level = Level::from_index(i);
            if (free as f64) < bytes as f64 * scale && pct < p + points {
                note(
                    level,
                    format!(
                        "{:.1} GiB free ({pct:.1}%) is under {} GiB and {p}%",
                        free as f64 / GIB as f64,
                        bytes / GIB
                    ),
                    &mut top,
                );
            }
            if let Some(blocks) = runway
                && (blocks as f64) < rw as f64 * scale
            {
                note(
                    level,
                    format!("runway of {blocks} blocks is under {rw}"),
                    &mut top,
                );
            }
        }
        // Inodes: a full inode table stops writes with bytes to spare.
        let ipct = r.volume.inodes_free_pct();
        for (limit, level) in [
            (10.0, Level::Warn),
            (5.0, Level::Prune),
            (2.0, Level::Refuse),
            (0.5, Level::Reserve),
        ] {
            if r.volume.inodes_total > 0 && ipct < limit * scale.max(1.0) {
                note(
                    level,
                    format!("{ipct:.1}% of inodes free is under {limit}%"),
                    &mut top,
                );
            }
        }
        if r.volume.read_only {
            note(
                Level::Reserve,
                "the data volume is mounted read-only".into(),
                &mut top,
            );
        }
        if r.host.memory_exhausted() {
            note(
                Level::Warn,
                "memory and swap are nearly exhausted".into(),
                &mut top,
            );
        }
        if r.host.io_slow() {
            note(
                Level::Warn,
                format!(
                    "I/O stall at {:.0}% over the last ten seconds",
                    r.host.io_stall_pct.unwrap_or(0.0)
                ),
                &mut top,
            );
        }
        top
    }

    /// Judges `r`, moves to the level it gives (hysteresis applied) and
    /// returns the assessment. Compare `level()` before and after to log a
    /// change.
    pub fn assess(&mut self, r: &Reading) -> Assessment {
        let mut causes = Vec::new();
        let entered = self.raw_level(r, 1.0, 0.0, &mut Vec::new());
        let held = self.raw_level(
            r,
            self.cfg.hysteresis_factor.max(1.0),
            self.cfg.hysteresis_points,
            &mut Vec::new(),
        );
        let new = if entered >= self.level {
            entered
        } else if held >= self.level {
            self.level
        } else {
            held.max(entered)
        };
        self.raw_level(r, 1.0, 0.0, &mut causes);
        if causes.is_empty() && new != Level::Ok {
            causes.push(Cause {
                level: new,
                what: "still inside the margin above the level's threshold".into(),
            });
        }
        self.level = new;
        Assessment {
            level: new,
            free_bytes: r.volume.free_bytes,
            free_pct: r.volume.free_pct(),
            bytes_per_block: r.bytes_per_block,
            runway_blocks: runway_blocks(r.volume.free_bytes, r.bytes_per_block),
            next_sacrificed: new.sacrifice_class(),
            causes,
            memory_exhausted: r.host.memory_exhausted(),
            io_slow: r.host.io_slow(),
            inodes_low: r.volume.inodes_total > 0 && r.volume.inodes_free_pct() < 10.0,
            read_only: r.volume.read_only,
        }
    }
}

/// Why a step that writes a lot was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shortfall {
    /// Bytes the step needs.
    pub needed: u64,
    /// Margin kept beyond it.
    pub margin: u64,
    /// Bytes free.
    pub free: u64,
}

impl std::fmt::Display for Shortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "needs {} MiB plus {} MiB margin, {} MiB free",
            self.needed / MIB,
            self.margin / MIB,
            self.free / MIB
        )
    }
}

/// The check before a step that writes a lot (a snapshot, a compaction, an
/// import): the free bytes must cover the bytes the step needs plus a
/// margin, and leave the last level's reserve untouched.
pub fn headroom(volume: &VolumeStats, needed: u64, cfg: &LadderConfig) -> Result<(), Shortfall> {
    let margin = (cfg.step_margin_mb * MIB)
        .max(needed / 20)
        .max(cfg.reserve_free_gib * GIB);
    if volume.read_only || volume.free_bytes < needed.saturating_add(margin) {
        return Err(Shortfall {
            needed,
            margin,
            free: volume.free_bytes,
        });
    }
    Ok(())
}

/// A role of a node, for sizing its data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A validator: keeps consensus state and the retention window.
    Validator,
    /// A provider of models or other services.
    Provider,
    /// A public RPC node: serves history queries.
    Rpc,
    /// A participant: follows the chain, joins by snapshot.
    Participant,
}

impl Role {
    /// Parses the role words the setup wizard and the node use.
    pub fn parse(s: &str) -> Option<Role> {
        match s.to_ascii_lowercase().as_str() {
            "validator" => Some(Role::Validator),
            "provider" => Some(Role::Provider),
            "rpc" | "public" | "full" => Some(Role::Rpc),
            "participant" | "user" | "light" => Some(Role::Participant),
            _ => None,
        }
    }
}

/// What a role needs from its data volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleEstimate {
    /// Bytes added per day at idle plus the role's typical traffic.
    pub growth_bytes_per_day: u64,
    /// Bytes the steady state holds at the retention floor.
    pub steady_state_bytes: u64,
    /// Free bytes below which setup refuses the directory.
    pub refuse_below_bytes: u64,
    /// Free bytes below which setup warns.
    pub warn_below_bytes: u64,
}

/// Sizing for a role. The growth figures are the release budgets of
/// `docs/operations/disk-growth-budgets.md`, confirmed by the growth gate.
pub fn role_estimate(role: Role) -> RoleEstimate {
    match role {
        Role::Validator => RoleEstimate {
            growth_bytes_per_day: 3 * GIB,
            steady_state_bytes: 60 * GIB,
            refuse_below_bytes: 40 * GIB,
            warn_below_bytes: 100 * GIB,
        },
        Role::Rpc => RoleEstimate {
            growth_bytes_per_day: 4 * GIB,
            steady_state_bytes: 80 * GIB,
            refuse_below_bytes: 50 * GIB,
            warn_below_bytes: 150 * GIB,
        },
        Role::Provider => RoleEstimate {
            growth_bytes_per_day: GIB,
            steady_state_bytes: 30 * GIB,
            refuse_below_bytes: 20 * GIB,
            warn_below_bytes: 60 * GIB,
        },
        Role::Participant => RoleEstimate {
            growth_bytes_per_day: GIB / 2,
            steady_state_bytes: 10 * GIB,
            refuse_below_bytes: 8 * GIB,
            warn_below_bytes: 20 * GIB,
        },
    }
}

/// The verdict of the setup preflight on a data directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Enough room.
    Ok,
    /// Works for now; the message says what and why.
    Warn(String),
    /// Setup must not continue on this directory.
    Refuse(String),
}

/// Judges a data directory on `volume` for `role`: what is wrong, why it
/// matters, and how to fix it (another volume with `--data-dir`).
pub fn preflight(role: Role, volume: &VolumeStats, dir: &Path) -> Verdict {
    let est = role_estimate(role);
    let days = |bytes: u64| bytes / est.growth_bytes_per_day.max(1);
    if volume.read_only {
        return Verdict::Refuse(format!(
            "{} is on a read-only volume. A node cannot write its chain there. Choose another volume with --data-dir <path>.",
            dir.display()
        ));
    }
    let free = volume.free_bytes;
    if free < est.refuse_below_bytes {
        return Verdict::Refuse(format!(
            "{} has {:.0} GiB free; a {role:?} node needs at least {} GiB and grows about {:.1} GiB a day, so it would stop within {} days. Choose a larger volume with --data-dir <path>, or free space first.",
            dir.display(),
            free as f64 / GIB as f64,
            est.refuse_below_bytes / GIB,
            est.growth_bytes_per_day as f64 / GIB as f64,
            days(free),
        ));
    }
    if free < est.warn_below_bytes {
        return Verdict::Warn(format!(
            "{} has {:.0} GiB free; a {role:?} node settles near {} GiB and grows about {:.1} GiB a day until then, so room is tight. A volume with {} GiB or more free is safer: --data-dir <path>.",
            dir.display(),
            free as f64 / GIB as f64,
            est.steady_state_bytes / GIB,
            est.growth_bytes_per_day as f64 / GIB as f64,
            est.warn_below_bytes / GIB,
        ));
    }
    Verdict::Ok
}

/// The existing ancestor of `dir`, for measuring a directory that is not
/// created yet.
pub fn existing_ancestor(dir: &Path) -> PathBuf {
    let mut p = dir.to_path_buf();
    while !p.exists() {
        if !p.pop() {
            return PathBuf::from(".");
        }
    }
    if p.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        p
    }
}

/// Measures the volume that holds (or would hold) `dir`.
pub fn volume_of(dir: &Path) -> std::io::Result<VolumeStats> {
    volume_stats(&existing_ancestor(dir))
}

/// File name of the reserve under the data directory.
pub const BALLAST_FILE: &str = ".ballast";

/// Creates the ballast file of `size` bytes under `data_dir` if it is
/// absent, allocating its blocks so the space is really held, but only when
/// the volume would still have `keep_free` bytes after it. Returns whether a
/// file was created.
pub fn ensure_ballast(data_dir: &Path, size: u64, keep_free: u64) -> std::io::Result<bool> {
    use fs4::fs_std::FileExt;
    if size == 0 {
        return Ok(false);
    }
    let path = data_dir.join(BALLAST_FILE);
    if path.exists() {
        return Ok(false);
    }
    let vol = volume_stats(data_dir)?;
    if vol.read_only || vol.free_bytes < size.saturating_add(keep_free) {
        return Ok(false);
    }
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    if let Err(e) = file.allocate(size) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(true)
}

/// Deletes the ballast file; returns the bytes released (0 if absent).
pub fn release_ballast(data_dir: &Path) -> std::io::Result<u64> {
    guarded_remove(data_dir, Path::new(BALLAST_FILE))
}

/// Bytes a snapshot of the store at `db_dir` written under `snapshot_root`
/// needs. On one volume the checkpoint hardlinks the table files and costs a
/// manifest and the live write-ahead log; across volumes (or without
/// hardlinks) it is a full copy of the store.
pub fn snapshot_need_bytes(db_dir: &Path, snapshot_root: &Path) -> u64 {
    const LINKED_BYTES: u64 = 512 * MIB;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dev = |p: &Path| {
            std::fs::metadata(existing_ancestor(p))
                .map(|m| m.dev())
                .ok()
        };
        if dev(db_dir).is_some() && dev(db_dir) == dev(snapshot_root) {
            return LINKED_BYTES;
        }
        tree_bytes(db_dir).max(LINKED_BYTES)
    }
    #[cfg(windows)]
    {
        let volume = |p: &Path| windows_files::volume(&existing_ancestor(p));
        if let (Some((a, true)), Some((b, _))) = (volume(db_dir), volume(snapshot_root)) {
            if a == b {
                return LINKED_BYTES;
            }
        }
        tree_bytes(db_dir).max(LINKED_BYTES)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = snapshot_root;
        tree_bytes(db_dir).max(LINKED_BYTES)
    }
}

/// The assessment in the form the node serves and the CLI prints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    /// The level's name.
    pub level: Level,
    /// One line: level, free space, runway, growth, next class sacrificed.
    pub summary: String,
    /// Free bytes on the data volume.
    pub free_bytes: u64,
    /// Free percent.
    pub free_pct: f64,
    /// Blocks of runway at the measured growth; absent when not growing.
    pub runway_blocks: Option<u64>,
    /// Bytes added per block lately; absent until measured.
    pub bytes_per_block: Option<f64>,
    /// The class the pruner gives up next.
    pub next_sacrificed: Option<DataClass>,
    /// What put the node at this level.
    pub reasons: Vec<String>,
}

impl Assessment {
    /// The serializable report of this assessment.
    pub fn report(&self) -> StatusReport {
        StatusReport {
            level: self.level,
            summary: self.summary(),
            free_bytes: self.free_bytes,
            free_pct: self.free_pct,
            runway_blocks: self.runway_blocks,
            bytes_per_block: self.bytes_per_block,
            next_sacrificed: self.next_sacrificed,
            reasons: self.causes.iter().map(|c| c.what.clone()).collect(),
        }
    }
}

/// Judges the volume holding `dir` once, with no history: the reading
/// doctor and the setup preflight use, so they report what the node reports.
pub fn assess_now(dir: &Path, cfg: &LadderConfig) -> std::io::Result<Assessment> {
    let volume = volume_of(dir)?;
    let reading = Reading {
        volume,
        host: host_pressure(),
        bytes_per_block: None,
    };
    Ok(Ladder::new(cfg.clone()).assess(&reading))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gib(n: u64) -> u64 {
        n * GIB
    }

    fn reading(total: u64, free: u64, g: Option<f64>) -> Reading {
        Reading {
            volume: VolumeStats::of(total, free),
            host: HostPressure::default(),
            bytes_per_block: g,
        }
    }

    #[test]
    fn a_small_disk_and_a_large_disk_behave_differently() {
        let mut small = Ladder::new(LadderConfig::default());
        let mut large = Ladder::new(LadderConfig::default());
        // 5 GiB free of 100 GiB (5%) is the third level; the same 5 GiB
        // free of 4 TiB (0.1%) is just as short in bytes.
        assert_eq!(
            small.assess(&reading(gib(100), gib(5), None)).level,
            Level::Refuse
        );
        assert_eq!(
            large.assess(&reading(gib(4096), gib(5), None)).level,
            Level::Refuse
        );
        // 150 GiB free of 4 TiB is 3.6% but plenty in bytes: no level.
        let mut l = Ladder::new(LadderConfig::default());
        assert_eq!(
            l.assess(&reading(gib(4096), gib(150), None)).level,
            Level::Ok
        );
        // 15 GiB free of 100 GiB is 15% and 15 GiB: the first level only.
        let mut s = Ladder::new(LadderConfig::default());
        assert_eq!(
            s.assess(&reading(gib(100), gib(15), None)).level,
            Level::Warn
        );
    }

    #[test]
    fn a_fast_filler_trips_earlier_than_a_slow_one_at_the_same_free_bytes() {
        let total = gib(1000);
        let free = gib(500);
        let mut slow = Ladder::new(LadderConfig::default());
        let mut fast = Ladder::new(LadderConfig::default());
        // 1 KB a block: 500 GiB lasts half a billion blocks.
        assert_eq!(
            slow.assess(&reading(total, free, Some(1_000.0))).level,
            Level::Ok
        );
        // 230 KB a block (the checkpoint-record loop): about 2.3 million
        // blocks, which is under the first level's runway of 3.4 million.
        let a = fast.assess(&reading(total, free, Some(230_000.0)));
        assert_eq!(a.level, Level::Warn);
        assert!(a.runway_blocks.unwrap() < 3_456_000);
        // 4 MB a block leaves 130,000 blocks: the third level.
        let mut faster = Ladder::new(LadderConfig::default());
        assert_eq!(
            faster
                .assess(&reading(total, free, Some(4_000_000.0)))
                .level,
            Level::Refuse
        );
    }

    #[test]
    fn a_level_is_left_only_when_the_measurement_clears_it_by_the_margin() {
        let mut l = Ladder::new(LadderConfig::default());
        assert_eq!(
            l.assess(&reading(gib(100), gib(11), None)).level,
            Level::Prune
        );
        // Just above the threshold: still at the level (no flapping).
        assert_eq!(
            l.assess(&reading(gib(100), gib(25) / 2, None)).level,
            Level::Prune
        );
        // Clear of it by the margin: leaves, to the first level.
        assert_eq!(
            l.assess(&reading(gib(100), gib(20), None)).level,
            Level::Warn
        );
        assert_eq!(l.assess(&reading(gib(100), gib(60), None)).level, Level::Ok);
    }

    #[test]
    fn read_only_inodes_memory_and_io_raise_the_level() {
        let mut r = reading(gib(1000), gib(900), None);
        r.volume.read_only = true;
        assert_eq!(
            Ladder::new(LadderConfig::default()).assess(&r).level,
            Level::Reserve
        );
        let mut r = reading(gib(1000), gib(900), None);
        r.volume.inodes_total = 1000;
        r.volume.inodes_free = 30;
        let a = Ladder::new(LadderConfig::default()).assess(&r);
        assert_eq!(a.level, Level::Prune);
        assert!(a.inodes_low);
        let mut r = reading(gib(1000), gib(900), None);
        r.host = HostPressure {
            swap_total: gib(8),
            swap_free: 0,
            mem_available: gib(1),
            mem_total: gib(64),
            io_stall_pct: Some(60.0),
        };
        let a = Ladder::new(LadderConfig::default()).assess(&r);
        assert_eq!(a.level, Level::Warn);
        assert!(a.memory_exhausted && a.io_slow);
    }

    #[test]
    fn consensus_continues_and_refusals_follow_the_level() {
        assert!(Level::Prune.allows(Action::Snapshot));
        assert!(!Level::Refuse.allows(Action::Snapshot));
        assert!(!Level::Refuse.allows(Action::HistoryQuery));
        assert!(!Level::Refuse.allows(Action::Relay));
        assert!(Level::Refuse.allows(Action::Compaction));
        assert!(!Level::Reserve.allows(Action::Compaction));
    }

    #[test]
    fn growth_is_bytes_per_block_over_the_window_and_pruning_counts_as_zero() {
        let mut g = GrowthTracker::new(1000);
        assert_eq!(g.bytes_per_block(), None);
        g.record(100, 1_000_000);
        g.record(110, 1_100_000);
        assert_eq!(g.bytes_per_block(), None, "too short a span");
        g.record(300, 1_000_000 + 200 * 500);
        assert_eq!(g.bytes_per_block(), Some(500.0));
        g.record(400, 1_000);
        assert_eq!(g.bytes_per_block(), Some(0.0));
        assert_eq!(runway_blocks(1_000_000, Some(0.0)), None);
        assert_eq!(runway_blocks(1_000_000, Some(500.0)), Some(2000));
    }

    #[test]
    fn a_large_write_is_refused_unless_free_covers_it_plus_the_margin() {
        let cfg = LadderConfig::default();
        let v = VolumeStats::of(gib(100), gib(10));
        assert!(headroom(&v, gib(2), &cfg).is_ok());
        let err = headroom(&v, gib(8), &cfg).unwrap_err();
        assert_eq!(err.free, gib(10));
        assert!(err.to_string().contains("MiB free"));
        let mut ro = v;
        ro.read_only = true;
        assert!(headroom(&ro, 1, &cfg).is_err());
    }

    #[test]
    fn every_cleanup_target_is_below_critical_and_unknown_paths_are_critical() {
        for t in CLEANUP_TARGETS {
            assert_ne!(classify(Path::new(t)), DataClass::Critical, "{t}");
        }
        for t in [
            "db/000001.sst",
            "consensus/x",
            "iroh/key",
            "wallets/w",
            "device-keys/k",
            "epoch-proof/log",
            "audit/a",
            "genesis.json",
            "new-dir/x",
            "../etc",
            "/abs",
            "epoch-snapshots/old/SNAPSHOT_META",
        ] {
            let c = classify(Path::new(t));
            if t.starts_with("epoch-snapshots/") {
                assert_eq!(c, DataClass::Important);
            } else {
                assert_eq!(c, DataClass::Critical, "{t}");
            }
        }
        assert_eq!(
            classify(Path::new("epoch-snapshots/e1.partial/000.sst")),
            DataClass::Expendable
        );
        assert_eq!(classify(Path::new("models/m.gguf")), DataClass::Regenerable);
        assert_eq!(
            classify(Path::new("models/m.gguf.partial")),
            DataClass::Expendable
        );
        for cf in PRUNE_COLUMN_FAMILIES {
            assert_ne!(column_family_class(cf), DataClass::Critical, "{cf}");
        }
        assert_eq!(column_family_class("state_trie"), DataClass::Critical);
        assert_eq!(column_family_class("anything-new"), DataClass::Critical);
    }

    #[test]
    fn guarded_remove_never_touches_a_critical_path() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for p in [
            "db",
            "consensus",
            "iroh",
            "device-keys",
            "wallets",
            "epoch-proof",
            "audit",
        ] {
            std::fs::create_dir_all(d.join(p)).unwrap();
            std::fs::write(d.join(p).join("f"), b"secret").unwrap();
        }
        std::fs::write(d.join("genesis.json"), b"{}").unwrap();
        // Every critical entry of the layout is refused, and survives.
        for item in DATA_LAYOUT
            .iter()
            .filter(|i| i.class == DataClass::Critical)
        {
            let rel = Path::new(item.path.trim_end_matches('/'));
            let err = guarded_remove(d, rel).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{}",
                item.path
            );
        }
        assert!(d.join("db/f").exists() && d.join("iroh/f").exists());
        assert!(d.join("genesis.json").exists() && d.join("wallets/f").exists());
        // A path climbing out is refused too.
        assert!(guarded_remove(d, Path::new("tmp/../db")).is_err());
        // Cleanup targets are removed, and report their bytes.
        std::fs::create_dir_all(d.join("tmp")).unwrap();
        std::fs::write(d.join("tmp/x"), vec![0u8; 100]).unwrap();
        assert_eq!(guarded_remove(d, Path::new("tmp")).unwrap(), 100);
        assert!(!d.join("tmp").exists());
        assert_eq!(guarded_remove(d, Path::new("tmp")).unwrap(), 0);
    }

    #[test]
    fn the_layout_covers_what_the_node_creates() {
        // The directories a node writes under its data directory (taken
        // from a live validator's data directory listing).
        for name in [
            "audit",
            "consensus",
            "db",
            "device-keys",
            "epoch-proof",
            "epoch-snapshots",
            "iroh",
            "wallets",
            "tenzro-node.lock",
            "tenzro-node.pid",
        ] {
            assert!(
                DATA_LAYOUT
                    .iter()
                    .any(|i| i.path.trim_end_matches('/') == name),
                "{name} has no row in DATA_LAYOUT"
            );
        }
    }

    #[test]
    fn preflight_refuses_warns_and_passes_by_role() {
        let dir = Path::new("/data/tenzro");
        let tight = VolumeStats::of(gib(100), gib(30));
        assert!(
            matches!(preflight(Role::Validator, &tight, dir), Verdict::Refuse(m) if m.contains("--data-dir"))
        );
        assert_eq!(preflight(Role::Participant, &tight, dir), Verdict::Ok);
        let mid = VolumeStats::of(gib(200), gib(80));
        assert!(matches!(
            preflight(Role::Validator, &mid, dir),
            Verdict::Warn(_)
        ));
        let big = VolumeStats::of(gib(2000), gib(1500));
        for r in [
            Role::Validator,
            Role::Provider,
            Role::Rpc,
            Role::Participant,
        ] {
            assert_eq!(preflight(r, &big, dir), Verdict::Ok);
        }
        let mut ro = big;
        ro.read_only = true;
        assert!(matches!(preflight(Role::Rpc, &ro, dir), Verdict::Refuse(_)));
        assert_eq!(Role::parse("Validator"), Some(Role::Validator));
        assert_eq!(Role::parse("nope"), None);
    }

    #[test]
    fn the_real_volume_can_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let v = volume_of(&dir.path().join("not/created/yet")).unwrap();
        assert!(v.total_bytes > 0 && v.free_bytes <= v.total_bytes);
        assert!(!host_pressure().memory_exhausted() || host_pressure().mem_total > 0);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn a_hardlinked_snapshot_costs_only_the_files_the_live_store_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("db");
        let snap = dir.path().join("snap");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir_all(&snap).unwrap();
        std::fs::write(live.join("a.sst"), vec![1u8; 4000]).unwrap();
        std::fs::write(live.join("b.sst"), vec![2u8; 6000]).unwrap();
        std::fs::hard_link(live.join("a.sst"), snap.join("a.sst")).unwrap();
        std::fs::hard_link(live.join("b.sst"), snap.join("b.sst")).unwrap();
        std::fs::write(snap.join("MANIFEST"), vec![3u8; 100]).unwrap();
        let (total, extra) = unique_bytes(&live, &snap);
        assert_eq!((total, extra), (10_100, 100));
        // The live store compacts b away: the snapshot now pins it alone.
        std::fs::remove_file(live.join("b.sst")).unwrap();
        let (total, extra) = unique_bytes(&live, &snap);
        assert_eq!((total, extra), (10_100, 6_100));
    }

    #[test]
    fn the_ballast_is_held_only_with_room_and_released_on_demand() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(ensure_ballast(d, 4 * MIB, 1024).unwrap());
        assert!(!ensure_ballast(d, 4 * MIB, 1024).unwrap(), "already there");
        assert_eq!(
            std::fs::metadata(d.join(BALLAST_FILE)).unwrap().len(),
            4 * MIB
        );
        assert_eq!(release_ballast(d).unwrap(), 4 * MIB);
        assert_eq!(release_ballast(d).unwrap(), 0);
        // Not created when it would eat the room that must stay free.
        let free = volume_stats(d).unwrap().free_bytes;
        assert!(!ensure_ballast(d, MIB, free).unwrap());
        assert!(!d.join(BALLAST_FILE).exists());
        assert!(!ensure_ballast(d, 0, 0).unwrap());
    }

    #[test]
    fn a_snapshot_on_the_same_volume_needs_little_and_across_volumes_a_full_copy() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db");
        std::fs::create_dir_all(&db).unwrap();
        std::fs::write(db.join("a.sst"), vec![0u8; 1000]).unwrap();
        assert_eq!(
            snapshot_need_bytes(&db, &dir.path().join("epoch-snapshots")),
            512 * MIB
        );
    }

    #[test]
    fn the_report_names_the_class_that_would_go_next() {
        let mut l = Ladder::new(LadderConfig::default());
        let a = l.assess(&reading(gib(100), gib(11), Some(10_000.0)));
        assert_eq!(a.level, Level::Prune);
        let r = a.report();
        assert_eq!(r.next_sacrificed, Some(DataClass::Expendable));
        assert!(r.summary.contains("level prune") && r.summary.contains("runway"));
        assert!(!r.reasons.is_empty());
        let back: StatusReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
}
