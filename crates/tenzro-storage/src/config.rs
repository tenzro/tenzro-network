//! Storage configuration for Tenzro Network
//!
//! This module provides configuration options for the storage layer.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to the database directory
    pub db_path: PathBuf,

    /// Memory the store may hold, in bytes: the block cache, with every
    /// column family's memtables charged against it, so reads and writes
    /// draw from one limit (default: 512 MiB). The node takes this figure
    /// from its memory budget.
    pub memory_bytes: usize,

    /// Bytes per second compaction and flush may write (default: 64 MiB/s).
    /// Background I/O is paced so it never starves the writes consensus
    /// waits on.
    pub background_write_bytes_per_sec: i64,

    /// Background flush and compaction jobs (default: 2). Compaction runs
    /// at idle CPU and I/O priority.
    pub background_jobs: i32,

    /// Enable compression
    pub compression: bool,

    /// Maximum open files (default: 1000)
    pub max_open_files: i32,

    /// Write buffer size in bytes (default: 64 MB)
    pub write_buffer_size: usize,

    /// Maximum write buffer number (default: 3)
    pub max_write_buffer_number: i32,

    /// Target file size base in bytes (default: 64 MB)
    pub target_file_size_base: u64,

    /// Enable statistics
    pub enable_statistics: bool,

    /// Enable WAL (Write-Ahead Log)
    pub enable_wal: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: tenzro_types::paths::default_data_dir().join("db"),
            memory_bytes: 512 * 1024 * 1024,
            background_write_bytes_per_sec: 64 * 1024 * 1024,
            background_jobs: 2,
            compression: true,
            max_open_files: 1000,
            write_buffer_size: 64 * 1024 * 1024, // 64 MB
            max_write_buffer_number: 3,
            target_file_size_base: 64 * 1024 * 1024, // 64 MB
            enable_statistics: false,
            enable_wal: true,
        }
    }
}

impl StorageConfig {
    /// Creates a new storage configuration with the given database path
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            ..Default::default()
        }
    }

    /// Sets the memory the store may hold (block cache plus memtables).
    pub fn with_memory_bytes(mut self, bytes: usize) -> Self {
        self.memory_bytes = bytes;
        self
    }

    /// Sets the background write rate for compaction and flush.
    pub fn with_background_write_rate(mut self, bytes_per_sec: i64) -> Self {
        self.background_write_bytes_per_sec = bytes_per_sec;
        self
    }

    /// Sets compression enabled/disabled
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression = enabled;
        self
    }

    /// Sets the maximum number of open files
    pub fn with_max_open_files(mut self, max: i32) -> Self {
        self.max_open_files = max;
        self
    }

    /// Sets the write buffer size
    pub fn with_write_buffer_size(mut self, size: usize) -> Self {
        self.write_buffer_size = size;
        self
    }

    /// Enables or disables WAL
    pub fn with_wal(mut self, enabled: bool) -> Self {
        self.enable_wal = enabled;
        self
    }
}
