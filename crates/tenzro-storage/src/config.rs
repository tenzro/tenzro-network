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

    /// Cache size in bytes (default: 512 MB)
    pub cache_size: usize,

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

    /// Snapshot retention count
    pub snapshot_retention: u64,

    /// Enable WAL (Write-Ahead Log)
    pub enable_wal: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: tenzro_types::paths::default_data_dir().join("db"),
            cache_size: 512 * 1024 * 1024, // 512 MB
            compression: true,
            max_open_files: 1000,
            write_buffer_size: 64 * 1024 * 1024, // 64 MB
            max_write_buffer_number: 3,
            target_file_size_base: 64 * 1024 * 1024, // 64 MB
            enable_statistics: false,
            snapshot_retention: 100,
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

    /// Sets the cache size
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
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

    /// Sets snapshot retention count
    pub fn with_snapshot_retention(mut self, count: u64) -> Self {
        self.snapshot_retention = count;
        self
    }

    /// Enables or disables WAL
    pub fn with_wal(mut self, enabled: bool) -> Self {
        self.enable_wal = enabled;
        self
    }
}
