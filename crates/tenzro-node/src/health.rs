//! Health monitoring for node subsystems

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::Instant;
use tenzro_types::primitives::BlockHeight;

/// Health monitor for tracking subsystem status
#[derive(Clone)]
pub struct HealthMonitor {
    inner: Arc<RwLock<HealthMonitorInner>>,
}

struct HealthMonitorInner {
    subsystem_status: HashMap<String, SubsystemHealth>,
    start_time: Instant,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HealthMonitorInner {
                subsystem_status: HashMap::new(),
                start_time: Instant::now(),
            })),
        }
    }

    /// Update health status for a subsystem
    pub fn update_subsystem(&self, name: impl Into<String>, status: SubsystemStatus) {
        let mut inner = self.inner.write();
        let name = name.into();

        let status_clone = status.clone();
        inner.subsystem_status
            .entry(name.clone())
            .and_modify(|h| {
                h.status = status_clone;
                h.last_updated = Instant::now();
            })
            .or_insert_with(|| SubsystemHealth {
                name,
                status,
                last_updated: Instant::now(),
            });
    }

    /// Mark a subsystem as healthy
    pub fn mark_healthy(&self, name: impl Into<String>) {
        self.update_subsystem(name, SubsystemStatus::Healthy);
    }

    /// Mark a subsystem as degraded
    pub fn mark_degraded(&self, name: impl Into<String>, reason: String) {
        self.update_subsystem(name, SubsystemStatus::Degraded { reason });
    }

    /// Mark a subsystem as unhealthy
    pub fn mark_unhealthy(&self, name: impl Into<String>, reason: String) {
        self.update_subsystem(name, SubsystemStatus::Unhealthy { reason });
    }

    /// Check overall health status
    pub fn check_health(&self) -> OverallHealth {
        let inner = self.inner.read();

        let mut healthy_count = 0;
        let mut degraded_count = 0;
        let mut unhealthy_count = 0;

        for health in inner.subsystem_status.values() {
            match health.status {
                SubsystemStatus::Healthy => healthy_count += 1,
                SubsystemStatus::Degraded { .. } => degraded_count += 1,
                SubsystemStatus::Unhealthy { .. } => unhealthy_count += 1,
            }
        }

        if unhealthy_count > 0 {
            OverallHealth::Unhealthy
        } else if degraded_count > 0 {
            OverallHealth::Degraded
        } else if healthy_count > 0 {
            OverallHealth::Healthy
        } else {
            OverallHealth::Unknown
        }
    }

    /// Get full health status report
    pub fn get_status(&self, block_height: BlockHeight, peer_count: usize) -> HealthStatus {
        let inner = self.inner.read();
        let uptime = inner.start_time.elapsed().as_secs();
        let overall = self.check_health();

        let subsystems: HashMap<String, SubsystemStatus> = inner
            .subsystem_status
            .iter()
            .map(|(name, health)| (name.clone(), health.status.clone()))
            .collect();

        HealthStatus {
            overall,
            subsystems,
            uptime_secs: uptime,
            block_height,
            peer_count,
        }
    }

    /// Check whether a specific subsystem is OK (Healthy or Degraded — i.e. not Unhealthy).
    ///
    /// Returns `true` if the subsystem is unregistered (absent ≠ broken — many
    /// optional subsystems like TEE may never register on hardware that lacks them).
    /// Returns `false` only if the subsystem is explicitly `Unhealthy`.
    pub fn subsystem_is_ok(&self, name: &str) -> bool {
        let inner = self.inner.read();
        match inner.subsystem_status.get(name) {
            Some(h) => !matches!(h.status, SubsystemStatus::Unhealthy { .. }),
            None => true,
        }
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Overall health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverallHealth {
    /// All subsystems are healthy
    Healthy,

    /// Some subsystems are degraded but functional
    Degraded,

    /// One or more subsystems are unhealthy
    Unhealthy,

    /// Health status unknown (no subsystems registered)
    Unknown,
}

/// Health status for an individual subsystem
#[derive(Debug, Clone)]
struct SubsystemHealth {
    /// Subsystem name (duplicates HashMap key but useful for Debug output)
    #[allow(dead_code)]
    name: String,
    status: SubsystemStatus,
    last_updated: Instant,
}

/// Subsystem status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum SubsystemStatus {
    /// Subsystem is operating normally
    Healthy,

    /// Subsystem is degraded but operational
    Degraded { reason: String },

    /// Subsystem is not functional
    Unhealthy { reason: String },
}

/// Complete health status report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health
    pub overall: OverallHealth,

    /// Per-subsystem health
    pub subsystems: HashMap<String, SubsystemStatus>,

    /// Node uptime in seconds
    pub uptime_secs: u64,

    /// Current block height
    pub block_height: BlockHeight,

    /// Number of connected peers
    pub peer_count: usize,
}

impl HealthStatus {
    /// Check if the node is ready to serve requests
    pub fn is_ready(&self) -> bool {
        matches!(
            self.overall,
            OverallHealth::Healthy | OverallHealth::Degraded
        )
    }

    /// Get a human-readable status message
    pub fn status_message(&self) -> String {
        match self.overall {
            OverallHealth::Healthy => "All systems operational".to_string(),
            OverallHealth::Degraded => {
                let degraded: Vec<_> = self
                    .subsystems
                    .iter()
                    .filter_map(|(name, status)| match status {
                        SubsystemStatus::Degraded { reason } => {
                            Some(format!("{}: {}", name, reason))
                        }
                        _ => None,
                    })
                    .collect();
                format!("Degraded: {}", degraded.join(", "))
            }
            OverallHealth::Unhealthy => {
                let unhealthy: Vec<_> = self
                    .subsystems
                    .iter()
                    .filter_map(|(name, status)| match status {
                        SubsystemStatus::Unhealthy { reason } => {
                            Some(format!("{}: {}", name, reason))
                        }
                        _ => None,
                    })
                    .collect();
                format!("Unhealthy: {}", unhealthy.join(", "))
            }
            OverallHealth::Unknown => "Status unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_monitor() {
        let monitor = HealthMonitor::new();

        // Initially unknown
        assert_eq!(monitor.check_health(), OverallHealth::Unknown);

        // Mark network as healthy
        monitor.mark_healthy("network");
        assert_eq!(monitor.check_health(), OverallHealth::Healthy);

        // Mark storage as degraded
        monitor.mark_degraded("storage", "High latency".to_string());
        assert_eq!(monitor.check_health(), OverallHealth::Degraded);

        // Mark consensus as unhealthy
        monitor.mark_unhealthy("consensus", "Cannot reach quorum".to_string());
        assert_eq!(monitor.check_health(), OverallHealth::Unhealthy);
    }

    #[test]
    fn test_subsystem_is_ok() {
        let monitor = HealthMonitor::new();

        // Unregistered subsystem is treated as OK (absent ≠ broken).
        assert!(monitor.subsystem_is_ok("tee"));

        // Healthy → OK.
        monitor.mark_healthy("auth");
        assert!(monitor.subsystem_is_ok("auth"));

        // Degraded → still OK (functional, just impaired).
        monitor.mark_degraded("tee", "No TEE hardware".to_string());
        assert!(monitor.subsystem_is_ok("tee"));

        // Unhealthy → not OK.
        monitor.mark_unhealthy("storage", "Disk full".to_string());
        assert!(!monitor.subsystem_is_ok("storage"));
    }

    #[test]
    fn test_health_status_ready() {
        let status = HealthStatus {
            overall: OverallHealth::Healthy,
            subsystems: HashMap::new(),
            uptime_secs: 100,
            block_height: BlockHeight::from(10),
            peer_count: 5,
        };
        assert!(status.is_ready());

        let status = HealthStatus {
            overall: OverallHealth::Degraded,
            subsystems: HashMap::new(),
            uptime_secs: 100,
            block_height: BlockHeight::from(10),
            peer_count: 5,
        };
        assert!(status.is_ready());

        let status = HealthStatus {
            overall: OverallHealth::Unhealthy,
            subsystems: HashMap::new(),
            uptime_secs: 100,
            block_height: BlockHeight::from(10),
            peer_count: 5,
        };
        assert!(!status.is_ready());
    }

    #[test]
    fn test_status_message() {
        let mut subsystems = HashMap::new();
        subsystems.insert(
            "network".to_string(),
            SubsystemStatus::Degraded {
                reason: "Few peers".to_string(),
            },
        );

        let status = HealthStatus {
            overall: OverallHealth::Degraded,
            subsystems,
            uptime_secs: 100,
            block_height: BlockHeight::from(10),
            peer_count: 2,
        };

        let message = status.status_message();
        assert!(message.contains("Degraded"));
        assert!(message.contains("network"));
    }
}
