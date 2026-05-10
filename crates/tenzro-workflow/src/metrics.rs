//! Operational metrics for the workflow subsystem.
//!
//! `OperationalMetrics` is a *snapshot* projection of the in-memory
//! `WorkflowManager` indices into Prometheus-compatible counters and
//! gauges. It is computed on demand — no hot-path mutation, no atomic
//! counters incremented per event. The render is exposed on the node's
//! `/metrics` axum endpoint and consumed by the Tenzro Grafana board.
//!
//! ## Why snapshot, not stream
//!
//! The manager already holds the authoritative per-status indices
//! (`by_status`, plus the in-memory `obligations`/`requests` maps).
//! Re-deriving the counts on each scrape costs O(N_workflows + N_obligations)
//! which at testnet scale (≤ 10k live workflows) is well under a
//! millisecond. Stream mutation would force every workflow/obligation
//! state transition through an extra atomic + risk drift between the
//! counters and the actual storage.
//!
//! ## Surface
//!
//! - `tenzro_workflow_workflows_total{status="..."}` — gauge per status
//! - `tenzro_workflow_obligations_total{status="..."}` — gauge per status
//! - `tenzro_workflow_approvals_total{status="..."}` — gauge per status
//! - `tenzro_workflow_signatures_collected_total` — gauge (sum across active workflows)
//! - `tenzro_workflow_canton_mirrored_total` — gauge (workflows with `canton_mirror.is_some()`)

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Snapshot of operational counters derived from the workflow manager.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationalMetrics {
    /// `status_label → count`. Status labels are the lower-snake-case
    /// `WorkflowStatus::as_str()` values: `"draft"`, `"awaiting_signatures"`,
    /// `"active"`, `"suspended"`, `"settling"`, `"completed"`, `"failed"`,
    /// `"disputed"`, `"cancelled"`. BTreeMap so the rendered output is
    /// deterministic.
    pub workflows_by_status: BTreeMap<String, u64>,
    /// `obligation_status_label → count`. Labels: `"pending"`,
    /// `"in_progress"`, `"discharged"`, `"defaulted"`, `"forgiven"`.
    pub obligations_by_status: BTreeMap<String, u64>,
    /// `approval_status_label → count`. Labels: `"open"`, `"approved"`,
    /// `"rejected"`, `"timed_out"`.
    pub approvals_by_status: BTreeMap<String, u64>,
    /// Total participant signatures collected across all active workflows.
    pub signatures_collected_total: u64,
    /// Workflows with a non-`None` `canton_mirror`.
    pub canton_mirrored_total: u64,
    /// Total registered fee routes.
    pub fee_routes_total: u64,
    /// Total registered privacy domains.
    pub privacy_domains_total: u64,
}

impl OperationalMetrics {
    /// Render in Prometheus text exposition format.
    ///
    /// Output is deterministic (BTreeMap key ordering) so the same
    /// snapshot produces byte-identical output, which makes scrape-diff
    /// comparisons in tests straightforward.
    pub fn render_prometheus(&self) -> String {
        let mut s = String::with_capacity(1024);

        // workflows_by_status
        let _ = writeln!(s, "# HELP tenzro_workflow_workflows_total Workflows partitioned by current status.");
        let _ = writeln!(s, "# TYPE tenzro_workflow_workflows_total gauge");
        for (status, n) in &self.workflows_by_status {
            let _ = writeln!(s, "tenzro_workflow_workflows_total{{status=\"{}\"}} {}", status, n);
        }

        // obligations_by_status
        let _ = writeln!(s, "# HELP tenzro_workflow_obligations_total Obligations partitioned by current status.");
        let _ = writeln!(s, "# TYPE tenzro_workflow_obligations_total gauge");
        for (status, n) in &self.obligations_by_status {
            let _ = writeln!(s, "tenzro_workflow_obligations_total{{status=\"{}\"}} {}", status, n);
        }

        // approvals_by_status
        let _ = writeln!(s, "# HELP tenzro_workflow_approvals_total Approval requests partitioned by current status.");
        let _ = writeln!(s, "# TYPE tenzro_workflow_approvals_total gauge");
        for (status, n) in &self.approvals_by_status {
            let _ = writeln!(s, "tenzro_workflow_approvals_total{{status=\"{}\"}} {}", status, n);
        }

        // signatures_collected_total
        let _ = writeln!(s, "# HELP tenzro_workflow_signatures_collected_total Sum of participant signatures across all workflows.");
        let _ = writeln!(s, "# TYPE tenzro_workflow_signatures_collected_total gauge");
        let _ = writeln!(s, "tenzro_workflow_signatures_collected_total {}", self.signatures_collected_total);

        // canton_mirrored_total
        let _ = writeln!(s, "# HELP tenzro_workflow_canton_mirrored_total Workflows with a Canton synchronizer mirror.");
        let _ = writeln!(s, "# TYPE tenzro_workflow_canton_mirrored_total gauge");
        let _ = writeln!(s, "tenzro_workflow_canton_mirrored_total {}", self.canton_mirrored_total);

        // fee_routes_total
        let _ = writeln!(s, "# HELP tenzro_workflow_fee_routes_total Registered fee routes.");
        let _ = writeln!(s, "# TYPE tenzro_workflow_fee_routes_total gauge");
        let _ = writeln!(s, "tenzro_workflow_fee_routes_total {}", self.fee_routes_total);

        // privacy_domains_total
        let _ = writeln!(s, "# HELP tenzro_workflow_privacy_domains_total Registered privacy domains.");
        let _ = writeln!(s, "# TYPE tenzro_workflow_privacy_domains_total gauge");
        let _ = writeln!(s, "tenzro_workflow_privacy_domains_total {}", self.privacy_domains_total);

        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_deterministic() {
        let mut m = OperationalMetrics::default();
        m.workflows_by_status.insert("active".into(), 3);
        m.workflows_by_status.insert("draft".into(), 1);
        m.obligations_by_status.insert("pending".into(), 5);
        m.signatures_collected_total = 12;
        m.canton_mirrored_total = 2;
        m.fee_routes_total = 4;
        m.privacy_domains_total = 1;
        let a = m.render_prometheus();
        let b = m.render_prometheus();
        assert_eq!(a, b);
    }

    #[test]
    fn render_contains_canonical_labels() {
        let mut m = OperationalMetrics::default();
        m.workflows_by_status.insert("active".into(), 7);
        m.obligations_by_status.insert("discharged".into(), 11);
        m.approvals_by_status.insert("approved".into(), 2);
        let s = m.render_prometheus();
        assert!(s.contains("tenzro_workflow_workflows_total{status=\"active\"} 7"));
        assert!(s.contains("tenzro_workflow_obligations_total{status=\"discharged\"} 11"));
        assert!(s.contains("tenzro_workflow_approvals_total{status=\"approved\"} 2"));
        // HELP/TYPE present for each metric.
        assert!(s.contains("# HELP tenzro_workflow_workflows_total"));
        assert!(s.contains("# TYPE tenzro_workflow_workflows_total gauge"));
    }

    #[test]
    fn render_btreemap_ordering() {
        let mut m = OperationalMetrics::default();
        m.workflows_by_status.insert("draft".into(), 1);
        m.workflows_by_status.insert("active".into(), 2);
        m.workflows_by_status.insert("completed".into(), 3);
        let s = m.render_prometheus();
        let active = s.find("active").unwrap();
        let completed = s.find("completed").unwrap();
        let draft = s.find("draft").unwrap();
        assert!(active < completed && completed < draft, "BTreeMap iteration must yield alphabetical order");
    }
}
