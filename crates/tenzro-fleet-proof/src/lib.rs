//! One operator's fleet hardware proof, assembled from its hosts' evidence.
//!
//! Each host's node makes its own evidence, a
//! [`tenzro_types::hardware_level::FleetHost`]: only that machine's TPM can
//! quote with its admitted attestation key. The operator gathers the hosts'
//! evidence and sends it in one `HardwareProof` transaction from the
//! operator's wallet. [`assemble`] builds that transaction's operation and
//! [`gas_limit`] the gas the chain charges for it.

use tenzro_types::hardware_level::{FleetHost, FleetUnit, HardwareProofOp};

/// Gas of a hardware proof before its quotes and GPU reports: the VM's
/// `GAS_HARDWARE_PROOF`, which a VM test holds this equal to.
pub const GAS_PROOF: u64 = 150_000;
/// Gas each TPM quote adds: the VM's `GAS_FLEET_QUOTE`.
pub const GAS_QUOTE: u64 = 40_000;
/// Gas each GPU report adds: the VM's `GAS_FLEET_GPU`.
pub const GAS_GPU: u64 = 60_000;

/// A rack-scale system proven as one unit: the operator's label for it and
/// its hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rack {
    /// The operator's name for the rack, unique among its racks.
    pub label: String,
    /// The rack's hosts.
    pub hosts: Vec<FleetHost>,
}

/// The fleet proof of `hosts`, each judged on its own, and `racks`, each
/// judged whole, with the certificates every GPU chain shares in `issuers`.
/// Refuses what the chain would refuse at admission: no unit, a size limit
/// passed, or a host named twice.
pub fn assemble(
    hosts: Vec<FleetHost>,
    racks: Vec<Rack>,
    issuers: Vec<u8>,
) -> Result<HardwareProofOp, String> {
    let units: Vec<FleetUnit> = hosts
        .into_iter()
        .map(FleetUnit::Host)
        .chain(racks.into_iter().map(|rack| FleetUnit::Rack {
            label: rack.label,
            hosts: rack.hosts,
        }))
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    for host in units.iter().flat_map(FleetUnit::hosts) {
        if !seen.insert(host.did.as_str()) {
            return Err(format!("{} appears twice in the proof", host.did));
        }
    }
    let op = HardwareProofOp::Fleet { issuers, units };
    op.validate()?;
    Ok(op)
}

/// The gas the chain charges for `op`: a hardware proof's gas, and for a
/// fleet proof as much again for each quote and GPU report it carries.
pub fn gas_limit(op: &HardwareProofOp) -> u64 {
    let HardwareProofOp::Fleet { units, .. } = op else {
        return GAS_PROOF;
    };
    let (quotes, gpus) = units
        .iter()
        .flat_map(FleetUnit::hosts)
        .fold((0u64, 0u64), |(q, g), h| {
            (
                q + 1 + u64::from(h.binding.is_some()),
                g + h.gpus.len() as u64,
            )
        });
    GAS_PROOF
        .saturating_add(quotes.saturating_mul(GAS_QUOTE))
        .saturating_add(gpus.saturating_mul(GAS_GPU))
}
