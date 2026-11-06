//! OpenShell extension protocol negotiation.

use crate::openshell::extension::v1::{PeerMetadata, ProtocolVersion};

/// The implementation name every extension in this crate reports.
pub const IMPLEMENTATION: &str = "tenzro/openshell";

/// Credential-driver base capability.
pub const CREDENTIALS: &str = "openshell.credentials.contract";
/// Gateway-interceptor base capability.
pub const INTERCEPTOR: &str = "openshell.gateway-interceptor.contract";
/// Supervisor-middleware base capability.
pub const MIDDLEWARE: &str = "openshell.supervisor-middleware.contract";

/// This extension's metadata for the family `capability`: protocol 1.0.
pub fn metadata(capability: &str) -> PeerMetadata {
    PeerMetadata {
        protocol_version: Some(ProtocolVersion { major: 1, minor: 0 }),
        implementation_name: IMPLEMENTATION.to_string(),
        implementation_version: env!("CARGO_PKG_VERSION").to_string(),
        supported_capabilities: vec![capability.to_string()],
        required_capabilities: Vec::new(),
    }
}

/// Refuse a peer that speaks another major version or requires a capability
/// this extension lacks. A peer that sends no metadata requires nothing.
pub fn negotiate(peer: Option<&PeerMetadata>, capability: &str) -> Result<(), tonic::Status> {
    let Some(peer) = peer else {
        return Ok(());
    };
    let major = peer.protocol_version.as_ref().map(|v| v.major);
    if major != Some(1) {
        return Err(tonic::Status::failed_precondition(format!(
            "protocol major {major:?} is not 1"
        )));
    }
    if let Some(missing) = peer
        .required_capabilities
        .iter()
        .find(|c| c.as_str() != capability)
    {
        return Err(tonic::Status::failed_precondition(format!(
            "peer requires {missing}, which {IMPLEMENTATION} does not support"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_refuses_another_major_and_unknown_requirements() {
        let mut gw = metadata(CREDENTIALS);
        assert!(negotiate(Some(&gw), CREDENTIALS).is_ok());
        gw.required_capabilities = vec!["openshell.credentials.rotation".into()];
        assert!(negotiate(Some(&gw), CREDENTIALS).is_err());
        gw.required_capabilities.clear();
        gw.protocol_version = Some(ProtocolVersion { major: 2, minor: 0 });
        assert!(negotiate(Some(&gw), CREDENTIALS).is_err());
        assert!(negotiate(None, CREDENTIALS).is_ok());
    }
}
