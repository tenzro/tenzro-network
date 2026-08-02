//! Runtime view of the [`ExecutionSpec`] types defined in `tenzro-types`.
//!
//! The wire-level types live in `tenzro-types::agent_template` so that
//! both the on-chain registry and the runtime kit speak the same JSON
//! schema. This module adds runtime-only helpers (template variable
//! substitution, hard-cap checks).

use std::collections::HashMap;

use tenzro_types::agent_template::{DelegationSpec, HardCaps};

use crate::error::AgentKitError;

/// Substitutes `{{var}}` placeholders in a string against the given
/// context. Unknown variables return [`AgentKitError::MissingVariable`].
///
/// Substitution is intentionally simple: no escaping, no expressions —
/// just `{{key}}` → `context[key]`. For richer logic, use the `When`
/// step variant with a JMESPath expression.
pub fn substitute(
    template: &str,
    context: &HashMap<String, String>,
) -> Result<String, AgentKitError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find("}}").ok_or_else(|| {
            AgentKitError::Other(format!("unterminated template variable in: {template}"))
        })?;
        let key = after[..end].trim();
        let value = context
            .get(key)
            .ok_or_else(|| AgentKitError::MissingVariable(key.to_string()))?;
        out.push_str(value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Confirms a step value is within the configured per-operation hard cap.
pub fn check_hard_cap(operation: &str, value: u128, caps: &HardCaps) -> Result<(), AgentKitError> {
    if value > caps.per_operation_value {
        return Err(AgentKitError::HardCapExceeded {
            operation: operation.to_string(),
            value,
            cap: caps.per_operation_value,
        });
    }
    Ok(())
}

/// Parses the `kyc_tier` string from a [`DelegationSpec`] into a
/// [`tenzro_types::identity::KycTier`].
pub fn parse_kyc_tier(spec: &DelegationSpec) -> tenzro_types::identity::KycTier {
    use tenzro_types::identity::KycTier;
    match spec.kyc_tier.as_str() {
        "Unverified" | "unverified" => KycTier::Unverified,
        "Basic" | "basic" => KycTier::Basic,
        "Enhanced" | "enhanced" => KycTier::Enhanced,
        "Full" | "full" => KycTier::Full,
        _ => KycTier::Unverified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_simple_variable() {
        let mut ctx = HashMap::new();
        ctx.insert("amount".to_string(), "100".to_string());
        let out = substitute("pay {{amount}} USDC", &ctx).unwrap();
        assert_eq!(out, "pay 100 USDC");
    }

    #[test]
    fn substitutes_multiple_variables() {
        let mut ctx = HashMap::new();
        ctx.insert("from".to_string(), "ethereum".to_string());
        ctx.insert("to".to_string(), "arbitrum".to_string());
        let out = substitute("bridge {{from}} to {{to}}", &ctx).unwrap();
        assert_eq!(out, "bridge ethereum to arbitrum");
    }

    #[test]
    fn missing_variable_errors() {
        let ctx = HashMap::new();
        let err = substitute("hello {{name}}", &ctx).unwrap_err();
        match err {
            AgentKitError::MissingVariable(v) => assert_eq!(v, "name"),
            _ => panic!("expected MissingVariable, got {err:?}"),
        }
    }

    #[test]
    fn hard_cap_rejects_oversized() {
        let caps = HardCaps {
            per_operation_value: 100,
            per_day_value: 1000,
        };
        let err = check_hard_cap("trade", 200, &caps).unwrap_err();
        match err {
            AgentKitError::HardCapExceeded { value, cap, .. } => {
                assert_eq!(value, 200);
                assert_eq!(cap, 100);
            }
            _ => panic!("expected HardCapExceeded"),
        }
    }

    #[test]
    fn parses_kyc_tier_strings() {
        use tenzro_types::identity::KycTier;
        let mk = |s: &str| DelegationSpec {
            max_transaction_value: 0,
            max_daily_spend: 0,
            allowed_operations: vec![],
            allowed_chains: vec![],
            time_bound_days: 0,
            kyc_tier: s.to_string(),
        };
        assert_eq!(parse_kyc_tier(&mk("Full")), KycTier::Full);
        assert_eq!(parse_kyc_tier(&mk("Basic")), KycTier::Basic);
        assert_eq!(parse_kyc_tier(&mk("Enhanced")), KycTier::Enhanced);
        assert_eq!(parse_kyc_tier(&mk("Unverified")), KycTier::Unverified);
        // Unknown defaults to Unverified
        assert_eq!(parse_kyc_tier(&mk("garbage")), KycTier::Unverified);
    }
}
