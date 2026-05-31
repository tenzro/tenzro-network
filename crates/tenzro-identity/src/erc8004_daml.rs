//! ERC-8004 Canton/DAML port — command builders + transport abstraction.
//!
//! Mirrors the EVM-side [`crate::erc8004`] and SVM-side
//! [`crate::erc8004_svm`] modules against the in-tree DAML templates
//! under `vendor/erc8004-daml/daml/Tenzro/Erc8004/`. Where the EVM port
//! uses 4-byte selectors + ABI-encoded calldata and the SVM port uses
//! 8-byte Anchor discriminators + Borsh, the DAML port emits Canton
//! Ledger API v2 commands as `serde_json::Value` — the wire shape the
//! Canton JSON Ledger API accepts via `/v2/commands/submit-and-wait`.
//!
//! # Wire format: DAML vs EVM/SVM
//!
//! | concept            | EVM (Solidity)          | SVM (Anchor)               | DAML (Canton Ledger API v2)               |
//! | ------------------ | ----------------------- | -------------------------- | ----------------------------------------- |
//! | call dispatch tag  | 4-byte selector         | 8-byte discriminator       | `templateId` + `choice` strings           |
//! | argument encoding  | ABI heads/tails         | Borsh                      | JSON `Record { fields: [...] }`           |
//! | state identifier   | contract address        | program ID (32B Pubkey)    | `{package_id}:{module}:{entity}` triple   |
//! | identity key       | `uint256 agentId`       | Metaplex Asset Pubkey      | Contract id `Registered@(admin,agentId)`  |
//! | event emission     | `LOG` opcode            | `emit_cpi!`                | `CreatedEvent` in `TransactionTree`       |
//!
//! Canton template ids are `{package_id}:{module_name}:{entity_name}`
//! where `package_id` is the SHA-256 of the compiled `.dar` artifact
//! and is assigned at DAML compile time — not at source-author time.
//! That hash is therefore **not** hard-coded here; callers pass it via
//! [`DamlPackageIds::tenzro_erc8004`] at registry construction time.
//!
//! # Position in Tenzro
//!
//! As with the EVM and SVM mirrors, the DAML mirror is **outbound
//! only**: a TDIP machine identity can optionally publish itself to a
//! Canton participant so enterprise counterparties that only speak
//! DAML can discover Tenzro agents. TDIP remains the source of truth.
//!
//! The DAML port is not predeployed in the Tenzro testnet — Canton is
//! external infrastructure. Activating the mirror requires (a) an
//! uploaded `.dar` containing the three `Tenzro.Erc8004.*` modules,
//! (b) the Tenzro Network admin party allocated on the target
//! participant, and (c) the operator wiring a
//! [`DamlMirrorTransport`] implementation that holds the JSON Ledger
//! API endpoint + admin auth token.
//!
//! The mirror wiring lives in `tenzro-node` (`erc8004_daml_mirror.rs`)
//! and is gated on `Option<Arc<dyn OnChainAgentDamlRegistry>>` on
//! [`crate::registry::IdentityRegistry`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{IdentityError, Result};

/// Canton package id (the SHA-256 of the compiled `.dar` artifact
/// containing a set of DAML templates). Length is always 64 hex chars.
/// Stored as a `String` because the canonical Canton API shape is hex
/// text, not raw bytes.
pub type PackageId = String;

/// Canton party identifier (`{display_name}::{namespace_hash}`).
/// Format is participant-defined; we do not parse it here.
pub type PartyId = String;

/// Hook for mirroring TDIP machine registrations into the Canton DAML
/// port of ERC-8004. Parallel to
/// [`crate::erc8004::OnChainAgentRegistry`] (EVM) and
/// [`crate::erc8004_svm::OnChainAgentSvmRegistry`] (SVM).
///
/// Implementors live in `tenzro-node` so `tenzro-identity` does not
/// depend on `tonic` or any Canton client crate.
///
/// # Async-by-spawn pattern
///
/// `mirror_register_agent` is **sync from the TDIP caller's
/// perspective** but performs its on-chain work as a detached
/// `tokio::spawn`: it builds the Canton command JSON + submits it via
/// the JSON Ledger API. Returns to the TDIP caller immediately.
///
/// The newly-allocated `agentId` is **not** returned synchronously —
/// it arrives later via the `Registered` CreatedEvent reflected back
/// into the off-chain `erc8004_daml_did_index:` keyspace in
/// `CF_IDENTITIES`. The reflector also patches
/// `IdentityData::Machine.erc8004_daml_agent_id` on the TDIP record.
///
/// Failures are logged but never block TDIP registration — the
/// on-chain mirror is best-effort and additive.
pub trait OnChainAgentDamlRegistry: Send + Sync {
    /// Mirror a TDIP machine registration into the Canton DAML
    /// registry. Builds a `Register` choice exercise against the admin
    /// party's `RegistryAdmin` contract, signs it with the node-held
    /// `erc8004-daml-system` party token, and submits via the JSON
    /// Ledger API as a detached tokio task. Returns immediately on
    /// command-build success; transport / submission failures inside
    /// the spawned task are logged and dropped.
    fn mirror_register_agent(&self, did: &str, metadata_uri: &str) -> Result<()>;

    /// Resolve a TDIP DID string back to its allocated DAML `agentId`.
    /// Reads from the off-chain DID index in RocksDB (`CF_IDENTITIES`
    /// under the `erc8004_daml_did_index:` prefix), which is populated
    /// by the `Registered` CreatedEvent reflector.
    ///
    /// Returns `None` if the DID has never been mirrored OR if the
    /// mirror command has not yet been committed + indexed. Callers
    /// MUST tolerate the `None` case.
    fn lookup_agent_id_by_did(&self, did: &str) -> Option<u64>;
}

/// Transport abstraction so this module stays free of Canton-client
/// deps. Implementors (typically in `tenzro-node`) wrap a Canton JSON
/// Ledger API client (HTTP/JSON via `reqwest`) or a Canton gRPC
/// Ledger API client (`tonic`).
///
/// The `command_json` argument is the full
/// `/v2/commands/submit-and-wait` request body produced by
/// [`commands::build_submit_and_wait`].
#[async_trait::async_trait]
pub trait Erc8004DamlTransport: Send + Sync {
    /// Submit a `submit-and-wait` command and return the transaction
    /// id. Implementations are expected to deserialize the response,
    /// extract the resulting `Registered` contract's `agentId`, and
    /// write it to the off-chain DID index keyspace as a side effect
    /// — the keyspace mechanics are owned by the mirror adapter in
    /// `tenzro-node`, not by this trait.
    async fn submit_and_wait(&self, command_json: Value) -> Result<String>;
}

/// Compile-time package ids for the in-tree `Tenzro.Erc8004.*` DAML
/// modules. The `package_id` is the SHA-256 of the compiled `.dar`
/// artifact and is assigned by `daml build` — it must be supplied by
/// the operator at node startup (read from `daml.yaml` /
/// `<workspace>/.daml/dist/*.dar` after the build).
///
/// The vendored DAML source lives under
/// `vendor/erc8004-daml/daml/Tenzro/Erc8004/`. After running
/// `daml build`, the package id is printed to stdout and is also
/// queryable via the Canton participant's
/// `PackageManagementService.ListKnownPackages` RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DamlPackageIds {
    /// Package id of the compiled `Tenzro.Erc8004.*` DAR. Same package
    /// id covers all three modules (Identity / Reputation /
    /// Validation) because they ship in a single DAR.
    pub tenzro_erc8004: PackageId,
}

impl DamlPackageIds {
    /// Convenience constructor when a single package id covers all
    /// three modules (the in-tree case).
    pub fn new_single(package_id: impl Into<PackageId>) -> Self {
        Self {
            tenzro_erc8004: package_id.into(),
        }
    }
}

/// Canton template identifiers — pure constants, parameterized at call
/// time by [`DamlPackageIds`].
pub mod templates {
    /// Module name for the Identity registry templates.
    pub const IDENTITY_MODULE: &str = "Tenzro.Erc8004.Identity";

    /// Module name for the Reputation registry templates.
    pub const REPUTATION_MODULE: &str = "Tenzro.Erc8004.Reputation";

    /// Module name for the Validation registry templates.
    pub const VALIDATION_MODULE: &str = "Tenzro.Erc8004.Validation";

    // -- Identity entities --

    /// The admin-held registry contract carrying the next-id counter.
    pub const REGISTRY_ADMIN: &str = "RegistryAdmin";

    /// A registered agent. Co-signed by the admin and the controller.
    pub const REGISTERED: &str = "Registered";

    /// A retired (controller-cleared) agent. Held by the admin only.
    pub const RETIRED: &str = "Retired";

    // -- Reputation entities --

    /// A single reputation feedback row.
    pub const FEEDBACK: &str = "Feedback";

    /// The admin-held reputation factory that authors `Feedback` rows.
    pub const REPUTATION_ADMIN: &str = "ReputationAdmin";

    // -- Validation entities --

    /// An outstanding validation request awaiting validator countersig.
    pub const VALIDATION_REQUEST: &str = "ValidationRequest";

    /// A completed validation. Counterpart to EVM `getValidation`.
    pub const VALIDATION_RESPONSE: &str = "ValidationResponse";
}

/// Canton template choice names — string literals exactly as authored
/// in the DAML modules under `vendor/erc8004-daml/`.
pub mod choices {
    // -- Identity --

    /// Allocate a fresh agent id + create the canonical `Registered`
    /// record.
    pub const REGISTER: &str = "Register";

    /// Bump the agent-id counter (admin-only re-sync).
    pub const BUMP_COUNTER: &str = "BumpCounter";

    /// Update the resolvable metadata URI on a `Registered` contract.
    pub const SET_AGENT_URI: &str = "SetAgentURI";

    /// Rebind the controller party of a `Registered` contract.
    pub const SET_AGENT_WALLET: &str = "SetAgentWallet";

    /// Clear the controller binding — produces a `Retired` contract.
    pub const UNSET_AGENT_WALLET: &str = "UnsetAgentWallet";

    // -- Reputation --

    /// Submit a new feedback row via `ReputationAdmin`.
    pub const SUBMIT_FEEDBACK: &str = "SubmitFeedback";

    /// Mark a previously-submitted feedback row as revoked.
    pub const REVOKE: &str = "Revoke";

    /// Attach a response URI to a feedback row.
    pub const APPEND_RESPONSE: &str = "AppendResponse";

    // -- Validation --

    /// Validator countersignature on a `ValidationRequest`.
    pub const RESPOND: &str = "Respond";
}

/// Build a fully-qualified Canton template id of the form
/// `{package_id}:{module_name}:{entity_name}` — the JSON-shape that
/// `/v2/commands/submit-and-wait` accepts.
pub fn template_id(package_ids: &DamlPackageIds, module: &str, entity: &str) -> String {
    format!("{}:{}:{}", package_ids.tenzro_erc8004, module, entity)
}

/// A subset of `Tenzro.Erc8004.Identity.Registered` as exposed by
/// off-chain query (the `CreatedEvent.argument` shape). Mirrors the
/// EVM [`crate::erc8004::AgentRecord`] for symmetric API surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DamlAgentRecord {
    /// Sequentially-allocated agent id.
    pub agent_id: u64,
    /// The admin party (Tenzro Network) co-signing the record.
    pub admin: PartyId,
    /// The controller party authoritative for this agent's choices.
    pub controller: PartyId,
    /// Resolvable metadata URI (DID document / AgentCard).
    pub metadata_uri: String,
}

/// JSON command builders. Pure, no I/O — these produce the
/// `serde_json::Value` payloads accepted by Canton JSON Ledger API v2
/// at `/v2/commands/submit-and-wait`.
///
/// The shape follows Canton's v2 JSON API contract:
///
/// ```json
/// {
///   "commands": [
///     { "ExerciseCommand": {
///         "templateId": "<package>:Tenzro.Erc8004.Identity:RegistryAdmin",
///         "contractId": "<cid>",
///         "choice": "Register",
///         "choiceArgument": { /* fields */ }
///       }
///     }
///   ],
///   "actAs": ["Admin::...", "Caller::..."],
///   "commandId": "tenzro-erc8004-mirror-<did>",
///   "applicationId": "tenzro-erc8004-mirror"
/// }
/// ```
///
/// `commandId` is set to a deterministic per-DID string so retries are
/// idempotent at the Canton participant layer (per Canton's
/// command-deduplication contract).
pub mod commands {
    use super::*;

    /// Tenzro's reserved Canton `applicationId` for ERC-8004 mirror
    /// commands. Visible in Canton audit logs + admin tooling.
    pub const APPLICATION_ID: &str = "tenzro-erc8004-mirror";

    /// Build a deterministic `commandId` for a DID-keyed mirror
    /// dispatch. Canton uses `commandId` as the dedup key within a
    /// configurable window (default 24h), so a stable per-DID id
    /// makes retries safe.
    pub fn command_id(prefix: &str, did: &str) -> String {
        format!("{}-{}", prefix, did)
    }

    /// Build the `submit-and-wait` request body that exercises
    /// `RegistryAdmin.Register` for the given controller + metadata
    /// URI. The caller supplies the `RegistryAdmin` contract id (the
    /// admin party allocates this once at participant setup).
    pub fn build_register(
        package_ids: &DamlPackageIds,
        admin_contract_id: &str,
        admin_party: &str,
        controller_party: &str,
        metadata_uri: &str,
        did_for_command_id: &str,
    ) -> Value {
        let tid = template_id(package_ids, templates::IDENTITY_MODULE, templates::REGISTRY_ADMIN);
        let choice_argument = json!({
            "controller": controller_party,
            "metadataUri": metadata_uri,
        });
        build_submit_and_wait(
            &tid,
            admin_contract_id,
            choices::REGISTER,
            choice_argument,
            &[admin_party, controller_party],
            &command_id(APPLICATION_ID, did_for_command_id),
        )
    }

    /// Build the `submit-and-wait` request body that exercises
    /// `Registered.SetAgentURI` to update an agent's metadata URI.
    pub fn build_set_agent_uri(
        package_ids: &DamlPackageIds,
        registered_contract_id: &str,
        controller_party: &str,
        new_uri: &str,
        did_for_command_id: &str,
    ) -> Value {
        let tid = template_id(package_ids, templates::IDENTITY_MODULE, templates::REGISTERED);
        let choice_argument = json!({ "newUri": new_uri });
        build_submit_and_wait(
            &tid,
            registered_contract_id,
            choices::SET_AGENT_URI,
            choice_argument,
            &[controller_party],
            &command_id(&format!("{}-set-uri", APPLICATION_ID), did_for_command_id),
        )
    }

    /// Build the `submit-and-wait` request body that exercises
    /// `Registered.SetAgentWallet` to rebind an agent's controller
    /// party. Both the current and new controllers must counter-sign
    /// (DAML analogue of EVM's `(deadline, signature)` consent pair).
    pub fn build_set_agent_wallet(
        package_ids: &DamlPackageIds,
        registered_contract_id: &str,
        current_controller_party: &str,
        new_controller_party: &str,
        did_for_command_id: &str,
    ) -> Value {
        let tid = template_id(package_ids, templates::IDENTITY_MODULE, templates::REGISTERED);
        let choice_argument = json!({ "newController": new_controller_party });
        build_submit_and_wait(
            &tid,
            registered_contract_id,
            choices::SET_AGENT_WALLET,
            choice_argument,
            &[current_controller_party, new_controller_party],
            &command_id(&format!("{}-set-wallet", APPLICATION_ID), did_for_command_id),
        )
    }

    /// Build the `submit-and-wait` request body that exercises
    /// `ReputationAdmin.SubmitFeedback` to add a new feedback row.
    /// The rating is asserted -128..=127 on the DAML side; values
    /// outside this range are rejected by the participant.
    pub fn build_submit_feedback(
        package_ids: &DamlPackageIds,
        admin_contract_id: &str,
        admin_party: &str,
        rater_party: &str,
        subject_agent_id: u64,
        rating: i8,
        context_uri: &str,
        feedback_id_hex32: &str,
    ) -> Value {
        let tid = template_id(
            package_ids,
            templates::REPUTATION_MODULE,
            templates::REPUTATION_ADMIN,
        );
        let choice_argument = json!({
            "rater": rater_party,
            "subjectAgentId": subject_agent_id,
            "rating": rating as i64,
            "contextUri": context_uri,
            "feedbackId": feedback_id_hex32,
        });
        build_submit_and_wait(
            &tid,
            admin_contract_id,
            choices::SUBMIT_FEEDBACK,
            choice_argument,
            &[admin_party, rater_party],
            &command_id(
                &format!("{}-submit-feedback", APPLICATION_ID),
                feedback_id_hex32,
            ),
        )
    }

    /// Build the canonical Canton `submit-and-wait` request body
    /// shape. Visible to callers that need to author choices not yet
    /// covered by a typed builder above.
    pub fn build_submit_and_wait(
        template_id: &str,
        contract_id: &str,
        choice: &str,
        choice_argument: Value,
        act_as: &[&str],
        command_id: &str,
    ) -> Value {
        json!({
            "commands": [{
                "ExerciseCommand": {
                    "templateId": template_id,
                    "contractId": contract_id,
                    "choice": choice,
                    "choiceArgument": choice_argument,
                }
            }],
            "actAs": act_as,
            "commandId": command_id,
            "applicationId": APPLICATION_ID,
        })
    }
}

/// Convert the standard `lookup_agent_id_by_did` result into the
/// unified [`IdentityError::VerificationFailed`] shape — used by RPC
/// handlers that want a typed error for the "not yet mirrored" case.
pub fn require_agent_id(did: &str, registry: &dyn OnChainAgentDamlRegistry) -> Result<u64> {
    registry.lookup_agent_id_by_did(did).ok_or_else(|| {
        IdentityError::VerificationFailed(format!(
            "no ERC-8004 DAML agentId mirrored for DID '{}' yet \
             (mirror command may still be pending — retry after a few seconds)",
            did
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg() -> DamlPackageIds {
        DamlPackageIds::new_single(
            "1122334455667788112233445566778811223344556677881122334455667788",
        )
    }

    #[test]
    fn template_id_format_is_three_part_colon() {
        let id = template_id(&pkg(), templates::IDENTITY_MODULE, templates::REGISTRY_ADMIN);
        let parts: Vec<&str> = id.split(':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 64); // package id is 64 hex chars
        assert_eq!(parts[1], "Tenzro.Erc8004.Identity");
        assert_eq!(parts[2], "RegistryAdmin");
    }

    #[test]
    fn command_id_is_deterministic_per_did() {
        let a = commands::command_id(commands::APPLICATION_ID, "did:tenzro:machine:abc");
        let b = commands::command_id(commands::APPLICATION_ID, "did:tenzro:machine:abc");
        assert_eq!(a, b);
        assert_ne!(
            a,
            commands::command_id(commands::APPLICATION_ID, "did:tenzro:machine:xyz")
        );
    }

    #[test]
    fn build_register_emits_canton_v2_shape() {
        let cmd = commands::build_register(
            &pkg(),
            "00abcd...cid",
            "TenzroAdmin::123",
            "Controller::456",
            "did:tenzro:machine:test",
            "did:tenzro:machine:test",
        );
        let commands_arr = cmd.get("commands").and_then(|v| v.as_array()).unwrap();
        assert_eq!(commands_arr.len(), 1);
        let ex = commands_arr[0].get("ExerciseCommand").unwrap();
        assert_eq!(ex.get("choice").and_then(|v| v.as_str()), Some("Register"));
        assert_eq!(
            ex.get("contractId").and_then(|v| v.as_str()),
            Some("00abcd...cid")
        );
        let tid = ex.get("templateId").and_then(|v| v.as_str()).unwrap();
        assert!(tid.ends_with(":Tenzro.Erc8004.Identity:RegistryAdmin"));
        let arg = ex.get("choiceArgument").unwrap();
        assert_eq!(
            arg.get("controller").and_then(|v| v.as_str()),
            Some("Controller::456")
        );
        assert_eq!(
            arg.get("metadataUri").and_then(|v| v.as_str()),
            Some("did:tenzro:machine:test")
        );
        let act_as = cmd.get("actAs").and_then(|v| v.as_array()).unwrap();
        assert_eq!(act_as.len(), 2);
        assert_eq!(act_as[0].as_str(), Some("TenzroAdmin::123"));
        assert_eq!(act_as[1].as_str(), Some("Controller::456"));
        assert_eq!(
            cmd.get("applicationId").and_then(|v| v.as_str()),
            Some(commands::APPLICATION_ID)
        );
    }

    #[test]
    fn build_set_agent_uri_targets_registered_template() {
        let cmd = commands::build_set_agent_uri(
            &pkg(),
            "00cid",
            "Controller::1",
            "did:tenzro:machine:new-uri",
            "did:tenzro:machine:abc",
        );
        let tid = cmd["commands"][0]["ExerciseCommand"]["templateId"]
            .as_str()
            .unwrap();
        assert!(tid.ends_with(":Tenzro.Erc8004.Identity:Registered"));
        assert_eq!(
            cmd["commands"][0]["ExerciseCommand"]["choice"]
                .as_str()
                .unwrap(),
            "SetAgentURI"
        );
    }

    #[test]
    fn build_set_agent_wallet_requires_both_signatures() {
        let cmd = commands::build_set_agent_wallet(
            &pkg(),
            "00cid",
            "Old::1",
            "New::2",
            "did:tenzro:machine:abc",
        );
        let act_as: Vec<&str> = cmd["actAs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(act_as, vec!["Old::1", "New::2"]);
    }

    #[test]
    fn build_submit_feedback_widens_i8_rating_to_i64() {
        let cmd = commands::build_submit_feedback(
            &pkg(),
            "00cid",
            "Admin::1",
            "Rater::2",
            42,
            -7,
            "ipfs://bafy...",
            "0000000000000000000000000000000000000000000000000000000000000abc",
        );
        let arg = &cmd["commands"][0]["ExerciseCommand"]["choiceArgument"];
        assert_eq!(arg["rating"].as_i64(), Some(-7));
        assert_eq!(arg["subjectAgentId"].as_u64(), Some(42));
        assert_eq!(arg["rater"].as_str(), Some("Rater::2"));
    }

    struct StubRegistry;
    impl OnChainAgentDamlRegistry for StubRegistry {
        fn mirror_register_agent(&self, _did: &str, _uri: &str) -> Result<()> {
            Ok(())
        }
        fn lookup_agent_id_by_did(&self, _did: &str) -> Option<u64> {
            None
        }
    }

    #[test]
    fn require_agent_id_returns_typed_error_when_unindexed() {
        let reg = StubRegistry;
        let err = require_agent_id("did:tenzro:machine:x", &reg).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("did:tenzro:machine:x"));
        assert!(msg.contains("DAML"));
    }
}
