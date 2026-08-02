//! DAML codegen — emit a `.daml` source for a `Workflow` whose
//! `canton_mirror.is_some()`.
//!
//! The emitter targets the **Multiple Party Agreement** pattern:
//! a `Pending<Template>` contract collects per-participant `Sign` choices,
//! and on the last signature materializes an `Active<Template>` contract.
//! `Active<Template>` carries one `Discharge<Obligation>` choice per
//! obligation in the workflow spec, and an optional `Cancel` choice
//! restricted to the creator.
//!
//! ## Determinism
//!
//! Same `(Workflow, DamlMap)` input → byte-identical `.daml` output. This
//! is required so that DAR builds are reproducible — operators can verify
//! a published DAR by re-running the codegen on the published workflow
//! spec.
//!
//! ## Mapping file (`daml_map.json`)
//!
//! The mapping resolves Tenzro-side `ObligationKind` and `DischargeProofKind`
//! variants to concrete DAML record types and choice argument shapes.
//! Without it, the emitter cannot pick the right DAML types — e.g. is
//! `Pay { amount_wei, asset: USDC }` mirrored as a `PaymentProposal` with
//! `Decimal` amount, or as a CIP-56 `TransferInstruction`?
//!
//! ## Invocation
//!
//! Codegen is exercised by the `tenzro workflow daml-emit` CLI command,
//! which writes the result to `target/daml/<template>/<Module>.daml`.
//! The emitted file is compiled to a DAR by the offline `daml build`
//! toolchain (Tenzro does not ship a Rust-native DAR builder — see
//! `docs/architecture/canton-workflow/README.md` §1.9).

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

use crate::error::WorkflowError;
use crate::obligation::{DischargeProofKind, Obligation, ObligationKind};
use crate::participant::ParticipantRole;
use crate::workflow::Workflow;

/// Mapping from Tenzro-side workflow types to DAML-side types.
///
/// Loaded alongside the workflow spec to drive codegen — it tells the
/// emitter which DAML record / interface to bind for each
/// `ObligationKind` and which discharge-proof DAML type to use.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DamlMap {
    /// DAML module name (without the `module` keyword). Convention:
    /// `Tenzro.Workflow.<UpperCamelTemplateName>`.
    pub module: String,
    /// Short template name used for the `Pending<Name>` and
    /// `Active<Name>` contracts. PascalCase.
    pub template_name: String,
    /// DAML record type that holds the `obligations : [...]` list element.
    /// Convention: `ObligationSpec` (a record carrying obligation_id,
    /// obligor, obligee, kind discriminant, kind payload).
    pub obligation_spec_type: String,
    /// Per-`ObligationKind` mapping to a DAML choice name and argument
    /// record. Looked up by the variant tag (`"Pay"`, `"Deliver"`,
    /// `"Attest"`, `"Settle"`, `"Custom"`).
    pub obligation_choices: Vec<ObligationChoiceMap>,
    /// External DAML interface to bind on the `Active<Name>` contract,
    /// e.g. `Token.TransferInstruction` for CIP-56 payment obligations.
    /// `None` skips the `interface instance` clause.
    pub external_interface: Option<String>,
}

/// Mapping for one `ObligationKind` variant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObligationChoiceMap {
    /// Variant tag of `ObligationKind` — `"Pay"` / `"Deliver"` /
    /// `"Attest"` / `"Settle"` / `"Custom"`.
    pub kind_tag: String,
    /// DAML choice name. Convention: `Discharge<Tag>` (e.g.
    /// `DischargePay`, `DischargeDeliver`).
    pub choice_name: String,
    /// Ordered list of choice argument fields rendered as DAML
    /// `(name : Type)` pairs. The emitter writes these into the
    /// `with` clause of the choice.
    pub choice_args: Vec<DamlArgField>,
}

/// One field on a DAML choice's `with` argument record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DamlArgField {
    pub name: String,
    /// DAML type — `"Text"`, `"Decimal"`, `"Party"`, `"ContractId Foo"`,
    /// etc. Written verbatim into the emitted source.
    pub daml_type: String,
}

/// Codegen entry point.
pub struct WorkflowDamlCodegen;

impl WorkflowDamlCodegen {
    /// Emit a `.daml` source file for the given workflow + mapping.
    ///
    /// Returns `WorkflowError::Invalid` if:
    /// - the workflow has no `canton_mirror` (nothing to emit for),
    /// - the workflow has zero participants,
    /// - any obligation references a `kind_tag` not present in the mapping,
    /// - obligation owners (`obligor` / `obligee`) are not in the
    ///   workflow's participants list (DAML controllers must resolve to
    ///   known parties).
    pub fn emit(
        workflow: &Workflow,
        map: &DamlMap,
        obligations: &[Obligation],
    ) -> crate::Result<String> {
        if workflow.canton_mirror.is_none() {
            return Err(WorkflowError::Invalid(
                "workflow has no canton_mirror — nothing to emit".into(),
            ));
        }
        if workflow.participants.is_empty() {
            return Err(WorkflowError::Invalid(
                "workflow has zero participants".into(),
            ));
        }
        // Validate every obligation tag has a choice mapping.
        for ob in obligations {
            let tag = obligation_tag(&ob.kind);
            if !map.obligation_choices.iter().any(|c| c.kind_tag == tag) {
                return Err(WorkflowError::Invalid(format!(
                    "no choice mapping for ObligationKind tag '{}' in DamlMap",
                    tag
                )));
            }
            // obligor/obligee must be participants
            if !workflow.participants.iter().any(|p| p.did == ob.obligor) {
                return Err(WorkflowError::Invalid(format!(
                    "obligation obligor '{}' is not a workflow participant",
                    ob.obligor
                )));
            }
            if !workflow.participants.iter().any(|p| p.did == ob.obligee) {
                return Err(WorkflowError::Invalid(format!(
                    "obligation obligee '{}' is not a workflow participant",
                    ob.obligee
                )));
            }
        }

        let mut s = String::new();
        // Header comment binds the emitted source back to its inputs.
        let _ = writeln!(s, "-- Generated by tenzro-workflow::codegen.");
        let _ = writeln!(
            s,
            "-- Source workflow: 0x{}",
            hex::encode(workflow.workflow_id.as_bytes())
        );
        let _ = writeln!(
            s,
            "-- Canonical hash:  0x{}",
            hex::encode(workflow.canonical_hash().as_bytes())
        );
        let _ = writeln!(s, "-- DamlMap module:  {}", map.module);
        let _ = writeln!(
            s,
            "-- DO NOT EDIT — re-run codegen if the workflow spec changes."
        );
        let _ = writeln!(s);

        let _ = writeln!(s, "module {} where", map.module);
        let _ = writeln!(s);
        let _ = writeln!(s, "import DA.List ((!!), elem, length, notElem)");
        let _ = writeln!(s, "import DA.Optional (fromOptional)");
        let _ = writeln!(s);

        // Obligation spec record type — minimal projection of the Tenzro
        // obligation onto the DAML side. Carries enough to identify which
        // obligation a discharge choice targets, but does not encode the
        // full `ObligationKind` payload (that is in the choice arguments).
        let _ = writeln!(
            s,
            "data {} = {} with",
            map.obligation_spec_type, map.obligation_spec_type
        );
        let _ = writeln!(s, "    obligation_id : Text");
        let _ = writeln!(s, "    obligor : Party");
        let _ = writeln!(s, "    obligee : Party");
        let _ = writeln!(s, "    kind_tag : Text");
        let _ = writeln!(s, "  deriving (Eq, Show)");
        let _ = writeln!(s);

        // Pending<Template>: the multi-party signature collector.
        let pending = format!("Pending{}", map.template_name);
        let active = format!("Active{}", map.template_name);
        let _ = writeln!(s, "template {}", pending);
        let _ = writeln!(s, "  with");
        let _ = writeln!(s, "    workflow_id : Text");
        let _ = writeln!(s, "    creator : Party");
        let _ = writeln!(s, "    participants : [Party]");
        let _ = writeln!(s, "    signatories_so_far : [Party]");
        let _ = writeln!(s, "    obligations : [{}]", map.obligation_spec_type);
        let _ = writeln!(s, "  where");
        let _ = writeln!(s, "    signatory creator");
        let _ = writeln!(s, "    observer participants");
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "    choice Sign : Either (ContractId {}) (ContractId {})",
            pending, active
        );
        let _ = writeln!(s, "      with");
        let _ = writeln!(s, "        signer : Party");
        let _ = writeln!(s, "      controller signer");
        let _ = writeln!(s, "      do");
        let _ = writeln!(
            s,
            "        assertMsg \"signer not a participant\" (signer `elem` participants)"
        );
        let _ = writeln!(
            s,
            "        assertMsg \"already signed\" (signer `notElem` signatories_so_far)"
        );
        let _ = writeln!(s, "        let next = signer :: signatories_so_far");
        let _ = writeln!(s, "        if length next == length participants");
        let _ = writeln!(s, "          then do");
        let _ = writeln!(s, "            cid <- create {} with", active);
        let _ = writeln!(s, "              workflow_id");
        let _ = writeln!(s, "              creator");
        let _ = writeln!(s, "              participants");
        let _ = writeln!(s, "              obligations");
        let _ = writeln!(s, "              discharged_ids = []");
        let _ = writeln!(s, "            return (Right cid)");
        let _ = writeln!(s, "          else do");
        let _ = writeln!(
            s,
            "            cid <- create this with signatories_so_far = next"
        );
        let _ = writeln!(s, "            return (Left cid)");
        let _ = writeln!(s);
        let _ = writeln!(s, "    choice Cancel : ()");
        let _ = writeln!(s, "      controller creator");
        let _ = writeln!(s, "      do return ()");
        let _ = writeln!(s);

        // Active<Template>: the live workflow.
        let _ = writeln!(s, "template {}", active);
        let _ = writeln!(s, "  with");
        let _ = writeln!(s, "    workflow_id : Text");
        let _ = writeln!(s, "    creator : Party");
        let _ = writeln!(s, "    participants : [Party]");
        let _ = writeln!(s, "    obligations : [{}]", map.obligation_spec_type);
        let _ = writeln!(s, "    discharged_ids : [Text]");
        let _ = writeln!(s, "  where");
        let _ = writeln!(s, "    signatory participants");
        if let Some(iface) = &map.external_interface {
            let _ = writeln!(s);
            let _ = writeln!(
                s,
                "    -- External interface binding (e.g. CIP-56 TransferInstruction)"
            );
            let _ = writeln!(s, "    interface instance {} for {} where", iface, active);
            let _ = writeln!(s, "      view = ()");
        }

        // One discharge choice per obligation.
        for ob in obligations {
            let tag = obligation_tag(&ob.kind);
            let cm = map
                .obligation_choices
                .iter()
                .find(|c| c.kind_tag == tag)
                .expect("validated above");
            let _ = writeln!(s);
            let _ = writeln!(
                s,
                "    -- Obligation 0x{} ({} → {})",
                hex::encode(ob.obligation_id.as_bytes()),
                short_did(&ob.obligor),
                short_did(&ob.obligee),
            );
            let _ = writeln!(
                s,
                "    nonconsuming choice {}_{} : ContractId {}",
                cm.choice_name,
                obligation_short_id(ob),
                active
            );
            let _ = writeln!(s, "      with");
            for f in &cm.choice_args {
                let _ = writeln!(s, "        {} : {}", f.name, f.daml_type);
            }
            let _ = writeln!(
                s,
                "      controller obligor_party_for \"0x{}\" obligations participants",
                hex::encode(ob.obligation_id.as_bytes())
            );
            let _ = writeln!(s, "      do");
            let _ = writeln!(
                s,
                "        let next_discharged = \"0x{}\" :: discharged_ids",
                hex::encode(ob.obligation_id.as_bytes())
            );
            let _ = writeln!(
                s,
                "        create this with discharged_ids = next_discharged"
            );
        }

        // Helper used by every discharge choice to resolve obligor → Party.
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "obligor_party_for : Text -> [{}] -> [Party] -> Party",
            map.obligation_spec_type
        );
        let _ = writeln!(s, "obligor_party_for oid obs _ =");
        let _ = writeln!(
            s,
            "  let matches = [o.obligor | o <- obs, o.obligation_id == oid]"
        );
        let _ = writeln!(
            s,
            "  in fromOptional (error (\"unknown obligation \" <> oid))"
        );
        let _ = writeln!(
            s,
            "       (if length matches > 0 then Some (matches !! 0) else None)"
        );
        let _ = writeln!(s);

        // Auditor / Treasurer participants emitted as comments — they
        // don't drive choices on the active template, but operators
        // grant them observer rights via party allocation.
        let auditors: Vec<&str> = workflow
            .participants
            .iter()
            .filter(|p| p.has_role(&ParticipantRole::Auditor))
            .map(|p| p.did.as_str())
            .collect();
        if !auditors.is_empty() {
            let _ = writeln!(
                s,
                "-- Auditor parties (observer-only via party allocation):"
            );
            for did in auditors {
                let _ = writeln!(s, "--   {}", did);
            }
            let _ = writeln!(s);
        }

        let treasurers: Vec<&str> = workflow
            .participants
            .iter()
            .filter(|p| p.has_role(&ParticipantRole::Treasurer))
            .map(|p| p.did.as_str())
            .collect();
        if !treasurers.is_empty() {
            let _ = writeln!(s, "-- Treasurer parties (control fee splits + escrow):");
            for did in treasurers {
                let _ = writeln!(s, "--   {}", did);
            }
            let _ = writeln!(s);
        }

        // Discharge proof kinds the obligations require — surfaced as
        // a comment for human review of the emitted DAML.
        let _ = writeln!(s, "-- Discharge proof kinds expected per obligation:");
        for ob in obligations {
            let _ = writeln!(
                s,
                "--   0x{}: {}",
                hex::encode(ob.obligation_id.as_bytes()),
                discharge_kind_label(&ob.discharge_proof_required)
            );
        }

        Ok(s)
    }
}

fn obligation_tag(kind: &ObligationKind) -> &'static str {
    match kind {
        ObligationKind::Pay { .. } => "Pay",
        ObligationKind::Deliver { .. } => "Deliver",
        ObligationKind::Attest { .. } => "Attest",
        ObligationKind::Settle { .. } => "Settle",
        ObligationKind::Custom { .. } => "Custom",
    }
}

fn obligation_short_id(ob: &Obligation) -> String {
    let bytes = ob.obligation_id.as_bytes();
    // First 4 bytes (8 hex chars) — collisions inside one workflow are
    // extremely unlikely; the full id still drives the controller lookup.
    hex::encode(&bytes[..4])
}

fn short_did(did: &str) -> String {
    // Strip the `did:tenzro:human:`/`machine:` prefix for readability
    // in emitted comments; full DIDs remain in the runtime payload.
    did.split(':').next_back().unwrap_or(did).to_string()
}

fn discharge_kind_label(k: &DischargeProofKind) -> String {
    match k {
        DischargeProofKind::PaymentReceipt => "PaymentReceipt".into(),
        DischargeProofKind::SettlementReceipt => "SettlementReceipt".into(),
        DischargeProofKind::Credential => "Credential".into(),
        DischargeProofKind::TeeAttestation => "TeeAttestation".into(),
        DischargeProofKind::ZkProof { circuit_id } => format!("ZkProof({})", circuit_id),
        DischargeProofKind::CantonExercise {
            template_id,
            choice,
        } => {
            format!("CantonExercise({}::{})", template_id, choice)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obligation::{
        AssetRef, DischargeProofKind, Obligation, ObligationKind, ObligationStatus,
    };
    use crate::participant::{Participant, ParticipantRole};
    use crate::policy_dsl::PolicyExpr;
    use crate::workflow::{CantonMirror, Workflow, WorkflowStatus};
    use tenzro_types::primitives::Hash;

    fn mk_wf_with_mirror() -> Workflow {
        let id = Workflow::derive_id("did:tenzro:human:alice:1", "proc-test", 1700000000);
        Workflow {
            workflow_id: id,
            template_id: None,
            creator: "did:tenzro:human:alice:1".into(),
            title: "proc-test".into(),
            description: None,
            participants: vec![
                Participant::new("did:tenzro:human:alice:1", vec![ParticipantRole::Initiator]),
                Participant::new(
                    "did:tenzro:machine:alice:bot:1",
                    vec![ParticipantRole::Counterparty],
                ),
                Participant::new(
                    "did:tenzro:human:bob:1",
                    vec![ParticipantRole::Counterparty],
                ),
                Participant::new("did:tenzro:human:t:1", vec![ParticipantRole::Treasurer]),
                Participant::new("did:tenzro:human:aud:1", vec![ParticipantRole::Auditor]),
            ],
            obligations: vec![],
            approval_gates: vec![],
            root_policy: PolicyExpr::Allow,
            privacy_domain: None,
            fee_route: None,
            signatures: vec![],
            status: WorkflowStatus::Draft,
            canton_mirror: Some(CantonMirror {
                synchronizer_id: "global-synchronizer".into(),
                party: "tenzro::1220deadbeef".into(),
                contract_id: "00abc#0".into(),
            }),
            created_at: 1700000000,
            updated_at: 1700000000,
        }
    }

    fn mk_obligation(
        workflow_id: Hash,
        obligor: &str,
        obligee: &str,
        nonce: u64,
        kind: ObligationKind,
        dp: DischargeProofKind,
    ) -> Obligation {
        Obligation {
            obligation_id: Obligation::derive_id(&workflow_id, obligor, obligee, nonce),
            workflow_id,
            obligor: obligor.into(),
            obligee: obligee.into(),
            kind,
            due_by: None,
            status: ObligationStatus::Pending,
            discharge_proof_required: dp,
            bond_anchor: None,
        }
    }

    fn mk_map() -> DamlMap {
        DamlMap {
            module: "Tenzro.Workflow.AutonomousProcurement".into(),
            template_name: "AutonomousProcurement".into(),
            obligation_spec_type: "ObligationSpec".into(),
            obligation_choices: vec![
                ObligationChoiceMap {
                    kind_tag: "Pay".into(),
                    choice_name: "DischargePay".into(),
                    choice_args: vec![
                        DamlArgField {
                            name: "amount".into(),
                            daml_type: "Decimal".into(),
                        },
                        DamlArgField {
                            name: "asset_symbol".into(),
                            daml_type: "Text".into(),
                        },
                        DamlArgField {
                            name: "payment_receipt_hash".into(),
                            daml_type: "Text".into(),
                        },
                    ],
                },
                ObligationChoiceMap {
                    kind_tag: "Deliver".into(),
                    choice_name: "DischargeDeliver".into(),
                    choice_args: vec![
                        DamlArgField {
                            name: "resource_did".into(),
                            daml_type: "Text".into(),
                        },
                        DamlArgField {
                            name: "qty".into(),
                            daml_type: "Int".into(),
                        },
                        DamlArgField {
                            name: "delivery_credential_hash".into(),
                            daml_type: "Text".into(),
                        },
                    ],
                },
            ],
            external_interface: Some("Token.TransferInstruction".into()),
        }
    }

    #[test]
    fn emit_rejects_workflow_without_mirror() {
        let mut wf = mk_wf_with_mirror();
        wf.canton_mirror = None;
        let r = WorkflowDamlCodegen::emit(&wf, &mk_map(), &[]);
        assert!(r.is_err());
    }

    #[test]
    fn emit_rejects_unknown_obligation_tag() {
        let wf = mk_wf_with_mirror();
        let map = DamlMap {
            // Map without "Settle" mapping
            obligation_choices: vec![],
            ..mk_map()
        };
        let ob = mk_obligation(
            wf.workflow_id,
            "did:tenzro:machine:alice:bot:1",
            "did:tenzro:human:bob:1",
            0,
            ObligationKind::Settle {
                settlement_id: Hash::zero(),
            },
            DischargeProofKind::SettlementReceipt,
        );
        let r = WorkflowDamlCodegen::emit(&wf, &map, &[ob]);
        assert!(r.is_err());
    }

    #[test]
    fn emit_rejects_obligor_not_in_participants() {
        let wf = mk_wf_with_mirror();
        let ob = mk_obligation(
            wf.workflow_id,
            "did:tenzro:human:notamember:1",
            "did:tenzro:human:bob:1",
            0,
            ObligationKind::Pay {
                amount_wei: 1_000,
                asset: AssetRef {
                    chain: "tenzro".into(),
                    symbol: "USDC".into(),
                    token_address: None,
                },
            },
            DischargeProofKind::PaymentReceipt,
        );
        let r = WorkflowDamlCodegen::emit(&wf, &mk_map(), &[ob]);
        assert!(r.is_err());
    }

    #[test]
    fn emit_is_deterministic() {
        let wf = mk_wf_with_mirror();
        let map = mk_map();
        let ob = mk_obligation(
            wf.workflow_id,
            "did:tenzro:machine:alice:bot:1",
            "did:tenzro:human:bob:1",
            0,
            ObligationKind::Pay {
                amount_wei: 50_000,
                asset: AssetRef {
                    chain: "tenzro".into(),
                    symbol: "USDC".into(),
                    token_address: None,
                },
            },
            DischargeProofKind::PaymentReceipt,
        );
        let a = WorkflowDamlCodegen::emit(&wf, &map, std::slice::from_ref(&ob)).unwrap();
        let b = WorkflowDamlCodegen::emit(&wf, &map, &[ob]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn reference_daml_map_parses() {
        // Locks in the on-disk format of the autonomous_procurement DAML map.
        // If the DamlMap shape changes, regenerate the file.
        let raw = include_str!("../reference_workflows/autonomous_procurement_daml_map.json");
        let map: DamlMap = serde_json::from_str(raw).expect("daml map must parse");
        assert_eq!(map.module, "Tenzro.Workflow.AutonomousProcurement");
        assert_eq!(map.template_name, "AutonomousProcurement");
        assert_eq!(map.obligation_spec_type, "ObligationSpec");
        // Pay + Deliver are both mapped.
        assert!(map.obligation_choices.iter().any(|c| c.kind_tag == "Pay"));
        assert!(
            map.obligation_choices
                .iter()
                .any(|c| c.kind_tag == "Deliver")
        );
        assert_eq!(
            map.external_interface.as_deref(),
            Some("Token.TransferInstruction")
        );
    }

    #[test]
    fn all_reference_daml_maps_parse() {
        // Locks in the on-disk format of every reference workflow's DAML map.
        // Adding a new reference template requires adding it here.
        let cases = [
            (
                include_str!("../reference_workflows/autonomous_treasury_daml_map.json"),
                "Tenzro.Workflow.AutonomousTreasury",
                "AutonomousTreasury",
                "Settle",
                None,
            ),
            (
                include_str!("../reference_workflows/dvp_settlement_daml_map.json"),
                "Tenzro.Workflow.DvpSettlement",
                "DvpSettlement",
                "Pay",
                Some("Token.AtomicSwap"),
            ),
            (
                include_str!("../reference_workflows/supply_chain_dpp_daml_map.json"),
                "Tenzro.Workflow.SupplyChainDpp",
                "SupplyChainDpp",
                "Attest",
                None,
            ),
            (
                include_str!("../reference_workflows/environmental_mrv_daml_map.json"),
                "Tenzro.Workflow.EnvironmentalMrv",
                "EnvironmentalMrv",
                "Pay",
                Some("Token.MintInstruction"),
            ),
        ];
        for (raw, module, template, expected_tag, iface) in cases {
            let map: DamlMap = serde_json::from_str(raw)
                .unwrap_or_else(|e| panic!("{} must parse: {}", module, e));
            assert_eq!(map.module, module);
            assert_eq!(map.template_name, template);
            assert!(
                map.obligation_choices
                    .iter()
                    .any(|c| c.kind_tag == expected_tag),
                "{} missing {} mapping",
                module,
                expected_tag
            );
            assert_eq!(map.external_interface.as_deref(), iface);
        }
    }

    #[test]
    fn emit_contains_required_skeleton() {
        let wf = mk_wf_with_mirror();
        let map = mk_map();
        let ob1 = mk_obligation(
            wf.workflow_id,
            "did:tenzro:machine:alice:bot:1",
            "did:tenzro:human:bob:1",
            0,
            ObligationKind::Pay {
                amount_wei: 50_000,
                asset: AssetRef {
                    chain: "tenzro".into(),
                    symbol: "USDC".into(),
                    token_address: None,
                },
            },
            DischargeProofKind::PaymentReceipt,
        );
        let ob2 = mk_obligation(
            wf.workflow_id,
            "did:tenzro:human:bob:1",
            "did:tenzro:machine:alice:bot:1",
            1,
            ObligationKind::Deliver {
                resource_did: "did:tenzro:resource:widget:1".into(),
                qty: 5,
            },
            DischargeProofKind::Credential,
        );
        let s = WorkflowDamlCodegen::emit(&wf, &map, &[ob1, ob2]).unwrap();
        assert!(s.contains("module Tenzro.Workflow.AutonomousProcurement where"));
        assert!(s.contains("template PendingAutonomousProcurement"));
        assert!(s.contains("template ActiveAutonomousProcurement"));
        assert!(s.contains("choice Sign"));
        assert!(s.contains("choice Cancel"));
        assert!(s.contains("DischargePay_"));
        assert!(s.contains("DischargeDeliver_"));
        assert!(s.contains("interface instance Token.TransferInstruction"));
        assert!(s.contains("Treasurer"));
        assert!(s.contains("Auditor"));
    }
}
