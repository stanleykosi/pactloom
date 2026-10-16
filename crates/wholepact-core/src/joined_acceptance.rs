//! Metadata-only itinerary for the ordinary two-owner acceptance boundary.
//!
//! A captured value is an untrusted transcription, never a receipt, capability,
//! permission, native decision, live lease or financial outcome. This module
//! cannot execute a stage or generate an original identifier or artifact.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_CONFIG_BYTES: usize = 65_536;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    schema_version: u32,
    route: Route,
    network: Network,
    dispatch: Dispatch,
    originals: BTreeMap<String, String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Route {
    OrdinaryTwoOwner,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Network {
    Testnet,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Dispatch {
    Disabled,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("Invalid bounded metadata config; unknown fields, duplicate keys and execution/approval flags are forbidden")]
    InvalidConfig,
    #[error(
        "Unknown or malformed original reference; preserve the genuine native source unchanged"
    )]
    InvalidReference,
    #[error("The two slots must refer to distinct original owners and authorizations")]
    DuplicateOwner,
    #[error("A previously captured original was removed or changed; automatic replacement or renewal is forbidden")]
    ChangedOriginal,
}

#[derive(Clone, Copy)]
enum Kind {
    Id,
    Digest,
    Revision,
    Height,
    Sequence,
    MessageId,
    Time,
}
#[derive(Clone, Copy)]
struct Reference {
    name: &'static str,
    kind: Kind,
}
const fn id(name: &'static str) -> Reference {
    Reference {
        name,
        kind: Kind::Id,
    }
}
const fn digest(name: &'static str) -> Reference {
    Reference {
        name,
        kind: Kind::Digest,
    }
}
const fn typed(name: &'static str, kind: Kind) -> Reference {
    Reference { name, kind }
}
const REFERENCES: &[Reference] = &[
    id("network_profile_id"),
    typed("proposal_revision", Kind::Revision),
    typed("proof_revision", Kind::Revision),
    typed("coordination_deadline", Kind::Time),
    id("agreement_id"),
    id("candidate_id"),
    digest("manifest_digest"),
    Reference {
        name: "construction_revision",
        kind: Kind::Revision,
    },
    Reference {
        name: "transaction_expiry_height",
        kind: Kind::Height,
    },
    id("construction_key"),
    id("job_id"),
    digest("scope_digest"),
    digest("coordination_request_digest"),
    digest("input_digest"),
    digest("effects_commitment"),
    digest("review_binding"),
    id("proof_operation_key"),
    digest("proved_artifact_digest"),
    id("review_request_id"),
    id("signature_retention_key"),
    id("signed_result_id"),
    id("checkpoint_id"),
    digest("transaction_digest"),
    digest("txid"),
    id("submission_operation_id"),
    id("owner_a.account_id"),
    id("owner_a.participant_id"),
    digest("owner_a.enrollment_ref"),
    digest("owner_a.accepted_manifest_ref"),
    id("owner_a.authorization_id"),
    digest("owner_a.original_consent_ref"),
    id("owner_a.export_redelivery_operation_id"),
    id("owner_a.intake_redelivery_operation_id"),
    digest("owner_a.authorization_ciphertext_digest"),
    id("owner_a.record_id"),
    id("owner_a.record_retention_key"),
    typed("owner_a.record_revision", Kind::Revision),
    id("owner_a.transport_recipient_id"),
    typed("owner_a.transport_message_id", Kind::MessageId),
    typed("owner_a.transport_sequence", Kind::Sequence),
    typed("owner_a.transport_issued_at", Kind::Time),
    typed("owner_a.transport_expires_at", Kind::Time),
    id("owner_a.dispatch_operation_id"),
    id("owner_a.resolution_redelivery_operation_id"),
    id("owner_b.account_id"),
    id("owner_b.participant_id"),
    digest("owner_b.enrollment_ref"),
    digest("owner_b.accepted_manifest_ref"),
    id("owner_b.authorization_id"),
    digest("owner_b.original_consent_ref"),
    id("owner_b.export_redelivery_operation_id"),
    id("owner_b.intake_redelivery_operation_id"),
    digest("owner_b.authorization_ciphertext_digest"),
    id("owner_b.record_id"),
    id("owner_b.record_retention_key"),
    typed("owner_b.record_revision", Kind::Revision),
    id("owner_b.transport_recipient_id"),
    typed("owner_b.transport_message_id", Kind::MessageId),
    typed("owner_b.transport_sequence", Kind::Sequence),
    typed("owner_b.transport_issued_at", Kind::Time),
    typed("owner_b.transport_expires_at", Kind::Time),
    id("owner_b.dispatch_operation_id"),
    id("owner_b.resolution_redelivery_operation_id"),
];

#[derive(Serialize)]
pub struct Stage {
    pub name: &'static str,
    pub source: &'static str,
    pub entry_point: &'static str,
    pub native_step: &'static str,
    pub consumes: Vec<&'static str>,
    pub capture: &'static [&'static str],
    pub status: &'static str,
    pub missing_originals: Vec<&'static str>,
    pub warning: &'static str,
}
macro_rules! stage {
    ($name:literal, $source:literal, $entry:literal, $step:literal,
     [$($input:literal),* $(,)?], [$($output:literal),* $(,)?], $warning:literal) => {
        Stage { name: $name, source: $source, entry_point: $entry, native_step: $step,
            consumes: vec![$($input),*], capture: &[$($output),*], status: "pending_native_step",
            missing_originals: Vec::new(), warning: $warning }
    };
}

fn stages() -> Vec<Stage> {
    vec![
        stage!("candidate", "crates/wholepact-native-host/src/host/financial.rs", "financial_candidate",
            "candidate-prepare / candidate-read / candidate-review",
            ["owner_a.account_id", "owner_a.participant_id", "owner_b.account_id", "owner_b.participant_id"],
            ["agreement_id", "candidate_id", "manifest_digest", "network_profile_id", "proposal_revision", "coordination_deadline", "transaction_expiry_height"],
            "Use the actual immutable two-owner candidate. Claims-only review is not cryptographic review or authorization."),
        stage!("construction", "crates/wholepact-native-host/src/host/financial/construction.rs", "financial_construct",
            "candidate-construct",
            ["candidate_id", "manifest_digest", "owner_a.enrollment_ref", "owner_a.accepted_manifest_ref", "owner_b.enrollment_ref", "owner_b.accepted_manifest_ref"],
            ["construction_key", "construction_revision", "job_id", "scope_digest", "coordination_request_digest", "input_digest", "effects_commitment", "review_binding"],
            "Each real signer must separately approve FVK disclosure, exact destinations and complete reviewer roster; genuine scans and held leases create the constructor receipt and private checkpoint. A receipt alone does not establish both journal commits."),
        stage!("proof", "crates/wholepact-native-host/src/host/financial.rs", "financial_proof",
            "proof-status / proof-run / proof-review",
            ["candidate_id", "job_id", "scope_digest", "coordination_request_digest", "input_digest", "review_binding"],
            ["proof_operation_key", "proof_revision", "proved_artifact_digest"],
            "Proving is separately authorized future native work. Keep original job/randomness; after interruption inspect and reconcile, never rebuild under a new key."),
        stage!("proved_disclosure", "crates/wholepact-native-host/src/host/financial/proof_delivery.rs", "financial_proof_delivery",
            "proof-send-for-review",
            ["candidate_id", "job_id", "proved_artifact_digest", "review_binding", "owner_a.enrollment_ref", "owner_a.accepted_manifest_ref", "owner_b.enrollment_ref", "owner_b.accepted_manifest_ref"],
            ["review_request_id"],
            "Every owner explicitly accepts peer FVK/private proved-PCZT disclosure to the complete actual installed reviewer roster. Pairing or a request acknowledgment is not spend approval."),
        stage!("owner_a_authorization", "crates/wholepact-signer/src/authority_bridge/signing.rs", "authorize_with_wallet",
            "Independent signer A: local wallet/witness and exact spending review",
            ["candidate_id", "manifest_digest", "proved_artifact_digest", "review_request_id", "owner_a.account_id", "owner_a.enrollment_ref", "owner_a.accepted_manifest_ref"],
            ["owner_a.authorization_id", "owner_a.original_consent_ref"],
            "Complete the focused signing/wallet/witness worker before switching windows. The host cannot issue this native decision."),
        stage!("owner_b_authorization", "crates/wholepact-signer/src/authority_bridge/signing.rs", "authorize_with_wallet",
            "Independent signer B: local wallet/witness and exact spending review",
            ["candidate_id", "manifest_digest", "proved_artifact_digest", "review_request_id", "owner_b.account_id", "owner_b.enrollment_ref", "owner_b.accepted_manifest_ref"],
            ["owner_b.authorization_id", "owner_b.original_consent_ref"],
            "Complete the focused signing/wallet/witness worker before switching windows. Earlier idle exact leases retain only their original scope and deadline."),
        stage!("authorization_transport", "crates/wholepact-native-host/src/host/financial/signature_export.rs", "financial_signature_export",
            "signature-export separately for each original owner",
            ["candidate_id", "owner_a.authorization_id", "owner_a.original_consent_ref", "owner_b.authorization_id", "owner_b.original_consent_ref"],
            ["owner_a.export_redelivery_operation_id", "owner_a.authorization_ciphertext_digest", "owner_a.transport_recipient_id", "owner_a.transport_message_id", "owner_a.transport_sequence", "owner_a.transport_issued_at", "owner_a.transport_expires_at", "owner_b.export_redelivery_operation_id", "owner_b.authorization_ciphertext_digest", "owner_b.transport_recipient_id", "owner_b.transport_message_id", "owner_b.transport_sequence", "owner_b.transport_issued_at", "owner_b.transport_expires_at"],
            "Separate signer exact-result redelivery and pinned-recipient transport consent; retained ciphertext/file write is not delivery or approval. Retry immutable bytes only."),
        stage!("signature_intake", "crates/wholepact-native-host/src/host/financial/settlement.rs", "financial_settle",
            "signature-retain / signature-reconcile",
            ["candidate_id", "job_id", "proved_artifact_digest", "owner_a.authorization_id", "owner_a.original_consent_ref", "owner_a.authorization_ciphertext_digest", "owner_b.authorization_id", "owner_b.original_consent_ref", "owner_b.authorization_ciphertext_digest"],
            ["owner_a.intake_redelivery_operation_id", "owner_b.intake_redelivery_operation_id", "signature_retention_key", "signed_result_id"],
            "Authenticate original encrypted deliveries and nested original-signer account histories through commit. Transport identity cannot substitute for owner association."),
        stage!("transaction_checkpoint", "crates/wholepact-native-host/src/host/financial/settlement.rs", "financial_settle",
            "transaction-checkpoint",
            ["candidate_id", "job_id", "signature_retention_key", "signed_result_id"],
            ["checkpoint_id", "transaction_digest", "txid"],
            "Separately approve exact extraction/retention. An interrupted randomized extraction stays fenced; no automatic regeneration."),
        stage!("dispatch", "crates/wholepact-native-host/src/host/financial/settlement.rs", "financial_settle",
            "transaction-dispatch (disabled in this planner; separate future authorization required)",
            ["candidate_id", "job_id", "signature_retention_key", "transaction_digest", "txid", "owner_a.authorization_id", "owner_b.authorization_id"],
            ["submission_operation_id", "owner_a.dispatch_operation_id", "owner_b.dispatch_operation_id"],
            "No execution switch exists. Future native dispatch needs exact provider approval and every original signer admission. A timeout may have submitted; preserve exposure and original bytes/operation."),
        stage!("observation", "crates/wholepact-native-host/src/host.rs", "fn observe",
            "observe / serve / Ctrl+C and complete drain (future attended runtime only)",
            ["submission_operation_id", "candidate_id", "transaction_digest"], [],
            "Conservative observation can invalidate confidence/reopen exposure. It cannot positively resolve signer/witness stores or clear exposure. Stop and drain before any native command."),
        stage!("participant_records", "crates/wholepact-native-host/src/host/financial/settlement.rs", "financial_settle",
            "record-retain separately for each original participant",
            ["candidate_id", "job_id", "signature_retention_key", "transaction_digest", "owner_a.authorization_id", "owner_b.authorization_id"],
            ["owner_a.record_id", "owner_a.record_retention_key", "owner_a.record_revision", "owner_b.record_id", "owner_b.record_retention_key", "owner_b.record_revision"],
            "Retain genuine owner-bound private records, preserving original revisions/keys. A record or selected receipt does not independently prove payment."),
        stage!("positive_resolution", "crates/wholepact-native-host/src/host/financial/record_resolution.rs", "financial_record_resolve",
            "resolution-source / record-resolve separately for each participant",
            ["submission_operation_id", "candidate_id", "transaction_digest", "owner_a.authorization_id", "owner_a.record_id", "owner_b.authorization_id", "owner_b.record_id", "owner_a.dispatch_operation_id", "owner_b.dispatch_operation_id"], ["owner_a.resolution_redelivery_operation_id", "owner_b.resolution_redelivery_operation_id"],
            "Requires separate host-owned and signer-owned validating-node sources, fresh native decisions and live permits. Partial independent commits remain possible; no replacement or finality is inferred."),
    ]
}

#[derive(Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub mode: &'static str,
    pub config_shape: &'static str,
    pub original_reference_count: usize,
    pub captured_references_are: &'static str,
    pub execution_enabled: bool,
    pub dispatch_enabled: bool,
    pub runtime_qualification: &'static str,
    pub product_acceptance: &'static str,
    pub prerequisites: &'static [&'static str],
    pub stages: Vec<Stage>,
}

pub fn parse_config(bytes: &[u8]) -> Result<Config, PlanError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(PlanError::InvalidConfig);
    }
    let config: Config = crate::parse_typed_json(bytes).map_err(|_| PlanError::InvalidConfig)?;
    if config.schema_version != 1 {
        return Err(PlanError::InvalidConfig);
    }
    for (name, value) in &config.originals {
        let reference = REFERENCES
            .iter()
            .find(|r| r.name == name)
            .ok_or(PlanError::InvalidReference)?;
        let valid = match reference.kind {
            Kind::Id => {
                !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            }
            Kind::Digest => {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
            Kind::MessageId => {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
            Kind::Sequence => value
                .parse::<u64>()
                .is_ok_and(|n| n > 0 && n <= i64::MAX as u64 && n.to_string() == *value),
            Kind::Time => {
                crate::agreement::validate_timestamp(value).is_ok()
                    && value.as_str() >= "1970-01-01T00:00:00Z"
            }
            Kind::Revision => value.parse::<u64>().is_ok_and(|n| n.to_string() == *value),
            Kind::Height => value
                .parse::<u32>()
                .is_ok_and(|n| n.to_string() == *value && n > 0),
        };
        if !valid {
            return Err(PlanError::InvalidReference);
        }
    }
    for owner in ["owner_a", "owner_b"] {
        if let (Some(start), Some(end)) = (
            config
                .originals
                .get(&format!("{owner}.transport_issued_at")),
            config
                .originals
                .get(&format!("{owner}.transport_expires_at")),
        ) {
            if end <= start {
                return Err(PlanError::InvalidReference);
            }
        }
    }
    for field in [
        "account_id",
        "participant_id",
        "authorization_id",
        "record_id",
    ] {
        if let (Some(a), Some(b)) = (
            config.originals.get(&format!("owner_a.{field}")),
            config.originals.get(&format!("owner_b.{field}")),
        ) {
            if a == b {
                return Err(PlanError::DuplicateOwner);
            }
        }
    }
    Ok(config)
}

/// Add captured originals only. The optional prior file is local bookkeeping,
/// not a trusted journal or an anti-rollback authority.
pub fn preserve_originals(prior: &Config, current: &Config) -> Result<(), PlanError> {
    if prior
        .originals
        .iter()
        .any(|(key, value)| current.originals.get(key) != Some(value))
    {
        return Err(PlanError::ChangedOriginal);
    }
    Ok(())
}

pub fn plan(config: &Config) -> Plan {
    let mut stages = stages();
    for stage in &mut stages {
        // These native operations all consume complete original history. A
        // shared name joins metadata; it never authenticates the corresponding
        // signer-owned history or creates a lease.
        if matches!(
            stage.name,
            "authorization_transport"
                | "signature_intake"
                | "transaction_checkpoint"
                | "dispatch"
                | "participant_records"
                | "positive_resolution"
        ) {
            for name in [
                "owner_a.account_id",
                "owner_a.participant_id",
                "owner_a.enrollment_ref",
                "owner_a.accepted_manifest_ref",
                "owner_a.authorization_id",
                "owner_a.original_consent_ref",
                "owner_b.account_id",
                "owner_b.participant_id",
                "owner_b.enrollment_ref",
                "owner_b.accepted_manifest_ref",
                "owner_b.authorization_id",
                "owner_b.original_consent_ref",
            ] {
                if !stage.consumes.contains(&name) {
                    stage.consumes.push(name);
                }
            }
        }
        if matches!(
            stage.name,
            "authorization_transport"
                | "signature_intake"
                | "transaction_checkpoint"
                | "dispatch"
                | "participant_records"
        ) {
            stage
                .consumes
                .extend(["network_profile_id", "proposal_revision"]);
        }
        stage.missing_originals = stage
            .consumes
            .iter()
            .copied()
            .filter(|name| !config.originals.contains_key(*name))
            .collect();
        if !stage.missing_originals.is_empty() {
            stage.status = "pending_original_references_and_native_step";
        }
        if stage.name == "dispatch" {
            stage.status = "disabled_separate_authorization_required";
        }
    }
    Plan {
        schema_version: 1, mode: "dry_run_only", config_shape: "valid",
        original_reference_count: config.originals.len(),
        captured_references_are: "untrusted_metadata_never_authority_or_completion",
        execution_enabled: false, dispatch_enabled: false,
        runtime_qualification: "not_run", product_acceptance: "not_established",
        prerequisites: &[
            "PENDING: separately authorized attended Linux controlling TTY and genuine independent owner signer windows; no automated PTY approval",
            "PENDING: qualified financial-runtime build and root-controlled installed signer pin; do not install/change trust roots in this workflow",
            "PENDING: ordinary unrecovered profile, exact native principal permissions, protected encrypted journals and complete financial attachment inventory",
            "PENDING: separately provisioned/backup-verified dedicated owner accounts, independent writer/witness authority and accepted immutable candidate",
            "PENDING: explicitly accepted irreversible peer FVK/proved-PCZT disclosure from EACH owner; no implied consent from membership or pairing",
            "PENDING: actual provider/source policy, fresh common-anchor scans and actual funds; no funding, credentials or external calls here",
            "PENDING: service stopped and all blocking jobs drained before native commands",
            "PENDING: keep idle consumed exact leases within original deadlines; finish each active signing/wallet/witness/recipient worker before changing focus",
            "PENDING: authentic original receipts/artifacts re-read by existing native owners; transcribed IDs and digests do not authenticate them",
            "PENDING: independent recipient verification, failure/reorg behavior and installed-platform/security qualification beyond this bounded itinerary",
        ], stages,
    }
}

#[cfg(test)]
mod tests;
