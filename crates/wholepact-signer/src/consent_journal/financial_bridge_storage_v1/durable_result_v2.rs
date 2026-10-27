//! Explicit completed-result recovery. Historical signing evidence is data;
//! only a new native V2 Read permits its private interpretation for disclosure.
//! The original schema, authorization, exposure and recipient rows never change.
use super::*;
use crate::authority_bridge::financial_continuation_v1::{
    DurableFinancialResultRequestV2, FinancialResultRequestV1,
};
use crate::native_peer::PeerProcess;
use crate::native_ui::durable_result_authority_v2::DurableFinancialResultReadV2;

/// No Clone/serde/public constructor. Full rows and pin come from one audited
/// actual encrypted transaction, not a stored "verified" assertion.
pub(crate) struct AuditedDurableFinancialResultRowsV2 {
    pub(crate) original: OriginalAuthorizationEvidence,
    pub(crate) result: RetainedAuthorizationResult,
    pub(crate) continuation: wholepact_authority::OwnerControlRequest,
    pub(crate) selection: DurableFinancialResultRequestV2,
    pub(crate) pin: FinancialReturnJournalPinV1,
}

/// Qualification observation of authenticated retained local evidence only.
/// Not a fresh Witness reconciliation, saved permission, or completed result.
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Serialize, PartialEq, Eq)]
pub(crate) struct FinancialStartedOnlyAuditV2 {
    pub(crate) account_id: String,
    pub(crate) authorization_id: String,
    pub(crate) original_rows_digest: String,
    pub(crate) continuation_history_digest: String,
    pub(crate) started_count: u64,
    pub(crate) result_count: u64,
    pub(crate) outbox_count: u64,
    pub(crate) retained_exposure_state: String,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl FinancialConsentJournalV1 {
    pub(crate) fn audit_started_only_rows_for_qualification_v2(
        &self,
        source: &FinancialSourceBindingV1,
        expected_account: &str,
        expected_authorization: &str,
    ) -> BridgeResult<FinancialStartedOnlyAuditV2> {
        let _fence = self.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.journal.connection.lock().map_err(|_| JournalError::Database)?;
        if !c.is_autocommit() { return Err(BridgeError::Conflict); }
        source.require(&self.journal, &c)?;
        source.require_pin(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred).map_err(JournalError::from)?;
        validate(&tx, &self.genesis)?;
        let retained = intent::read(&tx)?;
        let terms = retained.terms()?;
        let account_id = terms.scope.authorization.identity.account_id.clone();
        let authorization_id = terms.scope.authorization.authorization_id.clone();
        if account_id != expected_account || authorization_id != expected_authorization {
            return Err(BridgeError::Binding);
        }
        let started_count: u64 = tx.query_row("SELECT count(*) FROM signer_bridge_keyuse", [], |r| r.get(0)).map_err(JournalError::from)?;
        let exact_started: u64 = tx.query_row("SELECT count(*) FROM signer_bridge_keyuse WHERE authorization_id=?1", [&authorization_id], |r| r.get(0)).map_err(JournalError::from)?;
        let result_count: u64 = tx.query_row("SELECT count(*) FROM signer_bridge_results", [], |r| r.get(0)).map_err(JournalError::from)?;
        let outbox_count: u64 = tx.query_row("SELECT count(*) FROM signer_bridge_results WHERE outbox_payload IS NOT NULL", [], |r| r.get(0)).map_err(JournalError::from)?;
        let retained_exposure_state: String = tx.query_row("SELECT exposure_state FROM signer_release_intents WHERE authorization_id=?1", [&authorization_id], |r| r.get(0)).map_err(JournalError::from)?;
        if started_count != 1 || exact_started != 1 || result_count != 0 || outbox_count != 0
            || retained_exposure_state != "outstanding_uncertain"
        { return Err(BridgeError::Binding); }
        // Exercise the actual unchanged row reader, not an inferred count flag.
        if !matches!(read_retained_result_rows(&tx), Err(BridgeError::Uncertain)) {
            return Err(BridgeError::Binding);
        }
        let audit = FinancialStartedOnlyAuditV2 {
            account_id, authorization_id,
            original_rows_digest: original_rows_digest(&tx)?,
            continuation_history_digest: retained.history_digest()?,
            started_count, result_count, outbox_count, retained_exposure_state,
        };
        source.require(&self.journal, &tx)?;
        source.require_pin(&tx)?;
        tx.commit().map_err(JournalError::from)?;
        source.require(&self.journal, &c)?;
        source.require_pin(&c)?;
        Ok(audit)
    }
}

// Complete strict data projection, never a verified proof or current grant.
fn exact_fixed_identity_v2(
    original: &wholepact_authority::durable_payment_v1::DurableFixedCandidateBindingV1,
) -> BridgeResult<wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1> {
    let fixed = wholepact_core::parse_typed_json(&serde_json::to_vec(original)
        .map_err(|_| BridgeError::Binding)?).map_err(|_| BridgeError::Binding)?;
    let rebound = crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(&fixed)?;
    rebound.validate()?;
    if &rebound != original { return Err(BridgeError::Binding); }
    Ok(fixed)
}

fn exact_selection(
    c: &Connection,
    original: &OriginalAuthorizationEvidence,
    result: &RetainedAuthorizationResult,
    retained: &intent::RetainedFinancialContinuationIntentV1,
) -> BridgeResult<DurableFinancialResultRequestV2> {
    // Select a supported namespace once; a failed decoder never falls back.
    match original_delivery::profile(c)? {
        durable_born_entry_v1::OriginalDeliveryProfileV1::NativeV3 => {},
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        durable_born_entry_v1::OriginalDeliveryProfileV1::CoordinatedV3 => {},
    }
    let terms = retained.terms()?;
    let delivery = original_delivery::read(c, &result.authorization_id)?
        .ok_or(BridgeError::Missing)?;
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &retained.request().control
        else { return Err(BridgeError::Binding); };
    let fixed = exact_fixed_identity_v2(&terms.scope.authorization.fixed)?;
    let selection = DurableFinancialResultRequestV2 {
        version: 2,
        request: FinancialResultRequestV1 {
            account_id: terms.scope.authorization.identity.account_id.clone(),
            authorization_id: result.authorization_id.clone(),
            original_consent_ref: original.original_consent().reference().to_owned(),
            fixed,
        },
        result_digest: result.result_digest.clone(),
        outbox_digest: result.outbox_digest.clone(),
        continuation_request_digest: record.request_digest(retained.request())?,
        continuation_history_digest: retained.history_digest()?,
        original_delivery_intent_digest: delivery.recipient_intent_digest()?,
        original_host_process_instance: delivery.original_host_process_instance().to_owned(),
        original_terms_digest: terms.intent_terms_digest()?,
    };
    selection.validate()?;
    Ok(selection)
}

impl FinancialConsentJournalV1 {
    /// Metadata-only selection from the actual unlocked original. This returns
    /// neither private result bytes nor permission to read, sign or transmit.
    pub(crate) fn durable_result_selection_v2(
        &self, source: &FinancialSourceBindingV1,
    ) -> BridgeResult<(DurableFinancialResultRequestV2, String)> {
        let _fence = self.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.journal.connection.lock().map_err(|_| JournalError::Database)?;
        if !c.is_autocommit() { return Err(BridgeError::Conflict); }
        source.require(&self.journal, &c)?;
        source.require_pin(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred).map_err(JournalError::from)?;
        validate(&tx, &self.genesis)?;
        // Started without a committed result is Uncertain, never resumable Sign.
        let (original, _, _, result, retained) = read_retained_result_rows(&tx)?;
        let selection = exact_selection(&tx, &original, &result, &retained)?;
        let delivery = original_delivery::read(&tx, &result.authorization_id)?.ok_or(BridgeError::Missing)?;
        let recipient = match delivery {
            original_delivery::OriginalDeliveryEvidenceV1::Native(value) => serde_json::to_value(value.recipient_intent()),
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            original_delivery::OriginalDeliveryEvidenceV1::Coordinated(value) => serde_json::to_value(value.recipient_intent()),
        }.map_err(|_| BridgeError::Binding)?;
        // Audited human-readable original privacy/material/destination context;
        // never include signed PCZT, outbox bytes or a saved permission claim.
        let review_scope = serde_json::to_string_pretty(&serde_json::json!({
            "original_continuation_terms": retained.terms()?,
            "original_recipient_and_material_scope": recipient,
            "payload": "exact already committed external_spend_signatures_v1 outbox; no new signature or exposure release",
        })).map_err(|_| BridgeError::Binding)?;
        if review_scope.len() > 256 * 1024 { return Err(BridgeError::Limit); }
        source.require(&self.journal, &tx)?;
        source.require_pin(&tx)?;
        tx.commit().map_err(JournalError::from)?;
        source.require_pin(&c)?;
        Ok((selection, review_scope))
    }

    pub(crate) fn read_durable_result_v2(
        &self,
        source: &FinancialSourceBindingV1,
        expected: &DurableFinancialResultRequestV2,
        peer: &PeerProcess,
        read: &DurableFinancialResultReadV2,
    ) -> BridgeResult<AuditedDurableFinancialResultRowsV2> {
        let check = || -> BridgeResult<()> {
            read.check_scope(source.identity_digest(), expected, peer)
                .map_err(|_| BridgeError::Permission)?;
            peer.check_alive().map_err(|_| BridgeError::Permission)
        };
        check()?;
        let _publication = read.publication_lease().map_err(|_| BridgeError::Permission)?;
        let _fence = self.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
        check()?;
        let mut c = self.journal.connection.lock().map_err(|_| JournalError::Database)?;
        check()?;
        if !c.is_autocommit() { return Err(BridgeError::Conflict); }
        source.require(&self.journal, &c)?;
        source.require_pin(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred).map_err(JournalError::from)?;
        check()?;
        validate(&tx, &self.genesis)?;
        let (original, _, _, result, retained) = read_retained_result_rows(&tx)?;
        let selection = exact_selection(&tx, &original, &result, &retained)?;
        if &selection != expected { return Err(BridgeError::Binding); }
        // The historical Host is kept verbatim. The separately granted V2
        // recipient belongs to the source/Return owner, not these original rows.
        let pin = FinancialReturnJournalPinV1::from_audited_result(
            self, source, &tx, selection.original_host_process_instance.clone(),
            result.result_digest.clone(),
        )?;
        source.require(&self.journal, &tx)?;
        source.require_pin(&tx)?;
        check()?;
        tx.commit().map_err(JournalError::from)?;
        source.require_pin(&c)?;
        if !c.is_autocommit() { return Err(BridgeError::Conflict); }
        pin.require(self, source, &c)?;
        check()?;
        Ok(AuditedDurableFinancialResultRowsV2 {
            original, result, continuation: retained.request().clone(), selection, pin,
        })
    }
}

#[cfg(test)]
mod fixed_dto_tests {
    use super::*;
    use wholepact_authority::durable_payment_v1::DurableFixedCandidateBindingV1;
    use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
    use sha2::{Digest, Sha256};

    // Canonical historical DTO only: no proof, grant, key or journal fabricated.
    fn inert_fixed() -> FixedProposalIdentityV1 {
        let mut fixed = FixedProposalIdentityV1 {
            schema_version: 1, network_profile_id: "never-funded-network".into(),
            agreement_id: "never-funded-agreement".into(), obligation_id: "never-funded-obligation".into(),
            proposal_id: "never-funded-proposal".into(), revision: 1, expiry_height: 1,
            proposal_digest: "11".repeat(32), manifest_digest: "22".repeat(32),
            unsigned_artifact_digest: "33".repeat(32), proved_artifact_digest: "44".repeat(32),
            effects_commitment: "55".repeat(32), policy_digest: "66".repeat(32),
            review_binding: "77".repeat(32), action_mapping_digest: "88".repeat(32),
            anchor: "99".repeat(32), proposal_binding: String::new(),
        };
        let mut h = Sha256::new();
        h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
        for n in [fixed.schema_version, fixed.revision, fixed.expiry_height] { h.update(n.to_le_bytes()); }
        for value in [&fixed.network_profile_id, &fixed.agreement_id, &fixed.obligation_id, &fixed.proposal_id,
            &fixed.proposal_digest, &fixed.manifest_digest, &fixed.unsigned_artifact_digest, &fixed.proved_artifact_digest,
            &fixed.effects_commitment, &fixed.policy_digest, &fixed.review_binding, &fixed.action_mapping_digest, &fixed.anchor]
        { h.update((value.len() as u64).to_le_bytes()); h.update(value.as_bytes()); }
        fixed.proposal_binding = hex::encode(h.finalize());
        fixed
    }

    #[test]
    fn completed_result_fixed_dto_preserves_every_canonical_field_both_directions() {
        let fixed = inert_fixed();
        let original = crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(&fixed).unwrap();
        original.validate().unwrap();
        assert_eq!(exact_fixed_identity_v2(&original).unwrap(), fixed);
        assert_eq!(serde_json::to_vec(&original).unwrap(), serde_json::to_vec(&fixed).unwrap());
        let restored = crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(
            &exact_fixed_identity_v2(&original).unwrap()).unwrap();
        assert!(restored == original);
    }

    #[test]
    fn completed_result_fixed_dto_rejects_unknown_duplicate_and_mismatched_fields_both_directions() {
        let fixed = inert_fixed();
        let bytes = serde_json::to_string(&fixed).unwrap();
        for text in [bytes.replacen("{", "{\"unexpected\":0,", 1),
            bytes.replacen("\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1", 1)] {
            assert!(wholepact_core::parse_typed_json::<FixedProposalIdentityV1>(text.as_bytes()).is_err());
            assert!(wholepact_core::parse_typed_json::<DurableFixedCandidateBindingV1>(text.as_bytes()).is_err());
        }
        for field in ["schema_version", "network_profile_id", "agreement_id", "obligation_id", "proposal_id",
            "revision", "expiry_height", "proposal_digest", "manifest_digest", "unsigned_artifact_digest",
            "proved_artifact_digest", "effects_commitment", "policy_digest", "review_binding",
            "action_mapping_digest", "anchor", "proposal_binding"] {
            let mut value = serde_json::to_value(&fixed).unwrap();
            value[field] = if value[field].is_number() { serde_json::json!(2) }
                else { serde_json::json!("ee".repeat(32)) };
            let altered_bytes = serde_json::to_vec(&value).unwrap();
            let altered: DurableFixedCandidateBindingV1 = wholepact_core::parse_typed_json(&altered_bytes).unwrap();
            assert!(exact_fixed_identity_v2(&altered).is_err(), "forward {field}");
            let altered_fixed: FixedProposalIdentityV1 = wholepact_core::parse_typed_json(&altered_bytes).unwrap();
            let rebound = crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(&altered_fixed).unwrap();
            assert!(rebound.validate().is_err(), "reverse {field}");
        }
    }
}
