//! Ordinary two-original CompletedPair resource data, not service custody or
//! Host consent. The actual fixed W independently authenticates one namespace
//! core and both dispatcher pins. No parse/digest constructs Setup or Serve.
use crate::{
    financial_signing_data::{FinancialSigningInputsV1, FinancialSigningOriginalV1},
    rejected, signer_continue_channel::SignerContinueRoleV1, signer_continue_state::hash,
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const COMPLETED_PAIR_PURPOSE: &str = "original-completed-pair-service";
pub const COMPLETED_PAIR_MODE: &str = "two-original-dispatcher-accounts";
const MAX_ENCODED: usize = 60 * 1024;
const ORIGINAL_DOMAIN: &[u8] = b"wholepact:completed-pair:original:v1\0";
const PRESENTATION_DOMAIN: &[u8] = b"wholepact:completed-pair:presentation:v1\0";

/// These reused members contain ordinary paths/public selector data only.
/// Their Signing names do not import a Signing capability or action clock.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedPairInputsV1 {
    pub owners: [FinancialSigningInputsV1; 2],
}
impl CompletedPairInputsV1 {
    pub fn validate(&self) -> Result<()> {
        for owner in &self.owners { owner.validate()?; }
        let [a, b] = &self.owners;
        let x = &a.selectors;
        let y = &b.selectors;
        if x.expected_account_id == y.expected_account_id
            || a.continuation_operation_id == b.continuation_operation_id
            || x.endpoint != y.endpoint || x.server_name != y.server_name
            || x.witness_id != y.witness_id
            || x.pinned_server_certificate_digest != y.pinned_server_certificate_digest
            || x.network_profile_id != y.network_profile_id
            || x.owner_certificate_der_hex != y.owner_certificate_der_hex
            || x.storage_key_file != y.storage_key_file
            || x.server_certificate_der != y.server_certificate_der
            || x.server_private_key_pkcs8_der != y.server_private_key_pkcs8_der
            || x.trusted_client_root_der != y.trusted_client_root_der
        { return Err(rejected("completed pair shared namespace selectors rejected")); }
        // Necessary selection equality, never filesystem/source custody proof.
        encoded_bound(self)
    }
    pub fn require_original(&self, original: &CompletedPairOriginalV1) -> Result<()> {
        self.validate()?;
        original.validate()?;
        for (input, actual) in self.owners.iter().zip(&original.owners) {
            if input.selectors.expected_account_id != actual.account_id
                || input.selectors.network_profile_id != actual.network_profile_id
                || input.continuation_operation_id != actual.operation_id
            { return Err(rejected("completed pair original selector mismatch")); }
        }
        Ok(())
    }
}

/// Exact immutable correlation, sourced by C from its actual two retained
/// originals. These members contain no live WriterRead/Acquire/Signing grant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedPairOriginalV1 {
    pub owners: [FinancialSigningOriginalV1; 2],
}
impl CompletedPairOriginalV1 {
    pub fn validate(&self) -> Result<()> {
        for original in &self.owners { original.validate()?; }
        let [a, b] = &self.owners;
        if a.actor.signer_role != SignerContinueRoleV1::Signer1
            || b.actor.signer_role != SignerContinueRoleV1::Signer2
            || a.actor.signer_process_instance == b.actor.signer_process_instance
            || a.account_id == b.account_id || a.operation_id == b.operation_id
            || a.actor.profile != b.actor.profile
            || a.actor.coordinator_process_instance != b.actor.coordinator_process_instance
            || a.actor.coordinator_focus_epoch != b.actor.coordinator_focus_epoch
            || a.actor.common_image_measurement != b.actor.common_image_measurement
            || a.actor.session_challenge != b.actor.session_challenge
            || a.original_host_process_instance != b.original_host_process_instance
            || a.owner_certificate_digest != b.owner_certificate_digest
            || a.network_profile_id != b.network_profile_id
        { return Err(rejected("completed pair original actor/order mismatch")); }
        encoded_bound(self)
    }
    pub fn commitment(&self) -> Result<String> {
        self.validate()?;
        digest(ORIGINAL_DOMAIN, self)
    }
}

/// Current source observation, separate from the historical admitted prefix
/// in `original`. A greater head is not evidence of actual prefix membership.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedPairAccountV1 {
    pub account_id: String,
    pub network_profile_id: String,
    pub operation_id: String,
    pub admission_digest: String,
    pub source_commitment: String,
    pub policy_digest: String,
    pub dispatcher_certificate_digest: String,
    pub current_head_sequence: u64,
    pub current_head_digest: String,
}
impl CompletedPairAccountV1 {
    fn require_original(&self, original: &FinancialSigningOriginalV1) -> Result<()> {
        if ![&self.account_id, &self.admission_digest, &self.source_commitment,
            &self.policy_digest, &self.dispatcher_certificate_digest,
            &self.current_head_digest].iter().all(|v| hash(v))
            || self.account_id != original.account_id
            || self.network_profile_id != original.network_profile_id
            || self.operation_id != original.operation_id
            || self.current_head_sequence < original.admitted_head_sequence
            || (self.current_head_sequence == original.admitted_head_sequence
                && self.current_head_digest != original.admitted_head_digest)
        { return Err(rejected("completed pair account observation rejected")); }
        Ok(())
    }
}

/// Entire two-account resource display. The whole value, including BOTH exact
/// embedded requests and this display, must fit 60 KiB. No truncation or larger
/// transport frame is used. Original service Instants remain nominal custody.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedPairPresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub mode: String,
    pub display: String,
    pub backend_review_digest: String,
    pub presentation_digest: String,
    pub prepared_at_ms: u64,
    pub expires_at_ms: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub endpoint: String,
    pub server_name: String,
    pub witness_id: String,
    pub pinned_server_certificate_digest: String,
    pub owner_certificate_digest: String,
    pub fixed_digest: String,
    pub delivery_digest: String,
    pub accounts: [CompletedPairAccountV1; 2],
    pub original: CompletedPairOriginalV1,
}
impl CompletedPairPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        self.validate_shape()?;
        // Explicit fixed-order nested tuples bind every non-self-digest field.
        digest(PRESENTATION_DOMAIN, &(
            (self.version, &self.purpose, &self.mode, &self.display,
                &self.backend_review_digest, self.prepared_at_ms, self.expires_at_ms,
                self.valid_from_ms, self.valid_until_ms),
            (&self.endpoint, &self.server_name, &self.witness_id,
                &self.pinned_server_certificate_digest, &self.owner_certificate_digest,
                &self.fixed_digest, &self.delivery_digest),
            (&self.accounts, &self.original),
        ))
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        if !hash(&self.presentation_digest)
            || self.presentation_digest != self.calculate_presentation_digest()?
        { return Err(rejected("completed pair presentation commitment rejected")); }
        Ok(())
    }
    fn validate_shape(&self) -> Result<()> {
        self.original.validate()?;
        for (account, original) in self.accounts.iter().zip(&self.original.owners) {
            account.require_original(original)?;
        }
        if self.version != 1 || self.purpose != COMPLETED_PAIR_PURPOSE
            || self.mode != COMPLETED_PAIR_MODE || !text(&self.display, 32 * 1024)
            || ![&self.endpoint, &self.server_name, &self.witness_id].iter()
                .all(|value| text(value, 4096))
            || ![&self.backend_review_digest, &self.pinned_server_certificate_digest,
                &self.owner_certificate_digest, &self.fixed_digest, &self.delivery_digest]
                .iter().all(|value| hash(value))
            || self.owner_certificate_digest != self.original.owners[0].owner_certificate_digest
            || self.prepared_at_ms == 0 || self.valid_from_ms >= self.valid_until_ms
            || self.prepared_at_ms < self.valid_from_ms
            || self.expires_at_ms.checked_sub(self.prepared_at_ms)
                .is_none_or(|n| n == 0 || n > 120_000)
            || self.expires_at_ms > self.valid_until_ms
            || self.original.owners.iter().any(|o| self.valid_until_ms > o.source_expires_at_ms)
            || self.presentation_digest.len() > 64
        { return Err(rejected("completed pair presentation shape rejected")); }
        encoded_bound(self)
    }
}

fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes()
        .all(|b| b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b))
}
fn encoded_bound(value: &impl Serialize) -> Result<()> {
    if serde_json::to_vec(value).map_err(|_| rejected("completed pair data encoding"))?.len()
        > MAX_ENCODED
    { return Err(rejected("completed pair complete data exceeds frame budget")); }
    Ok(())
}
fn digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| rejected("completed pair digest encoding"))?;
    let mut state = Sha256::new();
    state.update(domain);
    state.update(bytes);
    Ok(hex::encode(state.finalize()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::signer_continue_channel::SignerContinuePresentationV1;
    fn h(n: u8) -> String { format!("{n:02x}").repeat(32) }
    fn original() -> CompletedPairOriginalV1 {
        // Ordinary inert metadata only: no actor, source, key, native grant,
        // clock read, socket, worker or service constructor is involved.
        let owners = [0u8, 1].map(|i| {
            let actor = serde_json::from_value(serde_json::json!({
                "profile":"coordinated-financial-workflow-v1",
                "coordinator_process_instance":h(9),"coordinator_focus_epoch":1,
                "signer_role":if i == 0 { "signer1" } else { "signer2" },
                "signer_process_instance":h(i+1),"common_image_measurement":h(9),
                "session_challenge":h(9)
            })).unwrap();
            let request_json = format!("{{\"public_fixture\":{i}}}");
            FinancialSigningOriginalV1 {
                actor, continue_presentation_digest:h(9), prepared_digest:h(9),
                admit_presentation_digest:h(9), admission_ready_digest:h(9),
                signer_source_identity_digest:h(9), admission_terms_digest:h(9),
                request_digest:SignerContinuePresentationV1::calculate_request_digest(&request_json),
                request_json, original_host_process_instance:h(9), owner_certificate_digest:h(9),
                owner_disclosure_json:"{\"public_fixture\":2}".into(), owner_disclosure_digest:h(9),
                owner_selection_digest:h(9), terms_digest:h(9), account_id:h(i+1),
                network_profile_id:"public-network".into(), operation_id:format!("operation-{i}"),
                admitted_head_sequence:20, admitted_head_digest:h(9),
                source_ceiling_ms:300000, source_expires_at_ms:300000,
            }
        });
        CompletedPairOriginalV1 { owners }
    }
    pub(crate) fn presentation() -> CompletedPairPresentationV1 {
        let original = original();
        let accounts = original.owners.each_ref().map(|o| CompletedPairAccountV1 {
            account_id:o.account_id.clone(),network_profile_id:o.network_profile_id.clone(),
            operation_id:o.operation_id.clone(),admission_digest:h(9),source_commitment:h(9),
            policy_digest:h(9),dispatcher_certificate_digest:h(8),
            current_head_sequence:o.admitted_head_sequence,current_head_digest:o.admitted_head_digest.clone(),
        });
        let mut p = CompletedPairPresentationV1 {
            version:1,purpose:COMPLETED_PAIR_PURPOSE.into(),mode:COMPLETED_PAIR_MODE.into(),
            display:"Public synthetic pair data only, no service created".into(),
            backend_review_digest:h(9),presentation_digest:String::new(),
            prepared_at_ms:2000,expires_at_ms:122000,valid_from_ms:1000,valid_until_ms:300000,
            endpoint:"127.0.0.1:12345".into(),server_name:"public.invalid".into(),
            witness_id:"public-witness".into(),pinned_server_certificate_digest:h(9),
            owner_certificate_digest:h(9),fixed_digest:h(9),delivery_digest:h(9),accounts,original,
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    #[test]
    fn completed_pair_data_binds_both_originals_and_strict_order_without_custody() {
        let p = presentation(); p.validate().unwrap();
        assert_ne!(p.original.commitment().unwrap(), p.presentation_digest);
        let json = serde_json::to_string(&p).unwrap();
        assert!(p == serde_json::from_str::<CompletedPairPresentationV1>(&json).unwrap());
        assert!(serde_json::from_str::<CompletedPairPresentationV1>(&format!(
            "{{\"caller_ready\":true,{}", &json[1..])).is_err());
        let mut swapped = p.original.clone(); swapped.owners.swap(0, 1);
        assert!(swapped.validate().is_err());
        let mut wrong = p.original.clone(); wrong.owners[1].original_host_process_instance = h(7);
        assert!(wrong.validate().is_err());
        for index in 0..2 {
            let mut changed = p.clone();
            changed.accounts[index].dispatcher_certificate_digest = h(7);
            assert!(changed.validate().is_err());
            let mut changed = p.clone();
            changed.original.owners[index].owner_disclosure_json.push(' ');
            assert!(changed.validate().is_err());
        }
    }
    #[test]
    fn completed_pair_historical_shape_and_original_ceilings_only_narrow() {
        let p = presentation();
        let mut changed = p.clone(); changed.accounts[1].current_head_sequence -= 1;
        assert!(changed.calculate_presentation_digest().is_err());
        let mut changed = p.clone(); changed.accounts[1].current_head_digest = h(7);
        assert!(changed.calculate_presentation_digest().is_err());
        let mut later = p.clone(); later.accounts[1].current_head_sequence += 1;
        later.accounts[1].current_head_digest = h(7);
        later.presentation_digest = later.calculate_presentation_digest().unwrap();
        later.validate().unwrap(); // Shape does not authenticate a real prefix.
        let mut changed = p.clone(); changed.valid_until_ms += 1;
        assert!(changed.calculate_presentation_digest().is_err());
        let mut changed = p; changed.expires_at_ms = changed.prepared_at_ms + 120001;
        assert!(changed.calculate_presentation_digest().is_err());
    }
    #[test]
    fn completed_pair_whole_frame_budget_includes_both_requests_and_display() {
        let mut p = presentation(); p.display = "x".repeat(24 * 1024);
        for original in &mut p.original.owners {
            original.request_json = format!("{{\"public_fixture\":\"{}\"}}", "x".repeat(20 * 1024));
            original.request_digest = SignerContinuePresentationV1::calculate_request_digest(&original.request_json);
            original.validate().unwrap();
        }
        p.original.validate().unwrap();
        assert!(p.calculate_presentation_digest().is_err());
        let mut p = presentation(); p.display = "\u{202e}hidden".into();
        assert!(p.calculate_presentation_digest().is_err());
    }
}
