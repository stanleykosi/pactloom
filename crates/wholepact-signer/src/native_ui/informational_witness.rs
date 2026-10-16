//! Separately approved read-only witness owner for an exact quarantined source.
//! No ordinary vault/workspace conversion, client accessor, session, writer or
//! control capability is exposed. Selected credentials remain private to the
//! maintained TLS client and are never generated, installed or serialized here.
use super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    witness_workspace::prepare_selected_witness_configuration,
};
use crate::{
    Error, Result,
    account::informational::{QuarantinedInformationalAccount, QuarantinedInformationalBinding},
};
use serde::Serialize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use wholepact_authority::{
    AccountSnapshot, AuthorityClient, ReconciledAuthorityHistory, WitnessDisclosureDescriptor,
    WriterStatus,
};
use wholepact_protocol::construction::PROFILE_ID;
use zeroize::Zeroizing;

/// Inert review data only. This is neither a native permission nor a source
/// owner, and there is deliberately no deserialization path into an owner.
#[derive(Clone, Serialize)]
struct InformationalWitnessScope {
    source_inventory_digest: String,
    account_id: String,
    historical_writer_epoch: u64,
    checkpoint_id: String,
    selected_configuration_digest: String,
    witness: WitnessDisclosureDescriptor,
    writer_certificate_digest: String,
}
impl InformationalWitnessScope {
    fn validate(&self) -> Result<()> {
        self.witness.validate().map_err(|_| Error::InvalidData)?;
        for digest in [
            &self.source_inventory_digest,
            &self.selected_configuration_digest,
            &self.writer_certificate_digest,
        ] {
            wholepact_core::proposal::validate_sha256(digest).map_err(|_| Error::InvalidData)?;
        }
        if self.account_id != self.witness.account_id
            || self.witness.network_profile_id != PROFILE_ID
            || self.historical_writer_epoch == 0
            || self.checkpoint_id.is_empty()
            || self.checkpoint_id.len() > 128
            || !self
                .checkpoint_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn require_source(&self, source: &QuarantinedInformationalAccount) -> Result<()> {
        if self.account_id != source.account_id()
            || self.historical_writer_epoch != source.historical_writer_epoch()
            || self.checkpoint_id != source.checkpoint_id()
            || self.source_inventory_digest != source.source_inventory_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn require_snapshot(&self, snapshot: &AccountSnapshot) -> Result<()> {
        if snapshot.account_id != self.account_id
            || snapshot.network_profile_id != self.witness.network_profile_id
            || snapshot.witness_id != self.witness.witness_id
            || snapshot.policy_digest != self.witness.policy_digest
            || snapshot.writer_epoch != self.historical_writer_epoch
            || snapshot.writer_certificate_digest != self.writer_certificate_digest
        {
            return Err(Error::Authentication);
        }
        // A restored independent witness cannot establish surviving continuity.
        // Active, paused and revoked states remain historical data only; none
        // grants session or financial capability through this owner.
        if snapshot.writer_status == WriterStatus::Quarantined {
            return Err(Error::RecoveryRequired);
        }
        Ok(())
    }
}

fn review_digest(
    scope: &InformationalWitnessScope,
    native_entry_digest: &str,
    review_nonce: &str,
) -> Result<String> {
    scope.validate()?;
    wholepact_core::proposal::validate_sha256(native_entry_digest)
        .map_err(|_| Error::InvalidData)?;
    wholepact_core::proposal::validate_sha256(review_nonce).map_err(|_| Error::InvalidData)?;
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-quarantined-informational-witness:v1",
        &(scope, native_entry_digest, review_nonce),
    )
    .map_err(|_| Error::InvalidData)
}

/// Pure deadline selection: an operation can shorten, but never renew, the
/// original source/setup lifetime. No fresh timeout is created by a read/page.
fn effective_deadline(original: Instant, requested: Instant, now: Instant) -> Result<Instant> {
    let deadline = original.min(requested);
    if now >= deadline {
        return Err(Error::Locked);
    }
    Ok(deadline)
}

pub(super) struct PreparedInformationalWitnessSetup {
    native: NativeAuthorityBinding,
    source_binding: QuarantinedInformationalBinding,
    scope: InformationalWitnessScope,
    deadline: Instant,
    digest: String,
    display: Zeroizing<String>,
    client: AuthorityClient,
}
impl PreparedInformationalWitnessSetup {
    pub(super) fn prepare(
        json: &str,
        source: &QuarantinedInformationalAccount,
        authority: &NativeAuthority,
        original_deadline: Instant,
    ) -> Result<Self> {
        authority.check_current()?;
        let now = Instant::now();
        let deadline = effective_deadline(source.deadline(), original_deadline, now)?;
        if deadline > now + Duration::from_secs(120) {
            return Err(Error::ReviewMismatch);
        }
        source.check_source_unchanged_until(deadline)?;
        let selected =
            prepare_selected_witness_configuration(json, source.account_id(), Some(PROFILE_ID))?;
        let scope = InformationalWitnessScope {
            source_inventory_digest: source.source_inventory_digest().into(),
            account_id: source.account_id().into(),
            historical_writer_epoch: source.historical_writer_epoch(),
            checkpoint_id: source.checkpoint_id().into(),
            selected_configuration_digest: selected.digest,
            witness: selected.client.disclosure_descriptor(),
            writer_certificate_digest: selected.writer_certificate_digest,
        };
        let native = authority.binding();
        // Fresh process-local review identity prevents a decision for another
        // preparation/source owner from matching identical saved metadata.
        let review_nonce = hex::encode(crate::vault::random::<32>()?);
        let digest = review_digest(&scope, native.entry_digest(), &review_nonce)?;
        let display = Zeroizing::new(format!(
            "READ-ONLY WITNESS FOR QUARANTINED INFORMATIONAL RECOVERY\n\n{}\n\nExact original source checkpoint: {}\nHistorical writer epoch: {}\nSource inventory commitment: {}\n\nThis separately permits only authenticated Snapshot and complete bounded ReadHistory requests to this exact witness using the selected client certificate. The operator receives this account/network identity, selected client certificate, read-history requests and network metadata. The complete returned history stays local unless a separate exact native review approves disclosure to a locally paired process.\n\nThis source supports only the explicitly selected {} profile; configuration does not establish freshness. Paused, revoked and fenced sessions are historical evidence. A restored/quarantined independent witness is refused. No writer acquisition, session activation, owner control, reservation, signing, credential provisioning or financial recovery is permitted. This owner expires with the original source/native lifetime. Lock, focus invalidation, source change or a late result denies further reads; a page never renews the original operation deadline.\n\nExact read-only review: {}",
            selected.display.as_str(),
            scope.checkpoint_id,
            scope.historical_writer_epoch,
            scope.source_inventory_digest,
            PROFILE_ID,
            digest,
        ));
        authority.check_current()?;
        source.check_source_unchanged_until(deadline)?;
        effective_deadline(deadline, deadline, Instant::now())?;
        Ok(Self {
            native,
            source_binding: source.binding(),
            scope,
            deadline,
            digest,
            display,
            client: selected.client,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.native.check_current()?;
        effective_deadline(self.deadline, self.deadline, Instant::now())?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        source: Arc<QuarantinedInformationalAccount>,
    ) -> Result<NativeInformationalWitness> {
        authority.check_current()?;
        self.native.check_current()?;
        effective_deadline(self.deadline, self.deadline, Instant::now())?;
        if decision.binding() != &self.native
            || authority.binding() != self.native
            || decision.reviewed_digest() != self.digest
            || source.binding() != self.source_binding
        {
            return Err(Error::ReviewMismatch);
        }
        self.scope.require_source(&source)?;
        source.check_source_unchanged_until(self.deadline)?;
        let approved = NativeInformationalWitness {
            native: self.native,
            source,
            source_binding: self.source_binding,
            scope: self.scope,
            deadline: self.deadline,
            client: self.client,
        };
        approved.check_current()?;
        Ok(approved)
    }
}

/// Issued solely by consuming the exact genuine NativeDecision above. The
/// retained source is key-free and never converted back to AccountVault. The
/// private client has no accessor and only the two read operations below exist.
/// No Clone, serde, writer/session/control or ordinary-workspace conversion.
pub(super) struct NativeInformationalWitness {
    native: NativeAuthorityBinding,
    source: Arc<QuarantinedInformationalAccount>,
    source_binding: QuarantinedInformationalBinding,
    scope: InformationalWitnessScope,
    deadline: Instant,
    client: AuthorityClient,
}
impl NativeInformationalWitness {
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(super) fn disclosure(&self) -> WitnessDisclosureDescriptor {
        self.scope.witness.clone()
    }
    pub(super) fn writer_certificate_digest(&self) -> &str {
        &self.scope.writer_certificate_digest
    }
    /// The caller's original operation deadline also bounds every nested
    /// source hash. This never falls back to the longer setup lifetime.
    pub(super) fn require_binding_until(
        &self,
        native: &NativeAuthorityBinding,
        source: &QuarantinedInformationalAccount,
        deadline: Instant,
    ) -> Result<()> {
        let deadline = effective_deadline(self.deadline, deadline, Instant::now())?;
        native.check_current()?;
        if native != &self.native || source.binding() != self.source_binding {
            return Err(Error::ReviewMismatch);
        }
        self.scope.require_source(source)?;
        // The retained owner and supplied owner have the exact same opaque
        // instance. One retained-source check suffices, under this deadline.
        self.check_until(deadline)
    }
    pub(super) fn check_current(&self) -> Result<()> {
        self.check_until(self.deadline)
    }
    fn check_lifetime_until(&self, deadline: Instant) -> Result<()> {
        effective_deadline(self.deadline, deadline, Instant::now())?;
        self.native.check_current()?;
        if self.source.binding() != self.source_binding {
            return Err(Error::ReviewMismatch);
        }
        self.scope.require_source(&self.source)?;
        Ok(())
    }
    fn check_until(&self, deadline: Instant) -> Result<()> {
        let deadline = effective_deadline(self.deadline, deadline, Instant::now())?;
        self.check_lifetime_until(deadline)?;
        self.source.check_source_unchanged_until(deadline)?;
        self.check_lifetime_until(deadline)
    }
    pub(super) fn snapshot_until(&self, deadline: Instant) -> Result<AccountSnapshot> {
        let deadline = effective_deadline(self.deadline, deadline, Instant::now())?;
        self.check_until(deadline)?;
        let snapshot = self
            .client
            .snapshot_until(deadline)
            .map_err(|_| Error::Uncertain)?;
        self.scope.require_snapshot(&snapshot)?;
        self.check_until(deadline)?;
        Ok(snapshot)
    }
    pub(super) fn reconcile_history_checked_until(
        &self,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<ReconciledAuthorityHistory> {
        let deadline = effective_deadline(self.deadline, deadline, Instant::now())?;
        self.check_until(deadline)?;
        check_current()?;
        let history = self
            .client
            .reconcile_history_checked_until(deadline, || {
                // Retained cooperative exclusion plus full source checks before
                // and after replay; each page rechecks immutable identity,
                // native revocation and the same absolute operation deadline.
                self.check_lifetime_until(deadline)
                    .and_then(|()| check_current())
                    .and_then(|()| self.check_lifetime_until(deadline))
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        self.scope.require_snapshot(history.snapshot())?;
        if history.disclosure() != &self.scope.witness {
            return Err(Error::Authentication);
        }
        check_current()?;
        self.check_until(deadline)?;
        Ok(history)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Inert data fixtures only: no credentials, TLS client, native authority,
    // decision, source owner, socket, history issuer or financial token exists.
    fn scope() -> InformationalWitnessScope {
        InformationalWitnessScope {
            source_inventory_digest: "11".repeat(32),
            account_id: "synthetic-quarantined-account".into(),
            historical_writer_epoch: 7,
            checkpoint_id: "synthetic-original-checkpoint".into(),
            selected_configuration_digest: "22".repeat(32),
            witness: WitnessDisclosureDescriptor {
                endpoint: "127.0.0.1:28443".into(),
                server_name: "synthetic-witness.invalid".into(),
                witness_id: "synthetic-witness".into(),
                account_id: "synthetic-quarantined-account".into(),
                network_profile_id: PROFILE_ID.into(),
                policy_digest: "33".repeat(32),
                pinned_server_certificate_digest: "44".repeat(32),
            },
            writer_certificate_digest: "55".repeat(32),
        }
    }
    fn snapshot(scope: &InformationalWitnessScope) -> AccountSnapshot {
        AccountSnapshot {
            transport_fences: None,
            account_use_checkpoint: None,
            witness_id: scope.witness.witness_id.clone(),
            account_id: scope.account_id.clone(),
            network_profile_id: scope.witness.network_profile_id.clone(),
            policy_digest: scope.witness.policy_digest.clone(),
            head: wholepact_authority::AuthorityHead {
                sequence: 3,
                digest: "66".repeat(32),
            },
            writer_epoch: scope.historical_writer_epoch,
            writer_certificate_digest: scope.writer_certificate_digest.clone(),
            writer_status: WriterStatus::Paused,
            outstanding_reservations: 1,
            outstanding_debit_zatoshis: 50,
            settled_debit_zatoshis: 0,
            aggregate_budget_zatoshis: 100,
            reserved_input_value_zatoshis: 60,
            last_witness_time_ms: 1,
            pending_writer_session: None,
            active_writer_session: None,
        }
    }
    #[test]
    fn informational_witness_configuration_scope_refuses_before_credential_reads() {
        // Deliberately invalid credential paths: each mismatch must be rejected
        // as ReviewMismatch before attempting to read any selected credential.
        let setup = serde_json::json!({
            "schema_version": 1,
            "endpoint": "127.0.0.1:28443",
            "server_name": "synthetic-witness.invalid",
            "witness_id": "synthetic-witness",
            "account_id": "synthetic-account",
            "network_profile_id": PROFILE_ID,
            "policy_digest": "33".repeat(32),
            "pinned_server_certificate_digest": "44".repeat(32),
            "trusted_server_root_der": "never-read-root",
            "client_certificate_der": "never-read-certificate",
            "client_private_key_pkcs8_der": "never-read-key",
            "operator_name": "Synthetic inert operator",
            "retention_statement": "Synthetic inert statement"
        });
        assert!(matches!(
            prepare_selected_witness_configuration(
                &setup.to_string(),
                "other-account",
                Some(PROFILE_ID)
            ),
            Err(Error::ReviewMismatch)
        ));
        assert!(matches!(
            prepare_selected_witness_configuration(
                &setup.to_string(),
                "synthetic-account",
                Some("wrong-profile")
            ),
            Err(Error::ReviewMismatch)
        ));
        let mut unknown = setup;
        unknown["source_inventory_digest"] = serde_json::json!("aa".repeat(32));
        assert!(matches!(
            prepare_selected_witness_configuration(
                &unknown.to_string(),
                "synthetic-account",
                Some(PROFILE_ID)
            ),
            Err(Error::InvalidData)
        ));
    }
    #[test]
    fn informational_witness_scope_rejects_account_network_and_source_mismatches() {
        let original = scope();
        original.validate().unwrap();
        let mut changed = original.clone();
        changed.account_id = "another-account".into();
        assert!(changed.validate().is_err());
        let mut changed = original.clone();
        changed.witness.network_profile_id = "unsupported-profile".into();
        assert!(changed.validate().is_err());
        let mut changed = original.clone();
        changed.source_inventory_digest = "not-a-commitment".into();
        assert!(changed.validate().is_err());
        let mut changed = original.clone();
        changed.historical_writer_epoch = 0;
        assert!(changed.validate().is_err());
        let mut changed = original;
        changed.checkpoint_id = "substituted\ncheckpoint".into();
        assert!(changed.validate().is_err());
    }
    #[test]
    fn informational_witness_review_commits_every_selected_identity() {
        let original = scope();
        let native = "77".repeat(32);
        let nonce = "88".repeat(32);
        let original_digest = review_digest(&original, &native, &nonce).unwrap();
        for mode in 0..11 {
            let mut changed = original.clone();
            match mode {
                0 => changed.source_inventory_digest = "aa".repeat(32),
                1 => {
                    changed.account_id = "another-account".into();
                    changed.witness.account_id = changed.account_id.clone();
                }
                2 => changed.historical_writer_epoch += 1,
                3 => changed.checkpoint_id = "another-checkpoint".into(),
                4 => changed.selected_configuration_digest = "bb".repeat(32),
                5 => changed.witness.endpoint = "127.0.0.1:29443".into(),
                6 => changed.witness.server_name = "other.invalid".into(),
                7 => changed.witness.witness_id = "other-witness".into(),
                8 => changed.witness.policy_digest = "cc".repeat(32),
                9 => changed.witness.pinned_server_certificate_digest = "dd".repeat(32),
                10 => changed.writer_certificate_digest = "ee".repeat(32),
                _ => unreachable!(),
            }
            assert_ne!(
                review_digest(&changed, &native, &nonce).unwrap(),
                original_digest
            );
        }
        assert_ne!(
            review_digest(&original, &"99".repeat(32), &nonce).unwrap(),
            original_digest
        );
        assert_ne!(
            review_digest(&original, &native, &"aa".repeat(32)).unwrap(),
            original_digest
        );
    }
    #[test]
    fn informational_witness_snapshot_rejects_scope_substitution_and_restored_witness() {
        let scope = scope();
        for status in [
            WriterStatus::Active,
            WriterStatus::Paused,
            WriterStatus::Revoked,
        ] {
            let mut original = snapshot(&scope);
            original.writer_status = status;
            scope.require_snapshot(&original).unwrap();
        }
        for mode in 0..7 {
            let mut changed = snapshot(&scope);
            match mode {
                0 => changed.account_id = "other-account".into(),
                1 => changed.network_profile_id = "other-network".into(),
                2 => changed.witness_id = "other-witness".into(),
                3 => changed.policy_digest = "aa".repeat(32),
                4 => changed.writer_epoch += 1,
                5 => changed.writer_certificate_digest = "bb".repeat(32),
                6 => changed.writer_status = WriterStatus::Quarantined,
                _ => unreachable!(),
            }
            assert!(scope.require_snapshot(&changed).is_err());
        }
    }
    #[test]
    fn informational_witness_original_deadline_can_only_shorten_and_expiry_refuses() {
        let now = Instant::now();
        let original = now + Duration::from_secs(90);
        let operation = now + Duration::from_secs(30);
        assert_eq!(
            effective_deadline(original, operation, now).unwrap(),
            operation
        );
        assert_eq!(
            effective_deadline(original, now + Duration::from_secs(120), now).unwrap(),
            original
        );
        assert!(effective_deadline(original, operation, operation).is_err());
        assert!(effective_deadline(original, operation, original).is_err());
        assert!(effective_deadline(original, original, original).is_err());
    }
}
