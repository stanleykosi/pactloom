//! STAGED, UNCOMPILED. Real V2 same-peer pre-acquire reentry and irreversible marker.
//! Fresh native reentry before the very first acquisition. No TLS/session state
//! is restored. The immutable first record/transport remain historical unchanged.
use super::*;
use crate::native_ui::{AuthenticatedPairing, NativeApprovedWriterSession};
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterPublicationRequestV2, ManualRosterPublicationAttemptV2,
};

pub(crate) struct PreparedBornManualRosterReentryV2 {
    retained: RetainedBornManualRosterEnrollmentV2,
    source: NativeAuthorityBinding,
    peer: AuthenticatedPeer,
    current_process: TransportIdentityBinding,
    principal: String,
    measurement: String,
    digest: String,
    display: Zeroizing<String>,
}
pub(crate) struct ApprovedBornManualRosterReentryV2(PreparedBornManualRosterReentryV2);
impl PreparedBornManualRosterReentryV2 {
    pub(crate) fn prepare(
        retained: RetainedBornManualRosterEnrollmentV2,
        request: &HostManualRosterPublicationRequestV2,
        pairing: &AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        retained.check_current_source(owner)?;
        require_unattempted_inventory(&retained.account.directory)?;
        pairing.check_current()?;
        let peer = pairing.current_peer();
        let terms = &retained.record.account_record.terms;
        let now = now_ms()?;
        if now < terms.issued_at_ms || now >= terms.scope.expires_at_ms {
            return Err(Error::ReviewMismatch);
        }
        require_initial_pair(&retained.record, request, &peer.scope)?;
        if pairing.native_origin() != &owner.native().binding() {
            return Err(Error::Authentication);
        }
        let current_process = pairing.binding().clone();
        let principal = owner.native().principal_id().to_owned();
        let measurement = owner.native().measurement().to_owned();
        let digest = canonical(
            "wholepact:native-born-manual-roster-preacquire-reentry:v2",
            &(
                &retained.record,
                &retained.intent_digest,
                &current_process,
                &principal,
                &measurement,
            ),
        )?;
        let display = Zeroizing::new(format!(
            "REENTER THE EXACT ORIGINAL MANUAL INTENT BEFORE FIRST ACQUIRE\n\nOriginal immutable record, including historical first process/native review:\n{}\n\nFresh actual paired process:\n{}\n\nThis new native entry cannot replace any original term, operation, transport audit or deadline. No local acquisition attempt, journal or completion exists. Before the first network send, a durable encrypted attempt marker will permanently close this reentry path; a prior or uncertain session cannot be recreated here. The complete original witness must still show only this first extension. No financial authority is granted.\nExact review: {}",
            serde_json::to_string_pretty(&retained.record).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&current_process).map_err(|_| Error::InvalidData)?,
            digest
        ));
        Ok(Self {
            retained,
            source: owner.native().binding(),
            peer,
            current_process,
            principal,
            measurement,
            digest,
            display,
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        self.peer.check_current()?;
        Ok(self.display.to_string())
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ApprovedBornManualRosterReentryV2> {
        self.retained.check_current_source(owner)?;
        self.peer.check_current()?;
        require_unattempted_inventory(&self.retained.account.directory)?;
        if self.source != owner.native().binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedBornManualRosterReentryV2(self))
    }
}
impl ApprovedBornManualRosterReentryV2 {
    pub(crate) fn check_current(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.0.retained.check_current_source(owner)?;
        let now = now_ms()?;
        if now < self.0.retained.record.account_record.terms.issued_at_ms
            || now
                >= self
                    .0
                    .retained
                    .record
                    .account_record
                    .terms
                    .scope
                    .expires_at_ms
        {
            return Err(Error::ReviewMismatch);
        }
        self.0.source.check_current()?;
        self.0.peer.check_current()?;
        if self.0.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn matches_peer(
        &self,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check_current(owner)?;
        peer.check_current()?;
        if peer.grant_id != self.0.peer.grant_id
            || peer.scope != self.0.peer.scope
            || peer.native_origin != self.0.source
        {
            return Err(Error::Authentication);
        }
        peer.peer.same_live_process(&self.0.peer.peer)?;
        Ok(())
    }
    /// Accepts the actual approved writer owner, never a digest/boolean approval
    /// factory. This record contains no session key, exporter or credential.
    pub(crate) fn persist_before_first_acquire(
        &self,
        approved: &NativeApprovedWriterSession,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check_current(owner)?;
        let p = &self.0;
        let retained = &p.retained;
        let extension = retained.record.extension()?;
        let acquire_review = approved.born_roster_attempt_review_v2(&extension, &p.source)?;
        if retained.account.directory.exists(JOURNAL)?
            || retained.account.directory.exists(ROSTER_COMMIT)?
        {
            return Err(Error::RecoveryRequired);
        }
        let expected = AcquireAttempt {
            version: 2,
            enrollment_ref: retained.record.account_record.reference()?,
            intent_digest: retained.intent_digest.clone(),
            extension_digest: extension.digest().map_err(|_| Error::InvalidData)?,
            acquire_operation_id: extension
                .acquire_operation_id()
                .map_err(|_| Error::InvalidData)?,
            reentry_review_digest: p.digest.clone(),
            acquire_review_digest: acquire_review,
            current_process: p.current_process.clone(),
            native_principal: p.principal.clone(),
            native_measurement: p.measurement.clone(),
        };
        expected.validate(&retained.record, &retained.intent_digest)?;
        let _lease = p.source.publication_lease()?;
        self.check_current(owner)?;
        if retained.account.directory.exists(ROSTER_ACQUIRE)? {
            if read_attempt(retained)? != expected {
                return Err(Error::RecoveryRequired);
            }
        } else {
            let plain =
                Zeroizing::new(serde_json::to_vec(&expected).map_err(|_| Error::InvalidData)?);
            let encrypted = vault::encrypt(
                &retained.account.encryption_key,
                &domain(&retained.record)?,
                &plain,
            )?;
            retained
                .account
                .directory
                .write(ROSTER_ACQUIRE, &encrypted)?;
            retained.account.directory.sync_all_files()?;
        }
        if read_attempt(retained)? != expected {
            return Err(Error::Authentication);
        }
        self.check_current(owner)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquireAttempt {
    version: u16,
    enrollment_ref: String,
    intent_digest: String,
    extension_digest: String,
    acquire_operation_id: String,
    reentry_review_digest: String,
    acquire_review_digest: String,
    current_process: TransportIdentityBinding,
    native_principal: String,
    native_measurement: String,
}
impl AcquireAttempt {
    fn validate(&self, record: &BornManualRosterEnrollmentRecordV2, intent: &str) -> Result<()> {
        let e = record.extension()?;
        if self.version != 2
            || self.enrollment_ref != record.account_record.reference()?
            || self.intent_digest != intent
            || self.extension_digest != e.digest().map_err(|_| Error::InvalidData)?
            || self.acquire_operation_id
                != e.acquire_operation_id().map_err(|_| Error::InvalidData)?
            || !is_hash(&self.reentry_review_digest)
            || !is_hash(&self.acquire_review_digest)
            || self.native_principal.is_empty()
            || self.native_principal.len() > 128
            || !is_hash(&self.native_measurement)
            || self.reentry_review_digest
                != canonical(
                    "wholepact:native-born-manual-roster-preacquire-reentry:v2",
                    &(
                        record,
                        intent,
                        &self.current_process,
                        &self.native_principal,
                        &self.native_measurement,
                    ),
                )?
        {
            return Err(Error::Authentication);
        }
        match &self.current_process {
            TransportIdentityBinding::LocalProcess {
                account_id,
                agreement_id,
                participant_id,
                pid,
                signer_generation,
                ..
            } if account_id == &record.account_record.terms.identity.account_id
                && agreement_id == &record.account_record.terms.scope.agreement_id
                && participant_id == &record.account_record.terms.scope.participant_id
                && *pid > 0
                && *signer_generation > 0 => {}
            _ => return Err(Error::Authentication),
        }
        Ok(())
    }
}
fn domain(record: &BornManualRosterEnrollmentRecordV2) -> Result<Vec<u8>> {
    let mut d = b"wholepact:born-manual-roster-first-acquire-attempt:v2\0".to_vec();
    d.extend(record.reference()?.as_bytes());
    Ok(d)
}
fn read_attempt(retained: &RetainedBornManualRosterEnrollmentV2) -> Result<AcquireAttempt> {
    let bytes = retained
        .account
        .directory
        .read(ROSTER_ACQUIRE, MAX_INTENT)?;
    parse_attempt(
        &retained.record,
        &retained.intent_digest,
        &retained.account.encryption_key,
        &bytes,
    )
}
fn parse_attempt(
    record: &BornManualRosterEnrollmentRecordV2,
    intent: &str,
    key: &[u8; 32],
    bytes: &[u8],
) -> Result<AcquireAttempt> {
    let plain = vault::decrypt(key, &domain(record)?, bytes)?;
    let audit: AcquireAttempt = serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    audit.validate(record, intent)?;
    Ok(audit)
}
pub(in crate::account::birth) fn validate_acquire_attempt_bytes(
    record: &BornManualRosterEnrollmentRecordV2,
    intent: &str,
    key: &[u8; 32],
    bytes: &[u8],
) -> Result<()> {
    parse_attempt(record, intent, key, bytes).map(|_| ())
}
pub(crate) fn require_unattempted_inventory(directory: &PrivateDirectory) -> Result<()> {
    roster_inventory(directory)?;
    if !directory.exists(INTENT)?
        || directory.exists(ROSTER_ACQUIRE)?
        || directory.exists(JOURNAL)?
        || directory.exists(ROSTER_COMMIT)?
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
pub(super) fn validate_retained_marker(
    retained: &RetainedBornManualRosterEnrollmentV2,
) -> Result<()> {
    if retained.account.directory.exists(ROSTER_ACQUIRE)? {
        validate_acquire_attempt_bytes(
            &retained.record,
            &retained.intent_digest,
            &retained.account.encryption_key,
            &retained
                .account
                .directory
                .read(ROSTER_ACQUIRE, MAX_INTENT)?,
        )?;
    }
    Ok(())
}

fn require_initial_pair(
    record: &BornManualRosterEnrollmentRecordV2,
    request: &HostManualRosterPublicationRequestV2,
    scope: &crate::ipc::PairScope,
) -> Result<()> {
    record.validate()?;
    request
        .require_original(&record.request()?)
        .map_err(|_| Error::ReviewMismatch)?;
    scope.validate().map_err(|_| Error::InvalidData)?;
    let terms = &record.account_record.terms;
    if request.attempt != (ManualRosterPublicationAttemptV2::InitialV2 {})
        || scope.account_id != terms.identity.account_id
        || scope.agreement_id != terms.scope.agreement_id
        || scope.participant_id != terms.scope.participant_id
        || scope.manifest_digest != request.digest().map_err(|_| Error::InvalidData)?
        || scope.history_read
        || scope.authorization_export
        || scope.preconstruction_export
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_reentry_requires_actual_full_v2_publication_digest_without_pair_rewrite() {
        let record = super::super::tests::synthetic_record();
        let request = HostManualRosterPublicationRequestV2 {
            version: 2,
            enrollment: record.request().unwrap().enrollment,
            roster: record.roster.clone(),
            attempt: ManualRosterPublicationAttemptV2::InitialV2 {},
        };
        let scope = crate::ipc::PairScope {
            account_id: record.account_record.terms.identity.account_id.clone(),
            agreement_id: record.account_record.terms.scope.agreement_id.clone(),
            participant_id: record.account_record.terms.scope.participant_id.clone(),
            manifest_digest: request.digest().unwrap(),
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let before = serde_json::to_vec(&scope).unwrap();
        require_initial_pair(&record, &request, &scope).unwrap();
        assert_eq!(serde_json::to_vec(&scope).unwrap(), before);
        for manifest in [
            record.intent().unwrap().digest().unwrap(),
            record.request().unwrap().digest().unwrap(),
            record.account_record.terms.terms_digest().unwrap(),
        ] {
            let mut wrong = scope.clone();
            wrong.manifest_digest = manifest;
            assert!(require_initial_pair(&record, &request, &wrong).is_err());
        }
        let mut continued = request.clone();
        continued.attempt = ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest: "a".repeat(64),
            attempt_sequence: 2,
        };
        let mut changed = scope.clone();
        changed.manifest_digest = continued.digest().unwrap();
        assert!(require_initial_pair(&record, &continued, &changed).is_err());
        let mut export = scope;
        export.authorization_export = true;
        assert!(require_initial_pair(&record, &request, &export).is_err());
    }
    #[test]
    fn encrypted_attempt_binds_full_roster_and_never_changes_the_inner_birth_record() {
        let record = super::super::tests::synthetic_record();
        let before = serde_json::to_vec(&record.account_record).unwrap();
        let intent = "f".repeat(64);
        let process = record.account_record.first_process_binding.clone();
        let principal = "synthetic-roster-reviewer".to_owned();
        let measurement = "a".repeat(64);
        let extension = record.extension().unwrap();
        let audit = AcquireAttempt {
            version: 2,
            enrollment_ref: record.account_record.reference().unwrap(),
            intent_digest: intent.clone(),
            extension_digest: extension.digest().unwrap(),
            acquire_operation_id: extension.acquire_operation_id().unwrap(),
            reentry_review_digest: canonical(
                "wholepact:native-born-manual-roster-preacquire-reentry:v2",
                &(&record, &intent, &process, &principal, &measurement),
            )
            .unwrap(),
            acquire_review_digest: "b".repeat(64),
            current_process: process,
            native_principal: principal,
            native_measurement: measurement,
        };
        let key = [0x53; 32];
        let bytes = vault::encrypt(
            &key,
            &domain(&record).unwrap(),
            &serde_json::to_vec(&audit).unwrap(),
        )
        .unwrap();
        validate_acquire_attempt_bytes(&record, &intent, &key, &bytes).unwrap();
        assert!(parse_attempt(&record, &intent, &key, &bytes).unwrap() == audit);
        assert!(validate_acquire_attempt_bytes(&record, &intent, &[0x54; 32], &bytes).is_err());
        let mut altered = bytes.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(validate_acquire_attempt_bytes(&record, &intent, &key, &altered).is_err());
        let mut changed = record.clone();
        changed.roster.predecessor =
            wholepact_core::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: "c".repeat(64),
            };
        changed.signer_roster_native_review_digest =
            roster_review_digest(&changed.account_record, &changed.roster).unwrap();
        assert!(validate_acquire_attempt_bytes(&changed, &intent, &key, &bytes).is_err());
        assert_eq!(serde_json::to_vec(&record.account_record).unwrap(), before);
    }
}
