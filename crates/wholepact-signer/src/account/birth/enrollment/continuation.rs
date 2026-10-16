//! Fresh native reentry before the very first acquisition. No TLS/session state
//! is restored. The immutable first record/transport remain historical unchanged.
use super::*;
use crate::native_ui::{AuthenticatedPairing, NativeApprovedWriterSession};
use wholepact_signer_origin::manual::{HostManualEnrollmentIntent, HostManualEnrollmentRequest};

pub(crate) struct PreparedBornManualReentry {
    retained: RetainedBornManualEnrollment,
    source: NativeAuthorityBinding,
    peer: AuthenticatedPeer,
    current_process: TransportIdentityBinding,
    principal: String,
    measurement: String,
    digest: String,
    display: Zeroizing<String>,
}
pub(crate) struct ApprovedBornManualReentry(PreparedBornManualReentry);
impl PreparedBornManualReentry {
    pub(crate) fn prepare(
        retained: RetainedBornManualEnrollment,
        request: &HostManualEnrollmentRequest,
        pairing: &AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        retained.check_current_source(owner)?;
        require_unattempted_inventory(&retained.account.directory)?;
        pairing.check_current()?;
        let peer = pairing.current_peer();
        let terms = &retained.record.terms;
        let now = now_ms()?;
        if now < terms.issued_at_ms || now >= terms.scope.expires_at_ms {
            return Err(Error::ReviewMismatch);
        }
        let original_intent = HostManualEnrollmentIntent {
            version: 1,
            operation_id: terms.operation_id.clone(),
            host: terms.host.clone(),
            scope: terms.scope.clone(),
        };
        if request.terms != *terms
            || pairing.native_origin() != &owner.native().binding()
            || peer.scope.account_id != terms.identity.account_id
            || peer.scope.agreement_id != terms.scope.agreement_id
            || peer.scope.participant_id != terms.scope.participant_id
            || peer.scope.manifest_digest
                != original_intent.digest().map_err(|_| Error::InvalidData)?
            || peer.scope.history_read
            || peer.scope.authorization_export
            || peer.scope.preconstruction_export
        {
            return Err(Error::Authentication);
        }
        let current_process = pairing.binding().clone();
        let principal = owner.native().principal_id().to_owned();
        let measurement = owner.native().measurement().to_owned();
        let digest = canonical(
            "wholepact:native-born-manual-preacquire-reentry:v1",
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
    ) -> Result<ApprovedBornManualReentry> {
        self.retained.check_current_source(owner)?;
        self.peer.check_current()?;
        require_unattempted_inventory(&self.retained.account.directory)?;
        if self.source != owner.native().binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedBornManualReentry(self))
    }
}
impl ApprovedBornManualReentry {
    pub(crate) fn check_current(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.0.retained.check_current_source(owner)?;
        let now = now_ms()?;
        if now < self.0.retained.record.terms.issued_at_ms
            || now >= self.0.retained.record.terms.scope.expires_at_ms
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
        let acquire_review = approved.born_attempt_review(&extension, &p.source)?;
        if retained.account.directory.exists(JOURNAL)?
            || retained.account.directory.exists(COMMIT)?
        {
            return Err(Error::RecoveryRequired);
        }
        let expected = AcquireAttempt {
            version: 1,
            enrollment_ref: retained.record.reference()?,
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
        if retained.account.directory.exists(ACQUIRE_ATTEMPT)? {
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
                .write(ACQUIRE_ATTEMPT, &encrypted)?;
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
    fn validate(&self, record: &BornManualEnrollmentRecord, intent: &str) -> Result<()> {
        let e = record.extension()?;
        if self.version != 1
            || self.enrollment_ref != record.reference()?
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
                    "wholepact:native-born-manual-preacquire-reentry:v1",
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
            } if account_id == &record.terms.identity.account_id
                && agreement_id == &record.terms.scope.agreement_id
                && participant_id == &record.terms.scope.participant_id
                && *pid > 0
                && *signer_generation > 0 => {}
            _ => return Err(Error::Authentication),
        }
        Ok(())
    }
}
fn domain(record: &BornManualEnrollmentRecord) -> Result<Vec<u8>> {
    let mut d = b"wholepact:born-manual-first-acquire-attempt:v1\0".to_vec();
    d.extend(record.reference()?.as_bytes());
    Ok(d)
}
fn read_attempt(retained: &RetainedBornManualEnrollment) -> Result<AcquireAttempt> {
    let bytes = retained
        .account
        .directory
        .read(ACQUIRE_ATTEMPT, MAX_INTENT)?;
    parse_attempt(
        &retained.record,
        &retained.intent_digest,
        &retained.account.encryption_key,
        &bytes,
    )
}
fn parse_attempt(
    record: &BornManualEnrollmentRecord,
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
    record: &BornManualEnrollmentRecord,
    intent: &str,
    key: &[u8; 32],
    bytes: &[u8],
) -> Result<()> {
    parse_attempt(record, intent, key, bytes).map(|_| ())
}
pub(crate) fn require_unattempted_inventory(directory: &PrivateDirectory) -> Result<()> {
    inventory(directory)?;
    if !directory.exists(INTENT)?
        || directory.exists(ACQUIRE_ATTEMPT)?
        || directory.exists(JOURNAL)?
        || directory.exists(COMMIT)?
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
#[cfg(test)]
#[path = "continuation/marker_tests.rs"]
mod marker_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn each_partial_attempt_journal_or_completion_state_denies_reentry_unchanged() {
        for blocked in [
            ACQUIRE_ATTEMPT,
            JOURNAL,
            COMMIT,
            "tmp-interrupted-first-acquire",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let dir = PrivateDirectory::create(&temp.path().join("synthetic-source")).unwrap();
            for name in ["account.wp", "birth-owner-request.wp", INTENT] {
                dir.write(name, b"original retained synthetic bytes")
                    .unwrap();
            }
            dir.write(blocked, b"preserve this uncertain state")
                .unwrap();
            let before = std::fs::read_dir(dir.root())
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (e.file_name(), std::fs::read(e.path()).unwrap())
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            assert!(require_unattempted_inventory(&dir).is_err());
            let after = std::fs::read_dir(dir.root())
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (e.file_name(), std::fs::read(e.path()).unwrap())
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(before, after);
        }
    }
    #[test]
    fn retained_preacquire_inventory_is_repeatable_but_attempt_or_journal_blocks_reentry() {
        let temp = tempfile::tempdir().unwrap();
        let dir = PrivateDirectory::create(&temp.path().join("synthetic")).unwrap();
        for name in ["account.wp", "birth-owner-request.wp", INTENT] {
            dir.write(name, b"synthetic immutable bytes").unwrap();
        }
        let original = dir.read(INTENT, 128).unwrap();
        assert!(require_unattempted_inventory(&dir).is_ok());
        assert!(require_unattempted_inventory(&dir).is_ok());
        dir.write(
            ACQUIRE_ATTEMPT,
            b"synthetic attempted marker; never native authority",
        )
        .unwrap();
        assert!(require_unattempted_inventory(&dir).is_err());
        assert_eq!(dir.read(INTENT, 128).unwrap(), original);
        dir.write(JOURNAL, b"preserved uncertain journal").unwrap();
        dir.write(COMMIT, b"preserved completion").unwrap();
        assert!(require_unattempted_inventory(&dir).is_err());
        assert_eq!(dir.read(INTENT, 128).unwrap(), original);
    }
}
