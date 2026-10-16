//! Read-side conjunction before the configured owner can retain any new input.
//! The final existing transaction repeats authentication/accounting before commit.
use super::*;
use crate::offline::OfflineEnrollmentPolicy;

impl AuthorityJournal {
    pub(crate) fn offline_witness_policy_v1(
        &self,
        expected: &str,
    ) -> Result<OfflineEnrollmentPolicy> {
        self.require_born_mutation_current()?;
        hash(expected)?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = load(c.connection())?;
        // Explicit even in feature profiles where no native owner type exists.
        if ledger.policy.account_use_genesis.is_some() {
            return Err(AuthorityError::Permission);
        }
        if ledger.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        let policy = ledger
            .offline_policies
            .get(expected)
            .ok_or(AuthorityError::PolicyDenied)?;
        policy.validate()?;
        if policy.policy_digest()? != expected {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(policy.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticate_offline_witness_channel_v1(
        &self,
        peer: &str,
        record: &OfflineReservationRecord,
        proof: &protocol::WriterSessionProof,
        exporter: &[u8; 32],
        server_certificate: &str,
        expected_policy: &OfflineEnrollmentPolicy,
        now: u64,
    ) -> Result<()> {
        self.require_born_mutation_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let ledger = crate::offline_retry::gate(&tx, peer, &record.request, now)?;
        if ledger.policy.account_use_genesis.is_some() {
            return Err(AuthorityError::Permission);
        }
        let policy = ledger
            .offline_policies
            .get(&record.authentication.policy_digest)
            .ok_or(AuthorityError::PolicyDenied)?;
        if policy != expected_policy || policy.witness_certificate_digest != server_certificate {
            return Err(AuthorityError::Conflict);
        }
        record.authentication.matches(&record.request, policy)?;
        let active = ledger
            .snapshot
            .active_writer_session
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if active.session_id != proof.session_id {
            return Err(AuthorityError::SessionRequired);
        }
        let receipt = ledger
            .sessions
            .get(&proof.session_id)
            .ok_or(AuthorityError::SessionRequired)?;
        if receipt.writer_certificate_digest != peer
            || receipt.disclosure.pinned_server_certificate_digest != server_certificate
        {
            return Err(AuthorityError::Permission);
        }
        let key = read_session_key(&tx, &proof.session_id)?;
        crate::session::verify(
            &key,
            receipt,
            exporter,
            &AuthorityMutation::ReserveOfflineAuthorization(Box::new(record.clone())),
            proof,
        )
    }
}

impl AuthorityJournal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_offline_prepared_current_v1(
        &self,
        peer: &str,
        request: crate::offline::ReserveOfflineAuthorization,
        authentication: AuthenticatedOfflineIntent,
        proof: protocol::WriterSessionProof,
        exporter: &[u8; 32],
        server_certificate: &str,
        current: &crate::offline_witness_v1::CurrentOfflineWitnessWindowV1,
    ) -> Result<CommittedOfflineAdmission> {
        let record = OfflineReservationRecord {
            request,
            authentication: authentication.evidence().clone(),
        };
        authentication.matches(&record.request, &record.authentication)?;
        let result = self.mutate_inner_timed(
            peer,
            AuthorityMutation::ReserveOfflineAuthorization(Box::new(record)),
            Some(proof),
            exporter,
            server_certificate,
            current.check()?,
            Some(&authentication),
            true,
            Some(current),
        )?;
        let MutationResult::OfflineReserved(descriptor) = result else {
            return Err(AuthorityError::CorruptHistory);
        };
        Ok(CommittedOfflineAdmission {
            descriptor: *descriptor,
        })
    }
}
