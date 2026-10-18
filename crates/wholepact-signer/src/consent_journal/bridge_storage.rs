//! Typed immutable signer bridge persistence, in the same encrypted authority
//! journal and backup profile as originals. This module owns no independent
//! accounting, reset, release-clear or generic record-write API.
use super::*;
use crate::authority_bridge::{
    BridgeError, Result as BridgeResult,
    protocol::{RetainedAuthorizationRequest, RetainedAuthorizationResult, RetainedWitnessPermit},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use wholepact_authority::AuthenticatedPermit;

impl SignerConsentJournal {
    /// Read-only qualification evidence. Counts and exact row fingerprints are
    /// compared across the real retained-result retry, never used as authority.
    /// Result and original outbox share the one atomic results row.
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    pub(crate) fn qualification_durable_ledger_v1(
        &self,
        session: &SignerConsentSession,
    ) -> Result<Vec<(u64, [u8; 32])>> {
        use rusqlite::types::ValueRef;
        use sha2::{Digest, Sha256};
        // Fixed names/order only. No caller-controlled SQL or metadata export.
        // 0..7: consent, release, reserved inputs, request, permit, key-use,
        // result+outbox. Remaining entries cover current receipts, reconciled
        // remote exposure and explicit redelivery, all unchanged by retry.
        const QUERIES: [&str; 13] = [
            "SELECT * FROM signer_original_consents ORDER BY reference",
            "SELECT * FROM signer_release_intents ORDER BY authorization_id",
            "SELECT * FROM signer_input_reservations ORDER BY account_id,input_id",
            "SELECT * FROM signer_bridge_requests ORDER BY authorization_id",
            "SELECT * FROM signer_bridge_permits ORDER BY authorization_id",
            "SELECT * FROM signer_bridge_keyuse ORDER BY authorization_id",
            "SELECT * FROM signer_bridge_results ORDER BY authorization_id",
            "SELECT * FROM signer_enrollments ORDER BY reference",
            "SELECT * FROM signer_accepted_manifests ORDER BY reference",
            "SELECT * FROM signer_writer_reconciliations ORDER BY review_digest",
            "SELECT * FROM signer_remote_exposures ORDER BY authorization_id",
            "SELECT * FROM signer_remote_inputs ORDER BY authorization_id,nullifier",
            "SELECT * FROM signer_result_redeliveries ORDER BY operation_id",
        ];
        let account = self.account_state()?;
        let binding = self.binding();
        let permission = session.read_lease(&binding, &account)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        storage::check_account(&connection, &account)?;
        self.database_identity.check_current(&connection)?;
        storage::bounded(&connection, self.capacity_limits())?;
        let mut result = Vec::new();
        for query in QUERIES {
            permission.check_current()?;
            let mut hash = Sha256::new();
            hash.update(b"wholepact:qualification-durable-ledger:v1\0");
            hash.update(query.as_bytes());
            let mut statement = connection.prepare(query)?;
            let columns = statement.column_count();
            let mut rows = statement.query([])?;
            let mut count = 0u64;
            while let Some(row) = rows.next()? {
                count += 1;
                hash.update(count.to_le_bytes());
                hash.update((columns as u64).to_le_bytes());
                for column in 0..columns {
                    match row.get_ref(column)? {
                        ValueRef::Null => hash.update([0]),
                        ValueRef::Integer(value) => {
                            hash.update([1]);
                            hash.update(value.to_le_bytes());
                        }
                        ValueRef::Real(value) => {
                            hash.update([2]);
                            hash.update(value.to_bits().to_le_bytes());
                        }
                        ValueRef::Text(value) => {
                            hash.update([3]);
                            hash.update((value.len() as u64).to_le_bytes());
                            hash.update(value);
                        }
                        ValueRef::Blob(value) => {
                            hash.update([4]);
                            hash.update((value.len() as u64).to_le_bytes());
                            hash.update(value);
                        }
                    }
                }
            }
            result.push((count, hash.finalize().into()));
        }
        self.database_identity.check_current(&connection)?;
        permission.check_current()?;
        Ok(result)
    }

    pub(crate) fn bridge_retain_request(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
        request: &RetainedAuthorizationRequest,
    ) -> BridgeResult<()> {
        self.bridge_check_lease(lease)?;
        request.validate_original(lease.evidence())?;
        let raw = bridge_encode(&(&request.reservation, &request.delivery, &request.disclosure))?;
        let id = &request.reservation.authorization_id;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        if let Some(old) = read_request(&tx, id)? {
            if old != *request {
                return Err(BridgeError::Conflict);
            }
            return Ok(());
        }
        tx.execute("INSERT INTO signer_bridge_requests(authorization_id,original_consent_ref,request_payload,artifact_hex) VALUES(?1,?2,?3,?4)",
            params![id,request.reservation.original_consent_ref,raw.as_str(),request.artifact_hex]).map_err(JournalError::from)?;
        storage::bounded(&tx, self.capacity_limits())?;
        lease.check_current()?;
        tx.commit().map_err(JournalError::from)?;
        Ok(())
    }
    pub(crate) fn bridge_request(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
    ) -> BridgeResult<RetainedAuthorizationRequest> {
        self.bridge_check_lease(lease)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let record = read_request(
            &c,
            &lease.evidence().original_consent().terms().authorization_id,
        )?
        .ok_or(BridgeError::Missing)?;
        record.validate_original(lease.evidence())?;
        Ok(record)
    }
    pub(crate) fn bridge_retain_permit(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
        permit: &AuthenticatedPermit,
    ) -> BridgeResult<RetainedWitnessPermit> {
        self.bridge_check_lease(lease)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        let id = &lease.evidence().original_consent().terms().authorization_id;
        let request = read_request(&tx, id)?.ok_or(BridgeError::Missing)?;
        request.validate_original(lease.evidence())?;
        let record = RetainedWitnessPermit::from_authenticated(permit, &request.reservation)?;
        if let Some(old) = read_permit(&tx, id)? {
            if old != record {
                return Err(BridgeError::Conflict);
            }
            return Ok(old);
        }
        let raw = bridge_encode(&record)?;
        tx.execute(
            "INSERT INTO signer_bridge_permits(authorization_id,payload) VALUES(?1,?2)",
            params![id, raw.as_str()],
        )
        .map_err(JournalError::from)?;
        storage::bounded(&tx, self.capacity_limits())?;
        lease.check_current()?;
        tx.commit().map_err(JournalError::from)?;
        Ok(record)
    }
    /// Commit the uncertainty fence before touching any spending key. A second
    /// call always refuses, even when no signature/result can be found. There is
    /// no reset path and crashes cannot trigger another signature generation.
    pub(crate) fn bridge_begin_key_use(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
        permit: &AuthenticatedPermit,
    ) -> BridgeResult<()> {
        self.bridge_begin_authorized_key_use(lease, permit, None)
    }
    pub(crate) fn bridge_begin_authorized_key_use(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
        permit: &AuthenticatedPermit,
        automatic: Option<&wholepact_authority::AuthenticatedAutomaticKeyUseAdmission>,
    ) -> BridgeResult<()> {
        self.bridge_check_lease(lease)?;
        lease.require_current_authorization()?;
        match (
            &lease.evidence().original_consent().terms().automation,
            automatic,
        ) {
            (None, None) => {}
            (Some(binding), Some(admission)) => {
                let descriptor = admission.descriptor();
                admission.matches_request(&descriptor.request)?;
                if admission.authenticated_witness_certificate_digest()
                    != permit.authenticated_witness_certificate_digest()
                    || descriptor.request.automation != binding.grant
                    || descriptor.reservation != *permit.descriptor()
                    || descriptor.reservation.request.authorization_id
                        != lease.evidence().original_consent().terms().authorization_id
                {
                    return Err(BridgeError::Binding);
                }
                let now = now_ms()?;
                if now < descriptor.admitted_at_ms
                    || now >= descriptor.request.admission_expires_at_ms
                {
                    return Err(BridgeError::Permission);
                }
            }
            _ => return Err(BridgeError::Permission),
        }
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        #[cfg(feature = "authority-signing")]
        if !self.revalidate_settlements_in_transaction(&tx)? {
            tx.commit().map_err(JournalError::from)?;
            return Err(BridgeError::RecoveryRequired);
        }
        let id = &lease.evidence().original_consent().terms().authorization_id;
        let request = read_request(&tx, id)?.ok_or(BridgeError::Missing)?;
        request.validate_original(lease.evidence())?;
        if let Some(policy) =
            sponsor::current_for_consent(&tx, lease.evidence().original_consent().terms())?
        {
            if policy.witness.witness_id != permit.descriptor().witness_id
                || policy.witness.policy_digest != permit.descriptor().policy_digest
            {
                return Err(BridgeError::Binding);
            }
        }
        if let Some(grant) =
            automation::current_for_consent(&tx, lease.evidence().original_consent().terms())?
        {
            if grant.witness.witness_id != permit.descriptor().witness_id
                || grant.witness.policy_digest != permit.descriptor().policy_digest
            {
                return Err(BridgeError::Binding);
            }
        }
        let expected = RetainedWitnessPermit::from_authenticated(permit, &request.reservation)?;
        if read_permit(&tx, id)?.as_ref() != Some(&expected) {
            return Err(BridgeError::Binding);
        }
        let started: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM signer_bridge_keyuse WHERE authorization_id=?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(JournalError::from)?;
        if started {
            return Err(BridgeError::Uncertain);
        }
        tx.execute(
            "INSERT INTO signer_bridge_keyuse(authorization_id) VALUES(?1)",
            [id],
        )
        .map_err(JournalError::from)?;
        if let Some(admission) = automatic {
            let payload = bridge_encode(admission.descriptor())?;
            tx.execute(
                "INSERT INTO signer_automation_keyuse(authorization_id,payload) VALUES(?1,?2)",
                params![id, payload.as_str()],
            )
            .map_err(JournalError::from)?;
        }
        storage::bounded(&tx, self.capacity_limits())?;
        lease.require_current_authorization()?;
        tx.commit().map_err(JournalError::from)?;
        Ok(())
    }
    pub(crate) fn bridge_retain_result(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
        result: &RetainedAuthorizationResult,
    ) -> BridgeResult<()> {
        self.bridge_check_lease(lease)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        let id = &lease.evidence().original_consent().terms().authorization_id;
        let request = read_request(&tx, id)?.ok_or(BridgeError::Missing)?;
        request.validate_original(lease.evidence())?;
        result.validate(&request)?;
        if let Some(old) = read_result(&tx, id)? {
            if old != *result {
                return Err(BridgeError::Conflict);
            }
            return Ok(());
        }

        // FK to keyuse establishes the durable ordering, including result/outbox
        // atomicity. A failed insert leaves the key-use fence and exposure intact.
        tx.execute("INSERT INTO signer_bridge_results(authorization_id,result_digest,result_hex,outbox_payload) VALUES(?1,?2,?3,?4)",params![id,result.result_digest,result.signed_pczt_hex,result.outbox_payload]).map_err(JournalError::from)?;
        storage::bounded(&tx, self.capacity_limits())?;
        lease.check_current()?;
        tx.commit().map_err(JournalError::from)?;
        Ok(())
    }
    pub(crate) fn bridge_result(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
    ) -> BridgeResult<RetainedAuthorizationResult> {
        self.bridge_check_lease(lease)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let id = &lease.evidence().original_consent().terms().authorization_id;
        let result = read_validated_result(&c, id, lease.evidence())?;
        lease.check_current()?;
        Ok(result)
    }
    fn bridge_check_lease(&self, lease: &OriginalAuthorizationLease<'_>) -> BridgeResult<()> {
        lease.check_current()?;
        if lease.binding() != &self.binding() {
            return Err(BridgeError::Binding);
        }
        let account = self.account_state()?;
        if account.recovery_required {
            return Err(BridgeError::RecoveryRequired);
        }
        if account.account_id != lease.evidence().enrollment().account_id() {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}

pub(super) fn read_validated_result(
    c: &Connection,
    id: &str,
    original: &OriginalAuthorizationEvidence,
) -> BridgeResult<RetainedAuthorizationResult> {
    let request = read_request(c, id)?.ok_or(BridgeError::Missing)?;
    request.validate_original(original)?;
    let permit = read_permit(c, id)?.ok_or(BridgeError::Missing)?;
    permit
        .descriptor
        .matches_request(&request.reservation)
        .map_err(BridgeError::Authority)?;
    let result = read_result(c, id)?.ok_or(BridgeError::Uncertain)?;
    result.validate(&request)?;
    let started: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM signer_bridge_keyuse WHERE authorization_id=?1)",
            [id],
            |r| r.get(0),
        )
        .map_err(JournalError::from)?;
    if !started {
        return Err(BridgeError::Binding);
    }
    Ok(result)
}

fn bridge_encode<T: serde::Serialize>(v: &T) -> BridgeResult<zeroize::Zeroizing<String>> {
    let raw = zeroize::Zeroizing::new(serde_json::to_string(v).map_err(|_| BridgeError::Binding)?);
    if raw.len() > 512 * 1024 {
        return Err(BridgeError::Limit);
    }
    Ok(raw)
}
fn bridge_decode<T: serde::de::DeserializeOwned>(raw: String) -> BridgeResult<T> {
    let raw = zeroize::Zeroizing::new(raw);
    if raw.len() > 512 * 1024 {
        return Err(BridgeError::Limit);
    }
    serde_json::from_str(&raw).map_err(|_| BridgeError::Binding)
}
pub(super) fn read_request(
    c: &rusqlite::Connection,
    id: &str,
) -> BridgeResult<Option<RetainedAuthorizationRequest>> {
    let row: Option<(String,String,String)> = c.query_row("SELECT original_consent_ref,request_payload,artifact_hex FROM signer_bridge_requests WHERE authorization_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(JournalError::from)?;
    row.map(|(original, raw, artifact)| {
        let (reservation, delivery, disclosure) = bridge_decode(raw)?;
        let record = RetainedAuthorizationRequest {
            reservation,
            delivery,
            artifact_hex: artifact,
            disclosure,
        };
        if record.reservation.authorization_id != id
            || record.reservation.original_consent_ref != original
        {
            return Err(BridgeError::Binding);
        }
        Ok(record)
    })
    .transpose()
}
pub(super) fn read_permit(
    c: &rusqlite::Connection,
    id: &str,
) -> BridgeResult<Option<RetainedWitnessPermit>> {
    let row: Option<String> = c
        .query_row(
            "SELECT payload FROM signer_bridge_permits WHERE authorization_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()
        .map_err(JournalError::from)?;
    row.map(bridge_decode).transpose()
}
fn read_result(
    c: &rusqlite::Connection,
    id: &str,
) -> BridgeResult<Option<RetainedAuthorizationResult>> {
    let row: Option<(String,String,String)> = c.query_row("SELECT result_digest,result_hex,outbox_payload FROM signer_bridge_results WHERE authorization_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(JournalError::from)?;
    row.map(|(digest, raw, outbox)| {
        use sha2::{Digest, Sha256};
        let request = read_request(c, id)?.ok_or(BridgeError::Missing)?;
        let record = RetainedAuthorizationResult {
            authorization_id: id.into(),
            original_consent_ref: request.reservation.original_consent_ref.clone(),
            request_digest: request
                .reservation
                .request_digest()
                .map_err(BridgeError::Authority)?,
            result_digest: digest,
            signed_pczt_hex: raw,
            outbox_digest: hex::encode(Sha256::digest(outbox.as_bytes())),
            outbox_payload: outbox,
        };
        record.validate(&request)?;
        Ok(record)
    })
    .transpose()
}

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "bridge_storage_tests.rs"]
mod tests;
