//! Disabled recipient input/receipt crash journal. No spending or new reservation.
//! Staged after host v12; schema/capacity/backup/recovery hooks must land together.
#![allow(dead_code)]
use super::*;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "offline-review-foundation")]
use wholepact_offline_bridge::{
    AuthenticatedOfflineReviewReceipt, OfflineReviewInspection, RecoveredOfflineReviewReceipt,
};

// Includes accepted history: no cleanup/compaction or quota-recycling path exists.
const MAX_RETAINED_REVIEW_INPUTS: i64 = 64;
// Conservative staged supported input ceiling, not a claim all PCZTs fit here.
const MAX_RECEIPT_INPUT_BYTES: usize = 192 * 1024;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReceiptRecord {
    account_id: String,
    authorization_id: String,
    owner_setup_digest: String,
    terms_digest: String,
    package_digest: String,
    preview_json: String,
    sequence: u64,
    envelope_digest: String,
    content_digest: String,
}
impl ReceiptRecord {
    #[cfg(feature = "offline-review-foundation")]
    fn from_authenticated(r: &AuthenticatedOfflineReviewReceipt) -> Result<Self> {
        Ok(Self {
            account_id: r.account_id().into(),
            authorization_id: r.authorization_id().into(),
            owner_setup_digest: r.owner_setup_digest().into(),
            terms_digest: r.terms_digest().into(),
            package_digest: r.package_digest().into(),
            preview_json: serde_json::to_string(r.preview())
                .map_err(|_| JournalError::InvalidBinding)?,
            sequence: r.preview().order.sequence,
            envelope_digest: r.envelope_digest().into(),
            content_digest: r.content_digest().into(),
        })
    }
    fn reference(&self) -> Result<String> {
        digest("wholepact:offline-review-receipt:v1", self)
    }
}

/// Protected journal-selected historical retry input. Not a fresh-review token.
pub(crate) struct RetainedReviewInput {
    bytes: Zeroizing<Vec<u8>>,
    authenticated: Option<ReceiptRecord>,
    accepted: bool,
}
impl RetainedReviewInput {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn authenticated_pin(&self) -> Option<(u64, &str, &str)> {
        self.authenticated.as_ref().map(|r| {
            (
                r.sequence,
                r.envelope_digest.as_str(),
                r.content_digest.as_str(),
            )
        })
    }
    pub(crate) fn accepted(&self) -> bool {
        self.accepted
    }
}

/// Private source orchestration only; feature-gated module has no public writer.
/// It always rechecks the real journal/session binding and account-state fence.
#[cfg(feature = "offline-review-foundation")]
pub(crate) struct OfflineReceiptJournal<'a> {
    journal: &'a SignerConsentJournal,
    session: &'a SignerConsentSession,
}
#[cfg(feature = "offline-review-foundation")]
impl SignerConsentJournal {
    pub(crate) fn offline_receipt_journal<'a>(
        &'a self,
        session: &'a SignerConsentSession,
    ) -> Result<OfflineReceiptJournal<'a>> {
        // No partial schema/backup integration may create a callable write path.
        require_receipt_storage_qualified()?;
        Ok(OfflineReceiptJournal {
            journal: self,
            session,
        })
    }
}
#[cfg(feature = "offline-review-foundation")]
fn require_receipt_storage_qualified() -> Result<()> {
    Err(JournalError::RecoveryRequired)
}

#[cfg(feature = "offline-review-foundation")]
impl OfflineReceiptJournal<'_> {
    fn transaction<T>(&self, f: impl FnOnce(&Connection, &str) -> Result<T>) -> Result<T> {
        let account = self.journal.account_state()?;
        let lease = self.session.read_lease(&self.journal.binding(), &account)?;
        let _fence = self
            .journal
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        storage::check_account(&tx, &account)?;
        lease.check_current()?;
        storage::bounded(&tx, self.journal.capacity_limits())?;
        let result = f(&tx, &account.account_id)?;
        // Future coordinated schema hooks must include every receipt table.
        storage::bounded(&tx, self.journal.capacity_limits())?;
        lease.check_current()?;
        tx.commit()?;
        Ok(result)
    }
    /// Bounded immutable bytes before authentication; this allocates no transport
    /// order, authority, exposure or native consent. Same operation must retry exact.
    pub(crate) fn prepare(
        &self,
        authorization_id: &str,
        terms_digest: &str,
        package_digest: &str,
        bytes: &[u8],
    ) -> Result<RetainedReviewInput> {
        id(authorization_id)?;
        hash(terms_digest)?;
        hash(package_digest)?;
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_INPUT_BYTES {
            return Err(JournalError::Limit);
        }
        self.transaction(|c, account| {
            prepare_input(
                c,
                account,
                authorization_id,
                terms_digest,
                package_digest,
                bytes,
            )?;
            load_input(c, account, authorization_id)
        })
    }
    pub(crate) fn recover(&self, authorization_id: &str) -> Result<RetainedReviewInput> {
        id(authorization_id)?;
        self.transaction(|c, account| load_input(c, account, authorization_id))
    }
    pub(crate) fn record_authenticated(
        &self,
        receipt: &AuthenticatedOfflineReviewReceipt,
    ) -> Result<()> {
        let record = ReceiptRecord::from_authenticated(receipt)?;
        self.transaction(|c, account| record_authenticated(c, account, &record))
    }
    /// Only successful concrete inbox import can supply this process-local value.
    pub(crate) fn record_import_accepted(
        &self,
        inspection: &OfflineReviewInspection,
    ) -> Result<()> {
        self.record_accepted(inspection.receipt())
    }
    /// Recovery proves original inbox acceptance by reauthenticating its retained
    /// ciphertext. Expired recovery remains history; no clock or UI is refreshed.
    pub(crate) fn record_recovered_accepted(
        &self,
        recovered: &RecoveredOfflineReviewReceipt,
    ) -> Result<()> {
        self.record_accepted(recovered.receipt())
    }
    fn record_accepted(&self, receipt: &AuthenticatedOfflineReviewReceipt) -> Result<()> {
        let record = ReceiptRecord::from_authenticated(receipt)?;
        self.transaction(|c, account| record_accepted(c, account, &record))
    }
}
fn envelope_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact.encrypted-envelope.v1\0");
    h.update(bytes);
    hex::encode(h.finalize())
}
fn prepare_input(
    c: &Connection,
    account: &str,
    authorization: &str,
    terms: &str,
    package: &str,
    bytes: &[u8],
) -> Result<()> {
    let found: Option<(String,String,String,String,String)> = c.query_row(
        "SELECT account_id,terms_digest,package_digest,envelope_digest,envelope_hex FROM signer_offline_review_inputs WHERE authorization_id=?1",
        [authorization], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    let expected = (
        account.to_owned(),
        terms.to_owned(),
        package.to_owned(),
        envelope_digest(bytes),
        hex::encode(bytes),
    );
    if let Some(old) = found {
        return if old == expected {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    }
    let count: i64 = c.query_row(
        "SELECT count(*) FROM signer_offline_review_inputs",
        [],
        |r| r.get(0),
    )?;
    if count >= MAX_RETAINED_REVIEW_INPUTS {
        return Err(JournalError::Limit);
    }
    c.execute(
        "INSERT INTO signer_offline_review_inputs VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            authorization,
            expected.0,
            expected.1,
            expected.2,
            expected.3,
            expected.4
        ],
    )?;
    Ok(())
}
fn record_authenticated(c: &Connection, account: &str, r: &ReceiptRecord) -> Result<()> {
    if r.account_id != account {
        return Err(JournalError::InvalidBinding);
    }
    let row: (String,String,String,String) = c.query_row(
        "SELECT account_id,terms_digest,package_digest,envelope_digest FROM signer_offline_review_inputs WHERE authorization_id=?1",
        [&r.authorization_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    )?;
    if row
        != (
            r.account_id.clone(),
            r.terms_digest.clone(),
            r.package_digest.clone(),
            r.envelope_digest.clone(),
        )
    {
        return Err(JournalError::Conflict);
    }
    let payload = encode(r)?;
    let reference = r.reference()?;
    let old: Option<(String,String)> = c.query_row(
        "SELECT receipt_digest,payload FROM signer_offline_review_authenticated WHERE authorization_id=?1",
        [&r.authorization_id],|row|Ok((row.get(0)?,row.get(1)?)),
    ).optional()?;
    if let Some((old_ref, old_payload)) = old {
        return if old_ref == reference && old_payload == *payload {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    }
    c.execute(
        "INSERT INTO signer_offline_review_authenticated VALUES(?1,?2,?3)",
        params![r.authorization_id, reference, payload.as_str()],
    )?;
    Ok(())
}
fn load_input(c: &Connection, account: &str, authorization: &str) -> Result<RetainedReviewInput> {
    let (stored_account,terms,package,digest,encoded): (String,String,String,String,String) = c.query_row(
        "SELECT account_id,terms_digest,package_digest,envelope_digest,envelope_hex FROM signer_offline_review_inputs WHERE authorization_id=?1",
        [authorization],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    )?;
    hash(&terms)?;
    hash(&package)?;
    hash(&digest)?;
    if stored_account != account
        || encoded.is_empty()
        || encoded.len() > MAX_RECEIPT_INPUT_BYTES * 2
    {
        return Err(JournalError::InvalidBinding);
    }
    let bytes = Zeroizing::new(hex::decode(encoded).map_err(|_| JournalError::InvalidBinding)?);
    if envelope_digest(&bytes) != digest {
        return Err(JournalError::InvalidBinding);
    }
    let stored: Option<(String,String)> = c.query_row(
        "SELECT receipt_digest,payload FROM signer_offline_review_authenticated WHERE authorization_id=?1",
        [authorization],|r|Ok((r.get(0)?,r.get(1)?)),
    ).optional()?;
    let authenticated: Option<ReceiptRecord> = stored
        .map(|(reference, payload)| {
            let r: ReceiptRecord = decode(payload)?;
            if r.authorization_id != authorization
                || r.reference()? != reference
                || r.sequence == 0
                || r.sequence > i64::MAX as u64
            {
                return Err(JournalError::InvalidBinding);
            }
            for h in [
                &r.owner_setup_digest,
                &r.terms_digest,
                &r.package_digest,
                &r.envelope_digest,
                &r.content_digest,
            ] {
                hash(h)?;
            }
            record_authenticated(c, account, &r)?;
            Ok(r)
        })
        .transpose()?;
    let accepted: Option<String> = c
        .query_row(
            "SELECT receipt_digest FROM signer_offline_review_accepted WHERE authorization_id=?1",
            [authorization],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(reference) = &accepted {
        if authenticated
            .as_ref()
            .map(ReceiptRecord::reference)
            .transpose()?
            .as_ref()
            != Some(reference)
        {
            return Err(JournalError::Conflict);
        }
    }
    Ok(RetainedReviewInput {
        bytes,
        authenticated,
        accepted: accepted.is_some(),
    })
}

/// Historical retry never silently becomes a current native review.
#[cfg(feature = "offline-review-foundation")]
pub(crate) enum ReviewImportOutcome {
    NewlyInspected(Box<OfflineReviewInspection>),
    RecoveredHistory(Box<RecoveredOfflineReviewReceipt>),
}
#[cfg(feature = "offline-review-foundation")]
impl OfflineReceiptJournal<'_> {
    /// Connected prepare -> authenticated callback -> concrete inbox -> signer
    /// acceptance path. No closure ever receives a raw privileged writer.
    pub(crate) fn import_or_recover_review(
        &self,
        channel: &mut wholepact_offline_bridge::OfflineReviewChannel<'_>,
        setup: &wholepact_offline_bridge::OwnerEstablishedOfflineSetup,
        expected: &wholepact_offline_bridge::RetainedOfflineReviewInputs,
        input: &[u8],
        now_unix_seconds: i64,
    ) -> Result<ReviewImportOutcome> {
        let terms = expected.terms();
        if self.journal.account_state()?.account_id != terms.account_id {
            return Err(JournalError::InvalidBinding);
        }
        let pending = self.prepare(
            &terms.authorization_id,
            &terms
                .terms_digest()
                .map_err(|_| JournalError::InvalidBinding)?,
            &terms.review_package_digest,
            input,
        )?;
        if let Some((sequence, envelope_digest, content_digest)) = pending.authenticated_pin() {
            if let Some(recovered) = channel
                .recover_receipt(setup, expected, sequence, envelope_digest, content_digest)
                .map_err(|_| JournalError::InvalidBinding)?
            {
                self.record_recovered_accepted(&recovered)?;
                return Ok(ReviewImportOutcome::RecoveredHistory(Box::new(recovered)));
            }
        }
        // An accepted signer pin with absent inbox is rollback/incomplete restore,
        // never permission to recreate receipt ordering in another mailbox.
        if pending.accepted() {
            return Err(JournalError::RecoveryRequired);
        }
        let inspection = channel.import_recording(
            pending.bytes(),setup,expected,now_unix_seconds,
            |receipt| self.record_authenticated(receipt)
                .map_err(|_|wholepact_offline_bridge::OfflineReceiptPersistenceError::AuthorityUnavailable),
        ).map_err(|_|JournalError::InvalidBinding)?;
        self.record_import_accepted(&inspection)?;
        Ok(ReviewImportOutcome::NewlyInspected(Box::new(inspection)))
    }
}

fn record_accepted(c: &Connection, account: &str, record: &ReceiptRecord) -> Result<()> {
    record_authenticated(c, account, record)?;
    let reference = record.reference()?;
    let old: Option<String> = c
        .query_row(
            "SELECT receipt_digest FROM signer_offline_review_accepted WHERE authorization_id=?1",
            [&record.authorization_id],
            |r| r.get(0),
        )
        .optional()?;
    match old {
        Some(v) if v == reference => Ok(()),
        Some(_) => Err(JournalError::Conflict),
        None => {
            c.execute(
                "INSERT INTO signer_offline_review_accepted VALUES(?1,?2)",
                params![record.authorization_id, reference],
            )?;
            Ok(())
        }
    }
}

/// Always compiled semantic validation, including builds without offline feature.
pub(super) fn validate_all(c: &Connection, account: &str) -> Result<()> {
    let count: i64 = c.query_row(
        "SELECT count(*) FROM signer_offline_review_inputs",
        [],
        |r| r.get(0),
    )?;
    if count > MAX_RETAINED_REVIEW_INPUTS {
        return Err(JournalError::Limit);
    }
    let orphan: bool=c.query_row("SELECT EXISTS(SELECT 1 FROM signer_offline_review_authenticated a LEFT JOIN signer_offline_review_inputs i USING(authorization_id) WHERE i.authorization_id IS NULL) OR EXISTS(SELECT 1 FROM signer_offline_review_accepted a LEFT JOIN signer_offline_review_authenticated i USING(authorization_id) WHERE i.authorization_id IS NULL)",[],|r|r.get(0))?;
    if orphan {
        return Err(JournalError::InvalidBinding);
    }
    let mut q = c.prepare(
        "SELECT authorization_id FROM signer_offline_review_inputs ORDER BY authorization_id",
    )?;
    let ids = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(q);
    for authorization in ids {
        id(&authorization)?;
        load_input(c, account, &authorization)?;
    }
    Ok(())
}
/// Pending review observations must not be silently dropped by legacy recovery.
pub(super) fn require_legacy_journal(c: &Connection) -> Result<()> {
    let count: i64 = c.query_row(
        "SELECT count(*) FROM signer_offline_review_inputs",
        [],
        |r| r.get(0),
    )?;
    if count != 0 {
        return Err(JournalError::RecoveryRequired);
    }
    Ok(())
}

/// Same-snapshot audit projection; raw ciphertext remains inside the journal.
/// This cannot create authenticated review, native consent or return authority.
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
pub(super) fn continuity_metadata(
    c: &Connection,
    account: &str,
) -> Result<Vec<crate::authority_bridge::host_recovery_ipc::v2::OfflineReviewReceiptMetadataV2>> {
    use crate::authority_bridge::host_recovery_ipc::v2::{
        OfflineAuthenticatedReviewMetadataV2, OfflineReviewReceiptMetadataV2,
    };
    if c.is_autocommit() {
        return Err(JournalError::InvalidBinding);
    }
    validate_all(c, account)?;
    let mut q = c.prepare("SELECT authorization_id,account_id,terms_digest,package_digest,envelope_digest FROM signer_offline_review_inputs ORDER BY authorization_id")?;
    let mut result = Vec::new();
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })? {
        let (authorization_id, account_id, terms_digest, package_digest, envelope_digest) = row?;
        let retained = load_input(c, account, &authorization_id)?;
        let authenticated = retained
            .authenticated
            .map(|r| OfflineAuthenticatedReviewMetadataV2 {
                account_id: r.account_id,
                authorization_id: r.authorization_id,
                owner_setup_digest: r.owner_setup_digest,
                terms_digest: r.terms_digest,
                package_digest: r.package_digest,
                preview_json: r.preview_json,
                sequence: r.sequence,
                envelope_digest: r.envelope_digest,
                content_digest: r.content_digest,
            });
        let accepted_receipt_digest = if retained.accepted {
            Some(
                authenticated
                    .as_ref()
                    .ok_or(JournalError::InvalidBinding)?
                    .receipt_digest()
                    .map_err(|_| JournalError::InvalidBinding)?,
            )
        } else {
            None
        };
        result.push(OfflineReviewReceiptMetadataV2 {
            account_id,
            authorization_id,
            terms_digest,
            package_digest,
            envelope_digest,
            authenticated,
            accepted_receipt_digest,
        });
    }
    Ok(result)
}

/// Complete-history representation consistency. A pending review is not an
/// admission, but the same authorization ID cannot describe incompatible work.
/// No writes, inbox acceptance, original consent or authority are produced.
pub(super) fn validate_reconciled(
    c: &Connection,
    account: &str,
    history: &wholepact_authority::ReconciledAuthorityHistory,
) -> Result<()> {
    if c.is_autocommit() || history.snapshot().account_id != account {
        return Err(JournalError::InvalidBinding);
    }
    validate_all(c, account)?;
    let retained = offline_history::read_inventory(c, account)?;
    let union = retained.reconcile_reservations(history)?;
    validate_reconciled_union(c, &union)
}

/// V5-only financial receipt consistency inside a separately complete transport
/// wrapper. This function returns no projected history or native permission.
pub(super) fn validate_transport_reconciled(
    c: &Connection,
    account: &str,
    history: &wholepact_authority::ReconciledAuthorityHistory,
    complete: &wholepact_authority::construction_transport_handoff_v1::ConstructionHistoryWithTransportV1,
) -> Result<()> {
    if c.is_autocommit() || history.snapshot().account_id != account {
        return Err(JournalError::InvalidBinding);
    }
    validate_all(c, account)?;
    let retained = offline_history::read_inventory(c, account)?;
    let union = retained.reconcile_transport_financial_branch(history, complete)?;
    validate_reconciled_union(c, &union)
}

fn validate_reconciled_union(
    c: &Connection,
    union: &offline_reconciliation::OfflineReconciliationInventory<'_>,
) -> Result<()> {
    let mut q = c.prepare("SELECT authorization_id,terms_digest,package_digest FROM signer_offline_review_inputs ORDER BY authorization_id")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (authorization, terms, package) = row?;
        let local_online: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM signer_original_consents WHERE authorization_id=?1) OR EXISTS(SELECT 1 FROM signer_remote_exposures WHERE authorization_id=?1)",[&authorization],|r|r.get(0))?;
        if local_online
            || union
                .witness_online_reservations()
                .iter()
                .any(|p| p.request.authorization_id == authorization)
        {
            return Err(JournalError::Conflict);
        }
        for candidate in union.offline_origins().iter().map(|o| o.terms()).chain(
            union
                .retained_reservation_intents()
                .iter()
                .map(|i| &i.terms),
        ) {
            if candidate.authorization_id == authorization
                && (candidate
                    .terms_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
                    != terms
                    || candidate.review_package_digest != package)
            {
                return Err(JournalError::Conflict);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn database() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        c.execute_batch(include_str!("offline_receipts.sql"))
            .unwrap();
        c
    }
    fn record() -> ReceiptRecord {
        ReceiptRecord {
            account_id: "synthetic-account".into(),
            authorization_id: "synthetic-review".into(),
            owner_setup_digest: "a".repeat(64),
            terms_digest: "b".repeat(64),
            package_digest: "c".repeat(64),
            preview_json: "synthetic fixture only".into(),
            sequence: 1,
            envelope_digest: envelope_digest(b"synthetic encrypted envelope placeholder"),
            content_digest: "d".repeat(64),
        }
    }
    fn prepared(c: &Connection, r: &ReceiptRecord) {
        prepare_input(
            c,
            &r.account_id,
            &r.authorization_id,
            &r.terms_digest,
            &r.package_digest,
            b"synthetic encrypted envelope placeholder",
        )
        .unwrap();
    }
    #[cfg(all(
        feature = "native-ui",
        feature = "authority-signing",
        target_os = "linux"
    ))]
    #[test]
    fn complete_metadata_requires_snapshot_and_preserves_all_three_receipt_states() {
        let mut c = database();
        let r = record();
        prepared(&c, &r);
        assert!(continuity_metadata(&c, &r.account_id).is_err());
        let tx = c.transaction().unwrap();
        let input = continuity_metadata(&tx, &r.account_id).unwrap();
        assert_eq!(input.len(), 1);
        assert!(input[0].authenticated.is_none());
        assert!(input[0].accepted_receipt_digest.is_none());
        record_authenticated(&tx, &r.account_id, &r).unwrap();
        let pending = continuity_metadata(&tx, &r.account_id).unwrap();
        assert_eq!(
            pending[0]
                .authenticated
                .as_ref()
                .unwrap()
                .receipt_digest()
                .unwrap(),
            r.reference().unwrap()
        );
        assert!(pending[0].accepted_receipt_digest.is_none());
        record_accepted(&tx, &r.account_id, &r).unwrap();
        let accepted = continuity_metadata(&tx, &r.account_id).unwrap();
        assert_eq!(
            accepted[0].accepted_receipt_digest.as_ref(),
            Some(&r.reference().unwrap())
        );
        let json = serde_json::to_string(&accepted).unwrap();
        assert!(!json.contains("envelope_hex"));
        assert!(!json.contains("synthetic encrypted envelope placeholder"));
        assert!(continuity_metadata(&tx, "other-account").is_err());
        tx.rollback().unwrap();
    }

    #[test]
    fn input_only_crash_preserves_exact_retry_and_has_no_acceptance() {
        let c = database();
        let r = record();
        prepared(&c, &r);
        prepared(&c, &r);
        let retained = load_input(&c, &r.account_id, &r.authorization_id).unwrap();
        assert_eq!(
            retained.bytes(),
            b"synthetic encrypted envelope placeholder"
        );
        assert!(retained.authenticated_pin().is_none());
        assert!(!retained.accepted());
        assert!(
            prepare_input(
                &c,
                &r.account_id,
                &r.authorization_id,
                &r.terms_digest,
                &r.package_digest,
                b"changed"
            )
            .is_err()
        );
    }
    #[test]
    fn authenticated_pending_is_not_inbox_acceptance() {
        let c = database();
        let r = record();
        prepared(&c, &r);
        record_authenticated(&c, &r.account_id, &r).unwrap();
        let retained = load_input(&c, &r.account_id, &r.authorization_id).unwrap();
        assert!(retained.authenticated_pin().is_some());
        assert!(!retained.accepted());
    }
    #[test]
    fn exact_acceptance_retry_preserves_outcome_and_rejects_changed_pin() {
        let c = database();
        let mut r = record();
        prepared(&c, &r);
        record_authenticated(&c, &r.account_id, &r).unwrap();
        record_accepted(&c, &r.account_id, &r).unwrap();
        record_accepted(&c, &r.account_id, &r).unwrap();
        assert!(
            load_input(&c, &r.account_id, &r.authorization_id)
                .unwrap()
                .accepted()
        );
        r.content_digest = "e".repeat(64);
        assert!(record_accepted(&c, &r.account_id, &r).is_err());
    }
    #[test]
    fn failed_transaction_rolls_back_domain_link() {
        let mut c = database();
        let r = record();
        prepared(&c, &r);
        {
            let tx = c.transaction().unwrap();
            record_authenticated(&tx, &r.account_id, &r).unwrap();
        }
        assert!(
            load_input(&c, &r.account_id, &r.authorization_id)
                .unwrap()
                .authenticated_pin()
                .is_none()
        );
    }
    #[test]
    fn malformed_pending_history_never_passes_backup_validation() {
        let c = database();
        let r = record();
        c.execute(
            "INSERT INTO signer_offline_review_inputs VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                r.authorization_id,
                r.account_id,
                "not-a-digest",
                r.package_digest,
                envelope_digest(b"synthetic"),
                hex::encode(b"synthetic")
            ],
        )
        .unwrap();
        assert!(validate_all(&c, "synthetic-account").is_err());
    }
    #[test]
    fn pending_input_quota_and_immutable_triggers_are_enforced() {
        let c = database();
        let r = record();
        for n in 0..MAX_RETAINED_REVIEW_INPUTS {
            prepare_input(
                &c,
                &r.account_id,
                &format!("synthetic-{n}"),
                &r.terms_digest,
                &r.package_digest,
                b"synthetic",
            )
            .unwrap();
        }
        assert!(
            prepare_input(
                &c,
                &r.account_id,
                "excess",
                &r.terms_digest,
                &r.package_digest,
                b"synthetic"
            )
            .is_err()
        );
        assert!(
            c.execute("DELETE FROM signer_offline_review_inputs", [])
                .is_err()
        );
        assert!(
            c.execute(
                "UPDATE signer_offline_review_inputs SET envelope_hex='00'",
                []
            )
            .is_err()
        );
        assert!(c.execute("INSERT OR REPLACE INTO signer_offline_review_inputs SELECT * FROM signer_offline_review_inputs LIMIT 1",[]).is_err());
    }
}
