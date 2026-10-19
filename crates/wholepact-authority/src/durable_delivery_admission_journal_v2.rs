//! Private purpose-bound append kernels. Neither method accepts a caller bool,
//! generic mutation closure, raw scope descriptor or historical replay as authority.
use super::*;
use crate::durable_delivery_admission_owner_v2::{NativeDurableDeliveryAdmissionSourceV2};

impl AuthorityJournal {
    pub(crate) fn commit_native_durable_delivery_admission_v2(
        &self,
        source: &mut NativeDurableDeliveryAdmissionSourceV2,
        peer: &str,
        request: OwnerControlRequest,
    ) -> Result<MutationResult> {
        #[cfg(feature = "synthetic-qualification")]
        let observer = source.admission_observer().cloned();
        let result = (|| {
            crate::transport::admission_stage!(observer.as_ref(), JournalPreflight);
            source.check_open()?;
            let c = self
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
            authenticate_admission(&tx, peer)?;
            let mut ledger = load(&tx)?;
            let now = now_ms()?;
            crate::transport::admission_stage!(observer.as_ref(), ExactRequest);
            source.require_exact_locked(self, &ledger, peer, &request, now)?;
            let event = Event {
                mutation: AuthorityMutation::OwnerControl(request.clone()),
                authenticated_certificate_digest: peer.into(),
                witness_time_ms: now,
                writer_session_id: None,
                original_request_link: None,
            };
            ledger.authenticate_mutation(&event)?;
            if ledger.replay(&event)?.is_some() {
                return Err(AuthorityError::Uncertain);
            }
            // Correct lock order: journal lock and BEGIN IMMEDIATE + complete exact
            // preflight precede OPEN -> PUBLISHING. Never hold publication during TLS.
            crate::transport::admission_stage!(observer.as_ref(), Publication);
            let publication = crate::transport::admission_measure!(
                observer.as_ref(),
                Publication,
                source.take_publication_after_lock()
            )?;
            publication.check_current()?;
            let previous = ledger.snapshot.head.digest.clone();
            crate::transport::admission_stage!(observer.as_ref(), Apply);
            let result = ledger.apply(&event)?;
            crate::transport::admission_stage!(observer.as_ref(), Append);
            crate::transport::admission_measure!(
                observer.as_ref(),
                Append,
                append_exact(&tx, &ledger, &event, &previous)
            )?;
            crate::transport::admission_stage!(observer.as_ref(), FinalCurrent);
            self.born_owner
                .as_ref()
                .ok_or(AuthorityError::Permission)?
                .check_mutation_current()?;
            publication.check_current()?;
            let final_now = now_ms()?;
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control
            else {
                return Err(AuthorityError::Permission);
            };
            if final_now < now || record.require_live(final_now).is_err() {
                return Err(AuthorityError::Expired);
            }
            crate::transport::admission_stage!(observer.as_ref(), Commit);
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = &observer {
                observer.commit_entered();
            }
            let committed =
                crate::transport::admission_measure!(observer.as_ref(), Commit, tx.commit());
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = &observer {
                observer.commit_returned(&committed);
            }
            committed.map_err(|_| AuthorityError::Uncertain)?;
            crate::transport::admission_stage!(observer.as_ref(), ControlledResult);
            let MutationResult::Controlled(snapshot) = &result else {
                #[cfg(feature = "synthetic-qualification")]
                if let Some(observer) = &observer {
                    observer.controlled_result(false);
                }
                return Err(AuthorityError::CorruptHistory);
            };
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = &observer {
                observer.controlled_result(true);
            }
            crate::transport::admission_stage!(observer.as_ref(), SnapshotRecord);
            source.record_committed(snapshot.clone());
            Ok(result)
        })();
        crate::transport::admission_result!(observer.as_ref(), observe_semantic, result)
    }
}
fn append_exact(
    tx: &Transaction<'_>,
    ledger: &Ledger,
    event: &Event,
    previous: &str,
) -> Result<()> {
    let payload = encode(event)?;
    let bytes: u64 = tx.query_row(
        "SELECT coalesce(sum(length(payload)),0) FROM authority_events",
        [],
        |r| r.get(0),
    )?;
    if bytes
        .checked_add(payload.len() as u64)
        .filter(|v| *v <= MAX_JOURNAL_BYTES)
        .is_none()
    {
        return Err(AuthorityError::Limit);
    }
    tx.execute(
        "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
        params![
            ledger.snapshot.head.sequence,
            event.mutation.operation_id(),
            previous,
            ledger.snapshot.head.digest,
            &*payload
        ],
    )?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static OPERATIONAL_KEY_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(super) fn observe_operational_key_read_for_test() {
    OPERATIONAL_KEY_READS.with(|count| count.set(count.get() + 1));
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_delivery_admission_v2::{
        prepare_durable_delivery_admission_request_v2, tests::request_fixture,
    };
    use crate::durable_payment_v1::tests::{history, owner_event};
    use std::os::unix::fs::PermissionsExt;

    /// Installs inert recorded-history bytes in a never-funded encrypted test
    /// journal. This is NOT a native issuer or positive native qualification.
    fn recorded_journal(path: &Path) -> (AuthorityJournal, Vec<Event>, Vec<u8>) {
        let (birth, old, _, request) = request_fixture();
        let extension = old
            .manual_roster_extension()
            .unwrap()
            .unwrap()
            .extension
            .clone();
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = request.control else {
            panic!()
        };
        let key = [0x73; 32];
        let mut ledger = Ledger::new(birth.request.policy.clone()).unwrap();
        let first = crate::manual_roster_witness_v2::tests::extension_event(&ledger, &extension);
        ledger.apply(&first).unwrap();
        let mut events = vec![first];
        crate::manual_roster_witness_v2::tests::bootstrap(
            &birth,
            &extension,
            &mut ledger,
            &mut events,
            5_000,
            crate::session::session_id(&key),
        );
        let request =
            prepare_durable_delivery_admission_request_v2(record.scope, &history(&birth, &events))
                .unwrap();
        events.push(owner_event(&ledger, request, 128_000));
        let connection = wholepact_storage_security::create_encrypted(
            path,
            &DatabaseKey::from_bytes([0x74; 32]),
        )
        .unwrap();
        configure(connection.connection()).unwrap();
        let tx =
            Transaction::new_unchecked(connection.connection(), TransactionBehavior::Immediate)
                .unwrap();
        tx.execute_batch(SCHEMA).unwrap();
        tx.execute(
            "INSERT INTO authority_genesis VALUES(1,?1)",
            [&*encode(&birth.request.policy).unwrap()],
        )
        .unwrap();
        tx.execute("INSERT INTO authority_quarantine VALUES(1,0)", [])
            .unwrap();
        for peer in [
            &birth.request.policy.owner_certificate_digest,
            &birth.request.policy.initial_writer_certificate_digest,
        ] {
            tx.execute("INSERT INTO authority_principals VALUES(?1)", [peer])
                .unwrap();
        }
        tx.execute(
            "INSERT INTO authority_pending_birth_commit VALUES(1,?1,?2,?3)",
            params![
                birth.request.operation_id,
                birth.request_digest,
                serde_json::to_string(&birth).unwrap()
            ],
        )
        .unwrap();
        let mut replay = Ledger::new(birth.request.policy).unwrap();
        for event in &events {
            let previous = replay.snapshot.head.digest.clone();
            replay.apply(event).unwrap();
            append_exact(&tx, &replay, event, &previous).unwrap();
        }
        tx.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .unwrap();
        // The complete inert history is not valid before its ORIGINAL key is
        // first retained. Never remove a retained key or bypass its trigger.
        assert!(matches!(load(&tx), Err(AuthorityError::CorruptHistory)));
        tx.execute(
            "INSERT INTO authority_session_keys VALUES(?1,?2)",
            params![crate::session::session_id(&key), key.as_slice()],
        )
        .unwrap();
        load(&tx).unwrap();
        tx.commit().unwrap();
        (
            AuthorityJournal {
                connection: Mutex::new(connection),
                resolution_node: Mutex::new(None),
                born_owner: None,
                born_manual_scope: None,
            },
            events,
            key.to_vec(),
        )
    }
    #[test]
    fn v2_encrypted_live_bootstrap_denial_precedes_operational_key_and_mac() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (journal, events, key) = recorded_journal(&directory.path().join("never-funded-v2.db"));
        OPERATIONAL_KEY_READS.with(|count| count.set(0));
        let AuthorityMutation::AcquireWriter(acquire) = &events[1].mutation else {
            panic!()
        };
        for event in &events[..4] {
            let fake = protocol::WriterSessionProof {
                session_id: acquire.session_id.clone(),
                tag: "0".repeat(64),
            };
            for result in [
                journal.mutate_inner_timed(
                    &event.authenticated_certificate_digest,
                    event.mutation.clone(),
                    Some(fake),
                    &[0; 32],
                    &"0".repeat(64),
                    128_001,
                    None,
                    false,
                    None,
                ),
                journal.mutate(
                    &event.authenticated_certificate_digest,
                    event.mutation.clone(),
                    128_001,
                ),
            ] {
                assert!(matches!(
                    result,
                    Err(AuthorityError::PolicyDenied) | Err(AuthorityError::Permission)
                ));
            }
        }
        assert!(matches!(
            journal.synthetic_activate(&events[1].authenticated_certificate_digest, 128_001),
            Err(AuthorityError::PolicyDenied)
        ));
        assert_eq!(OPERATIONAL_KEY_READS.with(|count| count.get()), 0);
        let c = journal.connection.lock().unwrap();
        let ledger = load(c.connection()).unwrap();
        assert_eq!(ledger.operations.len(), 5);
        assert_eq!(ledger.sessions.len(), 1);
        assert_eq!(
            read_session_key_retained(c.connection(), &acquire.session_id)
                .unwrap()
                .as_slice(),
            key.as_slice()
        );
        let retained: Vec<Vec<u8>> = c
            .connection()
            .prepare("SELECT payload FROM authority_events ORDER BY sequence")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert!(
            retained
                .iter()
                .zip(&events)
                .all(|(bytes, event)| *bytes == *encode(event).unwrap())
        );
    }
    #[test]
    fn v2_bootstrap_keys_remain_mandatory_for_complete_history_integrity() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (journal, events, key) = recorded_journal(&directory.path().join("never-funded-v2.db"));
        let AuthorityMutation::AcquireWriter(acquire) = &events[1].mutation else {
            panic!()
        };
        let c = journal.connection.lock().unwrap();
        let original_head = load(c.connection()).unwrap().snapshot.head;
        let tx =
            Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
        assert!(matches!(
            tx.execute("DELETE FROM authority_session_keys", []),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.extended_code == 1811
        ));
        assert_eq!(load(&tx).unwrap().snapshot.head, original_head);
        assert_eq!(
            read_session_key_retained(&tx, &acquire.session_id).unwrap().as_slice(),
            key.as_slice()
        );
        tx.rollback().unwrap();
        assert_eq!(load(c.connection()).unwrap().snapshot.head, original_head);
    }
    #[test]
    fn v2_serialized_admission_never_crosses_generic_append_routes() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (journal, events, _) = recorded_journal(&directory.path().join("never-funded-v2.db"));
        let event = events.last().unwrap();
        for result in [
            journal.mutate_on_channel(
                &event.authenticated_certificate_digest,
                event.mutation.clone(),
                None,
                &[0; 32],
                &"0".repeat(64),
                128_001,
            ),
            journal.mutate(
                &event.authenticated_certificate_digest,
                event.mutation.clone(),
                128_001,
            ),
        ] {
            assert!(matches!(result, Err(AuthorityError::Permission)));
        }
        let c = journal.connection.lock().unwrap();
        assert_eq!(load(c.connection()).unwrap().operations.len(), 5);
    }
}
