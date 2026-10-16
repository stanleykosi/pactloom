//! Actual encrypted historical replay only; the existing fixture's bootstrap is
//! synthetic. No native owner, live namespace or financial execution is created.
use super::*;
use crate::born_offline_enrollment_v1::tests::{event, record};
fn key() -> DatabaseKey {
    let mut bytes = [0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).unwrap();
    DatabaseKey::from_bytes(bytes)
}
#[test]
fn encrypted_born_offline_history_reopens_exactly_and_remote_dto_stays_denied() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp.path().join("synthetic-born-offline.wp");
    let key = key();
    let c = write_fixture(&path, &key, false);
    let (birth, _, _, _) = bootstrap_events();
    let mut ledger = load(c.connection()).unwrap();
    let r = record(&ledger, &birth);
    let e = event(&ledger, &r);
    let previous = ledger.snapshot.head.digest.clone();
    ledger.apply(&e).unwrap();
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
    tx.execute(
        "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
        params![
            ledger.snapshot.head.sequence,
            e.mutation.operation_id(),
            previous,
            ledger.snapshot.head.digest,
            encode(&e).unwrap().as_slice()
        ],
    )
    .unwrap();
    tx.commit().unwrap();
    drop(c);
    let before = tree(temp.path());
    let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(&path, &key).unwrap();
    verify_schema(snapshot.connection()).unwrap();
    let replay = load(snapshot.connection()).unwrap();
    assert!(replay.snapshot == ledger.snapshot);
    assert!(replay.born_offline_enrollment_v1().unwrap() == Some(&r));
    assert!(replay.policy == birth.request.policy);
    drop(snapshot);
    assert_eq!(tree(temp.path()), before);
    // Neither parsed evidence nor this synthetic journal handle supplies the
    // actual original namespace owner or a genuine witness-native decision.
    let journal = AuthorityJournal {
        connection: Mutex::new(wholepact_storage_security::open_encrypted(&path, &key).unwrap()),
        resolution_node: Mutex::new(None),
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        born_owner: None,
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        born_manual_scope: None,
    };
    assert!(matches!(
        journal.mutate_on_channel(
            &birth.request.policy.owner_certificate_digest,
            e.mutation,
            None,
            &[0; 32],
            &birth.request.disclosure.pinned_server_certificate_digest,
            r.enrollment.issued_at_ms + 2
        ),
        Err(AuthorityError::Permission)
    ));
    assert!(
        load(journal.connection.lock().unwrap().connection())
            .unwrap()
            .snapshot
            == ledger.snapshot
    );
}
