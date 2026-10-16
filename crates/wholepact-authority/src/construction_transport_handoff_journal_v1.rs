//! All new secret, claim and old-key fence rows commit with the event under the
//! same BEGIN IMMEDIATE. Immutable old writer keys are never overwritten.
use super::*;
use crate::construction_transport_handoff_v1::*;
impl AuthorityJournal {
    fn require_construction_transport_namespace_current(&self) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            self.born_owner
                .as_ref()
                .ok_or(AuthorityError::Permission)?
                .check_mutation_current()?;
            Ok(())
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        {
            Err(AuthorityError::Permission)
        }
    }
    pub(crate) fn commit_construction_transport_grant(
        &self,
        grant: ConstructionTransportGrantV1,
        expected_owner_pin: &str,
        check_current: &dyn Fn() -> Result<()>,
    ) -> Result<PendingConstructionTransportGrantV1> {
        self.require_construction_transport_namespace_current()?;
        check_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        ensure_handoff_schema(&tx)?;
        let mut l = load(&tx)?;
        if l.policy.owner_certificate_digest != expected_owner_pin {
            return Err(AuthorityError::Permission);
        }
        // An exact retry remains uncertain; inspect the retained grant through
        // complete authenticated history.
        if l.operations.contains_key(&grant.operation_id) {
            return Err(AuthorityError::Uncertain);
        }
        let a = &grant.authorization.authorization;
        let event = Event {
            mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
                operation_id: grant.operation_id.clone(),
                account_id: a.account_id.clone(),
                network_profile_id: a.network_profile_id.clone(),
                expected_head: grant.expected_head.clone(),
                writer_epoch: a.original_session.writer_epoch,
                control: OwnerControl::GrantConstructionTransportV1 {
                    grant: Box::new(grant.clone()),
                },
            }),
            authenticated_certificate_digest: expected_owner_pin.into(),
            witness_time_ms: now_ms()?,
            writer_session_id: None,
            original_request_link: None,
        };
        let result = append_handoff_event(&tx, &mut l, &event)?;
        let MutationResult::Controlled(snapshot) = result else {
            return Err(AuthorityError::CorruptHistory);
        };
        let pending = PendingConstructionTransportGrantV1 {
            grant,
            committed_head: snapshot.head,
        };
        let a = &pending.grant.authorization.authorization;
        tx.execute(
            "INSERT INTO authority_construction_transport_grants VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                pending.digest()?,
                a.original_session.session_id,
                a.invocation_digest,
                a.read_request_digest,
                a.nonce,
                &*encode(&pending)?
            ],
        )?;
        self.require_construction_transport_namespace_current()?;
        check_current()?;
        // Complete validation includes secret/fence table cardinality before commit.
        load(&tx)?;
        tx.commit()?;
        Ok(pending)
    }
    pub(crate) fn claim_construction_transport_on_channel(
        &self,
        peer: &str,
        claim: &SignedConstructionTransportClaimV1,
        exporter: &[u8; 32],
        server_certificate: &str,
        now: u64,
    ) -> Result<ConstructionTransportCredentialV1> {
        self.require_construction_transport_namespace_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        authenticate_admission(&tx, peer)?;
        let mut l = load(&tx)?;
        if claim.claim.credential_id != credential_id(exporter)
            || claim.claim.exporter_commitment != exporter_commitment(exporter)
        {
            return Err(AuthorityError::Authentication);
        }
        let p = l.construction_transport_grant(&claim.claim.pending_grant_digest)?;
        if p.grant
            .authorization
            .authorization
            .original_session
            .disclosure
            .pinned_server_certificate_digest
            != server_certificate
        {
            return Err(AuthorityError::Authentication);
        }
        // Never turn a cached claim into another live transport owner.
        if l.operations.contains_key(&claim.claim.operation_id) {
            return Err(AuthorityError::Uncertain);
        }
        let event = Event {
            mutation: AuthorityMutation::ClaimConstructionTransportV1(Box::new(claim.clone())),
            authenticated_certificate_digest: peer.into(),
            witness_time_ms: now,
            writer_session_id: None,
            original_request_link: None,
        };
        let result = append_handoff_event(&tx, &mut l, &event)?;
        let MutationResult::ConstructionTransportClaimedV1(credential) = result else {
            return Err(AuthorityError::CorruptHistory);
        };
        tx.execute(
            "INSERT INTO authority_construction_transport_credentials VALUES(?1,?2,?3,?4)",
            params![
                credential.credential_id(),
                credential.pending_grant.digest()?,
                exporter.as_slice(),
                &*encode(&credential)?
            ],
        )?;
        tx.execute(
            "INSERT INTO authority_transport_fences VALUES(?1,?2,?3)",
            params![
                credential.authorization().original_session.session_id,
                credential.credential_id(),
                credential.old_key_fence_digest
            ],
        )?;
        self.require_construction_transport_namespace_current()?;
        l.require_construction_transport_current(credential.credential_id(), peer, now_ms()?)?;
        load(&tx)?;
        tx.commit()?;
        Ok(*credential)
    }
    pub(crate) fn observe_construction_transport_on_channel(
        &self,
        peer: &str,
        id: &str,
        proof: &ConstructionTransportProofV1,
        exporter: &[u8; 32],
        server_certificate: &str,
        now: u64,
    ) -> Result<ConstructionTransportObservationV1> {
        self.require_construction_transport_namespace_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        authenticate_admission(&tx, peer)?;
        let l = load(&tx)?;
        let credential = l.require_construction_transport_current(id, peer, now)?;
        require_same_claimed_channel(credential, exporter, server_certificate)?;
        let key = read_construction_transport_key(&tx, id)?;
        verify_observe_proof(&key, exporter, id, proof)?;
        Ok(ConstructionTransportObservationV1 {
            version: 1,
            credential: credential.clone(),
            snapshot: l.snapshot.clone(),
        })
    }
    pub(crate) fn construction_transport_mutate_on_channel(
        &self,
        peer: &str,
        request: &ConstructionTransportRequestV1,
        proof: &ConstructionTransportProofV1,
        exporter: &[u8; 32],
        server_certificate: &str,
        now: u64,
    ) -> Result<MutationResult> {
        self.require_construction_transport_namespace_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        authenticate_admission(&tx, peer)?;
        let mut l = load(&tx)?;
        let credential =
            l.require_construction_transport_current(&request.credential_id, peer, now)?;
        require_same_claimed_channel(credential, exporter, server_certificate)?;
        let key = read_construction_transport_key(&tx, &request.credential_id)?;
        verify_proof(&key, exporter, request, proof)?;
        if l.operations.contains_key(request.operation_id()) {
            return Err(AuthorityError::Uncertain);
        }
        let event = Event {
            mutation: AuthorityMutation::UseConstructionTransportV1(Box::new(request.clone())),
            authenticated_certificate_digest: peer.into(),
            witness_time_ms: now,
            writer_session_id: None,
            original_request_link: None,
        };
        let result = append_handoff_event(&tx, &mut l, &event)?;
        self.require_construction_transport_namespace_current()?;
        l.require_construction_transport_current(&request.credential_id, peer, now_ms()?)?;
        load(&tx)?;
        tx.commit()?;
        Ok(result)
    }
}
fn require_same_claimed_channel(
    c: &ConstructionTransportCredentialV1,
    exporter: &[u8; 32],
    server: &str,
) -> Result<()> {
    if c.credential_id() != credential_id(exporter)
        || c.signed_claim.claim.exporter_commitment != exporter_commitment(exporter)
        || c.authorization()
            .original_session
            .disclosure
            .pinned_server_certificate_digest
            != server
    {
        return Err(AuthorityError::Authentication);
    }
    Ok(())
}
fn append_handoff_event(
    tx: &Transaction<'_>,
    ledger: &mut Ledger,
    event: &Event,
) -> Result<MutationResult> {
    let previous = ledger.snapshot.head.digest.clone();
    let result = ledger.apply(event)?;
    let payload = encode(event)?;
    // Conservative complete-history budget preflight, before any authority effect.
    // Original full-plan bytes are counted once per existing immutable event;
    // this stricter admission may refuse a large profile, never raise old limits.
    let retained: u64 = tx.query_row(
        "SELECT coalesce(sum(length(payload)),0) FROM authority_events",
        [],
        |r| r.get(0),
    )?;
    let auxiliary:u64=tx.query_row("SELECT (SELECT coalesce(sum(length(payload)),0) FROM authority_construction_transport_grants)+(SELECT coalesce(sum(length(payload)+length(secret)),0) FROM authority_construction_transport_credentials)+(SELECT count(*)*192 FROM authority_transport_fences)",[],|r|r.get(0))?;
    if retained
        .checked_add(payload.len() as u64)
        .and_then(|n| n.checked_add(auxiliary))
        .and_then(|n| n.checked_add(MAX_CONSTRUCTION_TRANSPORT_LINEAGE_BYTES as u64))
        .is_none_or(|n| {
            n > MAX_CONSTRUCTION_TRANSPORT_HISTORY_BYTES as u64 || n > MAX_JOURNAL_BYTES
        })
    {
        return Err(AuthorityError::Limit);
    }
    bounded(
        &ledger.construction_transport_history_v1(),
        MAX_CONSTRUCTION_TRANSPORT_HISTORY_BYTES,
    )?;
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
    Ok(result)
}
fn read_construction_transport_key(c: &Connection, id: &str) -> Result<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(c.query_row(
        "SELECT secret FROM authority_construction_transport_credentials WHERE credential_id=?1",
        [id],
        |r| r.get::<_, Vec<u8>>(0),
    )?);
    Ok(Zeroizing::new(
        raw.as_slice()
            .try_into()
            .map_err(|_| AuthorityError::CorruptHistory)?,
    ))
}
pub(super) fn verify_handoff_tables(c: &Connection, l: &Ledger) -> Result<()> {
    let h = l.construction_transport_history_v1();
    h.validate_for(&l.policy, &l.snapshot)?;
    if l.sessions
        .len()
        .checked_add(h.credentials.len())
        .is_none_or(|n| n > MAX_EVENTS as usize)
    {
        return Err(AuthorityError::Limit);
    }
    let retained:u64=c.query_row("SELECT (SELECT coalesce(sum(length(payload)),0) FROM authority_events)+(SELECT coalesce(sum(length(payload)),0) FROM authority_construction_transport_grants)+(SELECT coalesce(sum(length(payload)+length(secret)),0) FROM authority_construction_transport_credentials)+(SELECT count(*)*192 FROM authority_transport_fences)",[],|r|r.get(0))?;
    if retained > MAX_JOURNAL_BYTES {
        return Err(AuthorityError::Limit);
    }

    let count: u64 = c.query_row(
        "SELECT count(*) FROM authority_construction_transport_grants",
        [],
        |r| r.get(0),
    )?;
    if count != h.grants.len() as u64 {
        return Err(AuthorityError::CorruptHistory);
    }
    for g in &h.grants {
        let row:(String,String,String,String,Vec<u8>)=c.query_row("SELECT session_id,invocation_digest,read_request_digest,nonce,payload FROM authority_construction_transport_grants WHERE grant_digest=?1",[g.digest()?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        let a = &g.grant.authorization.authorization;
        if row.0 != a.original_session.session_id
            || row.1 != a.invocation_digest
            || row.2 != a.read_request_digest
            || row.3 != a.nonce
            || decode::<PendingConstructionTransportGrantV1>(&row.4)? != *g
        {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    for table in [
        "authority_construction_transport_credentials",
        "authority_transport_fences",
    ] {
        let count: u64 = c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        if count != h.credentials.len() as u64 {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    for v in &h.credentials {
        let row:(String,Vec<u8>)=c.query_row("SELECT grant_digest,payload FROM authority_construction_transport_credentials WHERE credential_id=?1",[v.credential_id()],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let key = read_construction_transport_key(c, v.credential_id())?;
        if row.0 != v.pending_grant.digest()?
            || decode::<ConstructionTransportCredentialV1>(&row.1)? != *v
            || credential_id(&key) != v.credential_id()
            || exporter_commitment(&key) != v.signed_claim.claim.exporter_commitment
        {
            return Err(AuthorityError::CorruptHistory);
        }
        let fence: (String, String) = c.query_row(
            "SELECT credential_id,fence_digest FROM authority_transport_fences WHERE session_id=?1",
            [&v.authorization().original_session.session_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if fence.0 != v.credential_id() || fence.1 != v.old_key_fence_digest {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    Ok(())
}
pub(super) fn copy_handoff_tables(source: &Connection, destination: &Connection) -> Result<()> {
    {
        let mut q=source.prepare("SELECT grant_digest,session_id,invocation_digest,read_request_digest,nonce,payload FROM authority_construction_transport_grants")?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let payload = Zeroizing::new(r.get::<_, Vec<u8>>(5)?);
            destination.execute(
                "INSERT INTO authority_construction_transport_grants VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    &*payload
                ],
            )?;
        }
    }
    {
        let mut q=source.prepare("SELECT credential_id,grant_digest,secret,payload FROM authority_construction_transport_credentials")?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let secret = Zeroizing::new(r.get::<_, Vec<u8>>(2)?);
            let payload = Zeroizing::new(r.get::<_, Vec<u8>>(3)?);
            destination.execute(
                "INSERT INTO authority_construction_transport_credentials VALUES(?1,?2,?3,?4)",
                params![
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    &*secret,
                    &*payload
                ],
            )?;
        }
    }
    {
        let mut q = source.prepare(
            "SELECT session_id,credential_id,fence_digest FROM authority_transport_fences",
        )?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            destination.execute(
                "INSERT INTO authority_transport_fences VALUES(?1,?2,?3)",
                params![
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?
                ],
            )?;
        }
    }
    Ok(())
}

fn ensure_handoff_schema(tx: &Transaction<'_>) -> Result<()> {
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == 5 {
        verify_schema_against(tx, SCHEMA_V5)?;
        let old = load(tx)?;
        if !old.construction_transport_history_v1().is_empty() {
            return Err(AuthorityError::CorruptHistory);
        }
        tx.execute_batch(include_str!("construction_transport_handoff_schema.sql"))?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    } else if version != SCHEMA_VERSION {
        return Err(AuthorityError::UnsupportedVersion);
    }
    verify_schema_against(tx, SCHEMA)?;
    Ok(())
}

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
mod tests {
    use super::*;
    use crate::construction_transport_handoff_v1::tests::{Fixture, fixture};
    use std::os::unix::fs::PermissionsExt;
    fn insert_claim_rows(tx: &Transaction<'_>, credential: &ConstructionTransportCredentialV1) {
        tx.execute(
            "INSERT INTO authority_construction_transport_credentials VALUES(?1,?2,?3,?4)",
            params![
                credential.credential_id(),
                credential.pending_grant.digest().unwrap(),
                [0x66u8; 32].as_slice(),
                &*encode(credential).unwrap()
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO authority_transport_fences VALUES(?1,?2,?3)",
            params![
                credential.authorization().original_session.session_id,
                credential.credential_id(),
                credential.old_key_fence_digest
            ],
        )
        .unwrap();
    }
    fn seed(path: &Path, key: &DatabaseKey, f: &Fixture, through: usize) -> EncryptedConnection {
        let c = wholepact_storage_security::create_encrypted(path, key).unwrap();
        configure(c.connection()).unwrap();
        let tx =
            Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
        tx.execute_batch(SCHEMA).unwrap();
        tx.execute(
            "INSERT INTO authority_genesis VALUES(1,?1)",
            [&*encode(&f.birth.request.policy).unwrap()],
        )
        .unwrap();
        tx.execute("INSERT INTO authority_quarantine VALUES(1,0)", [])
            .unwrap();
        for peer in [
            &f.birth.request.policy.owner_certificate_digest,
            &f.birth.request.policy.initial_writer_certificate_digest,
        ] {
            tx.execute("INSERT INTO authority_principals VALUES(?1)", [peer])
                .unwrap();
        }
        tx.execute(
            "INSERT INTO authority_pending_birth_commit VALUES(1,?1,?2,?3)",
            params![
                f.birth.request.operation_id,
                f.birth.request_digest,
                serde_json::to_string(&f.birth).unwrap()
            ],
        )
        .unwrap();
        let mut l = Ledger::new(f.birth.request.policy.clone()).unwrap();
        for event in &f.events[..through] {
            let prev = l.snapshot.head.digest.clone();
            let result = l.apply(event).unwrap();
            tx.execute(
                "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
                params![
                    l.snapshot.head.sequence,
                    event.mutation.operation_id(),
                    prev,
                    l.snapshot.head.digest,
                    &*encode(event).unwrap()
                ],
            )
            .unwrap();
            match result {
                MutationResult::Controlled(_)
                    if matches!(
                        &event.mutation,
                        AuthorityMutation::OwnerControl(OwnerControlRequest {
                            control: OwnerControl::GrantConstructionTransportV1 { .. },
                            ..
                        })
                    ) =>
                {
                    let p = l.construction_transport_history_v1().grants.pop().unwrap();
                    let a = &p.grant.authorization.authorization;
                    tx.execute("INSERT INTO authority_construction_transport_grants VALUES(?1,?2,?3,?4,?5,?6)",params![p.digest().unwrap(),a.original_session.session_id,a.invocation_digest,a.read_request_digest,a.nonce,&*encode(&p).unwrap()]).unwrap();
                }
                MutationResult::ConstructionTransportClaimedV1(v) => insert_claim_rows(&tx, &v),
                _ => {}
            }
        }
        for key in [[0x33u8; 32], [0x44u8; 32], [0x55u8; 32]] {
            tx.execute(
                "INSERT INTO authority_session_keys VALUES(?1,?2)",
                params![crate::session::session_id(&key), key.as_slice()],
            )
            .unwrap();
        }
        tx.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .unwrap();
        load(&tx).unwrap();
        tx.commit().unwrap();
        c
    }
    #[test]
    fn encrypted_claim_commit_or_rollback_never_exposes_both_transports() {
        let f = fixture();
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = DatabaseKey::from_bytes([0x71; 32]);
        let path = t.path().join("synthetic-transport.wp");
        let c = seed(&path, &key, &f, 14);
        let old = crate::session::session_id(&[0x55; 32]);
        {
            let tx =
                Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
            let mut l = load(&tx).unwrap();
            let MutationResult::ConstructionTransportClaimedV1(v) =
                append_handoff_event(&tx, &mut l, &f.events[14]).unwrap()
            else {
                panic!("claim");
            };
            tx.execute(
                "INSERT INTO authority_construction_transport_credentials VALUES(?1,?2,?3,?4)",
                params![
                    v.credential_id(),
                    v.pending_grant.digest().unwrap(),
                    [0x66u8; 32].as_slice(),
                    &*encode(&v).unwrap()
                ],
            )
            .unwrap();
            assert!(load(&tx).is_err()); /* simulated loss before commit rolls everything back */
        }
        let l = load(c.connection()).unwrap();
        assert_eq!(l.snapshot.head.sequence, 14);
        assert!(read_session_key(c.connection(), &old).is_ok());
        assert!(
            read_construction_transport_key(c.connection(), &credential_id(&[0x66; 32])).is_err()
        );
        {
            let tx =
                Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
            let mut l = load(&tx).unwrap();
            let MutationResult::ConstructionTransportClaimedV1(v) =
                append_handoff_event(&tx, &mut l, &f.events[14]).unwrap()
            else {
                panic!("claim");
            };
            insert_claim_rows(&tx, &v);
            load(&tx).unwrap();
            tx.commit().unwrap();
        }
        assert!(matches!(
            read_session_key(c.connection(), &old),
            Err(AuthorityError::SessionRequired)
        ));
        assert_eq!(
            *read_session_key_retained(c.connection(), &old).unwrap(),
            [0x55; 32]
        );
        assert_eq!(
            *read_construction_transport_key(c.connection(), &credential_id(&[0x66; 32])).unwrap(),
            [0x66; 32]
        );
        drop(c);
        let reopened = wholepact_storage_security::open_encrypted(&path, &key).unwrap();
        let l = load(reopened.connection()).unwrap();
        assert_eq!(l.construction_transport_history_v1().credentials.len(), 1);
        assert!(
            l.construction_transport_history_v1()
                .reservations
                .is_empty()
        );
    }
    #[test]
    fn encrypted_handoff_tables_are_immutable_and_backup_copies_all_secrets_and_fences() {
        let f = fixture();
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = DatabaseKey::from_bytes([0x72; 32]);
        let c = seed(&t.path().join("source.wp"), &key, &f, f.events.len());
        for sql in [
            "UPDATE authority_transport_fences SET fence_digest=fence_digest",
            "DELETE FROM authority_transport_fences",
            "INSERT OR REPLACE INTO authority_transport_fences SELECT * FROM authority_transport_fences",
            "UPDATE authority_construction_transport_credentials SET secret=secret",
            "DELETE FROM authority_construction_transport_credentials",
            "INSERT OR REPLACE INTO authority_construction_transport_credentials SELECT * FROM authority_construction_transport_credentials",
            "UPDATE authority_construction_transport_grants SET nonce=nonce",
            "DELETE FROM authority_construction_transport_grants",
            "INSERT OR REPLACE INTO authority_construction_transport_grants SELECT * FROM authority_construction_transport_grants",
        ] {
            assert!(c.connection().execute_batch(sql).is_err());
        }
        let backup =
            wholepact_storage_security::create_encrypted(t.path().join("backup.wp"), &key).unwrap();
        let tx = Transaction::new_unchecked(backup.connection(), TransactionBehavior::Immediate)
            .unwrap();
        tx.execute_batch(SCHEMA).unwrap();
        copy_handoff_tables(c.connection(), &tx).unwrap();
        for table in [
            "authority_construction_transport_grants",
            "authority_construction_transport_credentials",
            "authority_transport_fences",
        ] {
            let source: u64 = c
                .connection()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            let copied: u64 = tx
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(source, copied);
        }
        let restored = read_construction_transport_key(&tx, &credential_id(&[0x66; 32])).unwrap();
        assert_eq!(*restored, [0x66; 32]);
        tx.commit().unwrap();
        let source = load(c.connection()).unwrap();
        assert_eq!(source.snapshot.outstanding_debit_zatoshis, 400_012_000);
        assert_eq!(
            source
                .construction_transport_history_v1()
                .consumptions
                .len(),
            1
        );
    }
    #[test]
    fn complete_fenced_historical_replay_never_returns_active_writer_authority() {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("never-funded-read-only-history.wp");
        let key = DatabaseKey::from_bytes([0x72; 32]);
        let connection = seed(&path, &key, &f, f.events.len());
        let disclosure = &f.birth.request.disclosure;
        // Private test harness around the maintained encrypted read kernel.
        // A born journal cannot use the ordinary opener; no namespace owner,
        // manual scope or active writer capability is fabricated here.
        let journal = AuthorityJournal {
            connection: Mutex::new(connection),
            resolution_node: Mutex::new(None),
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            born_owner: None,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            born_manual_scope: None,
        };
        let peer = &f.birth.request.policy.initial_writer_certificate_digest;
        let before = journal
            .snapshot(peer, &disclosure.account_id, &disclosure.network_profile_id)
            .unwrap();
        let history =
            crate::transport::synthetic::reconciled_history(&journal, peer, disclosure).unwrap();
        let complete = history.construction_history_with_transport_v1().unwrap();
        complete.validate().unwrap();
        assert!(!complete.transport.credentials.is_empty());
        assert!(!complete.transport.reservations.is_empty());
        assert!(complete.retained_debit_zatoshis().unwrap() > 0);
        assert!(history.snapshot() == &before);
        assert!(
            crate::transport::synthetic::reconciled_session(
                &journal,
                peer,
                &disclosure.account_id,
                &disclosure.network_profile_id
            )
            .is_err()
        );
        let mut changed = disclosure.clone();
        changed.pinned_server_certificate_digest = "ef".repeat(32);
        assert!(crate::transport::synthetic::reconciled_history(&journal, peer, &changed).is_err());
        assert!(
            journal
                .snapshot(peer, &disclosure.account_id, &disclosure.network_profile_id)
                .unwrap()
                == before
        );
    }
}
