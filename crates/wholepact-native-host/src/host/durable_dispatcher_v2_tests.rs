//! Isolated source/storage components and maintained Host session integration.
//! No live credentials, network, native source issuer or true same-original
//! admission qualification occurs here.
use super::*;
use std::os::unix::fs::{MetadataExt,PermissionsExt};
pub(super) const PASSWORD:&[u8]=b"isolated-dispatcher-storage-password";
fn fixture()->(tempfile::TempDir,Directory,Secrets,String,String) {
    let temp=tempfile::tempdir().unwrap();
    let directory=Directory::create(&temp.path().join("host")).unwrap();
    let secrets=Secrets::fresh().unwrap().bind_successor_plan([71;32]).unwrap().bind_private_workspace_v3([72;32]).unwrap();
    let connection=wholepact_storage_security::create_encrypted(directory.path("submission.sqlite").unwrap(),&secrets.key(3).unwrap()).unwrap();
    let origin=hex::encode(connection.database_identity().unwrap().origin_commitment());
    let journal=wholepact_chain::EncryptedSubmissionJournal::from_encrypted_connection(connection).unwrap();
    let identity=journal.identity().to_owned(); drop(journal);
    (temp,directory,secrets,origin,identity)
}
fn bytes(directory:&Directory)->Vec<(String,u64,Vec<u8>)> {
    let mut result: Vec<(String,u64,Vec<u8>)>=std::fs::read_dir(directory.path("profile.lock").unwrap().parent().unwrap()).unwrap().map(|e| {
        let e=e.unwrap();(e.file_name().to_str().unwrap().into(),e.metadata().unwrap().ino(),std::fs::read(e.path()).unwrap())
    }).collect::<Vec<_>>(); result.sort_by(|a,b|a.0.cmp(&b.0));result
}
#[test]
fn v4_preserves_all_v3_slots_and_every_legacy_decoder_refuses() {
    let (_temp,_directory,secrets,_,_)=fixture();
    let original=secrets.dispatcher_test_payload().to_vec();
    let v4=secrets.bind_workspace_dispatcher_v4([73;32]).unwrap();
    assert_eq!(original.len(),273);assert_eq!(v4.dispatcher_test_payload().len(),305);
    assert_eq!(&v4.dispatcher_test_payload()[1..273],&original[1..]);
    assert_eq!(v4.private_workspace_anchor(),None);
    assert_eq!(v4.combined_workspace_anchor_v4(),Some([72;32].as_slice()));
    assert_eq!(v4.workspace_dispatcher_anchor_v4(),Some([73;32].as_slice()));
    assert_eq!(v4.generation_plan_digest(),Some([71;32].as_slice()));
    assert_eq!(&*v4.generation_seal_key().unwrap(),&original[209..241]);
    assert!(v4.require_portable_legacy().is_err());assert!(v4.recovery(PASSWORD,&[1;32]).is_err());
    let sealed=v4.seal(PASSWORD).unwrap();
    assert!(Secrets::open(&sealed,PASSWORD).is_err());
    assert!(Secrets::open_private_workspace_v3(&sealed,PASSWORD).is_err());
    let opened=Secrets::open_workspace_dispatcher_v4(&sealed,PASSWORD).unwrap();
    assert!(opened.same_recovery_material(&v4));assert!(opened.bind_workspace_dispatcher_v4([74;32]).is_err());
    assert!(Secrets::open_workspace_dispatcher_v4(&sealed,b"different-test-password").is_err());
}
#[test]
fn exact_v3_is_required_for_consuming_attachment() {
    assert!(Secrets::fresh().unwrap().bind_workspace_dispatcher_v4([1;32]).is_err());
    assert!(Secrets::fresh().unwrap().bind_successor_plan([1;32]).unwrap().bind_workspace_dispatcher_v4([2;32]).is_err());
}
#[test]
fn submission_preflight_reads_initialized_schema3_without_mutation() {
    let (_temp,directory,secrets,origin,identity)=fixture();let before=bytes(&directory);
    let proof=OriginalSubmissionPreflightV2::open(&directory,&secrets,&origin,&identity).unwrap();
    proof.check().unwrap();drop(proof);assert_eq!(before,bytes(&directory));
    assert!(OriginalSubmissionPreflightV2::open(&directory,&secrets,&"0".repeat(64),&identity).is_err());
    assert!(OriginalSubmissionPreflightV2::open(&directory,&secrets,&origin,&"1".repeat(64)).is_err());
    assert_eq!(before,bytes(&directory));
}
#[test]
fn submission_preflight_never_initializes_empty_or_migrates_legacy() {
    for version in [0,1,2] {
        let (_temp,directory,secrets,origin,identity)=fixture();
        let connection=wholepact_storage_security::open_encrypted_quiescent(directory.path("submission.sqlite").unwrap(),&secrets.key(3).unwrap()).unwrap();
        connection.connection().pragma_update(None,"user_version",version).unwrap();
        drop(connection);let before=bytes(&directory);
        assert!(OriginalSubmissionPreflightV2::open(&directory,&secrets,&origin,&identity).is_err());
        assert_eq!(before,bytes(&directory));
    }
    let temp=tempfile::tempdir().unwrap();let directory=Directory::create(&temp.path().join("host")).unwrap();
    let secrets=Secrets::fresh().unwrap();
    let connection=wholepact_storage_security::create_encrypted(directory.path("submission.sqlite").unwrap(),&secrets.key(3).unwrap()).unwrap();
    let origin=hex::encode(connection.database_identity().unwrap().origin_commitment());drop(connection);
    let before=bytes(&directory);
    assert!(OriginalSubmissionPreflightV2::open(&directory,&secrets,&origin,&"a".repeat(64)).is_err());
    assert_eq!(before,bytes(&directory));
}
#[test]
fn submission_copied_identity_and_same_inode_corruption_are_not_original() {
    let (_temp,directory,secrets,origin,identity)=fixture();
    let path=directory.path("submission.sqlite").unwrap();
    std::fs::rename(&path,directory.path("retained-original").unwrap()).unwrap();
    std::fs::copy(directory.path("retained-original").unwrap(),&path).unwrap();
    let before=bytes(&directory);
    assert!(OriginalSubmissionPreflightV2::open(&directory,&secrets,&origin,&identity).is_err());assert_eq!(before,bytes(&directory));
    std::fs::remove_file(&path).unwrap();std::fs::rename(directory.path("retained-original").unwrap(),&path).unwrap();
    let connection=wholepact_storage_security::open_encrypted_quiescent(&path,&secrets.key(3).unwrap()).unwrap();
    connection.connection().execute_batch("DROP TABLE settlement_deliveries;").unwrap();drop(connection);
    let before=bytes(&directory);
    assert!(OriginalSubmissionPreflightV2::open(&directory,&secrets,&origin,&identity).is_err());assert_eq!(before,bytes(&directory));
}
#[test]
fn fixed_role_files_keep_origins_and_never_replace_or_alias() {
    let temp=tempfile::tempdir().unwrap();let directory=Directory::create(&temp.path().join("host")).unwrap();
    let mut pending=DispatcherFileV2::stage(&directory,PENDING,b"isolated-encrypted-placeholder",MAX_PENDING).unwrap();
    let original=pending.origin().unwrap();let inode=std::fs::metadata(directory.path(pending.name()).unwrap()).unwrap().ino();
    assert!(DispatcherFileV2::open(&directory,pending.name(),COMMIT,MAX_COMMIT).is_err());
    assert!(DispatcherFileV2::open(&directory,pending.name(),PENDING,MAX_PENDING-1).is_err());
    pending.publish(&directory,MAX_PENDING).unwrap();assert_eq!(pending.origin().unwrap(),original);
    assert_eq!(std::fs::metadata(directory.path(PENDING).unwrap()).unwrap().ino(),inode);
    let mut replacement=DispatcherFileV2::stage(&directory,PENDING,b"must-not-replace",MAX_PENDING).unwrap();
    let before=bytes(&directory);assert!(replacement.publish(&directory,MAX_PENDING).is_err());assert_eq!(before,bytes(&directory));
    std::fs::set_permissions(directory.path(PENDING).unwrap(),std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(pending.check(&directory,MAX_PENDING).is_err());
}
#[test]
fn all_dispatcher_partial_names_are_early_portable_refusals() {
    for name in [PENDING,COMMIT,"staging-durable-dispatcher-","staging-durable-dispatcher-garbage","staging-durable-dispatcher-pending-v2-NOTHEX"] {
        let temp=tempfile::tempdir().unwrap();let directory=Directory::create(&temp.path().join("host")).unwrap();
        directory.write_new(name,b"preserve").unwrap();let before=bytes(&directory);
        assert!(directory.refuse_private_workspace_files().is_err());assert_eq!(before,bytes(&directory));
    }
}
#[test]
fn publication_order_is_closed_and_unrecognized_hex_is_rejected() {
    for (p,c,accepted) in [(false,false,true),(true,false,true),(true,true,true),(false,true,false)] {
        assert_eq!(require_publication_order(p,c).is_ok(),accepted);
    }
    for value in ["","0","AA","0x00","zz"] { assert!(decode_hex(value,16_384).is_err()); }
    assert!(decode_hex(&"ab".repeat(16_385),16_384).is_err());
    assert_eq!(&*decode_hex("00ab",16_384).unwrap(),&[0,171]);
}
#[test]
fn fixed_seal_domains_and_bounds_cannot_be_crossed() {
    let (_temp,_directory,secrets,_,_)=fixture();
    let sealed=crate::recovery_generation::seal_durable_dispatcher_v2(&secrets,true,b"bounded-json").unwrap();
    assert!(crate::recovery_generation::unseal_durable_dispatcher_v2(&secrets,false,&sealed).is_err());
    assert!(crate::recovery_generation::unseal_private_workspace_dependency_v1(&secrets,true,&sealed).is_err());
    assert!(crate::recovery_generation::seal_durable_dispatcher_v2(&secrets,false,&vec![0;16_385]).is_err());
    assert!(crate::recovery_generation::seal_durable_dispatcher_v2(&secrets,true,&vec![0;262_145]).is_err());
}
#[test]
fn deleting_all_attachments_cannot_downgrade_a_v4_vault() {
    let (_temp,directory,secrets,_,_)=fixture();let v4=secrets.bind_workspace_dispatcher_v4([91;32]).unwrap();
    directory.write_new("profile.vault",&v4.seal(PASSWORD).unwrap()).unwrap();let before=bytes(&directory);
    assert!(workspace::OriginalWorkspaceFilesV1::open_final(&directory,&v4).is_err());
    assert!(OriginalWorkspaceDispatcherFilesV4::open_final(&directory,&v4).is_err());
    assert!(v4.require_portable_legacy().is_err());assert_eq!(before,bytes(&directory));
}
#[test]
fn commit_json_rejects_duplicates_unknown_fields_and_incomplete_data() {
    for bytes in [
        br#"{"version":2,"version":2,"semantic_digest":"x","pending_ciphertext_sha256":"x","pending_original_file_origin":"x"}"#.as_slice(),
        br#"{"version":2,"semantic_digest":"x","pending_ciphertext_sha256":"x","pending_original_file_origin":"x","optional_extension":{}}"#.as_slice(),
        br#"{"version":2,"semantic_digest":"x"}"#.as_slice(),
    ] {assert!(wholepact_core::parse_typed_json::<Commit>(bytes).is_err());}
}
#[test]
fn submission_noncanonical_or_zero_singleton_identity_is_not_adopted() {
    for identity in ["0".repeat(64),"A".repeat(64)] {
        let (_temp,directory,secrets,origin,_)=fixture();
        let connection=wholepact_storage_security::open_encrypted_quiescent(directory.path("submission.sqlite").unwrap(),&secrets.key(3).unwrap()).unwrap();
        connection.connection().execute("UPDATE submission_journal_identity SET identity=?1",[&identity]).unwrap();drop(connection);
        let before=bytes(&directory);
        assert!(OriginalSubmissionPreflightV2::open(&directory,&secrets,&origin,&identity).is_err());assert_eq!(before,bytes(&directory));
    }
}

#[test]
fn encrypted_host_closed_source_permission_session_and_revocation_integration() {
    use std::collections::BTreeSet;
    use wholepact_engine::Access;
    use wholepact_service::security::{ClientConfig, Permission, SecurityConfig};

    const PRINCIPAL: &str = "closed-source-reader-v3";
    const OTHER_PRINCIPAL: &str = "closed-source-other-v3";
    const OPERATION: &str = "closed-source-observation-v3";

    fn config(principal: &str, permissions: &[Permission]) -> SecurityConfig {
        let config = SecurityConfig {
            clients: vec![ClientConfig {
                client_id: principal.into(),
                // Public, inert fixture only; no service or credential file is created.
                bootstrap_token: "closed-source-session-test-not-a-secret".into(),
                permissions: permissions.iter().copied().collect(),
                agreement_ids: BTreeSet::new(),
                all_agreements: false,
                include_owned_agreements: false,
            }],
            allowed_origins: BTreeSet::new(),
        };
        config.validate().unwrap();
        config
    }
    fn session(host: &mut Host, principal: &str, permissions: &[Permission]) {
        host.access = Some(Access {
            principal_id: principal.into(),
            agreement_ids: BTreeSet::new(),
            all_agreements: false,
            include_owned_agreements: false,
        });
        host.config = Some(config(principal, permissions));
    }
    fn journal_state(host: &Host) -> Vec<u8> {
        let journal = host.submission.lock().unwrap();
        let intent = journal.recover_intent_summary(OPERATION).unwrap();
        let descriptor = journal.retained_submission_descriptor(OPERATION).unwrap();
        let attempts = journal.submission_attempts(OPERATION).unwrap();
        assert!(intent.is_none() && descriptor.is_none() && attempts.is_empty());
        serde_json::to_vec(&(journal.identity(), intent, descriptor, attempts)).unwrap()
    }
    fn persisted_bytes(host: &Host) -> Vec<(String, u64, Vec<u8>)> {
        // SQLite readers may update transient SHM read marks. Preserve every
        // authoritative main DB/WAL, vault/lock and inode, plus logical rows.
        bytes(&host.directory).into_iter()
            .filter(|(name, _, _)| !name.ends_with("-shm"))
            .collect()
    }
    fn observe(host: &Host, historical_read: bool, manual_effect: bool) {
        let journal_before = journal_state(host);
        let original_bytes = persisted_bytes(host);
        for (purpose, allowed) in [
            (ClosedOriginalSourcePurposeV3::HistoricalRead, historical_read),
            (ClosedOriginalSourcePurposeV3::ManualEffect, manual_effect),
        ] {
            let result = require_closed_original_source_permission_v3(host, purpose);
            if allowed {
                result.unwrap();
            } else {
                assert!(matches!(result, Err(Error::Permission)));
            }
            assert_eq!(journal_state(host), journal_before);
            assert_eq!(persisted_bytes(host), original_bytes);
        }
    }

    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let profile = std::fs::canonicalize(temp.path()).unwrap().join("host");
    super::super::initialize(&profile, PASSWORD).unwrap();
    let directory = Directory::open(&profile).unwrap();
    assert_eq!(std::fs::metadata(&profile).unwrap().mode() & 0o777, 0o700);
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    let mut host = Host::open(directory, secrets, Terminal::disconnected_for_test()).unwrap();
    let initial_journal = journal_state(&host);
    let original_bytes = persisted_bytes(&host);
    let full = [Permission::Read, Permission::Coordinate, Permission::Disclose];

    // Exercise the actual Host, validated service configuration and Authority,
    // not a permission-set predicate or a fabricated source owner/approval.
    observe(&host, false, false);
    session(&mut host, PRINCIPAL, &full);
    observe(&host, false, false); // Configured but not enrolled with Authority.
    host.authority.enroll(PRINCIPAL).unwrap();

    session(&mut host, PRINCIPAL, &[Permission::Read]);
    observe(&host, true, false);
    for partial in [
        vec![Permission::Read, Permission::Coordinate],
        vec![Permission::Read, Permission::Disclose],
    ] {
        session(&mut host, PRINCIPAL, &partial);
        observe(&host, true, false);
    }
    session(&mut host, PRINCIPAL, &[Permission::Coordinate, Permission::Disclose]);
    observe(&host, false, false); // Manual permissions never substitute for READ.
    host.config = None;
    observe(&host, false, false);

    session(&mut host, PRINCIPAL, &full);
    host.config = Some(config(OTHER_PRINCIPAL, &full));
    observe(&host, false, false); // Access/config principal mismatch.
    session(&mut host, OTHER_PRINCIPAL, &full);
    observe(&host, false, false); // Matching config cannot replace enrolled identity.

    session(&mut host, PRINCIPAL, &full);
    observe(&host, true, true);
    host.authority.fence.revoke().unwrap();
    observe(&host, false, false); // Actual fence revocation, not a simulated flag.

    assert_eq!(journal_state(&host), initial_journal);
    assert_eq!(persisted_bytes(&host), original_bytes);
    // This establishes only the production selector's session/permission/fence
    // composition. Exact source identity and native approval are separate gates.
}
