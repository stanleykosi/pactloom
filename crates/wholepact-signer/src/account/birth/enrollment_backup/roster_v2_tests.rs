//! Synthetic encrypted data fixtures only. No NativeDecision, current witness,
//! session capability, live credential, socket, proof, or transaction is created.
use super::*;
use crate::account::birth::acknowledgement::RetainedBornAccountOrigin;
use crate::consent_journal::TransportIdentityBinding;
use std::{fs, os::unix::fs::MetadataExt};
use wholepact_authority::{
    AccountSnapshot, AuthorityHead, WriterSessionReceipt, pending_birth::PendingBirthRequest,
};
use wholepact_core::manual_enrollment::{
    BornManualEnrollmentTerms, BornManualScope, BornManualSignerBinding, ManualAccountIdentity,
    ManualHostGenerationBinding,
};
use wholepact_core::manual_roster_v2::{HostRosterAppendBindingV2, HostRosterPredecessorV2};

#[path = "roster_v2_ephemeral_fixture.rs"]
mod ephemeral_fixture;
const PASSWORD: &[u8] = b"synthetic-only-roster-archive-password";
const JOURNAL_KEY: [u8; 32] = [0x65; 32];
fn h(c: char) -> String {
    c.to_string().repeat(64)
}

struct Fixture {
    connection: Option<rusqlite::Connection>,
    account: Arc<AccountVault>,
    record: BornManualRosterEnrollmentRecordV2,
    owner: ephemeral_fixture::Owner,
    _temporary: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        Self::with_retention_policy(false)
    }
    fn with_retention_policy(retention_policy: bool) -> Self {
        let owner = ephemeral_fixture::Owner::new();
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("synthetic-source");
        let directory = PrivateDirectory::create(&root).unwrap();
        let account = crate::account::birth::tests::data_account();
        let mut anchor = crate::account::birth::tests::data_anchor(&account);
        anchor.intent.original_target = root.to_str().unwrap().into();
        anchor.intent.original_policy_terms.owner_certificate_digest =
            hex::encode(Sha256::digest(&owner.certificate_der));
        if retention_policy {
            let t = &anchor.intent.original_policy_terms;
            let policy: wholepact_core::born_recipient_policy_v2::BornConstructionRecipientPolicyV2 =
                serde_json::from_value(serde_json::json!({
                    "version":2,"account_id":t.account_id,"network_profile_id":t.network_profile_id,
                    "agreement_id":"synthetic-agreement","obligation_id":"synthetic-obligation",
                    "participant_id":"synthetic-participant",
                    "recipients":[{"recipient_id":"synthetic-recipient","address":"uSyntheticRecipient",
                        "memo":null,"instruction_provenance":"synthetic fixture","maximum_amount_zatoshis":80}],
                    "charges":[],"own_return_rule":"authenticated_same_account",
                    "original_limits":{"aggregate_budget_zatoshis":t.aggregate_budget_zatoshis,
                        "per_operation_limit_zatoshis":t.per_operation_limit_zatoshis,
                        "maximum_fee_share_zatoshis":t.maximum_fee_share_zatoshis,
                        "maximum_transaction_fee_zatoshis":t.maximum_transaction_fee_zatoshis,
                        "maximum_permit_lifetime_ms":t.maximum_permit_lifetime_ms,
                        "policy_expires_at_ms":t.policy_expires_at_ms}
                })).unwrap();
            anchor
                .intent
                .original_policy_terms
                .recipient_scope_digests
                .push(policy.digest().unwrap());
            anchor.intent.version = 2;
            anchor.recipient_policy_v2 = Some(policy);
        }
        anchor.intent.original_policy_terms_digest =
            anchor.intent.original_policy_terms.digest().unwrap();
        anchor.birth_digest = anchor.versioned_digest().unwrap();
        let mut policy: AccountPolicy = serde_json::from_value(
            serde_json::to_value(&anchor.intent.original_policy_terms).unwrap(),
        )
        .unwrap();
        let genesis = anchor.expected_account_use_genesis().unwrap();
        policy.account_use_genesis = Some(genesis.clone());
        let (_, disclosure) = anchor.audit_policy_match(&policy).unwrap();
        let request = PendingBirthRequest {
            version: 1,
            operation_id: anchor.operation_id().into(),
            generation_instance_id: anchor.generation_instance_id().into(),
            native_birth_digest: anchor.birth_digest().into(),
            original_terms_digest: anchor.original_policy_terms_digest().into(),
            original_target_digest: canonical(
                "wholepact:pending-birth-target:v1",
                &anchor.intent.original_target,
            )
            .unwrap(),
            disclosure: disclosure.clone(),
            policy: policy.clone(),
            issued_at_ms: 1000,
            initial_commit_deadline_ms: 2000,
        };
        let checkpoint = serde_json::json!({"genesis_digest":genesis.digest().unwrap(),"history_digest":h('a'),"permanent_exclusion_digest":null});
        let origin: RetainedBornAccountOrigin = serde_json::from_value(serde_json::json!({
            "anchor":anchor,
            "witness_commit":{"version":1,"request":request,"request_digest":request.digest().unwrap(),
                "authenticated_owner_certificate_digest":policy.owner_certificate_digest,
                "owner_approval_evidence_digest":h('b'),"local_target_digest":h('c'),
                "local_owner_review_digest":h('d'),"committed_at_ms":1500},
            "observed_checkpoint":checkpoint,"permanent_exclusion":null,
            "observed_snapshot":{"account_use_checkpoint":checkpoint,"witness_id":policy.witness_id,
                "account_id":policy.account_id,"network_profile_id":policy.network_profile_id,"policy_digest":disclosure.policy_digest,
                "head":{"sequence":0,"digest":h('e')},"writer_epoch":1,
                "writer_certificate_digest":policy.initial_writer_certificate_digest,"writer_status":"active",
                "outstanding_reservations":1,"outstanding_debit_zatoshis":40,"settled_debit_zatoshis":60,
                "aggregate_budget_zatoshis":100,"reserved_input_value_zatoshis":45,"last_witness_time_ms":1500,
                "pending_writer_session":null,"active_writer_session":null}
        })).unwrap();
        origin.validate_at_rest(&account).unwrap();
        let encoded = serde_json::to_vec(&origin).unwrap();
        let mut plain = Zeroizing::new(vec![origin.anchor().envelope_version()]);
        plain.extend([0x66; 32]);
        plain.extend((encoded.len() as u32).to_le_bytes());
        plain.extend(encoded);
        plain.extend(account.encode().iter());
        let envelope = vault::password_envelope(b"WPACB002", PASSWORD, &plain).unwrap();
        let (_, key, _) =
            vault::open_password_envelope(b"WPACB002", PASSWORD, &envelope, 512 * 1024).unwrap();
        let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
        domain.extend(origin.anchor().birth_digest().as_bytes());
        let request_bytes =
            vault::encrypt(&key, &domain, &serde_json::to_vec(&request).unwrap()).unwrap();
        directory.write("account.wp", &envelope).unwrap();
        directory
            .write("birth-owner-request.wp", &request_bytes)
            .unwrap();
        let process = TransportIdentityBinding::LocalProcess {
            transport_identity_id: "synthetic-pair".into(),
            channel_key_digest: h('1'),
            channel_binding_digest: h('2'),
            uid: 12345,
            pid: 42,
            process_instance: "synthetic-instance".into(),
            signer_generation: 1,
            account_id: account.account_id().unwrap(),
            agreement_id: "synthetic-agreement".into(),
            participant_id: "synthetic-participant".into(),
            manifest_digest: h('3'),
        };
        let terms = BornManualEnrollmentTerms {
            version: 1,
            operation_id: "synthetic-roster-enrollment".into(),
            identity: ManualAccountIdentity {
                account_id: genesis.identity.account_id.clone(),
                full_viewing_key_digest: genesis.identity.full_viewing_key_digest.clone(),
                network_profile_id: genesis.identity.network_profile_id.clone(),
                derivation_domain: genesis.identity.derivation_domain.clone(),
            },
            birth_request_digest: request.digest().unwrap(),
            birth_commit_digest:
                wholepact_authority::manual_enrollment::original_birth_commit_digest(
                    origin.witness_commit(),
                )
                .unwrap(),
            native_birth_digest: origin.anchor().birth_digest().into(),
            original_policy_digest: disclosure.policy_digest.clone(),
            account_use_genesis_digest: genesis.digest().unwrap(),
            original_witness_origin_digest: genesis.witness_origin_digest.clone(),
            host: ManualHostGenerationBinding {
                generation_id: h('4'),
                inventory_digest: h('5'),
                generation_plan_digest: h('6'),
                financial_journal_origin_digest: h('7'),
                store_destination_identity: "synthetic-store".into(),
                profile_id: "synthetic-profile".into(),
                canonical_root: "/synthetic/host".into(),
                destination_identity_digest: h('8'),
                inherited_identity_digest: h('9'),
                scope_predecessor_digest: None,
            },
            signer: BornManualSignerBinding {
                enrollment_generation_id: h('a'),
                signer_target_digest: canonical("wholepact:born-manual-signer-target:v1", &root)
                    .unwrap(),
                original_envelope_digest: hex::encode(Sha256::digest(&envelope)),
                owner_certificate_digest: policy.owner_certificate_digest.clone(),
                writer_certificate_digest: policy.initial_writer_certificate_digest.clone(),
                writer_epoch: 1,
                native_signer_measurement: h('b'),
            },
            scope: BornManualScope {
                agreement_id: "synthetic-agreement".into(),
                obligation_id: "synthetic-obligation".into(),
                participant_id: "synthetic-participant".into(),
                principal_id: "synthetic-principal".into(),
                privacy_domain: account.privacy_domain().into(),
                recipient_scope_digests: policy.recipient_scope_digests.clone(),
                aggregate_budget_zatoshis: 100,
                per_operation_limit_zatoshis: 90,
                maximum_fee_share_zatoshis: 5,
                maximum_transaction_fee_zatoshis: 10,
                maximum_permit_lifetime_ms: 60_000,
                expires_at_ms: 1_800_000_000_000,
            },
            transport_binding_digest: canonical("wholepact:born-manual-transport:v1", &process)
                .unwrap(),
            issued_at_ms: 3000,
        };
        let principal = "synthetic-reviewer".to_owned();
        let inner = BornManualEnrollmentRecord {
            terms_digest: terms.terms_digest().unwrap(),
            signer_native_review_digest: canonical(
                "wholepact:native-born-manual-enrollment-review:v1",
                &(&terms, &genesis, &process, &principal),
            )
            .unwrap(),
            terms,
            genesis,
            first_process_binding: process.clone(),
            first_native_principal: principal.clone(),
        };
        let roster = HostRosterAppendBindingV2 {
            version: 2,
            generation_id: inner.terms.host.generation_id.clone(),
            store_destination_identity: inner.terms.host.store_destination_identity.clone(),
            roster_sequence: 2,
            predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: h('c'),
            },
        };
        let record = BornManualRosterEnrollmentRecordV2 {
            version: 2,
            signer_roster_native_review_digest: canonical(
                "wholepact:native-born-manual-roster-enrollment-review:v2",
                &(&inner, &roster),
            )
            .unwrap(),
            account_record: inner,
            roster,
        };
        record.validate().unwrap();
        let mut plain = Zeroizing::new(vec![2]);
        plain.extend(JOURNAL_KEY);
        plain.extend(serde_json::to_vec(&record).unwrap());
        let mut domain = b"wholepact:born-manual-roster-enrollment-intent:v2\0".to_vec();
        domain.extend(origin.anchor().birth_digest().as_bytes());
        let intent = vault::encrypt(&key, &domain, &plain).unwrap();
        directory.write(INTENT, &intent).unwrap();
        let intent_digest = hex::encode(Sha256::digest(&intent));
        let measurement = h('d');
        let extension = record.extension().unwrap();
        let marker = serde_json::json!({
            "version":2,"enrollment_ref":record.account_record.reference().unwrap(),"intent_digest":intent_digest,
            "extension_digest":extension.digest().unwrap(),"acquire_operation_id":extension.acquire_operation_id().unwrap(),
            "reentry_review_digest":canonical("wholepact:native-born-manual-roster-preacquire-reentry:v2",&(&record,&intent_digest,&process,&principal,&measurement)).unwrap(),
            "acquire_review_digest":h('e'),"current_process":process,"native_principal":principal,"native_measurement":measurement,
        });
        let mut domain = b"wholepact:born-manual-roster-first-acquire-attempt:v2\0".to_vec();
        domain.extend(record.reference().unwrap().as_bytes());
        directory
            .write(
                ACQUIRE,
                &vault::encrypt(&key, &domain, &serde_json::to_vec(&marker).unwrap()).unwrap(),
            )
            .unwrap();
        let account = Arc::new(
            active::open_for_manual_roster_enrollment_v2(directory, PASSWORD, &envelope).unwrap(),
        );
        Self {
            connection: None,
            account,
            record,
            owner,
            _temporary: temporary,
        }
    }
    fn journal(&mut self, initialized: bool) {
        let mut c = wholepact_storage_security::create_encrypted(
            self.account.directory.root().join(JOURNAL),
            &DatabaseKey::from_bytes(JOURNAL_KEY),
        )
        .unwrap()
        .into_connection();
        if initialized {
            c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA max_page_count=32768;").unwrap();
            let tx = c.transaction().unwrap();
            tx.execute_batch(include_str!("../../../consent_journal/schema.sql"))
                .unwrap();
            let r = &self.record.account_record;
            tx.execute(
                "INSERT INTO signer_account VALUES(1,?1,?2,0)",
                rusqlite::params![r.genesis.identity.account_id, r.terms.signer.writer_epoch],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
                rusqlite::params![
                    r.genesis.identity.account_id,
                    r.genesis.identity.full_viewing_key_digest,
                    r.genesis.digest().unwrap(),
                    serde_json::to_string(&r.genesis).unwrap()
                ],
            )
            .unwrap();
            tx.pragma_update(None, "application_id", 0x57505343i64)
                .unwrap();
            tx.pragma_update(None, "user_version", 15).unwrap();
            tx.commit().unwrap();
        }
        self.connection = Some(c);
    }
    fn origin(&self) -> RetainedBornAccountOrigin {
        active::backup_origin(
            &self.account.encryption_key,
            &self
                .account
                .directory
                .read("account.wp", 512 * 1024)
                .unwrap(),
            &self
                .account
                .directory
                .read("birth-owner-request.wp", 128 * 1024)
                .unwrap(),
        )
        .unwrap()
    }
    fn snapshot(&self) -> AccountSnapshot {
        serde_json::from_value(
            serde_json::to_value(self.origin()).unwrap()["observed_snapshot"].clone(),
        )
        .unwrap()
    }
    fn admission(
        &self,
        continuation: Option<&ManualRosterSessionContinuationV2>,
    ) -> BornManualRosterAdmissionRecordV2 {
        use wholepact_authority::manual_roster_witness_v2::{
            BornManualRosterAdmissionRequestV2, initial_manual_roster_attempt_digest_v2,
        };
        let e = self.record.extension().unwrap();
        let mut snapshot = self.snapshot();
        let head = AuthorityHead {
            sequence: 3,
            digest: h('1'),
        };
        let session = WriterSessionReceipt {
            session_id: h('2'),
            writer_certificate_digest: self
                .record
                .account_record
                .terms
                .signer
                .writer_certificate_digest
                .clone(),
            writer_epoch: 1,
            reconciled_head: head.clone(),
            reconciled_history_digest: h('3'),
            acquired_head: head.clone(),
            expires_at_ms: 200_000,
            acquired_at_ms: 5000,
            disclosure: self.origin().original_request().disclosure.clone(),
        };
        snapshot.head = AuthorityHead {
            sequence: 4,
            digest: h('4'),
        };
        snapshot.last_witness_time_ms = 6000;
        snapshot.active_writer_session = Some(session.clone());
        let (operation_id, attempt_digest, attempt_sequence) = match continuation {
            None => (
                e.admission_operation_id().unwrap(),
                initial_manual_roster_attempt_digest_v2(&e).unwrap(),
                1,
            ),
            Some(c) => (
                c.admission_operation_id(&e).unwrap(),
                c.digest_for(&e).unwrap(),
                c.sequence(),
            ),
        };
        let result = BornManualRosterAdmissionRecordV2 {
            request: BornManualRosterAdmissionRequestV2 {
                version: 2,
                operation_id,
                account_id: snapshot.account_id.clone(),
                network_profile_id: snapshot.network_profile_id.clone(),
                extension_digest: e.digest().unwrap(),
                enrollment_ref: self.record.account_record.reference().unwrap(),
                writer_epoch: 1,
                expected_head: head,
                session_id: session.session_id.clone(),
                attempt_digest,
                attempt_sequence,
            },
            snapshot,
            session,
            admitted_at_ms: 6000,
            publication_expires_at_ms: 126_000,
        };
        result.validate_for(&e, continuation).unwrap();
        result
    }
    fn commit(&self, c: Option<ManualRosterSessionContinuationV2>) {
        let commit = HistoricalCommit {
            version: 2,
            signer_roster_record_digest: self.record.reference().unwrap(),
            intent_digest: hex::encode(Sha256::digest(
                self.account.directory.read(INTENT, MAX_INTENT).unwrap(),
            )),
            extension: self.record.extension().unwrap(),
            original_admission: self.admission(c.as_ref()),
            original_continuation: c,
        };
        let mut domain = b"wholepact:born-manual-roster-enrollment-commit:v2\0".to_vec();
        domain.extend(self.record.reference().unwrap().as_bytes());
        self.account
            .directory
            .write(
                COMMIT,
                &vault::encrypt(
                    &self.account.encryption_key,
                    &domain,
                    &serde_json::to_vec(&commit).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
}
impl Fixture {
    fn continuation(
        &self,
        index: u16,
        previous: Option<String>,
        complete: bool,
    ) -> continuation::ContinuationProposal {
        use wholepact_authority::manual_roster_continuation_signature_v2::{
            ManualRosterContinuationOwnerSignatureV2,
            manual_roster_continuation_owner_signing_bytes_v2,
        };
        let extension = self.record.extension().unwrap();
        let process = self.record.account_record.first_process_binding.clone();
        let mut p=continuation::ContinuationProposal {
            version:2,local_index:index,previous_local_digest:previous,
            enrollment_ref:self.record.account_record.reference().unwrap(),
            intent_digest:hex::encode(Sha256::digest(self.account.directory.read(INTENT,MAX_INTENT).unwrap())),
            first_marker_digest:hex::encode(Sha256::digest(self.account.directory.read(ACQUIRE,MAX_INTENT).unwrap())),
            continuation:ManualRosterSessionContinuationV2 {
                version:2,roster_extension_digest:extension.digest().unwrap(),
                continuation:wholepact_authority::manual_session_continuation::ManualEnrollmentSessionContinuation {
                    version:1,extension_digest:extension.account_extension.digest().unwrap(),sequence:2,
                    previous_attempt_digest:wholepact_authority::manual_roster_witness_v2::initial_manual_roster_attempt_digest_v2(&extension).unwrap(),
                    expected_snapshot:self.snapshot(),expected_previous_admission_digest:None,attempt_nonce:format!("{index:064x}"),
                    fresh_process_binding_digest:canonical("wholepact:born-manual-roster-continuation-process:v2",&process).unwrap(),
                    fresh_signer_review_digest:h('a'),issued_at_ms:4000,initial_commit_deadline_ms:124_000,
                },
            },process,native_principal:"synthetic-continuation-reviewer".into(),native_measurement:h('b'),complete_history_digest:h('c'),
        };
        let c = &p.continuation.continuation;
        let review = serde_json::json!({
            "local_index":p.local_index,"previous_local_digest":p.previous_local_digest,"enrollment_ref":p.enrollment_ref,
            "intent_digest":p.intent_digest,"first_marker_digest":p.first_marker_digest,"extension_digest":c.extension_digest,
            "roster_extension_digest":p.continuation.roster_extension_digest,"attempt_sequence":c.sequence,
            "previous_attempt_digest":c.previous_attempt_digest,"expected_snapshot":c.expected_snapshot,
            "previous_admission_digest":c.expected_previous_admission_digest,"attempt_nonce":c.attempt_nonce,
            "issued_at_ms":c.issued_at_ms,"initial_commit_deadline_ms":c.initial_commit_deadline_ms,
            "process":p.process,"native_principal":p.native_principal,"native_measurement":p.native_measurement,
            "complete_history_digest":p.complete_history_digest,
        });
        p.continuation.continuation.fresh_signer_review_digest = canonical(
            "wholepact:native-born-manual-roster-continuation-intent:v2",
            &review,
        )
        .unwrap();
        self.write_continuation(&p, "proposal", &p);
        if complete {
            let signature = ManualRosterContinuationOwnerSignatureV2 {
                version: 2,
                extension: extension.clone(),
                continuation: p.continuation.clone(),
                scheme: "ecdsa-p256-sha256-asn1-v1".into(),
                owner_certificate_der: self.owner.certificate_der.clone(),
                signature: self.owner.sign(
                    &manual_roster_continuation_owner_signing_bytes_v2(&extension, &p.continuation)
                        .unwrap(),
                ),
            };
            self.write_continuation(&p, "signature", &signature);
            let acquire = continuation::ContinuationAcquireAudit {
                version: 2,
                proposal_digest: p.digest().unwrap(),
                acquire_operation_id: p.continuation.acquire_operation_id(&extension).unwrap(),
                reentry_review_digest: continuation::reentry_digest(
                    &p,
                    &p.process,
                    &p.native_principal,
                    &p.native_measurement,
                )
                .unwrap(),
                acquire_review_digest: h('d'),
                process: p.process.clone(),
                native_principal: p.native_principal.clone(),
                native_measurement: p.native_measurement.clone(),
            };
            self.write_continuation(&p, "acquire", &acquire);
            self.write_continuation(&p, "admission", &self.admission(Some(&p.continuation)));
        }
        p
    }
    fn write_continuation(
        &self,
        p: &continuation::ContinuationProposal,
        kind: &str,
        value: &impl Serialize,
    ) {
        let name = format!(
            "born-manual-roster-continuation-v2-{:04}-{}.{kind}.wp",
            p.local_index,
            p.digest().unwrap()
        );
        let mut domain = b"wholepact:born-manual-roster-continuation-local-file:v2\0".to_vec();
        domain.extend(self.record.reference().unwrap().as_bytes());
        domain.push(0);
        domain.extend(name.as_bytes());
        self.account
            .directory
            .write(
                &name,
                &vault::encrypt(
                    &self.account.encryption_key,
                    &domain,
                    &serde_json::to_vec(value).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FileState {
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    device: u64,
    inode: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    bytes: Option<Vec<u8>>,
}
fn tree(root: &Path) -> BTreeMap<PathBuf, FileState> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, FileState>) {
        let m = fs::symlink_metadata(path).unwrap();
        let bytes = m.is_file().then(|| fs::read(path).unwrap());
        out.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            FileState {
                mode: m.mode(),
                uid: m.uid(),
                gid: m.gid(),
                links: m.nlink(),
                device: m.dev(),
                inode: m.ino(),
                len: m.len(),
                modified: (m.mtime(), m.mtime_nsec()),
                changed: (m.ctime(), m.ctime_nsec()),
                bytes,
            },
        );
        if m.is_dir() {
            for e in fs::read_dir(path).unwrap() {
                visit(root, &e.unwrap().path(), out);
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
fn state_is(h: &ExactHistory, s: AttemptedInventoryState) {
    assert!(h.format == HistoryFormat::RosterV3(s));
}

/// Pinpoint the exact producer/reader invariant before any negative fixture
/// mutates the journal. Every step is historical data validation only.
fn assert_fixture_capture_stages(f: &Fixture, mode: &str) {
    super::super::super::enrollment::original(&f.account)
        .unwrap_or_else(|e| panic!("{mode}: original account source: {e:?}"));
    for entry in fs::read_dir(f.account.directory.root()).unwrap() {
        let entry = entry.unwrap();
        let m = fs::symlink_metadata(entry.path()).unwrap();
        assert!(
            m.is_file(),
            "{mode}: nonregular file {:?}",
            entry.file_name()
        );
        assert_eq!(m.nlink(), 1, "{mode}: linked file {:?}", entry.file_name());
        assert_eq!(
            m.mode() & 0o077,
            0,
            "{mode}: nonprivate file {:?}, mode {:o}",
            entry.file_name(),
            m.mode()
        );
        assert_eq!(
            m.uid(),
            unsafe { libc::geteuid() },
            "{mode}: wrong owner {:?}",
            entry.file_name()
        );
    }
    let files = read_inventory(&f.account.directory)
        .unwrap_or_else(|e| panic!("{mode}: exact original inventory: {e:?}"));
    let format = HistoryFormat::RosterV3(AttemptedInventoryState::Unpublished);
    let digest = history_digest(format, &files)
        .unwrap_or_else(|e| panic!("{mode}: bounded inventory commitment: {e:?}"));
    let history = ExactHistory {
        format,
        key: Zeroizing::new(*f.account.encryption_key),
        files,
        digest,
    };
    history
        .verify_original_record(&f.record.account_record)
        .unwrap_or_else(|e| panic!("{mode}: original record/birth/policy: {e:?}"));
    let intent = hex::encode(Sha256::digest(history.file(INTENT).unwrap()));
    acquisition::validate_acquire_attempt_bytes(
        &f.record,
        &intent,
        &history.key,
        history.file(ACQUIRE).unwrap(),
    )
    .unwrap_or_else(|e| panic!("{mode}: first acquire ciphertext: {e:?}"));
    continuation::validate_files(
        &f.record,
        &intent,
        &history.key,
        history.file(ACQUIRE).unwrap(),
        &history.files,
    )
    .unwrap_or_else(|e| panic!("{mode}: continuation ciphertext inventory: {e:?}"));
    // No completion is present in this diagnostic; this isolates initial
    // encrypted journal producer layout from later history and commit checks.
    inspect_journal(&history, &JOURNAL_KEY, &f.record, &intent, None)
        .unwrap_or_else(|e| panic!("{mode}: immutable initial journal: {e:?}"));
    capture(&f.account).unwrap_or_else(|e| panic!("{mode}: whole exact capture: {e:?}"));
}

#[test]
fn roster_positive_fixture_matches_each_retained_producer_contract() {
    for mode in 0..3 {
        let mut f = Fixture::new();
        if mode > 0 {
            f.journal(mode > 1);
        }
        let before = tree(f.account.directory.root());
        assert_fixture_capture_stages(&f, &format!("fixture journal mode {mode}"));
        assert_eq!(tree(f.account.directory.root()), before);
    }
}

#[test]
fn roster_attempt_empty_initial_and_completed_archives_keep_full_source_tree() {
    for mode in 0..4 {
        let mut f = Fixture::new();
        if mode > 0 {
            f.journal(mode > 1);
        }
        if mode == 3 {
            f.commit(None);
        }
        let before = tree(f.account.directory.root());
        let history = capture(&f.account).unwrap();
        let state = match mode {
            0 => AttemptedInventoryState::Unpublished,
            1 => AttemptedInventoryState::AuthenticatedEmpty,
            2 => AttemptedInventoryState::InitializedUncompleted,
            _ => AttemptedInventoryState::CompletedOriginal,
        };
        state_is(&history, state);
        assert_eq!(tree(f.account.directory.root()), before);
        let decoded = ExactHistory::parse(&history.bytes().unwrap()).unwrap();
        state_is(&decoded, state);
        assert_eq!(decoded.files, history.files);
        assert_eq!(decoded.digest, history.digest);
        if mode > 1 {
            assert!(history.files.contains_key("authority.sqlite-wal"));
            assert!(history.files.contains_key("authority.sqlite-shm"));
        }
        assert_eq!(tree(f.account.directory.root()), before);
    }
}

#[test]
fn continued_first_completion_preserves_expired_proposal_and_all_original_roles() {
    let mut f = Fixture::new();
    f.journal(true);
    let expired = f.continuation(1, None, false);
    let current = f.continuation(2, Some(expired.digest().unwrap()), true);
    f.commit(Some(current.continuation.clone()));
    let before = tree(f.account.directory.root());
    let history = capture(&f.account).unwrap();
    state_is(&history, AttemptedInventoryState::CompletedContinued);
    let roles: Vec<_> = history
        .files
        .keys()
        .filter(|n| continuation::parse_name(n).is_some())
        .collect();
    assert_eq!(roles.len(), 5);
    let encoded = history.bytes().unwrap();
    assert_eq!(encoded[0], 3);
    let recovered = ExactHistory::parse(&encoded).unwrap();
    assert_eq!(recovered.files, history.files);
    assert_eq!(tree(f.account.directory.root()), before);
    let mut missing = recovered;
    let admission = missing
        .files
        .keys()
        .find(|n| n.ends_with(".admission.wp"))
        .unwrap()
        .clone();
    missing.files.remove(&admission);
    assert!(ExactHistory::parse(&missing.bytes().unwrap()).is_err());
    assert_eq!(tree(f.account.directory.root()), before);
}

#[test]
fn later_continuation_cannot_rewrite_original_completion_or_roster_predecessor() {
    let mut f = Fixture::new();
    f.journal(true);
    f.commit(None);
    let commit = f.account.directory.read(COMMIT, MAX_INTENT).unwrap();
    f.continuation(1, None, true);
    let history = capture(&f.account).unwrap();
    state_is(&history, AttemptedInventoryState::CompletedOriginal);
    assert_eq!(history.file(COMMIT).unwrap(), commit);
    let (decoded, _) = verify(&history).unwrap();
    assert!(decoded == f.record);
    let audit = history.audit_json().unwrap();
    assert!(audit.contains("roster_sequence"));
    assert!(audit.contains("predecessor"));
}

#[test]
fn roster_encrypted_package_and_inert_restore_retain_every_original_and_birth_anchor() {
    let mut f = Fixture::new();
    f.journal(true);
    let p = f.continuation(1, None, true);
    f.commit(Some(p.continuation));
    let before = tree(f.account.directory.root());
    let history = capture(&f.account).unwrap();
    let encrypted = vault::password_envelope(MAGIC, PASSWORD, &history.bytes().unwrap()).unwrap();
    let package_dir = PrivateDirectory::create(&f._temporary.path().join("package")).unwrap();
    package_dir.write(PACKAGE, &encrypted).unwrap();
    package_dir
        .write(
            "COMPLETE",
            hex::encode(Sha256::digest(&encrypted)).as_bytes(),
        )
        .unwrap();
    let package_before = tree(package_dir.root());
    let read = package(&package_dir).unwrap();
    let (plain, _, _) = vault::open_password_envelope(MAGIC, PASSWORD, &read, MAX + 128).unwrap();
    let verified = ExactHistory::parse(&plain).unwrap();
    let password = b"synthetic-new-roster-recovery-password";
    let (account, request) = active::recovered_envelopes(
        &verified.key,
        verified.file("account.wp").unwrap(),
        verified.file("birth-owner-request.wp").unwrap(),
        password,
    )
    .unwrap();
    let capsule = vault::password_envelope(MAGIC, password, &verified.bytes().unwrap()).unwrap();
    let restored = PrivateDirectory::create(&f._temporary.path().join("restored")).unwrap();
    restored.write("account.wp", &account).unwrap();
    restored.write("birth-owner-request.wp", &request).unwrap();
    restored.write(RECOVERED, &capsule).unwrap();
    restored
        .write(
            "born-manual-recovery-complete.wp",
            hex::encode(Sha256::digest(&capsule)).as_bytes(),
        )
        .unwrap();
    let restored_before = tree(restored.root());
    let text = read_restored_history(&restored, password).unwrap();
    assert!(text.contains("V2 roster"));
    assert!(text.contains("roster_sequence"));
    let (_, key, _) =
        vault::open_password_envelope(b"WPACB002", password, &account, 512 * 1024).unwrap();
    active::require_restored_backup_payload(&key, &account, &request).unwrap();
    assert_eq!(
        serde_json::to_vec(&active::backup_origin(&key, &account, &request).unwrap()).unwrap(),
        serde_json::to_vec(&f.origin()).unwrap()
    );
    assert!(!restored.exists(JOURNAL).unwrap());
    assert!(!restored.exists(INTENT).unwrap());
    assert!(!restored.exists(ACQUIRE).unwrap());
    assert!(!restored.exists(COMMIT).unwrap());
    assert!(roster::roster_inventory(&restored).is_err());
    assert_eq!(tree(restored.root()), restored_before);
    assert_eq!(tree(package_dir.root()), package_before);
    assert_eq!(tree(f.account.directory.root()), before);
    let target = restored.root().to_path_buf();
    drop(restored);
    assert!(AccountVault::unlock(&target, password).is_err());
    assert_eq!(tree(&target), restored_before);
}

#[test]
fn wrong_key_corruption_and_v1_reinterpretation_fail_without_mutating_source() {
    let mut f = Fixture::new();
    f.journal(true);
    let p = f.continuation(1, None, true);
    f.commit(Some(p.continuation));
    let before = tree(f.account.directory.root());
    let original = capture(&f.account).unwrap();
    let encoded = original.bytes().unwrap();
    for name in original.files.keys() {
        // SQLite sidecars can contain padding or unused trailing frames.
        // Their exact bytes are retained and authenticated by the outer AEAD;
        // logical journal verification does not claim an AEAD for each byte.
        if name.starts_with("authority.sqlite") {
            continue;
        }
        let mut damaged = ExactHistory::parse(&encoded).unwrap();
        *damaged.files.get_mut(name).unwrap().last_mut().unwrap() ^= 1;
        assert!(
            ExactHistory::parse(&damaged.bytes().unwrap()).is_err(),
            "{name}"
        );
    }
    let mut encrypted = vault::password_envelope(MAGIC, PASSWORD, &encoded).unwrap();
    *encrypted.last_mut().unwrap() ^= 1;
    assert!(vault::open_password_envelope(MAGIC, PASSWORD, &encrypted, MAX + 128).is_err());
    let mut wrong = encoded.to_vec();
    wrong[1] ^= 1;
    assert!(ExactHistory::parse(&wrong).is_err());
    for tag in [1, 2, 4] {
        let mut wrong = encoded.to_vec();
        wrong[0] = tag;
        assert!(ExactHistory::parse(&wrong).is_err());
    }
    let mut state = encoded.to_vec();
    state[35] = 1;
    assert!(ExactHistory::parse(&state).is_err());
    assert_eq!(tree(f.account.directory.root()), before);
}

#[test]
fn unknown_mixed_missing_and_misnamed_history_is_preserved_and_denied() {
    let f = Fixture::new();
    let history = capture(&f.account).unwrap();
    let encoded = history.bytes().unwrap();
    for name in [
        "born-manual-first-acquire.wp",
        "born-manual-commit.wp",
        "unknown.wp",
        "authority.sqlite-extra",
        "../account.wp",
    ] {
        let mut extra = ExactHistory::parse(&encoded).unwrap();
        extra
            .files
            .insert(name.into(), b"synthetic unknown retained bytes".to_vec());
        assert!(ExactHistory::parse(&extra.bytes().unwrap()).is_err());
    }
    for name in NAMES.iter().take(4) {
        let mut missing = ExactHistory::parse(&encoded).unwrap();
        missing.files.remove(*name);
        assert!(ExactHistory::parse(&missing.bytes().unwrap()).is_err());
    }
    f.account
        .directory
        .write("unknown.wp", b"preserve unknown history")
        .unwrap();
    let before = tree(f.account.directory.root());
    assert!(capture(&f.account).is_err());
    assert_eq!(tree(f.account.directory.root()), before);
}

#[test]
fn later_schema_rows_recovery_or_unknown_schema_never_become_empty_history() {
    for sql in [
        "INSERT INTO signer_enrollments VALUES('synthetic-later', 'synthetic-account', 'synthetic-agreement', 'synthetic-participant', '{}')",
        "UPDATE signer_account SET recovery_required=1 WHERE singleton=1",
        "UPDATE signer_account SET writer_epoch=2 WHERE singleton=1",
        "PRAGMA user_version=14",
        "CREATE TABLE unknown_history(value TEXT)",
    ] {
        let mut f = Fixture::new();
        f.journal(true);
        f.connection.as_ref().unwrap().execute_batch(sql).unwrap();
        let before = tree(f.account.directory.root());
        assert!(capture(&f.account).is_err(), "{sql}");
        assert_eq!(tree(f.account.directory.root()), before);
    }
}

#[test]
fn absent_and_empty_journals_never_accept_a_completion_claim() {
    for initialized in [false, true] {
        let mut f = Fixture::new();
        if initialized {
            f.journal(false);
        }
        f.commit(None);
        let before = tree(f.account.directory.root());
        assert!(capture(&f.account).is_err());
        assert_eq!(tree(f.account.directory.root()), before);
    }
}

#[test]
fn partial_packages_wrong_password_trailing_data_and_missing_lock_are_not_repaired() {
    let f = Fixture::new();
    let history = capture(&f.account).unwrap();
    let bytes = history.bytes().unwrap();
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(ExactHistory::parse(&trailing).is_err());
    let encrypted = vault::password_envelope(MAGIC, PASSWORD, &bytes).unwrap();
    assert!(
        vault::open_password_envelope(MAGIC, b"synthetic-wrong-password", &encrypted, MAX + 128)
            .is_err()
    );
    let d = PrivateDirectory::create(&f._temporary.path().join("partial-package")).unwrap();
    d.write(PACKAGE, &encrypted).unwrap();
    let before = tree(d.root());
    assert!(package(&d).is_err());
    assert_eq!(tree(d.root()), before);
    let path = d.root().to_path_buf();
    drop(d);
    fs::remove_file(path.join("signer.lock")).unwrap();
    let before = tree(&path);
    assert!(PrivateDirectory::open_existing(&path).is_err());
    assert_eq!(tree(&path), before);
}

#[test]
fn roster_inventory_commitment_remains_bounded_for_large_ciphertext_and_binds_names() {
    let format = HistoryFormat::RosterV3(AttemptedInventoryState::Unpublished);
    let mut files = BTreeMap::from([("authority.sqlite".into(), vec![0x85; 2 * 1024 * 1024])]);
    let original = history_digest(format, &files).unwrap();
    files.get_mut("authority.sqlite").unwrap()[0] ^= 1;
    assert_ne!(history_digest(format, &files).unwrap(), original);
    files.get_mut("authority.sqlite").unwrap()[0] ^= 1;
    let bytes = files.remove("authority.sqlite").unwrap();
    files.insert("authority.sqlite-wal".into(), bytes);
    assert_ne!(history_digest(format, &files).unwrap(), original);
}

#[test]
fn retained_contribution_receipt_ciphertext_is_included_and_never_silently_dropped() {
    let mut f = Fixture::new();
    f.journal(true);
    f.commit(None);
    let name = format!("born-roster-contribution-retained-v2-{}.wp", h('a'));
    // Public synthetic corrupt ciphertext tests inventory preservation; it does
    // not fabricate a NativeDecision or a current retained contribution owner.
    let ciphertext = b"synthetic invalid receipt ciphertext preserved exactly";
    f.account.directory.write(&name, ciphertext).unwrap();
    let before = tree(f.account.directory.root());
    let files = read_inventory(&f.account.directory).unwrap();
    assert_eq!(files.get(&name).unwrap(), ciphertext);
    let format = HistoryFormat::RosterV3(AttemptedInventoryState::CompletedOriginal);
    let committed = history_digest(format, &files).unwrap();
    let mut missing = files.clone();
    missing.remove(&name);
    assert_ne!(history_digest(format, &missing).unwrap(), committed);
    let mut mutated = files.clone();
    mutated.get_mut(&name).unwrap()[0] ^= 1;
    assert_ne!(history_digest(format, &mutated).unwrap(), committed);
    // Authentication fails closed and leaves every original file untouched.
    assert!(capture(&f.account).is_err());
    assert_eq!(tree(f.account.directory.root()), before);
}

#[test]
fn retention_receipts_need_original_completed_source_and_bound_count() {
    let name = format!("born-roster-contribution-retained-v2-{}.wp", h('a'));
    let mut files = BTreeMap::from([
        ("account.wp".into(), vec![]),
        ("birth-owner-request.wp".into(), vec![]),
        (INTENT.into(), vec![]),
        (ACQUIRE.into(), vec![]),
        (name, vec![]),
    ]);
    assert!(check_names(&files).is_err());
    files.insert(COMMIT.into(), vec![]);
    files.insert(JOURNAL.into(), vec![]);
    check_names(&files).unwrap();
    for n in 0..=retention::MAX_RECEIPTS {
        files.insert(
            format!("born-roster-contribution-retained-v2-{n:064x}.wp"),
            vec![],
        );
    }
    assert!(check_names(&files).is_err());
}

impl Fixture {
    /// Historical synthetic data only. This encrypts a valid inert receipt with
    /// the fixture's original account envelope key. It cannot issue a retained
    /// owner, native decision, active session or witness construction permit.
    fn retention_receipt(
        &self,
        continuation: &ManualRosterSessionContinuationV2,
    ) -> (String, Vec<u8>) {
        use wholepact_core::{
            manual_candidate_selection::ManualCandidateEconomicIntent,
            manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2,
            manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
        };
        use wholepact_signer_origin::manual_roster_construction_v2::ManualRosterContributionRetentionEvidenceV2;
        let record = &self.record.account_record;
        let terms = &record.terms;
        let origin = self.origin();
        let policy_origin = origin.anchor().complete_policy_origin_v2().unwrap();
        let economics: ManualCandidateEconomicIntent = serde_json::from_value(serde_json::json!({
            "version":1,"candidate_id":"synthetic-candidate","candidate_revision":1,
            "proposal_id":"synthetic-proposal","previous_proposal_id":null,
            "created_at":"2026-10-15T13:00:00Z","transaction_fee":"4","expiry_height":1000,
            "own_return_rule":"authenticated_same_account",
            "agreement":{"schema_version":1,"agreement_id":"synthetic-agreement",
                "obligation_id":"synthetic-obligation","revision":1,"purpose":"Synthetic backup fixture. No funds.",
                "organizer_identity":"synthetic-organizer","network_profile_id":terms.identity.network_profile_id,
                "recipients":[{"recipient_id":"synthetic-recipient","address":"uSyntheticRecipient","amount":"80",
                    "memo":null,"instruction_provenance":"synthetic fixture"}],
                "funding_policy":{"kind":"exact","target":"80"},"fee_policy":{"kind":"pro_rata"},
                "privacy_profile":{"mode":"local_only","proving_operator":null,"dedicated_accounts_required":true},
                "coordination_deadline":null,"confirmation_policy":{"required_confirmations":1},"extensions":[]},
            "participants":[
                {"participant_id":"synthetic-other","account_id":h('f'),"contribution":"40","fee_share":"2","fee_cap":"2","maximum_net_debit":"42","charges":[]},
                {"participant_id":terms.scope.participant_id,"account_id":terms.identity.account_id,"contribution":"40","fee_share":"2","fee_cap":"2","maximum_net_debit":"42","charges":[]}
            ]
        })).unwrap();
        economics.validate().unwrap();
        let extension = self.record.extension().unwrap();
        let selection: ManualRosterCandidateSelectionRequestV2 = serde_json::from_value(serde_json::json!({
            "version":2,"operation_id":"synthetic-selection","current_caller_binding_digest":h('1'),
            "requested_at_ms":7000,"disclosure_expires_at_ms":37000,
            "scope":{"version":2,
                "provenance":{"version":2,"original_host_audit":{"kind":"additional_publication_v3","audit_digest":h('2')},
                    "roster":self.record.roster,"signer_roster_record_digest":self.record.reference().unwrap(),
                    "witness_roster_extension_digest":extension.digest().unwrap()},
                "selection":{"version":1,"purpose":"prepare_one_private_contribution",
                    "original_policy_origin":policy_origin,"economic_intent":economics,
                    "invocation":{"version":1,"operation_id":"synthetic-invocation","idempotency_key_digest":h('3'),
                        "invocation_nonce":h('4'),"economic_intent_digest":economics.digest().unwrap(),
                        "checkpoint_destination":"/synthetic/checkpoint","requested_at_ms":7000,"construction_expires_at_ms":60000},
                    "inventory":{"version":1,"enrollment":terms,"enrollment_ref":record.reference().unwrap(),
                        "witness_extension_digest":extension.account_extension.digest().unwrap(),
                        "attempt":{"version":2,"continuation_digest":continuation.digest_for(&extension).unwrap(),"attempt_sequence":continuation.sequence()},
                        "original_recipient_policy":policy_origin.recipient_policy,
                        "attachment":{"version":1,"original_primary_journal_origin_digest":terms.host.financial_journal_origin_digest,
                            "predecessor_registry_digest":h('5'),"current_registry_digest":h('6'),"latest_extension_digest":h('7'),
                            "selected":{"account_id":terms.identity.account_id,"canonical_directory":"/synthetic/wallet",
                                "directory_identity_digest":h('8'),"journal_origin_digest":h('9')}},
                        "operator_name":"synthetic-local-host","operator_destination":"/synthetic/checkpoint",
                        "wallet_destination":"/synthetic/wallet/wallet.sqlite","purpose":"preliminary_inventory_only",
                        "retention_policy":"Keep exact disclosed input data locally until explicit deletion",
                        "provider":{"source_id":"synthetic-provider","endpoint":"https://synthetic.invalid","trust_profile":"single_tls_provider_report_not_consensus"},
                        "birthday":{"prior_height":1,"prior_block_hash":h('a'),"sapling_tree":"","orchard_tree":"","ironwood_tree":""},
                        "minimum_confirmations":1,"maximum_blocks":10,"anchor_height":100}
                }
            }
        })).unwrap();
        selection.validate().unwrap();
        let request: ManualRosterContributionRetentionRequestV2 = serde_json::from_value(serde_json::json!({
            "version":2,"operation_id":"synthetic-retention","selection":selection,"selection_evidence_digest":h('b'),
            "selected_inputs":[{"input_id":"synthetic-exact-input","nullifier":h('c'),"value_zatoshis":52}],
            "selection_context":{"tip_height":101,"tip_hash_protocol":h('d'),"anchor_height":100,
                "anchor_hash_protocol":h('e'),"anchor_root":h('f')},
            "local_exclusion_digest":h('1'),"change_address":"uSyntheticOwnReturn","change_value_zatoshis":10,
            "requested_at_ms":7001,"admission_expires_at_ms":37000
        })).unwrap();
        request.validate().unwrap();
        let evidence: ManualRosterContributionRetentionEvidenceV2 = serde_json::from_value(serde_json::json!({
            "version":2,"request":request,"retained_signer_intent_digest":hex::encode(Sha256::digest(self.account.directory.read(INTENT,MAX_INTENT).unwrap())),
            "native_review_digest":h('2'),"admitted_at_ms":7002,
            "selection_observation":{"writer_certificate_digest":terms.signer.writer_certificate_digest,
                "writer_epoch":terms.signer.writer_epoch,"writer_session_digest":h('3'),"writer_session_expires_at_ms":200000,
                "witness_head_sequence":4,"witness_head_digest":h('4'),"complete_history_digest":h('5'),
                "exclusion_checkpoint_digest":h('6'),"native_review_digest":h('7')}
        })).unwrap();
        evidence.validate().unwrap();
        let name = format!(
            "born-roster-contribution-retained-v2-{}.wp",
            request.digest().unwrap()
        );
        let mut domain = b"wholepact:born-roster-contribution-retention-file:v2\0".to_vec();
        domain.extend(self.record.reference().unwrap().as_bytes());
        domain.push(0);
        domain.extend(name.as_bytes());
        let ciphertext = vault::encrypt(
            &self.account.encryption_key,
            &domain,
            &serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
        self.account.directory.write(&name, &ciphertext).unwrap();
        (name, ciphertext)
    }
}

#[test]
fn valid_retention_receipt_survives_encrypted_archive_roundtrip_as_history_only() {
    let mut f = Fixture::with_retention_policy(true);
    f.journal(true);
    let continued = f.continuation(1, None, true);
    f.commit(Some(continued.continuation.clone()));
    let (name, ciphertext) = f.retention_receipt(&continued.continuation);
    let before = tree(f.account.directory.root());
    let history = capture(&f.account).unwrap();
    state_is(&history, AttemptedInventoryState::CompletedContinued);
    assert_eq!(history.file(&name).unwrap(), ciphertext);
    let encrypted = vault::password_envelope(MAGIC, PASSWORD, &history.bytes().unwrap()).unwrap();
    let (plain, _, _) =
        vault::open_password_envelope(MAGIC, PASSWORD, &encrypted, MAX + 128).unwrap();
    let recovered = ExactHistory::parse(&plain).unwrap();
    assert_eq!(recovered.files, history.files);
    assert_eq!(recovered.digest, history.digest);
    assert_eq!(recovered.file(&name).unwrap(), ciphertext);
    // The recovered capsule authenticates all receipt bytes, while ordinary
    // activation cannot turn a disclosure history file into a live capability.
    let mut changed = ExactHistory::parse(&plain).unwrap();
    *changed.files.get_mut(&name).unwrap().last_mut().unwrap() ^= 1;
    assert!(ExactHistory::parse(&changed.bytes().unwrap()).is_err());
    let mut renamed = ExactHistory::parse(&plain).unwrap();
    let bytes = renamed.files.remove(&name).unwrap();
    renamed.files.insert(
        format!("born-roster-contribution-retained-v2-{}.wp", h('a')),
        bytes,
    );
    assert!(ExactHistory::parse(&renamed.bytes().unwrap()).is_err());
    assert_eq!(tree(f.account.directory.root()), before);
}
