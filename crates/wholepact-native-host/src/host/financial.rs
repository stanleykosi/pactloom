//! Explicit, separately protected financial journal attachment. This creates no
//! account, grant, native signer approval or remote connection.
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(in crate::host) mod born_post_return_inputs_v1;
mod artifact_handoff_request;
mod account_inspection;
mod automation;
mod construction;
mod dispatch_request;
mod early_gates;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(in crate::host) mod manual_inventory_setup;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(in crate::host) mod manual_roster_inventory_setup_v2;
mod participant_delivery;
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub(in crate::host) mod private_durable_fixed_v2;
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub(in crate::host) mod durable_delivery_admission_v2;
mod proof_delivery;
mod proof_execution_request;
mod proof_request;
mod reconciliation_request;
mod record_resolution;
mod settlement;
mod settlement_request;
mod settlement_request_consent;
mod signature_export;
mod sponsor;
use super::*;

/// The permanent vault anchor distinguishes a restricted successor from an
/// ordinary profile. Publication's saved continuity is audit evidence, not a
/// current financial admission. Do not replace this with runtime_recovery_required
/// or an account-recovery flag: fresh coordination deliberately remains available
/// while historical account exposure and generation restrictions remain intact.
fn require_financial_generation_admission(secrets: &Secrets) -> Result<()> {
    if secrets.generation_plan_digest().is_some() {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    Ok(())
}

impl Host {
    pub(super) fn financial_open(&mut self, create: bool) -> Result<()> {
        self.access()?;
        if self.financial.is_some() {
            return Err(Error::Locked);
        }
        let path = self.path(if create {
            "NEW private financial profile directory (absolute): "
        } else {
            "Existing private financial profile directory (absolute): "
        })?;
        self.directory.external_destination(&path)?;
        self.terminal.confirm(&format!(
            "{} separately encrypted financial journals for this exact primary profile.\nPrimary: {}\nFinancial directory: {}\nThis stores private wallet/proof/signature/transaction artifacts under independent keys. It creates no spending account or signer permission and sends nothing. The primary profile will be durably marked as attached; its existing non-financial backup command will refuse incomplete backups even after lock/restart. Preserve both directories and the financial passphrase.",
            if create { "Create" } else { "Open" }, self.secrets.profile(), path.display(),
        ))?;
        let password = self.terminal.secret(if create {
            "New financial profile passphrase: "
        } else {
            "Financial profile passphrase: "
        })?;
        if create {
            let repeat = self
                .terminal
                .secret("Repeat financial profile passphrase: ")?;
            if *password != *repeat {
                return Err(Error::Authentication);
            }
        }
        let retained_v2 = crate::financial_inventory::prepare_primary_open(
            &self.directory,
            &self.secrets,
            &path,
            create,
        )?;
        let financial = if create {
            crate::financial_profile::FinancialProfile::create(
                &path,
                &self.secrets.profile(),
                password.as_bytes(),
            )?
        } else {
            crate::financial_profile::FinancialProfile::open(
                &path,
                &self.secrets.profile(),
                password.as_bytes(),
            )?
        };
        if retained_v2 {
            crate::financial_inventory::reopen_registered(
                &self.directory,
                &self.secrets,
                &financial,
                crate::financial_inventory::AttachmentRole::PrimaryFinancial,
                None,
            )?;
        }
        self.financial = Some(financial);
        self.terminal.message("Financial journals are open under the exclusive local profile lock. No construction, proof, authorization or submission has run.\n")
    }
}

impl Host {
    pub(in crate::host) fn require_financial_generation_admission(&self) -> Result<()> {
        require_financial_generation_admission(&self.secrets)
    }

    fn financial_permission(&self, permission: Permission) -> Result<()> {
        // Every financial command uses this entry gate before private artifact
        // access, wallet/proof work, signer IPC, retention, export or dispatch.
        // Fresh generation admission needs its own qualified typed protocol;
        // ordinary session permission cannot supply missing account continuity.
        self.require_financial_generation_admission()?;
        self.coordination_permission(permission)
    }

    fn coordination_permission(&self, permission: Permission) -> Result<()> {
        let principal = &self.access()?.principal_id;
        if self.config.as_ref().is_some_and(|config| {
            config.clients.iter().any(|client| {
                &client.client_id == principal && client.permissions.contains(&permission)
            })
        }) {
            self.authority.check_financial_principal(principal)
        } else {
            Err(Error::Permission)
        }
    }

    pub(super) fn financial_candidate(&self, operation: &str) -> Result<()> {
        // Candidate terms and claims-only review are coordination. None of these
        // operations touches wallet/proof/signature journals or grants key use.
        self.coordination_permission(match operation {
            "candidate-read" => Permission::Read,
            "candidate-prepare" => Permission::Propose,
            "candidate-review" => Permission::Coordinate,
            _ => return Err(Error::Invalid),
        })?;
        let access = self.access()?;
        self.authority
            .check_financial_principal(&access.principal_id)?;
        if operation == "candidate-prepare" {
            let agreement = self.terminal.ask("Agreement ID: ")?;
            let revision = self.financial_revision()?;
            let key = self
                .terminal
                .ask("Stable idempotency key (reuse unchanged on retry): ")?;
            let request: wholepact_engine::candidates::CandidateRequest =
                self.read_json("Exact candidate terms JSON file (no witnesses or keys): ")?;
            self.terminal.json(&request)?;
            self.terminal.confirm("Freeze these exact candidate terms locally? This does not construct, prove, sign or submit a transaction.")?;
            return self.terminal.json(
                &self
                    .engine
                    .create_candidate(access, &key, &agreement, revision, request)?,
            );
        }
        let candidate = self.terminal.ask("Candidate ID: ")?;
        if operation == "candidate-read" {
            return self
                .terminal
                .json(&self.engine.candidate(access, &candidate)?.1);
        }
        let revision = self.financial_revision()?;
        let key = self.terminal.ask("Stable review idempotency key: ")?;
        self.terminal.confirm("Record a claims-only economic review? This does not verify private transaction effects or authorize spending.")?;
        self.terminal.json(
            &self
                .engine
                .review_candidate(access, &key, &candidate, revision)?,
        )
    }

    fn financial_revision(&self) -> Result<u64> {
        self.terminal
            .ask("Current coordination revision: ")?
            .parse()
            .map_err(|_| Error::Invalid)
    }

    pub(super) fn financial_proof(&self, operation: &str) -> Result<()> {
        use wholepact_engine::proof_jobs::LocalProofJob;
        use wholepact_proof_jobs::LocalAction;
        self.financial_permission(match operation {
            "proof-status" => Permission::Read,
            "proof-review" => Permission::Disclose,
            "proof-reconcile" | "proof-recover" | "proof-run" => Permission::Coordinate,
            _ => return Err(Error::Invalid),
        })?;
        let access = self.access()?;
        let profile = self.financial.as_ref().ok_or(Error::Locked)?;
        profile.inventory()?;
        let candidate_id = self.terminal.ask("Candidate ID: ")?;
        let (_, candidate) = self.engine.candidate(access, &candidate_id)?;
        let job_id = self.terminal.ask("Original retained proof job ID: ")?;
        let action = match operation {
            "proof-status" | "proof-reconcile" => LocalAction::InspectStatus,
            "proof-review" => LocalAction::ReadPrivateArtifact,
            "proof-run" => LocalAction::ProveLocally,
            "proof-recover" => LocalAction::RecoverInterrupted,
            _ => return Err(Error::Invalid),
        };
        let mut actions = vec![LocalAction::InspectStatus, action];
        if operation == "proof-run" {
            actions.push(LocalAction::RetainPrivateWitnesses);
        }
        let consent = self.authority.proof_consent(
            &access.principal_id,
            &candidate_id,
            &candidate.manifest_digest,
            actions,
        )?;
        let local = || LocalProofJob {
            job_id: &job_id,
            jobs: &profile.proof,
            consent: &consent,
        };
        // This always establishes the engine-origin checkpoint and candidate
        // provenance before any direct recovery mutation of the private journal.
        let status = self
            .engine
            .candidate_proof_status(access, &candidate_id, local())?;
        match operation {
            "proof-status" => self.terminal.json(&status),
            "proof-review" => {
                let checkpoint = self.engine.load_candidate_proof_for_local_review(
                    access,
                    &candidate_id,
                    local(),
                )?;
                let review = wholepact_protocol::review::verify_review(
                    checkpoint.pczt_bytes(),
                    checkpoint.policy(),
                )
                .map_err(|_| Error::Invalid)?;
                self.terminal.json(&review)?;
                self.terminal.message("Exact saved proof reviewed locally. No raw witness, viewing key or PCZT bytes were printed. Account attribution and chain validity still need their separate authorities.\n")
            }
            "proof-recover" => {
                let attempt: u32 = self
                    .terminal
                    .ask("Expected interrupted attempt number: ")?
                    .parse()
                    .map_err(|_| Error::Invalid)?;
                let summary = profile
                    .proof
                    .recover_interrupted(&access.principal_id, &job_id, attempt, &consent)
                    .map_err(|_| Error::Invalid)?;
                self.terminal.json(&summary)?;
                self.terminal.message("Interrupted proof marked uncertain. Use proof-reconcile to update metadata; no proof was regenerated.\n")
            }
            "proof-reconcile" => {
                let revision = self.financial_revision()?;
                let key = self
                    .terminal
                    .ask("Stable reconciliation idempotency key: ")?;
                self.terminal
                    .json(&self.engine.reconcile_candidate_proof_job(
                        access,
                        &key,
                        &candidate_id,
                        revision,
                        local(),
                    )?)
            }
            "proof-run" => {
                let revision = self.financial_revision()?;
                let key = self
                    .terminal
                    .ask("Stable proof operation idempotency key: ")?;
                let result = self.run_native_proof_owned(
                    access,
                    &candidate_id,
                    &job_id,
                    revision,
                    &key,
                    &consent,
                )?;
                self.terminal.json(&result)
            }
            _ => Err(Error::Invalid),
        }
    }
}

#[cfg(test)]
mod generation_financial_gate_tests {
    use super::*;
    use std::cell::Cell;

    fn tree_bytes(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        let mut files = std::collections::BTreeMap::new();
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.extend(tree_bytes(&path));
            } else {
                files.insert(path.clone(), std::fs::read(path).unwrap());
            }
        }
        files
    }

    #[test]
    fn restricted_successor_direct_financial_commands_stop_before_private_effects() {
        let temporary = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temporary.path()).unwrap();
        let profile = root.join("synthetic-profile");
        let password = b"synthetic-only-financial-gate-storage-password";
        initialize(&profile, password).unwrap();
        let directory = Directory::open(&profile).unwrap();
        let secrets =
            Secrets::open(&directory.read("profile.vault", 1024).unwrap(), password).unwrap();
        let coordination_key = secrets.key(0).unwrap();
        let unmatched_release = wholepact_store::authority::ReleaseIntent {
            authorization_id: "synthetic-host-only-authorization".into(),
            account_id: "synthetic-unmatched-account".into(),
            writer_epoch: 7,
            obligation_id: "synthetic-unmatched-obligation".into(),
            proposal_id: "synthetic-unmatched-proposal".into(),
            manifest_digest: "a".repeat(64),
            effects_digest: "b".repeat(64),
            artifact_digest: "c".repeat(64),
            maximum_debit: "11".into(),
            input_ids: vec!["synthetic-unmatched-input".into()],
            aggregate_budget_limit: "100".into(),
        };
        // Host-only synthetic exposure: no signer journal, witness permit or
        // live financial authority exists for this release. Attaching new
        // financial storage must not make its uncertain debit disappear.
        let seed =
            Store::open_encrypted(directory.path(JOURNALS[0]).unwrap(), &coordination_key).unwrap();
        seed.initialize_authority_account(&unmatched_release.account_id, 7)
            .unwrap();
        let original_exposure = seed
            .record_authorization_release_intent(&unmatched_release)
            .unwrap();
        seed.require_account_recovery(&unmatched_release.account_id)
            .unwrap();
        let original_account = seed
            .authority_account(&unmatched_release.account_id)
            .unwrap()
            .unwrap();
        assert!(original_account.recovery_required);
        assert_eq!(
            original_exposure.state,
            wholepact_store::authority::ExposureState::OutstandingUncertain
        );
        drop(seed);
        let terminal = Terminal::disconnected_for_test();
        assert!(matches!(
            terminal.message("must not write"),
            Err(Error::Terminal)
        ));
        let mut host = Host::open(directory, secrets, terminal).unwrap();
        // This deliberately changes only the test host's storage identity. It
        // does not claim a published generation or manufacture native consent.
        // If a command misses the generation gate, absent permissions or this
        // non-TTY fail with a different error and the regression catches it.
        host.secrets = host.secrets.bind_successor_plan([23; 32]).unwrap();
        let before = tree_bytes(&root);
        let commands = [
            ("candidate-construct", host.financial_construct()),
            (
                "native-dispatch-request",
                host.native_dispatch_request(false),
            ),
            ("native-dispatch-status", host.native_dispatch_request(true)),
            (
                "native-reconciliation-request",
                host.native_reconciliation_request(false),
            ),
            (
                "native-reconciliation-status",
                host.native_reconciliation_request(true),
            ),
            (
                "native-proof-reconcile-original",
                host.native_proof_reconcile_original(),
            ),
            (
                "native-construction-original-status",
                host.native_construction_original_status(),
            ),
            (
                "native-proof-reconcile-request",
                host.native_proof_reconcile_request(),
            ),
            (
                "automatic-authorize",
                host.financial_automatic_authorization(),
            ),
            ("proof-run", host.financial_proof("proof-run")),
            (
                "native-artifact-handoff-request",
                host.native_artifact_handoff_request(),
            ),
            (
                "native-settlement-request",
                host.native_settlement_request(false),
            ),
            (
                "native-settlement-inspect",
                host.native_settlement_request(true),
            ),
            (
                "native-proof-execute-request",
                host.native_proof_execute_request(),
            ),
            ("proof-send-for-review", host.financial_proof_delivery()),
            ("signature-export", host.financial_signature_export()),
            (
                "signature-retain",
                host.financial_settle("signature-retain"),
            ),
            (
                "transaction-checkpoint",
                host.financial_settle("transaction-checkpoint"),
            ),
            (
                "transaction-dispatch",
                host.financial_settle("transaction-dispatch"),
            ),
            ("record-retain", host.financial_settle("record-retain")),
            ("resolution-source", host.financial_resolution_source()),
            ("record-resolve", host.financial_record_resolve()),
            ("observe", host.observe()),
        ];
        for (command, result) in commands {
            assert!(
                matches!(result, Err(Error::RecoveryFinancialUnsupported)),
                "{command} did not stop at the generation financial gate: {result:?}"
            );
        }
        // Claims-only coordination keeps its ordinary permission check rather
        // than inheriting financial denial. No approval is fabricated here.
        for command in ["candidate-read", "candidate-prepare", "candidate-review"] {
            assert!(matches!(
                host.financial_candidate(command),
                Err(Error::Permission)
            ));
        }
        assert!(host.financial.is_none());
        assert!(host.observation.is_none());
        assert!(host.resolution_source.is_none());
        assert!(host.signer_review_clients.is_empty());
        assert_eq!(tree_bytes(&root), before);
        drop(host);
        let retained = Store::open_encrypted(profile.join(JOURNALS[0]), &coordination_key).unwrap();
        assert_eq!(
            retained
                .exposure(&unmatched_release.authorization_id)
                .unwrap(),
            Some(original_exposure)
        );
        assert_eq!(
            retained
                .authority_account(&unmatched_release.account_id)
                .unwrap(),
            Some(original_account)
        );
        assert_eq!(
            retained
                .outstanding_debit(&unmatched_release.account_id)
                .unwrap(),
            "11"
        );
        assert_eq!(
            retained
                .settled_debit(&unmatched_release.account_id)
                .unwrap(),
            "0"
        );
    }

    #[test]
    fn restricted_successor_rejects_financial_continuation_before_effect() {
        let secrets = Secrets::fresh()
            .unwrap()
            .bind_successor_plan([17; 32])
            .unwrap();
        let touched = Cell::new(false);
        let result = require_financial_generation_admission(&secrets).map(|()| {
            touched.set(true);
        });
        assert!(matches!(result, Err(Error::RecoveryFinancialUnsupported)));
        assert!(!touched.get());
        assert_eq!(secrets.generation_plan_digest(), Some([17; 32].as_slice()));
    }

    #[test]
    fn every_successor_anchor_stays_denied_without_a_financial_admission() {
        for digest in [[0; 32], [1; 32], [255; 32]] {
            let secrets = Secrets::fresh()
                .unwrap()
                .bind_successor_plan(digest)
                .unwrap();
            for _ in 0..2 {
                assert!(matches!(
                    require_financial_generation_admission(&secrets),
                    Err(Error::RecoveryFinancialUnsupported)
                ));
            }
            assert_eq!(secrets.generation_plan_digest(), Some(digest.as_slice()));
        }
    }

    #[test]
    fn ordinary_profile_still_requires_its_separate_native_permissions() {
        // This only passes the generation guard. The production caller then
        // performs the unchanged principal and exact native permission checks.
        let secrets = Secrets::fresh().unwrap();
        assert!(secrets.generation_plan_digest().is_none());
        assert!(require_financial_generation_admission(&secrets).is_ok());
    }
}
