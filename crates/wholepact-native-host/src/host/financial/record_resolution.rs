//! Host-owned source enrollment and one-shot exact positive resolution. No live
//! permit, signer native decision or trust descriptor is accepted through IPC.
use super::*;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use wholepact_chain::local_node::{LocalNodeSourceDescriptor, LocalNodeTls, LocalValidatingNode};
use wholepact_signer::{
    authority_bridge::{
        ipc::{HistoryRequest, OriginalHistoryClient},
        provider::InstalledSignerProvider,
        settlement_ipc::SettlementRequest,
    },
    consent_journal::ResultRedeliveryRequest,
    ipc::PairScope,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSourceConfig {
    descriptor: LocalNodeSourceDescriptor,
    trusted_root_der: Vec<PathBuf>,
    client_certificate_der: Vec<PathBuf>,
    client_private_key_pkcs8_der: PathBuf,
}
fn credential(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    files::validate_absolute(path)?;
    let parent = path.parent().ok_or(Error::Invalid)?;
    if std::fs::canonicalize(parent)? != parent {
        return Err(Error::Invalid);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(parent)?;
        // SAFETY: reads only the effective uid.
        if !metadata.is_dir()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::Invalid);
        }
    }
    Ok(Zeroizing::new(files::read_private(path, 65536)?))
}
impl Host {
    pub(in crate::host) fn financial_resolution_source(&mut self) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        if self.resolution_source.is_some() {
            return Err(Error::Permission);
        }
        let config: HostSourceConfig = self.read_json(
            "Host-owned existing TLS source configuration JSON (never signer credentials): ",
        )?;
        config.descriptor.validate()?;
        if config.trusted_root_der.is_empty()
            || config.trusted_root_der.len() > 8
            || config.client_certificate_der.is_empty()
            || config.client_certificate_der.len() > 8
        {
            return Err(Error::Invalid);
        }
        let roots = config
            .trusted_root_der
            .iter()
            .map(|p| credential(p).map(|v| CertificateDer::from(v.to_vec())))
            .collect::<Result<Vec<_>>>()?;
        let certificates = config
            .client_certificate_der
            .iter()
            .map(|p| credential(p).map(|v| CertificateDer::from(v.to_vec())))
            .collect::<Result<Vec<_>>>()?;
        let key = credential(&config.client_private_key_pkcs8_der)?;
        let tls = LocalNodeTls::new(
            config.descriptor.server_name.clone(),
            config.descriptor.pinned_certificate_sha256.clone(),
            roots,
            certificates,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )?;
        let node = LocalValidatingNode::new(
            config.descriptor.source_id.clone(),
            config
                .descriptor
                .endpoint
                .parse()
                .map_err(|_| Error::Invalid)?,
            tls,
            config
                .descriptor
                .confirmation_policy
                .required_confirmations(),
        )?;
        if node.source_descriptor() != config.descriptor {
            return Err(Error::Permission);
        }
        self.resolution_source = Some(
            self.authority
                .enroll_resolution_source(&self.access()?.principal_id, node)?,
        );
        self.terminal.message("Independent host source enrolled for this unlocked session. No connection was made. record-resolve requires exact separate disclosure and mutation approval.\n")
    }
    pub(in crate::host) fn financial_record_resolve(&self) -> Result<()> {
        self.financial_record_resolve_exact(None)
    }
    pub(super) fn financial_record_resolve_request(
        &self,
        request: wholepact_engine::native_reconciliation_requests::NativeReconciliationAttempt,
    ) -> Result<()> {
        self.financial_record_resolve_exact(Some(request))
    }
    fn financial_record_resolve_exact(
        &self,
        request: Option<
            wholepact_engine::native_reconciliation_requests::NativeReconciliationAttempt,
        >,
    ) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let access = self.access()?;
        let source = self.resolution_source.as_ref().ok_or(Error::Permission)?;
        let operation = exact_or_selected(request.as_ref().map(|r| r.operation_id()), || {
            Ok(self
                .terminal
                .ask("Original retained submission operation ID: ")?
                .to_string())
        })?;
        let mut journal = self.submission.lock().map_err(|_| Error::Storage)?;
        let descriptor = journal
            .retained_submission_descriptor(&operation)?
            .ok_or(Error::Invalid)?;
        if let Some(request) = &request {
            self.engine
                .validate_native_reconciliation_attempt(access, request, &journal)?;
        }
        let scope = self
            .engine
            .settlement_sink_scope(journal.identity(), &descriptor)?;
        let candidate_id = exact_or_selected(
            request
                .as_ref()
                .map(|r| r.source().original.candidate_id.as_str()),
            || {
                Ok(self
                    .terminal
                    .ask("Exact original candidate ID: ")?
                    .to_string())
            },
        )?;
        let (_, candidate) = self.engine.candidate(access, &candidate_id)?;
        if descriptor.proposal_id != candidate_id.as_str() {
            return Err(Error::Invalid);
        }
        let original_participant = request
            .as_ref()
            .map(|r| r.participant_id().ok_or(Error::Invalid))
            .transpose()?;
        let participant_id = exact_or_selected(original_participant, || {
            Ok(self.terminal.ask("Original participant ID: ")?.to_string())
        })?;
        let participant = candidate
            .proposal
            .manifest
            .participants
            .iter()
            .find(|p| p.participant_id == participant_id.as_str())
            .ok_or(Error::Invalid)?;
        if !scope.affected_account_ids.contains(&participant.account_id)
            || !scope
                .affected_agreement_ids
                .contains(&candidate.proposal.manifest.agreement.agreement_id)
        {
            self.terminal.message("Retain the exact private participant record with record-retain first. No source read or positive mutation was attempted.\n")?;
            return Err(Error::Permission);
        }
        let profile = self.secrets.profile();
        let current = wholepact_transport::Timestamp::from_unix_seconds(
            i64::try_from(now()?).map_err(|_| Error::Invalid)?,
        )?;
        let window = wholepact_core::records::ObservationWindow {
            now: current.as_str().to_owned(),
            oldest_acceptable: current.as_str().to_owned(),
        };
        let record_runtime = wholepact_engine::participant_records::ParticipantRecordRuntime {
            profile_id: &profile,
            authority: &*self.authority,
            window: &window,
        };
        let record_guard = request
            .as_ref()
            .map(|request| {
                self.engine
                    .prepare_native_record_resolution(access, request, &record_runtime)
            })
            .transpose()?;
        let check_record = || -> Result<()> {
            if let Some(guard) = &record_guard {
                guard.check_current()?;
            }
            Ok(())
        };
        check_record()?;
        let socket = self.path("Installed independent signer socket (absolute): ")?;
        files::validate_absolute(&socket)?;
        let history: HistoryRequest =
            self.read_json("Exact original signer history references JSON: ")?;
        let redelivery_operation_id = self
            .terminal
            .ask("Stable exact signer result redelivery operation ID: ")?;
        id(&redelivery_operation_id)?;
        let dispatch_operation_id =
            wholepact_engine::settlement_fanout::native_account_dispatch_operation(
                &operation,
                &history.authorization_id,
            )?;
        // Only the ordinary native command may choose a conflict candidate.
        // An already-bound reconciliation request cannot silently change purpose.
        let conflict = if request.is_none() {
            let alternative = self
                .terminal
                .ask("Known conflicting transaction ID (blank checks original consumption): ")?;
            if alternative.is_empty() {
                None
            } else {
                let nullifier = self
                    .terminal
                    .ask("Exact original participant Ironwood nullifier to check: ")?;
                let value = wholepact_chain::local_node::CanonicalConflictCandidate::from_retained_original(
                    &journal, &operation, alternative.to_string(), nullifier.to_string(),
                )?;
                Some(value)
            }
        } else {
            None
        };
        let grant = self.authority.approve_positive_settlement(
            self.engine.clone(),
            access.clone(),
            scope.clone(),
            source.clone(),
            conflict.clone(),
        )?;
        self.terminal.confirm(&format!("Pair with installed signer {} for account {}, participant {}, agreement {}. Request its separate native exact settlement review for original authorization {} and account dispatch {} (retained host submission {}). The signer independently selects its enrolled source; the host supplies no approval decision or credentials.", socket.display(), participant.account_id, participant_id.as_str(), candidate.proposal.manifest.agreement.agreement_id, history.authorization_id, dispatch_operation_id, operation.as_str()))?;
        check_record()?;
        let client = OriginalHistoryClient::pair(
            InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
            &socket,
            "wholepact-native-record-resolution",
            PairScope {
                account_id: participant.account_id.clone(),
                agreement_id: candidate.proposal.manifest.agreement.agreement_id.clone(),
                participant_id: participant_id.to_string(),
                manifest_digest: candidate.manifest_digest.clone(),
                history_read: true,
                authorization_export: true,
                preconstruction_export: false,
            },
        )
        .map_err(|_| Error::Permission)?;
        check_record()?;
        let redelivery = client
            .request_result_redelivery(&ResultRedeliveryRequest {
                operation_id: redelivery_operation_id.to_string(),
                authorization_id: history.authorization_id.clone(),
                expected_original_consent_ref: history.expected_original_consent_ref.clone(),
                expected_enrollment_ref: history.expected_enrollment_ref.clone(),
                expected_manifest_ref: history.expected_manifest_ref.clone(),
            })
            .map_err(|_| Error::Permission)?;
        let signer_request = SettlementRequest {
            history,
            dispatch_operation_id,
            conflict,
        };
        check_record()?;
        // Authenticate the selected original before the signer's positive effect.
        // Its history lease holds the signer journal's read fence, so release that
        // lease before settlement needs the write fence. The selected local record
        // lease remains held and the same immutable original is reacquired afterward.
        let selected_original = if let Some(guard) = &record_guard {
            let original = client
                .acquire_redelivered(&signer_request.history, &redelivery)
                .map_err(|_| Error::Permission)?;
            Some((guard, original))
        } else {
            None
        };
        let (original, receipt) = match selected_original {
            Some((guard, original)) => settlement_with_original_recheck(
                original,
                |original| Ok(guard.validate_signer_history(original)?),
                || {
                    check_record()?;
                    client
                        .request_settlement(&signer_request)
                        .map_err(|_| Error::Permission)
                },
                || {
                    client
                        .acquire_redelivered(&signer_request.history, &redelivery)
                        .map_err(|_| Error::Permission)
                },
            )?,
            None => {
                // Preserve the ordinary unbound command's existing ordering.
                let receipt = client
                    .request_settlement(&signer_request)
                    .map_err(|_| Error::Permission)?;
                check_record()?;
                let original = client
                    .acquire_redelivered(&signer_request.history, &redelivery)
                    .map_err(|_| Error::Permission)?;
                (original, receipt)
            }
        };
        check_record()?;
        let held = grant.hold()?;
        // The signer receipt is historical only. This separate enrolled host node
        // must independently read the retained exact transaction NOW.
        check_record()?;
        let terms = original.evidence().consent.terms();
        let inputs: Vec<_> = terms
            .input_bindings
            .iter()
            .map(|i| (i.action_index, i.nullifier.clone()))
            .collect();
        let qualified = match &signer_request.conflict {
            Some(candidate) => source.node.qualify_conflict(
                &journal,
                &operation,
                candidate,
                &terms.effects_digest,
                &inputs,
            )?,
            None => source.node.qualify(&journal, &operation, None)?,
        };
        grant.check()?;
        held.check()?;
        original.check_current().map_err(|_| Error::Permission)?;
        check_record()?;
        let (evidence, permit) =
            qualified.retain(&mut journal, std::slice::from_ref(&scope.destination))?;
        if let Some(request) = &request {
            self.engine.apply_native_record_resolution(
                access,
                request,
                record_guard.as_ref().ok_or(Error::Permission)?,
                &scope,
                &evidence,
                &permit,
                source.descriptor(),
                &original,
                &receipt,
                &signer_request,
                &grant,
            )?;
        } else {
            self.engine.apply_settlement_resolution(
                &scope,
                &evidence,
                &permit,
                source.descriptor(),
                &original,
                &receipt,
                &signer_request,
                &grant,
            )?;
        }
        held.check()?;
        check_record()?;
        journal.acknowledge_settlement_delivery(evidence.evidence_id(), &scope.destination)?;
        if signer_request.conflict.is_some() {
            return self.terminal.message("Canonical exact-original conflict and alternative link retained in the independent witness, signer, and local record. Original IDs, debit and obligation remain blocked. This does not authorize replacement or revised terms; reorganization or lost source freshness reopens and fences the retained history.\n");
        }
        self.terminal.message("Exact original release resolution and matching private record confidence committed to this protected local store and acknowledged. Other authorizations, recovery fences and independent journals remain separately governed. This does not grant replacement or spending permission or export a receipt.\n")
    }
}

// Preserve the selected record guard (captured by check), but never hold the
// signer's original-history read fence across its settlement write. Any error
// after the effect remains unknown; this helper never retries it.
fn settlement_with_original_recheck<T, R>(
    original: T,
    check: impl Fn(&T) -> Result<()>,
    settle: impl FnOnce() -> Result<R>,
    reacquire: impl FnOnce() -> Result<T>,
) -> Result<(T, R)> {
    check(&original)?;
    drop(original);
    let receipt = settle()?;
    let original = reacquire()?;
    check(&original)?;
    Ok((original, receipt))
}

// A bound client handoff never prompts for replacement operation/candidate/participant.
fn exact_or_selected(
    original: Option<&str>,
    select: impl FnOnce() -> Result<String>,
) -> Result<String> {
    match original {
        Some(value) => Ok(value.to_owned()),
        None => select(),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    struct SyntheticHistoryLease<'a> {
        read_held: &'a std::cell::Cell<bool>,
        original: &'static str,
    }
    impl Drop for SyntheticHistoryLease<'_> {
        fn drop(&mut self) {
            self.read_held.set(false);
        }
    }
    #[test]
    fn mismatched_selected_original_prevents_signer_settlement_effect() {
        let effects = std::cell::Cell::new(0);
        let result = settlement_with_original_recheck(
            "different-original",
            |original| {
                if *original == "selected-original" {
                    Ok(())
                } else {
                    Err(Error::Permission)
                }
            },
            || {
                effects.set(effects.get() + 1);
                Ok(())
            },
            || Ok("selected-original"),
        );
        assert!(result.is_err());
        assert_eq!(effects.get(), 0);
    }
    #[test]
    fn original_read_fence_is_released_for_settlement_and_exact_history_rechecked() {
        let read_held = std::cell::Cell::new(true);
        let record_current = std::cell::Cell::new(true);
        let checks = std::cell::Cell::new(0);
        let (original, receipt) = settlement_with_original_recheck(
            SyntheticHistoryLease {
                read_held: &read_held,
                original: "selected-original",
            },
            |lease| {
                checks.set(checks.get() + 1);
                assert!(read_held.get());
                if record_current.get() && lease.original == "selected-original" {
                    Ok(())
                } else {
                    Err(Error::Permission)
                }
            },
            || {
                assert!(
                    !read_held.get(),
                    "signer write must not retain history read fence"
                );
                assert!(record_current.get());
                Ok("synthetic-receipt")
            },
            || {
                assert!(!read_held.get());
                read_held.set(true);
                Ok(SyntheticHistoryLease {
                    read_held: &read_held,
                    original: "selected-original",
                })
            },
        )
        .unwrap();
        assert_eq!(checks.get(), 2);
        assert_eq!(receipt, "synthetic-receipt");
        assert!(read_held.get());
        assert_eq!(original.original, "selected-original");
        drop(original);
        assert!(!read_held.get());
    }
    #[test]
    fn post_settlement_reacquisition_or_provenance_failure_never_retries_effect() {
        for mode in [
            "changed-original",
            "reacquisition-failed",
            "record-revoked",
            "host-failed",
        ] {
            let effects = std::cell::Cell::new(0);
            let record_current = std::cell::Cell::new(true);
            let completion = std::cell::Cell::new(false);
            let outcome = (|| -> Result<()> {
                let (_original, _receipt) = settlement_with_original_recheck(
                    "selected-original",
                    |original| {
                        if *original == "selected-original" && record_current.get() {
                            Ok(())
                        } else {
                            Err(Error::Permission)
                        }
                    },
                    || {
                        effects.set(effects.get() + 1);
                        if mode == "record-revoked" {
                            record_current.set(false);
                        }
                        Ok("synthetic-receipt")
                    },
                    || match mode {
                        "changed-original" => Ok("different-original"),
                        "reacquisition-failed" => Err(Error::Permission),
                        _ => Ok("selected-original"),
                    },
                )?;
                if mode == "host-failed" {
                    return Err(Error::Storage);
                }
                completion.set(true);
                Ok(())
            })();
            assert!(outcome.is_err(), "{mode}");
            assert_eq!(effects.get(), 1, "{mode}");
            assert!(!completion.get(), "must retain unknown: {mode}");
        }
    }
    #[test]
    fn bound_resolution_identity_never_calls_a_replacement_prompt() {
        for original in [
            "original-operation",
            "original-candidate",
            "original-participant",
        ] {
            assert_eq!(
                exact_or_selected(Some(original), || panic!("replacement prompt must not run"))
                    .unwrap(),
                original
            );
        }
        assert_eq!(
            exact_or_selected(None, || Ok("explicit-ordinary-selection".into())).unwrap(),
            "explicit-ordinary-selection"
        );
        assert!(exact_or_selected(None, || Err(Error::Permission)).is_err());
    }

    #[test]
    fn source_credentials_require_private_regular_single_link_files() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = directory.path().join("host-key.der");
        std::fs::write(&file, b"synthetic noncredential bytes").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(credential(&file).is_ok());
        let link = directory.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(credential(&link).is_err());
        std::fs::hard_link(&file, directory.path().join("hardlink")).unwrap();
        assert!(credential(&file).is_err());
        std::fs::remove_file(directory.path().join("hardlink")).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(credential(&file).is_err());
    }
}
