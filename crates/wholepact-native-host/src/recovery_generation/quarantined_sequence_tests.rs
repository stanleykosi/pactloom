//! Only inert DTOs, fake clocks/observations and disposable regular files. No
//! native approval, client, socket, peer, key, proof, source or runtime is created.
use super::*;
use std::{cell::Cell, collections::VecDeque};

fn endpoint(ino: u64) -> EndpointIdentity {
    EndpointIdentity {
        directory_dev: 1,
        directory_ino: 2,
        dev: 1,
        ino,
    }
}
fn observation(endpoint: Option<EndpointIdentity>) -> EndpointObservation {
    match endpoint {
        Some(endpoint) => EndpointObservation::occupied(endpoint),
        None => EndpointObservation {
            directory_dev: 1,
            directory_ino: 2,
            endpoint: None,
        },
    }
}
fn request(account: &str, socket: &str) -> SignerRequest {
    SignerRequest {
        socket: socket.into(),
        continuity: wholepact_signer::authority_bridge::host_recovery_ipc::v5::HostRecoveryContinuityRequestV5 {
            schema_version: 5, inventory_digest: "11".repeat(32), generation_id: "22".repeat(32),
            account_id: account.into(), network_profile_id: "synthetic-network".into(), expected_writer_epoch: 1,
            expected_witness: wholepact_authority::WitnessDisclosureDescriptor {
                endpoint: "127.0.0.1:4444".into(), server_name: "localhost".into(), witness_id: "synthetic-witness".into(),
                account_id: account.into(), network_profile_id: "synthetic-network".into(),
                policy_digest: "33".repeat(32), pinned_server_certificate_digest: "44".repeat(32),
            },
        },
    }
}
fn publication(request: &SignerRequest) -> HostRecoveryPublicationRequestV5 {
    HostRecoveryPublicationRequestV5 {
        schema_version: 5,
        continuity: request.continuity.clone(),
        target_profile: "/synthetic-unopened/target".into(),
        generation_manifest_digest: "55".repeat(32),
        continuity_evidence_digest: "66".repeat(32),
    }
}

#[test]
fn quarantined_sequence_waits_for_changed_exact_endpoint_before_one_attempt() {
    let start = Instant::now();
    let clock = Cell::new(start);
    let pauses = Cell::new(0);
    let mut observations = VecDeque::from([None, Some(endpoint(3)), Some(endpoint(4))]);
    let ready = await_changed_endpoint(
        observation(Some(endpoint(3))),
        start + Duration::from_secs(5),
        || clock.get(),
        || Ok(observation(observations.pop_front().unwrap())),
        || Ok(()),
        || {
            pauses.set(pauses.get() + 1);
            clock.set(clock.get() + Duration::from_secs(1));
        },
    )
    .unwrap();
    assert_eq!(ready, endpoint(4));
    assert_eq!(pauses.get(), 2);
    assert!(observations.is_empty());
    let attempts = Cell::new(0);
    assert!(matches!(
        attempt_once(
            || Ok(()),
            || {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(Error::Authentication)
            }
        ),
        Err(Error::Authentication)
    ));
    assert_eq!(attempts.get(), 1); // A failed effect is never retried.
}

#[test]
fn quarantined_sequence_rejects_cancellation_and_stale_approval_without_effect() {
    let start = Instant::now();
    let current = Cell::new(true);
    let observations = Cell::new(0);
    assert!(
        await_changed_endpoint(
            observation(None),
            start + Duration::from_secs(5),
            || start,
            || {
                observations.set(observations.get() + 1);
                Ok(observation(None))
            },
            || if current.get() {
                Ok(())
            } else {
                Err(Error::Permission)
            },
            || current.set(false)
        )
        .is_err()
    );
    assert_eq!(observations.get(), 1);
    let attempts = Cell::new(0);
    assert!(
        attempt_once(
            || Err(Error::Permission),
            || {
                attempts.set(attempts.get() + 1);
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(attempts.get(), 0);
    // Invalidation while an effect runs cannot renew its original approval.
    current.set(true);
    assert!(
        attempt_once(
            || if current.get() {
                Ok(())
            } else {
                Err(Error::Permission)
            },
            || {
                attempts.set(attempts.get() + 1);
                current.set(false);
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(attempts.get(), 1);
}

#[test]
fn quarantined_sequence_endpoint_wait_deadline_never_renews_on_missing_or_old_path() {
    let start = Instant::now();
    let clock = Cell::new(start);
    let pauses = Cell::new(0);
    assert!(
        await_changed_endpoint(
            observation(Some(endpoint(3))),
            start + Duration::from_secs(2),
            || clock.get(),
            || Ok(observation(Some(endpoint(3)))),
            || Ok(()),
            || {
                pauses.set(pauses.get() + 1);
                clock.set(clock.get() + Duration::from_secs(1));
            }
        )
        .is_err()
    );
    assert_eq!(pauses.get(), 2);
    // A changed inode discovered at/after the original deadline is not ready.
    clock.set(start);
    assert!(
        await_changed_endpoint(
            observation(None),
            start + Duration::from_secs(1),
            || clock.get(),
            || {
                clock.set(start + Duration::from_secs(1));
                Ok(observation(Some(endpoint(4))))
            },
            || Ok(()),
            || panic!("expired readiness must not wait again")
        )
        .is_err()
    );
}

#[test]
fn quarantined_sequence_rejects_endpoint_directory_or_retained_source_replacement() {
    let start = Instant::now();
    let mut replacement = endpoint(4);
    replacement.directory_ino = 99;
    assert!(matches!(
        await_changed_endpoint(
            observation(Some(endpoint(3))),
            start + Duration::from_secs(5),
            || start,
            || Ok(observation(Some(replacement))),
            || Ok(()),
            || panic!("no retry")
        ),
        Err(Error::Authentication)
    ));

    use std::os::unix::fs::MetadataExt;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("synthetic-source");
    let retained = root.path().join("retained-original");
    std::fs::write(&source, b"original immutable bytes").unwrap();
    let original = std::fs::metadata(&source).unwrap();
    let inspected = Cell::new(0);
    assert!(
        await_changed_endpoint(
            observation(None),
            start + Duration::from_secs(5),
            || start,
            || {
                inspected.set(inspected.get() + 1);
                Ok(observation(None))
            },
            || {
                let current = std::fs::metadata(&source)?;
                if (current.dev(), current.ino()) != (original.dev(), original.ino()) {
                    return Err(Error::Authentication);
                }
                Ok(())
            },
            || {
                std::fs::rename(&source, &retained).unwrap();
                std::fs::write(&source, b"replacement synthetic bytes").unwrap();
            }
        )
        .is_err()
    );
    assert_eq!(inspected.get(), 1);
    assert_eq!(
        std::fs::read(&retained).unwrap(),
        b"original immutable bytes"
    );
}

#[test]
fn quarantined_sequence_endpoint_observation_never_accepts_regular_files_or_symlinks() {
    let root = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("synthetic-endpoint");
    assert!(observe_endpoint(&path).unwrap().endpoint.is_none());
    std::fs::write(&path, b"not a socket").unwrap();
    assert!(observe_endpoint(&path).is_err());
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(observe_endpoint(&alias).is_err());
    let directory_alias = root.path().join("directory-alias");
    std::os::unix::fs::symlink(root.path(), &directory_alias).unwrap();
    assert!(observe_endpoint(&directory_alias.join("absent")).is_err());
    assert!(observe_endpoint(Path::new("relative.sock")).is_err());
}

#[test]
fn quarantined_sequence_refuses_duplicate_native_endpoints_before_any_contact() {
    assert!(
        require_distinct_endpoints(&[request("a", "/synthetic-unopened/arbitrary.sock")]).is_err()
    );
    let a = request("a", "/synthetic-unopened/a/quarantined-history-v5.sock");
    let b = request("b", "/synthetic-unopened/a/quarantined-history-v5.sock");
    assert!(require_distinct_endpoints(&[a, b]).is_err());
    assert!(
        require_distinct_endpoints(&[
            request("a", "/synthetic-unopened/a/quarantined-history-v5.sock"),
            request("b", "/synthetic-unopened/b/quarantined-history-v5.sock"),
        ])
        .is_ok()
    );
}

#[test]
fn quarantined_sequence_publication_requires_exact_complete_prior_request_set() {
    let a = request("a", "/synthetic-unopened/a/quarantined-history-v5.sock");
    let b = request("b", "/synthetic-unopened/b/quarantined-history-v5.sock");
    let first = publication(&a);
    let second = publication(&b);
    let targets = PublicationMetadata(vec![
        (a, endpoint(3), "66".repeat(32)),
        (b, endpoint(4), "66".repeat(32)),
    ]);
    let exact = vec![first.clone(), second.clone()];
    assert!(targets.validate_requests(&exact).is_ok());
    let rendered = targets.review_scope(&exact).unwrap();
    assert_eq!(
        rendered[0]["socket"],
        "/synthetic-unopened/a/quarantined-history-v5.sock"
    );
    assert_eq!(
        rendered[1]["socket"],
        "/synthetic-unopened/b/quarantined-history-v5.sock"
    );
    assert!(targets.validate_requests(std::slice::from_ref(&first)).is_err());
    assert!(
        targets
            .validate_requests(&[first.clone(), first.clone()])
            .is_err()
    );
    let mut changed_evidence = second.clone();
    changed_evidence.continuity_evidence_digest = "77".repeat(32);
    assert!(
        targets
            .validate_requests(&[first.clone(), changed_evidence])
            .is_err()
    );
    let mut changed = second;
    changed.continuity.expected_writer_epoch = 2;
    assert!(targets.validate_requests(&[first, changed]).is_err());
}

#[test]
fn quarantined_sequence_absent_socket_keeps_verified_directory_during_entire_wait() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = root.path().join("runtime");
    let retained = root.path().join("original-runtime");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&runtime)
        .unwrap();
    let path = runtime.join(wholepact_signer::ipc::QUARANTINED_INFORMATIONAL_SOCKET_BASENAME);
    let original = observe_endpoint(&path).unwrap();
    assert!(original.endpoint.is_none());
    let start = Instant::now();
    let observations = Cell::new(0);
    let attempts = Cell::new(0);
    let ready = await_changed_endpoint(
        original,
        start + Duration::from_secs(5),
        || start,
        || {
            observations.set(observations.get() + 1);
            observe_endpoint(&path)
        },
        || Ok(()),
        || {
            // Replace only disposable directories. Neither ever holds a socket.
            std::fs::rename(&runtime, &retained).unwrap();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&runtime)
                .unwrap();
        },
    );
    let result = ready.and_then(|_| {
        attempt_once(
            || Ok(()),
            || {
                attempts.set(attempts.get() + 1);
                Ok(())
            },
        )
    });
    assert!(matches!(result, Err(Error::Authentication)));
    assert_eq!(observations.get(), 2);
    assert_eq!(attempts.get(), 0);
    let replacement = observe_endpoint(&path).unwrap();
    assert!(replacement.endpoint.is_none());
    assert_ne!(
        (original.directory_dev, original.directory_ino),
        (replacement.directory_dev, replacement.directory_ino)
    );
    assert!(retained.is_dir());
    assert_eq!(std::fs::read_dir(&retained).unwrap().count(), 0);
}

#[test]
fn quarantined_sequence_requires_existing_private_runtime_before_approval_capture() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = root.path().join("missing-runtime");
    let path = runtime.join(wholepact_signer::ipc::QUARANTINED_INFORMATIONAL_SOCKET_BASENAME);
    assert!(observe_endpoint(&path).is_err());
    assert!(!runtime.exists());
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&runtime)
        .unwrap();
    let original = observe_endpoint(&path).unwrap();
    assert!(original.endpoint.is_none());
    // A parent swapped after capture but before the first wait observation is
    // refused even though the endpoint remains absent in both directories.
    std::fs::rename(&runtime, root.path().join("retained-runtime")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&runtime)
        .unwrap();
    let start = Instant::now();
    assert!(matches!(
        await_changed_endpoint(
            original,
            start + Duration::from_secs(5),
            || start,
            || observe_endpoint(&path),
            || Ok(()),
            || panic!("no retry after replacement")
        ),
        Err(Error::Authentication)
    ));
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(observe_endpoint(&path).is_err());
}

#[test]
fn quarantined_sequence_child_report_spends_only_original_approval_budget() {
    let start = Instant::now();
    let expected = Path::new("/synthetic-unopened/runtime/quarantined-history-v5.sock");
    let original_deadline = start + Duration::from_secs(3);
    assert_eq!(phase_deadline(original_deadline, start), original_deadline);
    assert_eq!(
        phase_deadline(original_deadline, start + Duration::from_secs(2)),
        original_deadline
    );
    assert_eq!(
        phase_deadline(start + Duration::from_secs(300), start),
        start + ENDPOINT_WAIT
    );
    let clock = Cell::new(start + Duration::from_secs(2));
    let reads = Cell::new(0);
    receive_endpoint_once(
        expected,
        original_deadline,
        || clock.get(),
        || Ok(()),
        |remaining| {
            reads.set(reads.get() + 1);
            assert_eq!(remaining, Duration::from_secs(1));
            Ok(expected.into()) // Inert report data only, never a provider/peer.
        },
    )
    .unwrap();
    assert_eq!(reads.get(), 1);
    let late = receive_endpoint_once(
        expected,
        original_deadline,
        || clock.get(),
        || Ok(()),
        |_| {
            reads.set(reads.get() + 1);
            clock.set(original_deadline);
            Ok(expected.into())
        },
    );
    assert!(matches!(late, Err(Error::Permission)));
    assert_eq!(reads.get(), 2);
    assert!(
        receive_endpoint_once(
            expected,
            original_deadline,
            || clock.get(),
            || Ok(()),
            |_| {
                reads.set(reads.get() + 1);
                Ok(expected.into())
            }
        )
        .is_err()
    );
    assert_eq!(reads.get(), 2); // Expired original budget never reads again.
}

#[test]
fn quarantined_sequence_child_exit_or_wrong_path_never_attempts_pairing() {
    let start = Instant::now();
    let expected = Path::new("/synthetic-unopened/runtime/quarantined-history-v5.sock");
    for child_exited in [false, true] {
        let reads = Cell::new(0);
        let pairings = Cell::new(0);
        let result = receive_endpoint_once(
            expected,
            start + Duration::from_secs(2),
            || start,
            || Ok(()),
            |_| {
                reads.set(reads.get() + 1);
                // Model only the maintained child verifier's refusal outcome.
                // No fake child, PID, provider or authenticated peer is built.
                if child_exited {
                    Err(Error::Permission)
                } else {
                    Ok("/synthetic-unopened/other/quarantined-history-v5.sock".into())
                }
            },
        )
        .and_then(|()| {
            attempt_once(
                || Ok(()),
                || {
                    pairings.set(pairings.get() + 1);
                    Ok(())
                },
            )
        });
        assert!(result.is_err());
        assert_eq!(reads.get(), 1);
        assert_eq!(pairings.get(), 0);
    }
}

#[test]
fn quarantined_sequence_child_peer_refusal_and_report_cancellation_never_fallback() {
    let start = Instant::now();
    let expected = Path::new("/synthetic-unopened/runtime/quarantined-history-v5.sock");
    let pairings = Cell::new(0);
    let result = receive_endpoint_once(
        expected,
        start + Duration::from_secs(2),
        || start,
        || Ok(()),
        |_| Ok(expected.into()),
    )
    .and_then(|()| {
        attempt_once(
            || Ok(()),
            || {
                pairings.set(pairings.get() + 1);
                // Model the actual owned-child verifier refusing a substituted PID.
                // This is an error-only callback, not an authenticated test owner.
                Err::<(), _>(Error::Authentication)
            },
        )
    });
    assert!(matches!(result, Err(Error::Authentication)));
    assert_eq!(pairings.get(), 1);
    let current = Cell::new(true);
    let reads = Cell::new(0);
    let result = receive_endpoint_once(
        expected,
        start + Duration::from_secs(2),
        || start,
        || {
            if current.get() {
                Ok(())
            } else {
                Err(Error::Permission)
            }
        },
        |_| {
            reads.set(reads.get() + 1);
            current.set(false);
            Ok(expected.into())
        },
    )
    .and_then(|()| {
        attempt_once(
            || Ok(()),
            || {
                pairings.set(pairings.get() + 1);
                Ok(())
            },
        )
    });
    assert!(matches!(result, Err(Error::Permission)));
    assert_eq!(reads.get(), 1);
    assert_eq!(pairings.get(), 1);
}

#[test]
fn quarantined_sequence_phase_budget_refuses_late_effects_without_acceptance_or_retry() {
    let start = Instant::now();
    let original = start + Duration::from_secs(1);
    let later_approval = start + Duration::from_secs(300);
    for boundary in [
        "continuity acquire",
        "continuity Current",
        "continuity Finish",
        "client release",
        "publication acquire",
        "publication Admit",
    ] {
        let clock = Cell::new(start);
        let effects = Cell::new(0);
        let accepted = Cell::new(0);
        let result = phase_attempt_once(
            original,
            || clock.get(),
            || {
                // A still-current later disclosure/publication approval does
                // not replace the earlier retained phase deadline.
                assert!(clock.get() < later_approval);
                Ok(())
            },
            || {
                effects.set(effects.get() + 1);
                clock.set(original);
                Ok(boundary) // Inert data only; never a lease or admission.
            },
        )
        .inspect(|_| {
            accepted.set(accepted.get() + 1);
        });
        assert!(matches!(result, Err(Error::Permission)), "{boundary}");
        assert_eq!(effects.get(), 1, "{boundary}");
        assert_eq!(accepted.get(), 0, "{boundary}");
        // Expiry cannot turn the uncertain previous effect into another try.
        assert!(
            phase_attempt_once(
                original,
                || clock.get(),
                || Ok(()),
                || {
                    effects.set(effects.get() + 1);
                    Ok(())
                },
            )
            .is_err()
        );
        assert_eq!(effects.get(), 1, "{boundary}");
        // An uncertain effect failure is also checked against the original
        // deadline; it cannot bypass the post-effect restriction or retry.
        clock.set(start);
        let uncertain = phase_attempt_once(
            original,
            || clock.get(),
            || Ok(()),
            || {
                effects.set(effects.get() + 1);
                clock.set(original);
                Err::<(), _>(Error::Authentication)
            },
        );
        assert!(matches!(uncertain, Err(Error::Permission)), "{boundary}");
        assert_eq!(effects.get(), 2, "{boundary}");
    }
}

#[test]
fn quarantined_sequence_phase_budget_expiring_during_restriction_check_blocks_effect() {
    let start = Instant::now();
    let original = start + Duration::from_secs(1);
    let clock = Cell::new(start);
    let effects = Cell::new(0);
    let result = phase_attempt_once(
        original,
        || clock.get(),
        || {
            clock.set(original);
            Ok(())
        },
        || {
            effects.set(effects.get() + 1);
            Ok(())
        },
    );
    assert!(matches!(result, Err(Error::Permission)));
    assert_eq!(effects.get(), 0);
    assert!(require_phase_current(original, original).is_err());
    assert!(require_phase_current(original, original + Duration::from_nanos(1)).is_err());
}
