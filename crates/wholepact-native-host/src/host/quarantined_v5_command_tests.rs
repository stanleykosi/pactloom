//! Pure parsing and command-to-source dispatch selection. Never call run(),
//! dispatch(), an enabled activation wrapper, Terminal, a source or an IPC peer.
use super::*;

const COMMANDS: [&str; 2] = [
    "generation-activate-quarantined-informational-v5",
    "recovery-activate-quarantined-informational-v5",
];
fn arguments(command: &str) -> Vec<&str> {
    let mut result = vec![
        "host",
        command,
        "--profile",
        "/synthetic-not-opened/source",
        "--successor",
        "/synthetic-never-created/target",
    ];
    if command.starts_with("recovery") {
        result.extend(["--backup", "/synthetic-not-opened/original-backup"]);
    }
    result
}

#[cfg(feature = "financial-runtime")]
#[test]
fn quarantined_v5_commands_choose_only_explicit_informational_source_without_dispatch() {
    use crate::recovery_generation::v5_routing::V5SignerSource;
    for command in COMMANDS {
        for resume in [false, true] {
            let mut args = arguments(command);
            if resume {
                args.push("--resume");
            }
            let parsed = Args::try_parse_from(args).unwrap();
            assert_eq!(
                parsed.command.v5_signer_source(),
                Some(V5SignerSource::QuarantinedInformational)
            );
            match &parsed.command {
                Command::GenerationActivateQuarantinedInformationalV5 {
                    profile,
                    successor,
                    resume: actual,
                } => {
                    assert!(command.starts_with("generation"));
                    assert_eq!(profile, Path::new("/synthetic-not-opened/source"));
                    assert_eq!(successor, Path::new("/synthetic-never-created/target"));
                    assert_eq!(*actual, resume);
                }
                Command::RecoveryActivateQuarantinedInformationalV5 {
                    profile,
                    backup,
                    successor,
                    resume: actual,
                } => {
                    assert!(command.starts_with("recovery"));
                    assert_eq!(profile, Path::new("/synthetic-not-opened/source"));
                    assert_eq!(backup, Path::new("/synthetic-not-opened/original-backup"));
                    assert_eq!(successor, Path::new("/synthetic-never-created/target"));
                    assert_eq!(*actual, resume);
                }
                _ => panic!("explicit informational command must not select another mode"),
            }
            // Only this pure availability check is exercised. No valid command
            // execution, terminal review, source open or signer contact follows.
            assert!(parsed.command.preflight().is_ok());
        }
    }
}

#[cfg(feature = "financial-runtime")]
#[test]
fn quarantined_v5_commands_refuse_source_family_substitution_and_implicit_selection() {
    assert!(
        Args::try_parse_from([
            "host",
            COMMANDS[1],
            "--profile",
            "/source",
            "--successor",
            "/target",
        ])
        .is_err()
    );
    let mut layered = arguments(COMMANDS[0]);
    layered.extend(["--backup", "/ordinary-backup-is-not-a-capsule"]);
    assert!(Args::try_parse_from(layered).is_err());
    for command in COMMANDS {
        let mut duplicate = arguments(command);
        duplicate.extend(["--successor", "/different-target"]);
        assert!(Args::try_parse_from(duplicate).is_err());
    }
    for command in ["generation-activate-v5", "recovery-activate-v5"] {
        for selector in [
            "--quarantined",
            "--quarantined-informational",
            "--signer-source",
        ] {
            let mut args = arguments(command);
            args.push(selector);
            assert!(Args::try_parse_from(args).is_err());
        }
    }
}

#[cfg(feature = "financial-runtime")]
#[test]
fn quarantined_v5_parser_cannot_import_permission_credentials_or_financial_approval() {
    for command in COMMANDS {
        for option in [
            "--approved",
            "--yes",
            "--saved-admission",
            "--activate-writer",
            "--allow-financial",
            "--signer-password",
            "--witness-key",
            "--fallback",
        ] {
            let mut args = arguments(command);
            args.push(option);
            assert!(Args::try_parse_from(args).is_err());
        }
    }
}

#[cfg(feature = "financial-runtime")]
#[test]
fn quarantined_commands_do_not_change_generic_v5_or_ordinary_source_selection() {
    use crate::recovery_generation::v5_routing::V5SignerSource;
    assert_eq!(V5SignerSource::default(), V5SignerSource::Ordinary);
    for command in ["generation-activate-v5", "recovery-activate-v5"] {
        let parsed = Args::try_parse_from(arguments(command)).unwrap();
        assert_eq!(
            parsed.command.v5_signer_source(),
            Some(V5SignerSource::Ordinary)
        );
        assert!(matches!(
            parsed.command.preflight(),
            Err(Error::CompleteOriginRecoveryUnavailable)
        ));
    }
    for command in ["generation-activate", "recovery-activate"] {
        let parsed = Args::try_parse_from(arguments(command)).unwrap();
        assert_eq!(parsed.command.v5_signer_source(), None);
        assert!(parsed.command.preflight().is_ok());
    }
    for command in ["init", "unlock"] {
        let parsed = Args::try_parse_from([
            "host",
            command,
            "--profile",
            "/synthetic-not-opened/profile",
        ])
        .unwrap();
        assert_eq!(parsed.command.v5_signer_source(), None);
        assert!(parsed.command.preflight().is_ok());
    }
    for command in [
        "generation-activate-v2",
        "recovery-activate-v2",
        "generation-activate-v3",
        "recovery-activate-v3",
    ] {
        let parsed = Args::try_parse_from(arguments(command)).unwrap();
        assert_eq!(parsed.command.v5_signer_source(), None);
        assert!(matches!(
            parsed.command.preflight(),
            Err(Error::CompleteOriginRecoveryUnavailable)
        ));
    }
}

#[cfg(not(feature = "financial-runtime"))]
#[test]
fn quarantined_v5_commands_are_absent_without_financial_runtime_feature() {
    for command in COMMANDS {
        assert!(Args::try_parse_from(arguments(command)).is_err());
    }
}
