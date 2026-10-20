#[cfg(all(test, feature = "synthetic-born-joined-qualification", feature = "durable-proposal"))]
pub(crate) mod financial_diagnostics_v1;
// Diagnostic projection exists only in the explicit synthetic test build. In
// every other build this macro expands to the original expression, evaluated once.
macro_rules! roster_trace {
    ($phase:ident, $operation:expr) => {
        roster_trace!(host, $phase, $operation)
    };
    ($kind:ident, $phase:ident, $operation:expr) => {{
        #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
        {
            use crate::host::synthetic_roster_trace_v1::{self as trace, Phase};
            trace::begin(Phase::$phase);
            let result = $operation;
            trace::$kind(Phase::$phase, &result);
            result
        }
        #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
        {
            $operation
        }
    }};
}
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(crate) mod synthetic_roster_trace_v1;
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(crate) mod synthetic_roster_timing_v1;

// Denial-only projection of the actual predicate/result. Outside the synthetic
// test build this is precisely the original expression, not an extra check.
macro_rules! roster_denial {
    ($kind:ident, $phase:ident, $operation:expr) => {{
        #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
        {
            use crate::host::synthetic_roster_trace_v1::{self as trace, Phase};
            let result = $operation;
            trace::$kind(Phase::$phase, &result);
            result
        }
        #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
        {
            $operation
        }
    }};
}
pub(crate) use roster_denial;

#[cfg(all(test, feature = "manual-admission", target_os = "linux"))]
mod born_test_host_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
mod born_offline_saved_proof_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
mod born_offline_return_commands_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
mod born_offline_checkpoint_commands_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
mod born_offline_checkpoint_carrier_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
mod born_offline_return_validation_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
mod born_offline_return_owner_v1;
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) mod durable_private_workspace_v1;
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
pub(crate) mod durable_dispatcher_v2;
#[cfg(feature = "financial-runtime")]
mod financial;
#[cfg(test)]
mod receipt_fixture;
mod receipts;

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
mod manual_enrollment;
use crate::{
    Error, Result,
    authority::Authority,
    backup::{self, Quiescent},
    files::{self, Directory},
    id, now,
    terminal::Terminal,
    vault::{JOURNALS, Secrets},
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use wholepact_chain::{
    ChainAdapter, ConfirmationPolicy, EncryptedSubmissionJournal, NetworkPolicy,
};
use wholepact_engine::{
    Access, Engine,
    transport_workflows::{InvitationExportRequest, TransportPeerGrantRequest},
};
use wholepact_service::{
    NativeRuntime, application_with_native_runtime,
    operator::Operator,
    operator_chain::{ChainObservationTask, EngineSettlementSink, ObservationScope},
    protected_records::ProtectedRecordsRuntime,
    protected_transport::{ProtectedTransportRuntime, TransportDirection},
    security::{ClientConfig, Permission, SecurityConfig},
};
use wholepact_storage_security::{create_encrypted, open_encrypted_quiescent as open_encrypted};
use wholepact_store::Store;
use wholepact_transport::{
    EncryptedEnvelope, ExportRequest, MessageContext, MessageOrder, PrivateInvitation,
    SqliteOutbox, SqliteReplayLedger, Timestamp, TransportPublicKey,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Explicit foreground protected NON-signing Wholepact host. Linux source configuration only; no silent profile/grant creation."
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    DurablePrivateCreateV1 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
    },

    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    DurablePrivateInitializeV1 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
    },

    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    DurablePrivateFixV1 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
    },

    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    DurablePrivateReadFixedV1 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
    },

#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    DurableDeliveryAdmitV2 {
        #[arg(long)] profile: PathBuf,
        #[arg(long)] workspace: PathBuf,
    },
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    DurableDeliveryAdmitV3 {
        #[arg(long)] profile: PathBuf,
        #[arg(long)] workspace: PathBuf,
    },
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    DurableDeliveryAdmissionStatusV3 {
        #[arg(long)] profile: PathBuf,
        #[arg(long)] workspace: PathBuf,
    },
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    DurableDeliveryAdmissionStatusV2 {
        #[arg(long)] profile: PathBuf,
        #[arg(long)] workspace: PathBuf,
    },
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    DurableDispatcherFinishV4 {
        #[arg(long)] profile: PathBuf,
        #[arg(long)] workspace: PathBuf,
    },
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    DurableDispatcherStatusV4 {
        #[arg(long)] profile: PathBuf,
        #[arg(long)] workspace: PathBuf,
    },
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    DurableDispatcherRegisterV4 {
        #[arg(long)] profile: PathBuf,
        #[arg(long)] workspace: PathBuf,
    },
    /// Back up a closed restricted successor, preserving its complete ancestor graph.
    #[cfg(feature = "financial-runtime")]
    GenerationBackup {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    /// Restore a complete generation capsule into a NEW permanently quarantined root.
    #[cfg(feature = "financial-runtime")]
    GenerationRestore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    /// Read exact lineage-qualified artifacts from a quarantined generation capsule.
    #[cfg(feature = "financial-runtime")]
    GenerationHistory {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Publish a fresh restricted layered successor; financial workflows stay disabled.
    #[cfg(feature = "financial-runtime")]
    GenerationActivate {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Unavailable complete-origin v2 informational recovery source route.
    #[cfg(feature = "financial-runtime")]
    GenerationActivateV2 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Unavailable complete-origin v3 construction-complete informational recovery source route.
    #[cfg(feature = "financial-runtime")]
    GenerationActivateV3 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Unavailable transport-complete v5 informational recovery source route.
    #[cfg(feature = "financial-runtime")]
    GenerationActivateV5 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Use explicitly entered signer-only quarantined V5 information to publish a restricted layered successor.
    #[cfg(feature = "financial-runtime")]
    GenerationActivateQuarantinedInformationalV5 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Read exact inherited artifacts under separate native private-history approval.
    #[cfg(feature = "financial-runtime")]
    RecoveryHistory {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Publish a restricted successor with fresh enrollment and preserved uncertainty.
    #[cfg(feature = "financial-runtime")]
    RecoveryActivate {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Unavailable complete-origin v2 informational recovery source route.
    #[cfg(feature = "financial-runtime")]
    RecoveryActivateV2 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Unavailable complete-origin v3 construction-complete informational recovery source route.
    #[cfg(feature = "financial-runtime")]
    RecoveryActivateV3 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Unavailable transport-complete v5 informational recovery source route.
    #[cfg(feature = "financial-runtime")]
    RecoveryActivateV5 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Use explicitly entered signer-only quarantined V5 information to publish a restricted original-backup successor.
    #[cfg(feature = "financial-runtime")]
    RecoveryActivateQuarantinedInformationalV5 {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Authenticate the complete restored inventory for native review only.
    RecoveryReview {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        successor: PathBuf,
    },
    /// Inspect exact agreement metadata from a verified quarantined restore.
    History {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        backup: PathBuf,
    },
    /// Explicitly provision a new non-signing storage profile; passphrase on /dev/tty.
    Init {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Unlock an already initialized profile. Grants and peers require fresh enrollment.
    Unlock {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Restore into a NEW quarantined profile, never an active writer.
    Restore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        test_only: bool,
    },
}
impl Command {
    /// Pure command routing only; selection does not open a source or grant any
    /// native/account permission. Generic V5 never falls back to quarantine.
    #[cfg(feature = "financial-runtime")]
    fn v5_signer_source(&self) -> Option<crate::recovery_generation::v5_routing::V5SignerSource> {
        use crate::recovery_generation::v5_routing::V5SignerSource;
        match self {
            Self::GenerationActivateV5 { .. } | Self::RecoveryActivateV5 { .. } => {
                Some(V5SignerSource::Ordinary)
            }
            Self::GenerationActivateQuarantinedInformationalV5 { .. }
            | Self::RecoveryActivateQuarantinedInformationalV5 { .. } => {
                Some(V5SignerSource::QuarantinedInformational)
            }
            _ => None,
        }
    }
    fn preflight(&self) -> Result<()> {
        #[cfg(feature = "financial-runtime")]
        if let Some(source) = self.v5_signer_source() {
            return source.require_available();
        }
        match self {
            #[cfg(feature = "financial-runtime")]
            Self::GenerationActivateV2 { .. } | Self::RecoveryActivateV2 { .. } => {
                crate::recovery_generation::v2_routing::require_available()
            }
            #[cfg(feature = "financial-runtime")]
            Self::GenerationActivateV3 { .. } | Self::RecoveryActivateV3 { .. } => {
                crate::recovery_generation::v3_routing::require_available()
            }
            _ => Ok(()),
        }
    }
}
/// No default answer: exact scope must be chosen on the foreground native terminal.
fn selected_agreement_scope(choice: &str) -> Result<(bool, bool)> {
    match choice {
        "SELECTED" => Ok((false, false)),
        "OWNED" => Ok((false, true)),
        "ALL" => Ok((true, false)),
        _ => Err(Error::Permission),
    }
}

pub fn run() -> Result<()> {
    let args = Args::parse();
    if !cfg!(target_os = "linux") {
        return Err(Error::Platform);
    }
    args.command.preflight()?;
    let terminal = Terminal::open()?;
    dispatch(terminal, args.command)
}
fn dispatch(terminal: Terminal, command: Command) -> Result<()> {
    match command {
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
        Command::DurableDeliveryAdmitV2 {profile,workspace} => financial::durable_delivery_admission_v2::admit_original(terminal,&profile,&workspace),
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
        Command::DurableDeliveryAdmissionStatusV2 {profile,workspace} => financial::durable_delivery_admission_v2::read_original_status(terminal,&profile,&workspace),
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
        Command::DurableDeliveryAdmitV3 {profile,workspace} => financial::durable_delivery_admission_v2::admit_original_v3(terminal,&profile,&workspace),
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
        Command::DurableDeliveryAdmissionStatusV3 {profile,workspace} => financial::durable_delivery_admission_v2::read_original_status_v3(terminal,&profile,&workspace),
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
        Command::DurableDispatcherFinishV4 {profile,workspace} => durable_dispatcher_v2::finish_command_v4(terminal,&profile,&workspace),
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
        Command::DurableDispatcherStatusV4 {profile,workspace} => durable_dispatcher_v2::status_command_v4(terminal,&profile,&workspace),
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
        Command::DurableDispatcherRegisterV4 {profile,workspace} => durable_dispatcher_v2::register_command_v4(terminal,&profile,&workspace),
        #[cfg(all(
            feature = "durable-proposal",
            feature = "manual-admission",
            target_os = "linux"
        ))]
        Command::DurablePrivateCreateV1 { profile, workspace } => {
            durable_private_workspace_v1::create_command_v1(terminal, &profile, &workspace)
        }
        #[cfg(all(
            feature = "durable-proposal",
            feature = "manual-admission",
            target_os = "linux"
        ))]
        Command::DurablePrivateInitializeV1 { profile, workspace } => {
            let host =
                Host::open_private_workspace_registered_v1(terminal, &profile, &workspace, true)?;
            drop(host);
            Ok(())
        }
        #[cfg(all(
            feature = "durable-proposal",
            feature = "manual-admission",
            target_os = "linux"
        ))]
        Command::DurablePrivateFixV1 { profile, workspace } => {
            let host =
                Host::open_private_workspace_registered_v1(terminal, &profile, &workspace, false)?;
            host.private_durable_fix_v1_command(&workspace)
        }
        #[cfg(all(
            feature = "durable-proposal",
            feature = "manual-admission",
            target_os = "linux"
        ))]
        Command::DurablePrivateReadFixedV1 { profile, workspace } => {
            let host =
                Host::open_private_workspace_registered_v1(terminal, &profile, &workspace, false)?;
            host.private_durable_read_fixed_v1_command(&workspace)
        }

        #[cfg(feature = "financial-runtime")]
        Command::GenerationBackup {
            profile,
            destination,
        } => crate::generation_backup::backup(terminal, &profile, &destination),
        #[cfg(feature = "financial-runtime")]
        Command::GenerationRestore {
            backup,
            destination,
        } => crate::generation_restore::restore(terminal, &backup, &destination),
        #[cfg(feature = "financial-runtime")]
        Command::GenerationHistory { profile } => {
            crate::recovered_capsule_history::read_quarantined(terminal, &profile)
        }
        #[cfg(feature = "financial-runtime")]
        Command::GenerationActivate {
            profile,
            successor,
            resume,
        } => crate::recovery_generation::layered_activate::activate(
            terminal, &profile, &successor, resume,
        ),
        #[cfg(feature = "financial-runtime")]
        Command::RecoveryHistory { profile } => crate::recovered_history::read(terminal, &profile),
        #[cfg(feature = "financial-runtime")]
        Command::RecoveryActivate {
            profile,
            backup,
            successor,
            resume,
        } => crate::recovery_generation::activate(terminal, &profile, &backup, &successor, resume),
        #[cfg(feature = "financial-runtime")]
        Command::GenerationActivateV2 {
            profile,
            successor,
            resume,
        } => crate::recovery_generation::layered_activate_v2::activate(
            terminal, &profile, &successor, resume,
        ),
        #[cfg(feature = "financial-runtime")]
        Command::GenerationActivateV3 {
            profile,
            successor,
            resume,
        } => crate::recovery_generation::layered_activate_v3::activate(
            terminal, &profile, &successor, resume,
        ),
        #[cfg(feature = "financial-runtime")]
        Command::GenerationActivateV5 {
            profile,
            successor,
            resume,
        } => crate::recovery_generation::layered_activate_v5::activate(
            terminal, &profile, &successor, resume,
        ),
        #[cfg(feature = "financial-runtime")]
        Command::RecoveryActivateV2 {
            profile,
            backup,
            successor,
            resume,
        } => crate::recovery_generation::v2_routing::activate_original(
            terminal, &profile, &backup, &successor, resume,
        ),
        #[cfg(feature = "financial-runtime")]
        Command::RecoveryActivateV3 {
            profile,
            backup,
            successor,
            resume,
        } => crate::recovery_generation::v3_routing::activate_original(
            terminal, &profile, &backup, &successor, resume,
        ),
        #[cfg(feature = "financial-runtime")]
        Command::RecoveryActivateV5 {
            profile,
            backup,
            successor,
            resume,
        } => crate::recovery_generation::v5_routing::activate_original(
            terminal, &profile, &backup, &successor, resume,
        ),
        #[cfg(feature = "financial-runtime")]
        Command::GenerationActivateQuarantinedInformationalV5 {
            profile,
            successor,
            resume,
        } => crate::recovery_generation::layered_activate_v5::activate_quarantined_informational(
            terminal, &profile, &successor, resume,
        ),
        #[cfg(feature = "financial-runtime")]
        Command::RecoveryActivateQuarantinedInformationalV5 {
            profile,
            backup,
            successor,
            resume,
        } => crate::recovery_generation::v5_routing::activate_quarantined_informational_original(
            terminal, &profile, &backup, &successor, resume,
        ),
        Command::RecoveryReview {
            profile,
            backup,
            successor,
        } => crate::recovery_inventory::review(terminal, &profile, &backup, &successor),
        Command::History { profile, backup } => crate::history::read(terminal, &profile, &backup),
        Command::Init { profile } => {
            terminal.confirm(&format!("Create a NEW local non-signing profile at {}. This generates independent encrypted journal keys, a NON-spending transport identity only. Native client credentials are generated freshly by explicit session enrollment. No wallet, peer, grant, account, signer, browser access, background service or network connection is created. Passphrase loss requires a separately verified backup. Same-user malicious PTY/OS compromise and clone detection are not solved by this terminal.",profile.display()))?;
            let p = terminal.secret("New storage passphrase (12–1024 bytes): ")?;
            let confirm = terminal.secret("Repeat passphrase: ")?;
            if *p != *confirm {
                return Err(Error::Authentication);
            }
            initialize(&profile, p.as_bytes())?;
            terminal.message("Non-signing profile initialized and locked. Run unlock explicitly to use it. No peers or app grants exist.\n")
        }
        Command::Unlock { profile } => {
            let directory = Directory::open(&profile)?;
            let password = terminal.secret("Storage passphrase: ")?;
            let secrets =
                Secrets::open(&directory.read("profile.vault", 1024)?, password.as_bytes())?;
            drop(password);
            if profile.join("restored.quarantine").exists() {
                return Err(Error::Quarantined);
            }
            let mut host = Host::open(directory, secrets, terminal.clone())?;
            let result = host.shell();
            // Revoke before dropping every runtime/authority/key owner.
            let revoked = host.authority.fence.revoke();
            drop(host);
            result?;
            revoked?;
            terminal.message("Locked. Native grants and pins ended; runtime keys and credentials were dropped and zeroized.\n")
        }
        Command::Restore {
            backup,
            destination,
            test_only,
        } => {
            let password = terminal.secret("Backup recovery passphrase: ")?;
            let new_password = terminal.secret("New restored-profile passphrase: ")?;
            let check = terminal.secret("Repeat new passphrase: ")?;
            if *new_password != *check {
                return Err(Error::Authentication);
            }
            let report = backup::restore(
                &terminal,
                &backup,
                &destination,
                password.as_bytes(),
                new_password.as_bytes(),
                test_only,
            )?;
            terminal.json(&report)?;
            terminal.message("Restored history is quarantined. No session grants, pinned peers, writer/signing authority or background observation were restored.\n")
        }
    }
}
fn initialize(path: &Path, password: &[u8]) -> Result<()> {
    let directory = Directory::create(path)?;
    let secrets = Secrets::fresh()?;
    let store = Store::create_encrypted(directory.path(JOURNALS[0])?, &secrets.key(0)?)?;
    drop(store);
    let inbox = SqliteReplayLedger::from_encrypted_connection(create_encrypted(
        directory.path(JOURNALS[1])?,
        &secrets.key(1)?,
    )?)?;
    drop(inbox);
    let outbox = SqliteOutbox::from_encrypted_connection(create_encrypted(
        directory.path(JOURNALS[2])?,
        &secrets.key(2)?,
    )?)?;
    drop(outbox);
    let submission = EncryptedSubmissionJournal::from_encrypted_connection(create_encrypted(
        directory.path(JOURNALS[3])?,
        &secrets.key(3)?,
    )?)?;
    drop(submission);
    // Last commit marker: a failed partial init is never adopted by unlock.
    directory.write_new("profile.vault", &secrets.seal(password)?)?;
    directory.inventory()
}
struct Host {
    secrets: Secrets,
    terminal: Terminal,
    engine: Engine,
    authority: Arc<Authority>,
    transport: Arc<Mutex<ProtectedTransportRuntime>>,
    submission: Arc<Mutex<EncryptedSubmissionJournal>>,
    submission_identity: wholepact_storage_security::DatabaseFileIdentity,
    access: Option<Access>,
    config: Option<SecurityConfig>,
    observation: Option<Operator>,
    #[cfg(feature = "financial-runtime")]
    financial: Option<crate::financial_profile::FinancialProfile>,
    #[cfg(feature = "financial-runtime")]
    signer_review_clients: std::collections::BTreeMap<
        (String, String),
        wholepact_signer::authority_bridge::ipc::OriginalHistoryClient,
    >,
    #[cfg(feature = "financial-runtime")]
    resolution_source: Option<Arc<crate::authority::positive_settlement::EnrolledResolutionSource>>,
    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    workspace_files: Option<durable_private_workspace_v1::OriginalWorkspaceFilesV1>,
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    dispatcher_files: Option<durable_dispatcher_v2::OriginalWorkspaceDispatcherFilesV4>,
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    dispatcher: Option<durable_dispatcher_v2::StoredDurableDispatcherV2>,
    // Rust drops fields in declaration order. Keep the exclusive profile lock
    // until every SQLite owner and possible final checkpoint above has dropped.
    directory: Directory,
}
impl Host {
    fn open(directory: Directory, secrets: Secrets, terminal: Terminal) -> Result<Self> {
        secrets.require_portable_legacy()?;
        directory.refuse_private_workspace_files()?;
        // The exclusive Directory lock is already owned; no Host/runtime exists
        // yet. Quiescent open preflights cannot race our own journal writers.
        // The vault itself distinguishes successors, even if external markers
        // disappear. Only the complete committed-generation opener admits them.
        let store = if secrets.generation_plan_digest().is_some() {
            #[cfg(feature = "financial-runtime")]
            {
                crate::recovery_generation::open_committed(&directory, &secrets)?
            }
            #[cfg(not(feature = "financial-runtime"))]
            {
                return Err(Error::Quarantined);
            }
        } else {
            directory.inventory()?;
            Store::from_encrypted_connection(open_encrypted(
                directory.path(JOURNALS[0])?,
                &secrets.key(0)?,
            )?)?
        };
        Self::open_runtime_from_store(directory, secrets, terminal, store)
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    fn open_private_workspace_original(
        directory: Directory,
        secrets: Secrets,
        terminal: Terminal,
        files: durable_private_workspace_v1::OriginalWorkspaceFilesV1,
        financial: crate::financial_profile::FinancialProfile,
    ) -> Result<Self> {
        files.check_inventory(&directory, &secrets)?;
        let store = crate::recovery_generation::open_private_workspace_original_store_v1(
            &directory, &secrets, &files,
        )?;
        let mut host = Self::open_runtime_from_store(directory, secrets, terminal, store)?;
        host.workspace_files = Some(files);
        host.financial = Some(financial);
        Ok(host)
    }
    fn open_runtime_from_store(
        directory: Directory,
        secrets: Secrets,
        terminal: Terminal,
        store: Store,
    ) -> Result<Self> {
        Self::open_runtime_from_store_checked(directory,secrets,terminal,store,None)
    }
    fn open_runtime_from_store_checked(
        directory:Directory,secrets:Secrets,terminal:Terminal,store:Store,
        expected_submission:Option<&wholepact_storage_security::DatabaseFileIdentity>,
    )->Result<Self> {
        #[cfg(feature = "financial-runtime")]
        if secrets.combined_workspace_anchor_v4().is_some() && expected_submission.is_none() { return Err(Error::Authentication); }
        let engine = Engine::from_store(store);
        let inbox = SqliteReplayLedger::from_encrypted_connection(open_encrypted(
            directory.path(JOURNALS[1])?,
            &secrets.key(1)?,
        )?)?;
        let outbox = SqliteOutbox::from_encrypted_connection(open_encrypted(
            directory.path(JOURNALS[2])?,
            &secrets.key(2)?,
        )?)?;
        #[cfg(feature = "financial-runtime")]
        let authorization_outbox =
            wholepact_signer_release::AuthorizationOutbox::from_encrypted_connection(
                &outbox,
                open_encrypted(directory.path(JOURNALS[2])?, &secrets.key(2)?)?,
            )?;
        let submission_connection = open_encrypted(directory.path(JOURNALS[3])?, &secrets.key(3)?)?;
        let submission_identity = submission_connection.database_identity()?;
        if expected_submission.is_some_and(|expected| expected != &submission_identity) { return Err(Error::Authentication); }
        let submission = Arc::new(Mutex::new(
            EncryptedSubmissionJournal::from_encrypted_connection(submission_connection)?,
        ));
        let authority = Arc::new(Authority::new(
            terminal.clone(),
            secrets.profile(),
            engine.protected_record_store_binding()?,
            secrets.transport_material()?,
        )?);
        #[cfg(not(feature = "financial-runtime"))]
        let runtime = ProtectedTransportRuntime::new(
            engine.clone(),
            inbox,
            outbox,
            authority.clone(),
            authority.clone(),
        )?;
        #[cfg(feature = "financial-runtime")]
        let runtime = ProtectedTransportRuntime::new_with_signer_release(
            engine.clone(),
            inbox,
            outbox,
            authorization_outbox,
            authority.clone(),
            authority.clone(),
        )?;
        let transport = Arc::new(Mutex::new(runtime));
        Ok(Self {
            directory,
            secrets,
            terminal,
            engine,
            authority,
            transport,
            submission,
            submission_identity,
            access: None,
            config: None,
            observation: None,
            #[cfg(feature = "financial-runtime")]
            financial: None,
            #[cfg(feature = "financial-runtime")]
            signer_review_clients: std::collections::BTreeMap::new(),
            #[cfg(feature = "financial-runtime")]
            resolution_source: None,
            #[cfg(all(
                feature = "durable-proposal",
                feature = "manual-admission",
                target_os = "linux"
            ))]
            workspace_files: None,
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
            dispatcher_files: None,
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
            dispatcher: None,
        })
    }
    fn access(&self) -> Result<&Access> {
        self.access.as_ref().ok_or(Error::Permission)
    }
    fn shell(&mut self) -> Result<()> {
        self.secrets.require_portable_legacy()?;
        self.directory.refuse_private_workspace_files()?;
        self.terminal.message("Unlocked NON-signing native host. No app grants, peers or observers are active.\nCommands: status, enroll, public-key, create, agreement, pin, grant-peer, intake, recover, recover-export, prepare-invitation, preview, invitation, import, seal, export, records, receipt-preview, receipt-preview-read, receipt-stage, receipt-write, receipt-status, observe, serve, backup, revoke, lock.\nEach sensitive selection and consent stays on this controlling terminal.\n")?;
        #[cfg(feature = "financial-runtime")]
        self.terminal.message("Financial commands: native-account-inspection-request, native-account-inspection-status, resolution-source, record-resolve, financial-init, financial-open, financial-close, candidate-prepare, candidate-read, candidate-review, candidate-construct, native-construction-request, native-proof-reconcile-request, native-proof-execute-request, native-artifact-handoff-request, native-settlement-request, native-settlement-inspect, native-dispatch-request, native-dispatch-status, native-reconciliation-request, native-reconciliation-status, native-proof-reconcile-original, native-construction-original-status, proof-status, proof-review, proof-reconcile, proof-recover, proof-run, proof-send-for-review, automatic-authorize, signature-export, transaction-export, portable-import, portable-receipt-export, signature-retain, signature-reconcile, transaction-checkpoint, transaction-dispatch, record-retain. Construction requests separate signer-native disclosure for each account; saved proof commands require an original engine-created checkpoint. Original signatures must be produced by the independently installed signer; exact dispatch requires all live signer admissions.\n")?;
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        self.terminal.message("Manual audit commands: manual-enrollment-intent, manual-enrollment-publish, manual-enrollment-continuation-intent, manual-enrollment-continuation-publish, manual-enrollment-initial-v2-intent, manual-enrollment-initial-v2-publish. The explicit initial-v2 commands retain a first Host audit after an interrupted original attempt; they never invent a V1 admission. This requests separate signer-native exact enrollment and retains audit history only; financial workflows remain disabled.\n")?;
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        self.terminal.message("Explicit viewing commands: manual-enrollment-initial-v2-publish-inventory, manual-enrollment-continuation-publish-inventory. Each adds separately reviewed fresh-wallet attachment, same-process viewing disclosure and bounded preliminary local inventory after its exact audit. Audit-only commands never disclose viewing keys. No contribution selection, construction, signing or dispatch is enabled.\n")?;
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        self.terminal.message("Restriction-only command: manual-permanent-stop-publish-v1. Source connected; native/kernel qualification-gated before prompts. It never reclaims funds or clears outstanding authorization.\n")?;
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        self.terminal.message("Additional-account audit commands: manual-roster-enrollment-intent-v2, manual-roster-enrollment-publish-v2, manual-roster-initial-continuation-intent-v2, manual-roster-initial-continued-publish-v2, manual-roster-continuation-intent-v2, manual-roster-continuation-publish-v2. Every route preserves the original account ledger and exact roster predecessor. The explicit manual-roster-continuation-publish-inventory-v2 command adds separately reviewed fresh-wallet viewing inventory only after an existing original V3 audit and exact V4 continuation. First-save routes remain audit-only. The separate manual-roster-continuation-select-v2 command adds one exact separately reviewed local input selection. The separate manual-roster-sequential-construct-v2 command permits one bounded unsigned local construction under all real owners. manual-roster-construction-inspect-v2 reads exact saved current-generation metadata only; neither command grants proving, spending or dispatch.\n")?;
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        self.terminal.message("Born proof command: born-offline-proof-run-v1 (ONE first proof of actual queued V3/V4 saved checkpoint, separate exact native one-hour permission, never uncertain retry). Born checkpoint command: born-offline-checkpoint-export-v1. Export/recover only an actual retained completed V3/V4 checkpoint to an already pinned signer; separate native proof-read/disclosure and create-only ciphertext output. No construction, new keys, signing or dispatch. Born return commands: born-return-retain-v1 (historical exact full-roster return retention/merge only), born-return-dispatch-v1 (separate genuine installed-signer, protected-wallet-current and native exact-backend gates). Every producer/origin qualification gate remains mandatory.\n")?;
        loop {
            let command = self.terminal.ask("wholepact-native> ")?;
            if matches!(command.as_str(), "lock" | "quit") {
                return Ok(());
            }
            let outcome=match command.as_str(){
                #[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
                "durable-private-source-select-v1" => self.private_durable_source_select_v1_command(),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "born-offline-checkpoint-export-v1" => self.born_offline_checkpoint_export_v1_command(),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "born-offline-proof-run-v1" => self.born_offline_proof_run_v1_command(),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "born-return-retain-v1" => self.born_return_command_v1(false),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "born-return-dispatch-v1" => self.born_return_command_v1(true),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-permanent-stop-publish-v1" => self.manual_permanent_stop_publish_v1_command().inspect_err(|_| { let _ = self.terminal.message("Permanent restriction publication is native/kernel qualification-gated before prompts. If a future admitted attempt fails after persistence, preserve the original local exclusion, witness receipt, Host publication and acknowledgment uncertainty. Never reset or infer funds reclaimed or authorization cancelled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-initial-continuation-intent-v2" => self.manual_roster_initial_continuation_intent_v2_command(),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-continuation-intent-v2" => self.manual_roster_continue_intent_v2_command(),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-enrollment-intent-v2" => self.manual_roster_enrollment_intent_v2_command().inspect_err(|_| { let _ = self.terminal.message("Roster publication did not complete cleanly; its audit may already be durable. Preserve the exact original account, roster predecessor, request, attempt and idempotency IDs. Do not rebase or reset a ledger. No financial action is enabled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-enrollment-publish-v2" => self.manual_roster_initial_publish_v2_command().inspect_err(|_| { let _ = self.terminal.message("Roster publication did not complete cleanly; its audit may already be durable. Preserve the exact original account, roster predecessor, request, attempt and idempotency IDs. Do not rebase or reset a ledger. No financial action is enabled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-initial-continued-publish-v2" => self.manual_roster_initial_continued_publish_v2_command().inspect_err(|_| { let _ = self.terminal.message("Roster publication did not complete cleanly; its audit may already be durable. Preserve the exact original account, roster predecessor, request, attempt and idempotency IDs. Do not rebase or reset a ledger. No financial action is enabled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-continuation-publish-v2" => self.manual_roster_continue_publish_v2_command().inspect_err(|_| { let _ = self.terminal.message("Roster publication did not complete cleanly; its audit may already be durable. Preserve the exact original account, roster predecessor, request, attempt and idempotency IDs. Do not rebase or reset a ledger. No financial action is enabled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-continuation-publish-inventory-v2" => self.manual_roster_continue_inventory_v2_command().inspect_err(|_| { let _ = self.terminal.message("Roster continuation inventory did not complete cleanly; its audit or import may already be durable. Preserve the exact original V3 audit, V4 attempt and immutable wallet import record. Do not replay, reopen as fresh or rebase a ledger. No financial action is enabled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-continuation-select-v2" => self.manual_roster_continue_select_v2_command().inspect_err(|_| { let _ = self.terminal.message("Roster contribution preparation did not complete cleanly. Preserve the original audit, attempt, immutable import and exact economics. Selection is one-use and cannot be replayed or used as construction, signing or dispatch authority.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-construction-inspect-v2" => self.manual_roster_construction_inspect_v2_command().inspect_err(|_| { let _ = self.terminal.message("Exact original construction metadata inspection did not complete. Preserve the original key and both journals. Missing, denied, corrupt or mismatched evidence never permits reconstruction, proof recovery, signing or dispatch. No journal repair or retry was performed.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-sequential-construct-v2" => self.manual_roster_sequential_construct_v2_command().inspect_err(|_| { let _ = self.terminal.message("Sequential non-signing construction did not complete cleanly. Retention receipts, fresh continuation attempts, witness Reserve/Consume, construction claim or exact checkpoint may already be durable. Preserve the original invocation, construction key and every journal. The separate manual-roster-construction-inspect-v2 command can review exact current-generation original metadata under fresh native consent. Do not rebuild randomized bytes, reopen a wallet as fresh, reset a ledger, prove, sign or dispatch.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-construction-inspect-v3" => self.manual_roster_construction_inspect_v3_command().inspect_err(|_| { let _ = self.terminal.message("Exact V3 saved metadata inspection did not complete. Preserve the original key and every journal. Fresh historical consent cannot recreate missing observations, consumed owners or randomized bytes. No retry, reconstruction, proof recovery, signing or dispatch is permitted.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-roster-sequential-construct-v3" => self.manual_roster_sequential_construct_v3_command().inspect_err(|_| { let _ = self.terminal.message("The V3 construction route remains qualification-gated before prompts. Preserve any original retained owners, exact invocation and construction key. The separate manual-roster-construction-inspect-v3 command reads exact saved metadata under fresh historical consent; it never grants retry, reconstruction, proof recovery, signing or dispatch.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-enrollment-intent" => self.manual_enrollment_intent_command().inspect_err(|_| { let _ = self.terminal.message("Manual enrollment did not complete cleanly. Original signer/witness admission or local audit may already exist. Preserve exact original operation, export and Host idempotency IDs; do not create a replacement or renew expired admission. No financial action is enabled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-enrollment-publish" => self.manual_enrollment_publish_command().inspect_err(|_| { let _ = self.terminal.message("Manual enrollment publication did not complete cleanly. Original signer/witness admission or local audit may already exist. Preserve exact original operation, export and Host idempotency IDs; do not create a replacement, reset an existing writer, or renew expired admission. No financial action is enabled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-enrollment-continuation-intent" => self.manual_enrollment_continuation_command(command.as_str()).inspect_err(|_| { let _ = self.terminal.message("Continuation preparation did not complete cleanly. Preserve the original enrollment, any exact retained continuation/signature export and all immutable IDs. No new acquisition, reset or financial action is authorized.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-enrollment-continuation-publish" => self.manual_enrollment_continuation_command(command.as_str()).inspect_err(|_| { let _ = self.terminal.message("Manual continuation publication did not complete cleanly. Original native/witness admission, session history or local audit may already exist. Preserve the exact continuation, operation and Host idempotency IDs; never reset the original certificate/epoch or renew an expired admission. No financial action is enabled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-enrollment-initial-v2-intent" => self.manual_enrollment_continuation_command(command.as_str()).inspect_err(|_| { let _ = self.terminal.message("Initial V2 preparation did not complete cleanly. Preserve the original born account, original enrollment intent and any exact successor-attempt export. No replacement birth, account, acquisition or financial operation is authorized.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-enrollment-initial-v2-publish" => self.manual_enrollment_continuation_command(command.as_str()).inspect_err(|_| { let _ = self.terminal.message("First Host publication through V2 did not complete cleanly. A genuine native/witness admission or immutable local audit may already exist. Preserve its exact request, continuation, session and first-publication key; retry that exact operation. Later attempts require the separate existing-audit continuation flow. No financial action is enabled.\n"); }),
                #[cfg(all(feature = "manual-admission", target_os = "linux"))]
                "manual-enrollment-initial-v2-publish-inventory" | "manual-enrollment-continuation-publish-inventory" => self.manual_enrollment_continuation_command(command.as_str()).inspect_err(|_| { let _ = self.terminal.message("Publication/inventory did not complete cleanly. The exact immutable audit, viewing disclosure, encrypted attachment or partial public-block scan may already exist. Preserve the original IDs, files and attachment. Reopened/pending wallets are denied by this fresh-only command; no automatic retry, replacement account, deadline renewal, empty-account claim or spending authority follows.\n"); }),
                #[cfg(feature = "financial-runtime")]
                "resolution-source" => self.financial_resolution_source(),
                #[cfg(feature = "financial-runtime")]
                "record-resolve" => self.financial_record_resolve().inspect_err(|_| { let _ = self.terminal.message("Resolution did not complete cleanly. Independent signer/witness or local commits may already exist. Preserve journals and reuse the exact original IDs with fresh review and node reads; no replacement is authorized.\n"); }),
                #[cfg(feature = "financial-runtime")]
                "financial-init"=>self.financial_open(true),
                #[cfg(feature = "financial-runtime")]
                "financial-open"=>self.financial_open(false),
                #[cfg(feature = "financial-runtime")]
                "proof-send-for-review" => self.financial_proof_delivery(),
                #[cfg(feature = "financial-runtime")]
                "automatic-authorize" => self.financial_automatic_authorization().inspect_err(|_| { let _ = self.terminal.message("Automatic authorization did not complete cleanly. Preserve the original authorization ID and all journals; a coordinator intent or original signer result may remain. No new attempt or replacement is authorized.\n"); }),
                #[cfg(feature = "financial-runtime")]
                "signature-export" => self.financial_signature_export(),
                #[cfg(feature = "financial-runtime")]
                "portable-import" => self.portable_import(),
                #[cfg(feature = "financial-runtime")]
                "portable-receipt-export" => self.portable_receipt_export(),
                #[cfg(feature = "financial-runtime")]
                "transaction-export" | "signature-retain" | "signature-reconcile" | "transaction-checkpoint" | "transaction-dispatch" | "record-retain" => self.financial_settle(&command),
                #[cfg(feature = "financial-runtime")]
                "candidate-construct" => self.financial_construct(),
                #[cfg(feature = "financial-runtime")]
                "native-construction-request" => self.native_construction_request(),
                #[cfg(feature = "financial-runtime")]
                "native-proof-reconcile-request" => self.native_proof_reconcile_request(),
                #[cfg(feature = "financial-runtime")]
                "native-proof-execute-request" => self.native_proof_execute_request(),
                #[cfg(feature = "financial-runtime")]
                "native-artifact-handoff-request" => self.native_artifact_handoff_request(),
                #[cfg(feature = "financial-runtime")]
                "native-settlement-request" => self.native_settlement_request(false),
                #[cfg(feature = "financial-runtime")]
                "native-settlement-inspect" => self.native_settlement_request(true),
                #[cfg(feature = "financial-runtime")]
                "native-dispatch-request" => self.native_dispatch_request(false),
                #[cfg(feature = "financial-runtime")]
                "native-dispatch-status" => self.native_dispatch_request(true),
                #[cfg(feature = "financial-runtime")]
                "native-account-inspection-request" => self.native_account_inspection_request(false),
                #[cfg(feature = "financial-runtime")]
                "native-account-inspection-status" => self.native_account_inspection_request(true),
                #[cfg(feature = "financial-runtime")]
                "native-reconciliation-request" => self.native_reconciliation_request(false),
                #[cfg(feature = "financial-runtime")]
                "native-reconciliation-status" => self.native_reconciliation_request(true),
                #[cfg(feature = "financial-runtime")]
                "native-proof-reconcile-original" => self.native_proof_reconcile_original(),
                #[cfg(feature = "financial-runtime")]
                "native-construction-original-status" => self.native_construction_original_status(),
                #[cfg(feature = "financial-runtime")]
                "candidate-prepare" | "candidate-read" | "candidate-review" => self.financial_candidate(&command),
                #[cfg(feature = "financial-runtime")]
                "proof-status" | "proof-review" | "proof-reconcile" | "proof-run" | "proof-recover" => self.financial_proof(&command),
                #[cfg(feature = "financial-runtime")]
                "financial-close"=>{self.signer_review_clients.clear();self.financial=None;self.terminal.message("Financial journals closed. Existing authority and exposure are preserved.\n")},
                "status"=>self.terminal.message("Protected storage open; wallet/signing/financial submission unavailable. Session grants and peer pins are nonrestorable. Account exposure remains unknown.\n"),
                "enroll"=>self.enroll(),"public-key"=>{let key=self.secrets.transport()?.public_key()?;self.terminal.message(&format!("NON-spending transport public key: {}\nFingerprint: {}\n",hex::encode(key.as_bytes()),key.fingerprint()))},
                "create"=>self.create(),"agreement"=>self.agreement(),"import"=>self.import(),"pin"=>self.pin(),"grant-peer"=>self.grant_peer(),"intake"=>self.intake(),"recover"=>self.recover(),"recover-export"=>self.recover_export(),"prepare-invitation"=>self.prepare_invitation(),"preview"=>self.preview(false),"invitation"=>self.preview(true),"seal"=>self.seal(),"export"=>self.export(),"records"=>self.records(),"receipt-preview"=>self.receipt_preview(),"receipt-preview-read"=>self.receipt_preview_read(),"receipt-stage"=>self.receipt_stage(),"receipt-write"=>self.receipt_write(),"receipt-status"=>self.receipt_status(),"observe"=>self.observe(),"serve"=>self.serve(),"backup"=>self.backup(),
                "revoke"=>{self.authority.fence.revoke()?;#[cfg(feature = "financial-runtime")] { self.resolution_source=None; self.signer_review_clients.clear(); } self.config=None;self.access=None;self.observation=None;self.terminal.message("All session authority revoked. Lock and unlock for a fresh native enrollment.\n")},
                _=>self.terminal.message("Unknown command. Type lock to end this session.\n"),
            };
            if let Err(error) = outcome {
                self.terminal.message(&format!("{error}\n"))?;
            }
        }
    }
    fn enroll(&mut self) -> Result<()> {
        if self.config.is_some() {
            return Err(Error::Permission);
        }
        let principal = self.terminal.ask("Local application principal ID: ")?;
        id(&principal)?;
        if !principal
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(Error::Invalid);
        }
        let choice = self.terminal.ask("Scope choice: type SELECTED for only exact agreement IDs (including any new IDs you intend to create), OWNED for all existing AND future agreements owned by this principal plus selected shared IDs, or ALL for every local agreement: ")?;
        let (all, include_owned) = selected_agreement_scope(&choice)?;
        let agreements = if all {
            BTreeSet::new()
        } else {
            self.terminal
                .ask(if include_owned {
                    "Additional shared agreement IDs, comma-separated; blank for none: "
                } else {
                    "Exact selected agreement IDs, comma-separated; blank grants no agreements: "
                })?
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        };
        for a in &agreements {
            id(a)?;
        }
        let mode=self.terminal.ask("Grant READ only, or PREPARE (read/propose/intent/coordinate/disclose; never signing/submission)? ")?;
        let permissions = match mode.as_str() {
            "READ" => BTreeSet::from([Permission::Read]),
            "PREPARE" => BTreeSet::from([
                Permission::Read,
                Permission::Propose,
                Permission::Intent,
                Permission::Coordinate,
                Permission::Disclose,
            ]),
            _ => return Err(Error::Permission),
        };
        let browser_origin = self.terminal.ask("Optional exact browser origin for this session (for example http://127.0.0.1:4319); blank keeps native-app-only access: ")?;
        let allowed_origins = native_browser_origins(&browser_origin);
        // Reuse the service's exact-origin validation before credentials or grants.
        SecurityConfig {
            clients: vec![ClientConfig {
                client_id: principal.to_string(),
                bootstrap_token: "x".repeat(32),
                permissions: permissions.clone(),
                agreement_ids: agreements.clone(),
                all_agreements: all,
                include_owned_agreements: include_owned,
            }],
            allowed_origins: allowed_origins.clone(),
        }
        .validate()
        .map_err(|_| Error::Invalid)?;
        let destination=PathBuf::from(self.terminal.ask("New private bootstrap credential file (absolute path; manually enter it only in the approved local application): ")?.as_str());
        self.directory.external_destination(&destination)?;
        self.terminal.confirm(&format!("Grant this session until lock/restart/revoke.\nProfile: {}\nPrincipal: {}\nPermissions: {permissions:?}\nEvery local agreement: {all}\nExplicit scope mode: {}\nOWNED expansion enabled: {include_owned} (ALL already includes every agreement)\nExplicit selected/shared agreement IDs: {agreements:?}\nSELECTED does not expand when this principal creates or owns another agreement.\nWrite native credential to: {}\nAllowed exact browser origins: {allowed_origins:?}. Browser requests still require separate native private-operation review. No spending, signing, account ownership or submission permission is granted.",self.secrets.profile(),principal.as_str(),choice.as_str(),destination.display()))?;
        let material = Zeroizing::new(crate::random::<32>()?);
        let token = Zeroizing::new(hex::encode(material.as_slice()));
        files::write_new(&destination, token.as_bytes())?;
        self.authority.enroll(&principal)?;
        self.access = Some(Access {
            include_owned_agreements: include_owned,
            principal_id: principal.to_string(),
            agreement_ids: agreements.clone(),
            all_agreements: all,
        });
        self.config = Some(SecurityConfig {
            clients: vec![ClientConfig {
                include_owned_agreements: include_owned,
                client_id: principal.to_string(),
                bootstrap_token: token.to_string(),
                permissions,
                agreement_ids: agreements,
                all_agreements: all,
            }],
            allowed_origins,
        });
        self.terminal.message("Session enrolled; credential was written privately to the exact selected native file. Keep that file private and remove it when no longer needed.\n")
    }
    fn path(&self, prompt: &str) -> Result<PathBuf> {
        Ok(PathBuf::from(self.terminal.ask(prompt)?.as_str()))
    }
    fn read_json<T: DeserializeOwned>(&self, prompt: &str) -> Result<T> {
        let path = self.path(prompt)?;
        let bytes = Zeroizing::new(files::read_artifact(&path, 262_144)?);
        wholepact_core::parse_typed_json(&bytes).map_err(|_| Error::Invalid)
    }
    fn pair(&self) -> Result<(String, String)> {
        Ok((
            self.terminal.ask("Agreement ID: ")?.to_string(),
            self.terminal.ask("Opaque artifact handle: ")?.to_string(),
        ))
    }
    fn create(&self) -> Result<()> {
        let draft: wholepact_core::AgreementDraft = self.read_json("Native draft JSON file: ")?;
        self.terminal.confirm(&format!(
            "Create NON-binding draft for principal {}:\n{}",
            self.access()?.principal_id,
            serde_json::to_string_pretty(&draft)?
        ))?;
        let result = self.engine.create(
            self.access()?,
            &wholepact_transport::random_message_id()?,
            draft,
        )?;
        self.terminal.json(&result)
    }
    fn agreement(&self) -> Result<()> {
        let agreement = self.terminal.ask("Agreement ID: ")?;
        self.terminal
            .json(&self.engine.get(self.access()?, &agreement)?)?;
        self.terminal.message(&format!(
            "Invitation agreement digest: {}\n",
            self.engine
                .invitation_agreement_digest(self.access()?, &agreement)?
        ))
    }
    fn import(&self) -> Result<()> {
        let (agreement, handle) = self.pair()?;
        let mut runtime = self.transport.lock().map_err(|_| Error::Invalid)?;
        let preview = runtime.preview(self.access()?, &agreement, &handle)?;
        let revision = preview.expected_revision.ok_or(Error::Unsupported)?;
        let key = preview.idempotency_key.ok_or(Error::Unsupported)?;
        let result = runtime.import(self.access()?, &agreement, &handle, &key, revision)?;
        self.terminal.json(&result)
    }
    fn pin(&self) -> Result<()> {
        let context: MessageContext = self.read_json("Exact expected context JSON file: ")?;
        let direction = match self
            .terminal
            .ask("Direction (incoming/outgoing): ")?
            .as_str()
        {
            "incoming" => TransportDirection::Incoming,
            "outgoing" => TransportDirection::Outgoing,
            _ => return Err(Error::Invalid),
        };
        let bytes = hex::decode(
            self.terminal
                .ask("Independently verified peer public key (64 hex): ")?
                .as_bytes(),
        )
        .map_err(|_| Error::Invalid)?;
        let peer = TransportPublicKey::from_bytes(bytes.try_into().map_err(|_| Error::Invalid)?)?;
        self.authority
            .pin(&self.access()?.principal_id, context, direction, peer)
    }
    fn grant_peer(&self) -> Result<()> {
        let request: TransportPeerGrantRequest =
            self.read_json("Exact nonbinding transport peer grant JSON file: ")?;
        let agreement = self.terminal.ask("Agreement ID: ")?;
        let revision = parse_number(&self.terminal.ask("Current agreement revision: ")?)?;
        self.terminal.confirm(&format!("Enroll this exact NON-spending transport participation grant into the encrypted agreement journal. It remains historical after restore; native peer pins still require re-enrollment.\nPrincipal: {}\nAgreement: {}\nRevision: {revision}\n{}",self.access()?.principal_id,agreement.as_str(),serde_json::to_string_pretty(&request)?))?;
        let result = self.engine.grant_transport_peer(
            self.access()?,
            &wholepact_transport::random_message_id()?,
            &agreement,
            revision,
            request,
        )?;
        self.terminal.json(&result)
    }
    fn intake(&self) -> Result<()> {
        let held = self.authority.fence.acquire(now()?.saturating_add(300))?;
        let context: MessageContext =
            self.read_json("Independently expected context JSON file: ")?;
        let path = self.path("Encrypted transport file: ")?;
        let bytes = files::read_artifact(&path, wholepact_transport::MAX_FILE_BYTES)?;
        use sha2::Digest;
        self.terminal.confirm(&format!("Authenticate and retain encrypted transport input locally, then preview exact private fields. Ciphertext may remain retained if a later approval is rejected.\nPrincipal: {}\nContext: {}\nSelected path: {}\nCiphertext SHA256: {}",self.access()?.principal_id,serde_json::to_string_pretty(&context)?,path.display(),hex::encode(sha2::Sha256::digest(&bytes))))?;
        let result = self
            .transport
            .lock()
            .map_err(|_| Error::Invalid)?
            .stage_incoming(
                self.access()?,
                context,
                &EncryptedEnvelope::from_bytes(bytes)?,
            )?;
        held.check()?;
        self.terminal.json(&result)
    }
    fn recover(&self) -> Result<()> {
        let context: MessageContext = self.read_json("Original exact context JSON file: ")?;
        let sequence = parse_number(&self.terminal.ask("Original retained sequence: ")?)?;
        let result = self
            .transport
            .lock()
            .map_err(|_| Error::Invalid)?
            .stage_recovered(self.access()?, context, sequence)?;
        self.terminal.json(&result)
    }
    fn recover_export(&self) -> Result<()> {
        let input: InvitationInput =
            self.read_json("Original exact invitation export JSON file: ")?;
        let result = self
            .transport
            .lock()
            .map_err(|_| Error::Invalid)?
            .stage_committed_invitation(
                self.access()?,
                InvitationExportRequest {
                    expected_agreement_revision: input.expected_agreement_revision,
                    transport: ExportRequest {
                        context: input.context,
                        order: input.order,
                        purpose: input.purpose,
                        persistence_warning: input.persistence_warning,
                    },
                    invitation: input.invitation,
                },
            )?;
        self.terminal.json(&result)
    }
    fn prepare_invitation(&self) -> Result<()> {
        let input: InvitationInput = self.read_json("Exact invitation export JSON file: ")?;
        let result = self
            .transport
            .lock()
            .map_err(|_| Error::Invalid)?
            .stage_invitation(
                self.access()?,
                InvitationExportRequest {
                    expected_agreement_revision: input.expected_agreement_revision,
                    transport: ExportRequest {
                        context: input.context,
                        order: input.order,
                        purpose: input.purpose,
                        persistence_warning: input.persistence_warning,
                    },
                    invitation: input.invitation,
                },
            )?;
        self.terminal.json(&result)
    }
    fn preview(&self, invitation: bool) -> Result<()> {
        let (a, h) = self.pair()?;
        let runtime = self.transport.lock().map_err(|_| Error::Invalid)?;
        if invitation {
            self.terminal
                .json(&runtime.received_invitation(self.access()?, &h)?)
        } else {
            self.terminal
                .json(&runtime.preview(self.access()?, &a, &h)?)
        }
    }
    fn seal(&self) -> Result<()> {
        let (a, h) = self.pair()?;
        let result = self
            .transport
            .lock()
            .map_err(|_| Error::Invalid)?
            .seal_invitation_export(self.access()?, &a, &h)?;
        self.terminal.json(&result)
    }
    fn export(&self) -> Result<()> {
        let (a, h) = self.pair()?;
        let destination = self.path("New local encrypted export path: ")?;
        self.directory.external_destination(&destination)?;
        let held = self.authority.fence.acquire(now()?.saturating_add(120))?;
        let envelope = self
            .transport
            .lock()
            .map_err(|_| Error::Invalid)?
            .retrieve_encrypted_export(self.access()?, &a, &h)?;
        use sha2::Digest;
        self.terminal.confirm(&format!("Write this exact already-committed ciphertext to a new local file. No transmission or delivery acknowledgment is implied.\nProfile: {}\nPrincipal: {}\nAgreement: {a}\nHandle: {h}\nDestination: {}\nCiphertext SHA256: {}",self.secrets.profile(),self.access()?.principal_id,destination.display(),hex::encode(sha2::Sha256::digest(envelope.as_bytes()))))?;
        held.check()?;
        files::write_new(&destination, envelope.as_bytes())?;
        held.check()?;
        self.terminal
            .message("Encrypted local export written. External delivery is not established.\n")
    }
    fn records(&self) -> Result<()> {
        let runtime = ProtectedRecordsRuntime::new(
            self.engine.clone(),
            self.secrets.profile(),
            self.authority.clone(),
            60,
        )?;
        self.terminal.json(&runtime.status(self.access()?)?)
    }
    fn observe(&mut self) -> Result<()> {
        #[cfg(feature = "financial-runtime")]
        self.require_financial_generation_admission()?;
        let access = self.access()?.clone();
        if !self.config.as_ref().is_some_and(|config| {
            config.clients.iter().any(|client| {
                client.client_id == access.principal_id
                    && client.permissions.contains(&Permission::Coordinate)
            })
        }) {
            return Err(Error::Permission);
        }
        let operation = self
            .terminal
            .ask("EXISTING retained submission operation ID (never a transaction ID): ")?;
        let source = self.terminal.ask("Provider source ID: ")?;
        let endpoint = self.terminal.ask("Exact HTTPS testnet provider origin: ")?;
        let adapter = ChainAdapter::testnet(&source, &endpoint, NetworkPolicy::default())?;
        let policy = ConfirmationPolicy::new(10, 10, vec![source.to_string()])?;
        let scope = {
            let journal = self.submission.lock().map_err(|_| Error::Invalid)?;
            ObservationScope {
                profile_id: self.secrets.profile(),
                journal_identity: journal.identity().to_owned(),
                transaction: journal
                    .retained_submission_descriptor(&operation)?
                    .ok_or(Error::Unsupported)?,
                sources: vec![adapter.identity().clone()],
                policy: policy.clone(),
            }
        };
        let expires = now()?.saturating_add(3600);
        self.authority.approve_observation(scope.clone(), expires)?;
        let sink_scope = self
            .engine
            .settlement_sink_scope(&scope.journal_identity, &scope.transaction)?;
        let mutation_authority = self.authority.approve_settlement_sink(
            self.engine.clone(),
            access,
            sink_scope,
            expires,
        )?;
        let sink = EngineSettlementSink::new(
            self.engine.clone(),
            &scope.journal_identity,
            &scope.transaction,
            mutation_authority,
        )
        .map_err(|_| Error::Permission)?;
        let task = ChainObservationTask::new(
            self.secrets.profile(),
            &operation,
            policy,
            vec![adapter],
            self.submission.clone(),
            self.authority.clone(),
        )
        .map_err(|_| Error::Permission)?
        .with_sinks(vec![Arc::new(sink)])
        .map_err(|_| Error::Permission)?;
        self.observation = Some(
            Operator::new(
                vec![Arc::new(task)],
                Duration::from_secs(30),
                Duration::from_secs(30),
            )
            .map_err(|_| Error::Invalid)?,
        );
        self.terminal.message("Exact provider observation and separately approved conservative local settlement invalidation are configured for up to one hour. They start only with serve and stop when that foreground server stops. Lost confidence can reopen local exposure; no positive resolution, independent signer/witness reconciliation or exposure clearance is implied.\n")
    }
    fn serve(&mut self) -> Result<()> {
        let config = self.config.clone().ok_or(Error::Permission)?;
        let port: u16 = self
            .terminal
            .ask("Explicit loopback service port (1–65535): ")?
            .parse()
            .map_err(|_| Error::Invalid)?;
        if port == 0 {
            return Err(Error::Invalid);
        }
        self.terminal.confirm(&format!("Start authenticated foreground loopback service at 127.0.0.1:{port}. Only the exact natively enrolled browser origins are allowed; no signing or submission route. Queued construction, proof execution and existing proof-job metadata requests wait until this service stops and a separate native command is selected. Ctrl+C stops and drains this runtime before returning. A maximum one-hour session is enforced.\nProfile: {}",self.secrets.profile()))?;
        let records = ProtectedRecordsRuntime::new(
            self.engine.clone(),
            self.secrets.profile(),
            self.authority.clone(),
            60,
        )?;
        let mut native = NativeRuntime::new(self.engine.clone())
            .with_records(records)
            .map_err(|_| Error::Invalid)?
            .with_shared_transport(self.transport.clone())
            .map_err(|_| Error::Invalid)?;
        #[cfg(feature = "financial-runtime")]
        if self.require_financial_generation_admission().is_ok() {
            native = native
                .with_native_request_queue()
                .map_err(|_| Error::Invalid)?;
        }
        let operator = self.observation.take();
        if let Some(ref o) = operator {
            native = native.with_operator_health(o.health());
        }
        let router = application_with_native_runtime(native, config, port, false)
            .map_err(|_| Error::Invalid)?;
        // A separately owned runtime guarantees all internal spawn_blocking jobs
        // finish before backup is reachable, even if an HTTP connection canceled.
        let rt = tokio::runtime::Runtime::new()?;
        let result=rt.block_on(async move{
            let listener=tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,port)).await?;
            let(shutdown,rx)=tokio::sync::watch::channel(false);
            let observer=operator.map(|o|tokio::spawn(o.run(rx)));
            let server=tokio::spawn(async move{axum::serve(listener,router).await});
            tokio::select!{_ = tokio::signal::ctrl_c()=>{},_ = tokio::time::sleep(Duration::from_secs(3600))=>{}}
            let _=shutdown.send(true);if let Some(t)=observer{t.await.map_err(|_|Error::Storage)?;}
            // Abort networking including SSE; runtime drop joins blocking engine work.
            server.abort();let _=server.await;Ok::<(),Error>(())
        });
        finish_foreground_service(rt, result)?;
        self.terminal.message("Foreground service and observer stopped; all runtime jobs drained. Native commands and backup are available.\n")
    }
    fn backup(&mut self) -> Result<()> {
        self.secrets.require_portable_legacy()?;
        self.directory.refuse_private_workspace_files()?;
        if self.secrets.generation_plan_digest().is_some() {
            return Err(Error::RecoveryBackupUnsupported);
        }
        let path = self.path("NEW private backup directory (absolute): ")?;
        self.directory.external_destination(&path)?;
        let password = self.terminal.secret("Backup recovery passphrase: ")?;
        let repeat = self
            .terminal
            .secret("Repeat backup recovery passphrase: ")?;
        if *password != *repeat {
            return Err(Error::Authentication);
        }
        // This command cannot run concurrently with serve: it is reached only
        // after serve has returned and dropped its entire owned Tokio runtime.
        self.observation = None;
        #[cfg(feature = "financial-runtime")]
        drop(self.financial.take());
        let quiescent = Quiescent {
            directory: &self.directory,
            secrets: &self.secrets,
            terminal: &self.terminal,
        };
        let report = quiescent.snapshot(&path, password.as_bytes())?;
        self.terminal.json(&report)
    }
}
fn parse_number(s: &str) -> Result<u64> {
    s.parse().map_err(|_| Error::Invalid)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationInput {
    expected_agreement_revision: u64,
    context: MessageContext,
    order: MessageOrder,
    purpose: String,
    persistence_warning: String,
    invitation: PrivateInvitation,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_init_private_lock_and_no_creation_on_open() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("profile");
        assert!(Directory::open(&path).is_err());
        assert!(!path.exists());
        let password = Zeroizing::new(hex::encode(crate::random::<24>().unwrap()));
        initialize(&path, password.as_bytes()).unwrap();
        let dir = Directory::open(&path).unwrap();
        assert!(matches!(Directory::open(&path), Err(Error::Locked)));
        dir.inventory().unwrap();
        let vault = dir.read("profile.vault", 1024).unwrap();
        let secrets = Secrets::open(&vault, password.as_bytes()).unwrap();
        let store = Store::open_encrypted(dir.path(JOURNALS[0]).unwrap(), &secrets.key(0).unwrap())
            .unwrap();
        assert_eq!(store.list_agreements().unwrap().len(), 0);
        assert!(Secrets::open(&vault, b"incorrect-long-password").is_err());
        assert!(initialize(&path, password.as_bytes()).is_err());
        drop(store);
        drop(dir);
        assert!(Directory::open(&path).is_ok());
    }
}

#[cfg(all(test, target_os = "linux", feature = "financial-runtime"))]
mod generation_commands_tests;

#[cfg(all(test, feature = "financial-runtime"))]
mod complete_origin_command_tests {
    use super::*;
    #[test]
    fn explicit_v2_commands_fail_preflight_and_legacy_commands_keep_their_mode() {
        for command in [
            "generation-activate-v2",
            "recovery-activate-v2",
            "generation-activate-v3",
            "recovery-activate-v3",
        ] {
            let mut args = vec![
                "host",
                command,
                "--profile",
                "/synthetic/source",
                "--successor",
                "/synthetic/target",
            ];
            if command.starts_with("recovery") {
                args.extend(["--backup", "/synthetic/backup"]);
            }
            for resume in [false, true] {
                let mut input = args.clone();
                if resume {
                    input.push("--resume");
                }
                let parsed = Args::try_parse_from(input).unwrap();
                assert!(matches!(
                    parsed.command.preflight(),
                    Err(Error::CompleteOriginRecoveryUnavailable)
                ));
            }
        }
        let parsed = Args::try_parse_from([
            "host",
            "generation-activate",
            "--profile",
            "/synthetic/source",
            "--successor",
            "/synthetic/target",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::GenerationActivate { .. }));
        assert!(parsed.command.preflight().is_ok());
        assert!(
            Args::try_parse_from([
                "host",
                "generation-activate",
                "--profile",
                "/source",
                "--successor",
                "/target",
                "--protocol-version",
                "2"
            ])
            .is_err()
        );
    }
}

#[cfg(test)]
mod selected_scope_tests {
    use super::*;
    #[test]
    fn selected_scope_requires_an_explicit_exact_mode() {
        assert_eq!(
            selected_agreement_scope("SELECTED").unwrap(),
            (false, false)
        );
        assert_eq!(selected_agreement_scope("OWNED").unwrap(), (false, true));
        assert_eq!(selected_agreement_scope("ALL").unwrap(), (true, false));
        for bad in ["", "selected", "ALL ", "YES", "true"] {
            assert!(selected_agreement_scope(bad).is_err());
        }
    }
}

/// Shell routing only, never an authority or a financial fallback selector.
#[cfg(any(test, all(feature = "manual-admission", target_os = "linux")))]
#[derive(Debug, PartialEq, Eq)]
enum ManualContinuationRoute {
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    Intent,
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    Publish,
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    InitialV2Intent,
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    InitialV2Publish,
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    PublishInventory,
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    InitialV2PublishInventory,
}
#[cfg(any(test, all(feature = "manual-admission", target_os = "linux")))]
fn manual_continuation_route(command: &str) -> Option<ManualContinuationRoute> {
    match command {
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        "manual-enrollment-continuation-intent" => Some(ManualContinuationRoute::Intent),
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        "manual-enrollment-continuation-publish" => Some(ManualContinuationRoute::Publish),
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        "manual-enrollment-initial-v2-intent" => Some(ManualContinuationRoute::InitialV2Intent),
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        "manual-enrollment-initial-v2-publish" => Some(ManualContinuationRoute::InitialV2Publish),
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        "manual-enrollment-continuation-publish-inventory" => {
            Some(ManualContinuationRoute::PublishInventory)
        }
        #[cfg(all(feature = "manual-admission", target_os = "linux"))]
        "manual-enrollment-initial-v2-publish-inventory" => {
            Some(ManualContinuationRoute::InitialV2PublishInventory)
        }
        _ => None,
    }
}
#[cfg(test)]
mod manual_continuation_routing_tests {
    use super::*;
    #[test]
    fn continuation_shell_rejects_arguments_and_other_financial_routes() {
        for command in [
            "manual-enrollment-continuation",
            "manual-enrollment-continuation-intent extra",
            "manual-enrollment-continuation-publish --approved",
            "manual-enrollment-continuation-publish=true",
            "manual-enrollment-continuation-publish\nnext",
            "manual-enrollment-initial-v2",
            "manual-enrollment-initial-v2-intent extra",
            "manual-enrollment-initial-v2-publish --approved",
            "manual-enrollment-initial-v2-publish=true",
            "manual-enrollment-initial-v2-publish\nnext",
            "manual-enrollment-initial-v2-publish ",
            "manual-enrollment-initial-v2-publish-inventory --approved",
            "manual-enrollment-continuation-publish-inventory=true",
            "manual-enrollment-continuation-publish-inventory\nnext",
            "manual-enrollment-initial-v2-publish-inventory ",
            "MANUAL-ENROLLMENT-INITIAL-V2-PUBLISH",
            "candidate-construct",
            "financial-open",
            "transaction-dispatch",
            "manual-enrollment-publish",
        ] {
            assert!(manual_continuation_route(command).is_none());
        }
    }
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    #[test]
    fn only_exact_continuation_names_select_nonfinancial_routes() {
        assert_eq!(
            manual_continuation_route("manual-enrollment-continuation-intent"),
            Some(ManualContinuationRoute::Intent)
        );
        assert_eq!(
            manual_continuation_route("manual-enrollment-continuation-publish"),
            Some(ManualContinuationRoute::Publish)
        );
        assert_eq!(
            manual_continuation_route("manual-enrollment-initial-v2-intent"),
            Some(ManualContinuationRoute::InitialV2Intent)
        );
        assert_eq!(
            manual_continuation_route("manual-enrollment-initial-v2-publish"),
            Some(ManualContinuationRoute::InitialV2Publish)
        );
    }
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    #[test]
    fn inventory_disclosure_requires_distinct_explicit_routes() {
        assert_eq!(
            manual_continuation_route("manual-enrollment-continuation-publish-inventory"),
            Some(ManualContinuationRoute::PublishInventory)
        );
        assert_eq!(
            manual_continuation_route("manual-enrollment-initial-v2-publish-inventory"),
            Some(ManualContinuationRoute::InitialV2PublishInventory)
        );
        assert_ne!(
            manual_continuation_route("manual-enrollment-continuation-publish"),
            Some(ManualContinuationRoute::PublishInventory)
        );
        assert_ne!(
            manual_continuation_route("manual-enrollment-initial-v2-publish"),
            Some(ManualContinuationRoute::InitialV2PublishInventory)
        );
    }
    #[cfg(not(all(feature = "manual-admission", target_os = "linux")))]
    #[test]
    fn continuation_routes_are_unavailable_without_feature_and_platform() {
        assert!(manual_continuation_route("manual-enrollment-continuation-intent").is_none());
        assert!(manual_continuation_route("manual-enrollment-continuation-publish").is_none());
        assert!(manual_continuation_route("manual-enrollment-initial-v2-intent").is_none());
        assert!(manual_continuation_route("manual-enrollment-initial-v2-publish").is_none());
        assert!(
            manual_continuation_route("manual-enrollment-initial-v2-publish-inventory").is_none()
        );
        assert!(
            manual_continuation_route("manual-enrollment-continuation-publish-inventory").is_none()
        );
    }
}

fn native_browser_origins(exact: &str) -> BTreeSet<String> {
    if exact.is_empty() {
        BTreeSet::new()
    } else {
        BTreeSet::from([exact.to_owned()])
    }
}
#[cfg(test)]
mod native_request_origin_tests {
    use super::*;
    #[test]
    fn browser_origin_is_explicit_exact_and_session_scoped() {
        let mut config = SecurityConfig::development_fixture();
        config.allowed_origins = native_browser_origins("");
        assert!(config.allowed_origins.is_empty());
        assert!(config.validate().is_ok());
        for origin in ["http://127.0.0.1:4319", "http://localhost:4320"] {
            config.allowed_origins = native_browser_origins(origin);
            assert_eq!(config.allowed_origins.len(), 1);
            assert!(config.allowed_origins.contains(origin));
            assert!(config.validate().is_ok());
        }
        for origin in [
            "*",
            "null",
            "https://example.com",
            "http://localhost:4319/",
            "http://localhost:4319/path",
            " http://localhost:4319",
        ] {
            config.allowed_origins = native_browser_origins(origin);
            assert!(config.validate().is_err());
        }
    }
}

/// The foreground command loop cannot reach native request execution until
/// every blocking job from the HTTP runtime has drained, including error paths.
fn finish_foreground_service(runtime: tokio::runtime::Runtime, result: Result<()>) -> Result<()> {
    drop(runtime);
    result
}
#[cfg(test)]
mod native_request_drain_tests {
    use super::*;
    #[test]
    fn native_command_handoff_waits_for_blocking_jobs_on_success_and_error() {
        use std::sync::atomic::{AtomicBool, Ordering};
        for fail in [false, true] {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let finished = Arc::new(AtomicBool::new(false));
            let task_finished = finished.clone();
            let (started, receiver) = std::sync::mpsc::channel();
            runtime.spawn_blocking(move || {
                started.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(15));
                task_finished.store(true, Ordering::Release);
            });
            receiver.recv().unwrap();
            let outcome =
                finish_foreground_service(runtime, if fail { Err(Error::Invalid) } else { Ok(()) });
            assert!(finished.load(Ordering::Acquire));
            assert_eq!(outcome.is_err(), fail);
        }
    }
}

#[cfg(all(test, feature = "financial-runtime"))]
mod transport_complete_v5_command_tests {
    use super::*;

    fn arguments(command: &str) -> Vec<&str> {
        let mut args = vec![
            "host",
            command,
            "--profile",
            "/synthetic-not-opened/source",
            "--successor",
            "/synthetic-never-created/target",
        ];
        if command.starts_with("recovery") {
            args.extend(["--backup", "/synthetic-not-opened/backup"]);
        }
        args
    }

    #[test]
    fn explicit_v5_commands_deny_before_terminal_source_or_credentials() {
        for command in ["generation-activate-v5", "recovery-activate-v5"] {
            for resume in [false, true] {
                let mut args = arguments(command);
                if resume {
                    args.push("--resume");
                }
                let parsed = Args::try_parse_from(args).unwrap();
                assert!(matches!(
                    parsed.command,
                    Command::GenerationActivateV5 { .. } | Command::RecoveryActivateV5 { .. }
                ));
                assert!(matches!(
                    parsed.command.preflight(),
                    Err(Error::CompleteOriginRecoveryUnavailable)
                ));
            }
        }
    }

    #[test]
    fn v5_parser_never_accepts_imported_permission_or_automatic_approval() {
        for command in ["generation-activate-v5", "recovery-activate-v5"] {
            for option in [
                "--approved",
                "--yes",
                "--saved-admission",
                "--activate-writer",
                "--allow-financial",
                "--signer-password",
                "--witness-key",
            ] {
                let mut args = arguments(command);
                args.push(option);
                assert!(Args::try_parse_from(args).is_err());
            }
        }
        // Recovery requires the original backup; layered activation does not
        // silently accept an ordinary backup as a capsule predecessor.
        assert!(
            Args::try_parse_from([
                "host",
                "recovery-activate-v5",
                "--profile",
                "/source",
                "--successor",
                "/target"
            ])
            .is_err()
        );
        let mut layered = arguments("generation-activate-v5");
        layered.extend(["--backup", "/wrong-source-family"]);
        assert!(Args::try_parse_from(layered).is_err());
        let mut duplicate_target = arguments("generation-activate-v5");
        duplicate_target.extend(["--successor", "/other-target"]);
        assert!(Args::try_parse_from(duplicate_target).is_err());
    }

    #[test]
    fn v5_commands_do_not_change_legacy_or_ordinary_command_selection() {
        for command in ["generation-activate", "recovery-activate"] {
            let parsed = Args::try_parse_from(arguments(command)).unwrap();
            assert!(matches!(
                parsed.command,
                Command::GenerationActivate { .. } | Command::RecoveryActivate { .. }
            ));
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
            assert!(matches!(
                parsed.command,
                Command::Init { .. } | Command::Unlock { .. }
            ));
            assert!(parsed.command.preflight().is_ok());
        }
        for command in [
            "generation-activate-v2",
            "recovery-activate-v2",
            "generation-activate-v3",
            "recovery-activate-v3",
        ] {
            let parsed = Args::try_parse_from(arguments(command)).unwrap();
            assert!(matches!(
                parsed.command.preflight(),
                Err(Error::CompleteOriginRecoveryUnavailable)
            ));
        }
    }
}

#[cfg(test)]
#[path = "host/quarantined_v5_command_tests.rs"]
mod quarantined_v5_command_tests;
