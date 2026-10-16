//! Test-only synthetic record initializer for the real native terminal shell.
//! This module is absent from the shipped binary. No real signer/account/proof
//! authority is created or implied by these deliberately synthetic records.
use super::*;
use wholepact_core::AuthorizationExposure;
use wholepact_core::records::{
    ExactTransactionReference, ObservationWindow, OwnAuthorizationRecord, SettlementRecord,
};
use wholepact_core::{
    AgreementDraft, Amount, ClaimedInput, ClaimedOutput, FundingPolicy, IntentStatus,
    OutputAllocation, ParticipantAllocation, ParticipationIntent, Proposal, ProposalManifest,
};
use wholepact_engine::{CandidateRequest, participant_records::*};

fn hash(b: u8) -> String {
    format!("{b:02x}").repeat(32)
}
fn amount(v: u64) -> Amount {
    Amount::from_zatoshis(v).unwrap()
}
struct FixtureAuthority {
    profile: String,
    binding: RecordStoreBinding,
    expires: String,
}
struct FixtureLease {
    scope: ParticipantRecordScope,
    expires: String,
}
impl ParticipantRecordLease for FixtureLease {
    fn scope(&self) -> &ParticipantRecordScope {
        &self.scope
    }
    fn expires_at(&self) -> &str {
        &self.expires
    }
    fn check_current(&self) -> wholepact_engine::Result<()> {
        Ok(())
    }
}
impl ParticipantRecordAuthority for FixtureAuthority {
    fn acquire<'a>(
        &'a self,
        s: &ParticipantRecordScope,
        _: &ObservationWindow,
    ) -> wholepact_engine::Result<Box<dyn ParticipantRecordLease + 'a>> {
        if s.store != self.binding
            || s.profile_id != self.profile
            || s.principal_id != "synthetic-receipt-owner"
            || s.record_id != "synthetic-private-record"
            || s.account_id != "synthetic-account-alice"
            || s.participant_id != "synthetic-alice"
            || s.action != ParticipantRecordAction::Retain
        {
            return Err(wholepact_engine::ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic fixture initializer scope mismatch",
            ));
        }
        Ok(Box::new(FixtureLease {
            scope: s.clone(),
            expires: self.expires.clone(),
        }))
    }
}
struct FixtureSource;
impl RetainedParticipantRecordSource for FixtureSource {
    fn source_id(&self) -> &str {
        "synthetic-native-receipt-fixture"
    }
    fn load_retained_record(
        &mut self,
        r: &RetainParticipantRecordRequest,
        candidate: &Proposal,
    ) -> wholepact_engine::Result<SettlementRecord> {
        let mut input = candidate.input().clone();
        input.artifact_digest = Some(hash(1));
        input.effects_commitment = Some(hash(2));
        let approved = Proposal::validate(input)?;
        let own = OwnAuthorizationRecord {
            participant_id: r.participant_id.clone(),
            account_id: r.account_id.clone(),
            proposal_digest: approved.proposal_digest().into(),
            manifest_digest: approved.manifest_digest().into(),
            effects_commitment: hash(2),
            consent_record_ref: "PRIVATE-SYNTHETIC-CONSENT-CANARY".into(),
            authorization_record_ref: "PRIVATE-SYNTHETIC-AUTHORIZATION-CANARY".into(),
            release_operation_id: Some("synthetic-never-submitted-release".into()),
            exposure: AuthorizationExposure::Released,
        };
        let tx = ExactTransactionReference {
            network_profile_id: approved.manifest().agreement.network_profile_id.clone(),
            transaction_id: hash(3),
            transaction_bytes_digest: hash(4),
            effects_commitment: hash(2),
        };
        Ok(SettlementRecord::new(
            r.record_id.clone(),
            approved,
            own,
            tx,
        )?)
    }
}
fn seed(engine: &Engine, profile: &str) -> Result<()> {
    let mut agreement: AgreementDraft = serde_json::from_slice(include_bytes!(
        "../../../wholepact-core/tests/fixtures/agreement.json"
    ))?;
    agreement.agreement_id = "synthetic-receipt-agreement".into();
    agreement.network_profile_id = wholepact_engine::candidates::PROFILE_ID.into();
    agreement.purpose = "SYNTHETIC NATIVE RECEIPT SOURCE ONLY".into();
    agreement.recipients[0].amount = amount(1000);
    agreement.funding_policy = FundingPolicy::Exact {
        target: amount(1000),
    };
    let participants: Vec<_> = [("synthetic-alice", 400, 4), ("synthetic-bob", 600, 6)]
        .into_iter()
        .map(|(name, contribution, fee)| ParticipantAllocation {
            participant_id: name.into(),
            account_id: format!(
                "synthetic-account-{}",
                name.strip_prefix("synthetic-").unwrap()
            ),
            contribution: amount(contribution),
            fee_share: amount(fee),
            fee_cap: amount(fee),
            maximum_net_debit: amount(contribution + fee),
            charges: vec![],
        })
        .collect();
    let inputs = participants
        .iter()
        .map(|p| ClaimedInput {
            input_id: format!("input-{}", p.participant_id),
            participant_id: p.participant_id.clone(),
            account_id: p.account_id.clone(),
            amount: p.maximum_net_debit,
            ownership_evidence_ref: None,
        })
        .collect();
    let request = CandidateRequest {
        manifest: ProposalManifest {
            outputs: vec![ClaimedOutput {
                output_id: "synthetic-recipient-output".into(),
                address: agreement.recipients[0].address.clone(),
                amount: amount(1000),
                allocation: OutputAllocation::Recipient {
                    recipient_id: agreement.recipients[0].recipient_id.clone(),
                },
            }],
            agreement: agreement.clone(),
            participants,
            inputs,
            transaction_fee: amount(10),
            expiry_height: 4_465_070,
        },
        previous_candidate_id: None,
    };
    let access = Access {
        include_owned_agreements: true,
        principal_id: "synthetic-receipt-owner".into(),
        all_agreements: true,
        ..Access::default()
    };
    engine.create(
        &access,
        "synthetic-native-receipt-create",
        agreement.clone(),
    )?;
    for (i, p) in request.manifest.participants.iter().enumerate() {
        engine.add_intent(
            &access,
            &format!("synthetic-native-receipt-intent-{i}"),
            &agreement.agreement_id,
            i as u64 + 1,
            ParticipationIntent {
                intent_id: format!("synthetic-intent-{i}"),
                agreement_id: agreement.agreement_id.clone(),
                participant_id: p.participant_id.clone(),
                desired_contribution: p.contribution,
                maximum_net_debit: p.maximum_net_debit,
                fee_cap: p.fee_cap,
                conditions: vec![],
                valid_until: None,
                status: IntentStatus::Active,
            },
        )?;
    }
    let candidate = engine.create_candidate(
        &access,
        "synthetic-native-receipt-candidate",
        &agreement.agreement_id,
        3,
        request,
    )?;
    let t = now()?;
    let window = ObservationWindow {
        now: Timestamp::from_unix_seconds(t as i64)?.as_str().into(),
        oldest_acceptable: Timestamp::from_unix_seconds(t.saturating_sub(60) as i64)?
            .as_str()
            .into(),
    };
    let authority = FixtureAuthority {
        profile: profile.into(),
        binding: engine.protected_record_store_binding()?,
        expires: Timestamp::from_unix_seconds(t.saturating_add(300) as i64)?
            .as_str()
            .into(),
    };
    engine.retain_participant_record(
        &access,
        "synthetic-native-receipt-retain",
        &agreement.agreement_id,
        candidate.agreement.revision,
        RetainParticipantRecordRequest {
            record_id: "synthetic-private-record".into(),
            candidate_id: candidate.agreement.candidates[0].candidate_id.clone(),
            participant_id: "synthetic-alice".into(),
            account_id: "synthetic-account-alice".into(),
        },
        ParticipantRecordRuntime {
            profile_id: profile,
            authority: &authority,
            window: &window,
        },
        &mut FixtureSource,
    )?;
    Ok(())
}
/// Run only under tests/receipt_terminal_flow.py, which allocates an isolated
/// disposable temp directory and a foreground PTY. There is no production flag.
#[test]
#[ignore = "explicit isolated PTY fixture; never a real profile initializer"]
fn native_receipt_fixture_session() {
    let terminal = Terminal::open().unwrap();
    let path = PathBuf::from(
        terminal
            .ask("Disposable synthetic profile root: ")
            .unwrap()
            .as_str(),
    );
    assert!(path.starts_with(std::env::temp_dir()));
    assert!(
        path.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("wholepact-native-receipt-synthetic-")
    );
    assert!(!path.exists());
    let password = terminal.secret("Synthetic storage passphrase: ").unwrap();
    initialize(&path, password.as_bytes()).unwrap();
    let directory = Directory::open(&path).unwrap();
    let secrets = Secrets::open(
        &directory.read("profile.vault", 1024).unwrap(),
        password.as_bytes(),
    )
    .unwrap();
    drop(password);
    let engine = Engine::from_store(
        Store::open_encrypted(
            directory.path(JOURNALS[0]).unwrap(),
            &secrets.key(0).unwrap(),
        )
        .unwrap(),
    );
    seed(&engine, &secrets.profile()).unwrap();
    drop(engine);
    drop(secrets);
    drop(directory);
    terminal.message("Synthetic fixture initialized and locked. Original wallet/proof provenance is fixture-only. Run the shipped native binary for all commands.\n").unwrap();
}
