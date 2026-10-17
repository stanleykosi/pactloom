//! Separate full-path synthetic scenario: THREE actual witness owners and
//! original listeners/certificate sets exist before any signer birth. The old
//! constructor-only scenario is unchanged. No endpoint switching, listener mux,
//! opaque owner fabrication, native gate relaxation or runtime evidence claim.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

use super::constructed_joined_v3::proved_checkpoint_joined_v1::CarriedJoinedStageV1;
use super::initial_joined_v3::{create_agreement, publish_roster_member, publish_single_anchor};
use super::joined_signer_worker_v1::{
    AGREEMENT_ID as AGREEMENT, JoinedSignerCommandV1 as Command, JoinedSignerReplyV1 as Reply,
    JoinedSignerWorkerV1, PublicJoinedBornV1,
};
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B, Outcome};
use super::*;
use std::path::{Path, PathBuf};
use wholepact_authority::native_witness_owner::{
    EphemeralNativeWitnessV1, EphemeralWitnessOriginV1,
};
use wholepact_core::agreement::PrivacyMode;
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterEnrollmentIntentV2, HostManualRosterPublicationRequestV2,
};
use wholepact_wallet::wallet::synthetic_born_payment_recipient_v1::SyntheticBornPaymentRecipientV1;

/// Main-thread owners remain here. Drop the full stage first, then this scenario:
/// signer controllers drain before witnesses, Host and the temporary root.
pub(super) struct FullJoinedV3 {
    signers: JoinedSignerWorkerV1,
    witnesses: OriginalJoinedWitnessSetV1,
    host: Host,
    born: [PublicJoinedBornV1; 3],
    roster_intents: [HostManualRosterEnrollmentIntentV2; 2],
    roster_requests: [HostManualRosterPublicationRequestV2; 2],
    roster_signed_extension_files: [PathBuf; 2],
    roster_original_policy_files: [PathBuf; 2],
    payment_recipient: SyntheticBornPaymentRecipientV1,
    expiry_ms: u64,
    scenario_deadline: Instant,
    full_path_started: bool,
    temporary: tempfile::TempDir,
}
impl Drop for FullJoinedV3 {
    fn drop(&mut self) {
        let _ = self.host.authority.fence.revoke();
    }
}

/// Private public-data restriction, not an authority or a transferable owner.
struct OriginalWitnessPinsV1 {
    endpoint: String,
    witness_id: String,
    server_name: String,
    server_certificate: String,
    owner_certificate: String,
    writer_certificate: String,
}
impl OriginalWitnessPinsV1 {
    fn from_original(origin: &EphemeralWitnessOriginV1) -> Self {
        Self {
            endpoint: origin.endpoint.clone(),
            witness_id: origin.witness_id.clone(),
            server_name: origin.server_name.clone(),
            server_certificate: origin.server_certificate_digest.clone(),
            owner_certificate: origin.owner_certificate_digest.clone(),
            writer_certificate: origin.writer_certificate_digest.clone(),
        }
    }
    fn values(&self) -> [&str; 5] {
        [
            &self.endpoint,
            &self.witness_id,
            &self.server_certificate,
            &self.owner_certificate,
            &self.writer_certificate,
        ]
    }
    fn matches_original(&self, origin: &EphemeralWitnessOriginV1) -> bool {
        self.endpoint == origin.endpoint
            && self.witness_id == origin.witness_id
            && self.server_name == origin.server_name
            && self.server_certificate == origin.server_certificate_digest
            && self.owner_certificate == origin.owner_certificate_digest
            && self.writer_certificate == origin.writer_certificate_digest
    }
}

/// Fixed private association made only after the actual signed births have been
/// natively enrolled and acknowledged by their same original signer controllers.
/// No raw/serialized constructor, endpoint substitution, Clone or owner export.
pub(super) struct OriginalJoinedWitnessSetV1 {
    owners: [EphemeralNativeWitnessV1; 3],
    originals: Option<[PublicJoinedBornV1; 3]>,
    pins: [OriginalWitnessPinsV1; 3],
}
impl OriginalJoinedWitnessSetV1 {
    pub(super) fn for_original(
        &mut self,
        actual: &PublicJoinedBornV1,
    ) -> Result<&mut EphemeralNativeWitnessV1> {
        let original = self
            .originals
            .as_ref()
            .ok_or(Error::Authentication)?
            .get(actual.index)
            .ok_or(Error::Authentication)?;
        if !same_original(original, actual) {
            return Err(Error::Authentication);
        }
        let owner = self
            .owners
            .get_mut(actual.index)
            .ok_or(Error::Authentication)?;
        let current = owner.origin().map_err(|_| Error::Authentication)?;
        if !self.pins[actual.index].matches_original(&current) {
            return Err(Error::Authentication);
        }
        Ok(owner)
    }
}

/// Only concrete actual owners can enter either branch. Legacy wrappers retain
/// their old single-owner behavior; full-path wrappers accept the private fixed
/// account set. This is not a callback issuer or production/wire routing API.
pub(super) enum JoinedWitnessRouteV1<'a> {
    ConstructorOnly(&'a mut EphemeralNativeWitnessV1),
    Distinct(&'a mut OriginalJoinedWitnessSetV1),
}
impl JoinedWitnessRouteV1<'_> {
    pub(super) fn for_original(
        &mut self,
        actual: &PublicJoinedBornV1,
    ) -> Result<&mut EphemeralNativeWitnessV1> {
        match self {
            Self::ConstructorOnly(owner) => Ok(&mut **owner),
            Self::Distinct(owners) => owners.for_original(actual),
        }
    }
}
fn same_original(a: &PublicJoinedBornV1, b: &PublicJoinedBornV1) -> bool {
    a.index == b.index
        && a.account_id == b.account_id
        && a.birth_digest == b.birth_digest
        && a.full_viewing_key_digest == b.full_viewing_key_digest
        && a.network_profile_id == b.network_profile_id
        && a.participant_id == b.participant_id
        && a.privacy_domain == b.privacy_domain
        && a.public_receive_address == b.public_receive_address
        && a.recipient_scope_digest == b.recipient_scope_digest
}
/// Pure public restriction only. All certificate identities are distinct even
/// across roles; the actual origins and credentials still come from producers.
fn distinct_original_pins(rows: &[[&str; 5]; 3]) -> bool {
    let mut endpoints = std::collections::BTreeSet::new();
    let mut identities = std::collections::BTreeSet::new();
    let mut certificates = std::collections::BTreeSet::new();
    rows.iter().all(|row| {
        row.iter().all(|v| !v.is_empty())
            && endpoints.insert(row[0])
            && identities.insert(row[1])
            && row[2..].iter().all(|v| certificates.insert(*v))
    })
}
fn mark(boundary: B) {
    diagnostic::emit(boundary, Outcome::Begin);
}
fn stage(label: &'static str) -> Error {
    Error::Receipt(format!(
        "synthetic three-original full stage failed: {label}"
    ))
}
fn check_scenario(deadline: Instant) -> Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(Error::Permission)
    }
}
fn require_original_declared_policy(host: &Host, receiver: &str) -> Result<()> {
    host.require_manual_session()?;
    let actual = host
        .engine
        .manual_enrollment_intent_target(host.access()?, AGREEMENT)?;
    let terms = actual.agreement();
    if terms.privacy_profile.mode != PrivacyMode::DeclaredOperator
        || terms.privacy_profile.proving_operator.as_deref() != Some("synthetic-local-host")
        || !terms.privacy_profile.dedicated_accounts_required
        || terms.recipients.len() != 1
        || terms.recipients[0].address != receiver
    {
        return Err(Error::Authentication);
    }
    actual.check_current(host.access()?)?;
    Ok(())
}

pub(super) fn prepare(terminal: crate::terminal::Terminal) -> Result<FullJoinedV3> {
    // One fixed outer synthetic scenario ceiling, set before setup/births. It
    // never replaces or renews any individual financial/native/source deadline.
    let scenario_deadline = Instant::now()
        .checked_add(Duration::from_secs(900))
        .ok_or(Error::Invalid)?;
    let (temporary, host) = diagnostic::host(B::Bootstrap, || {
        crate::host::born_test_host_v1::create(terminal)
    })?;
    diagnostic::host(B::Session, || host.require_manual_session())?;
    mark(B::PublicRefusal);
    if !matches!(
        host.manual_roster_sequential_construct_v3_command(),
        Err(Error::Receipt(_))
    ) {
        return Err(Error::Authentication);
    }
    mark(B::PaymentReceiver);
    let payment_recipient = SyntheticBornPaymentRecipientV1::new()
        .map_err(|_| stage("actual retained synthetic payment recipient"))?;
    let payment_receiver = payment_recipient.public_receive_address().to_owned();
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Invalid)?;
    let expiry_ms = now_ms.checked_add(3_600_000).ok_or(Error::Invalid)?;
    diagnostic::host(B::AgreementInput, || {
        create_agreement(&host, temporary.path(), &payment_receiver)
    })?;
    // Check the actually retained agreement, not the draft JSON or a later
    // relabelled proposal. This occurs before any of the three births.
    require_original_declared_policy(&host, &payment_receiver)?;
    let witness_owners = [
        diagnostic::host(B::WitnessSetup, || {
            EphemeralNativeWitnessV1::new().map_err(|_| stage("anchor original witness setup"))
        })?,
        diagnostic::host(B::WitnessSetup, || {
            EphemeralNativeWitnessV1::new()
                .map_err(|_| stage("first participant original witness setup"))
        })?,
        diagnostic::host(B::WitnessSetup, || {
            EphemeralNativeWitnessV1::new()
                .map_err(|_| stage("second participant original witness setup"))
        })?,
    ];
    let origins = [
        witness_owners[0]
            .origin()
            .map_err(|_| stage("anchor original witness pins"))?,
        witness_owners[1]
            .origin()
            .map_err(|_| stage("first participant original witness pins"))?,
        witness_owners[2]
            .origin()
            .map_err(|_| stage("second participant original witness pins"))?,
    ];
    let pins = origins.each_ref().map(OriginalWitnessPinsV1::from_original);
    if !distinct_original_pins(&pins.each_ref().map(OriginalWitnessPinsV1::values)) {
        return Err(Error::Authentication);
    }
    // Declare the concrete set BEFORE the worker, so every failed later stage
    // cancels/drains signer controllers before dropping witness Windows.
    let mut witnesses = OriginalJoinedWitnessSetV1 {
        owners: witness_owners,
        originals: None,
        pins,
    };
    check_scenario(scenario_deadline)?;
    mark(B::SignerStart);
    let signers = JoinedSignerWorkerV1::spawn_with_original_witnesses(
        origins,
        payment_receiver.clone(),
        expiry_ms,
    )
    .map_err(stage)?;
    let mut born = Vec::with_capacity(3);
    for (index, witness) in witnesses.owners.iter_mut().enumerate() {
        check_scenario(scenario_deadline)?;
        mark(B::BirthExport);
        signers.send(Command::ExportBirth(index)).map_err(stage)?;
        let (account_id, birth_digest, exported_file) = match signers.receive().map_err(stage)? {
            Reply::BirthExport {
                index: actual,
                account_id,
                birth_digest,
                exported_file,
            } if actual == index => (account_id, birth_digest, exported_file),
            _ => return Err(Error::Authentication),
        };
        mark(B::BirthRead);
        let bytes = zeroize::Zeroizing::new(crate::files::read_private(&exported_file, 131_072)?);
        mark(B::BirthEnroll);
        witness
            .enroll_signed_birth(&account_id, &bytes)
            .map_err(|_| stage("actual witness birth review"))?;
        mark(B::BirthHistory);
        let server = witness
            .serve_original_history()
            .map_err(|_| stage("original birth TLS server"))?;
        mark(B::BirthAcknowledge);
        signers.send(Command::Acknowledge(index)).map_err(stage)?;
        let acknowledged = match signers.receive().map_err(stage)? {
            Reply::Acknowledged(owner)
                if owner.index == index
                    && owner.account_id == account_id
                    && owner.birth_digest == birth_digest =>
            {
                owner
            }
            _ => return Err(Error::Authentication),
        };
        drop(server);
        born.push(acknowledged);
    }
    mark(B::BirthDistinct);
    let born: [PublicJoinedBornV1; 3] = born.try_into().map_err(|_| Error::Invalid)?;
    if born
        .iter()
        .enumerate()
        .any(|(i, a)| born[..i].iter().any(|b| a.account_id == b.account_id))
    {
        return Err(Error::Authentication);
    }
    // Bind only these actual enrolled + acknowledged outputs. No external DTO
    // can construct or rebind this private association after the fact.
    if witnesses.originals.is_some() {
        return Err(Error::Authentication);
    }
    witnesses.originals = Some(born.clone());
    check_scenario(scenario_deadline)?;
    publish_single_anchor(
        &host,
        witnesses.for_original(&born[0])?,
        &signers,
        &born[0],
        expiry_ms,
    )?;
    let mut intents = Vec::with_capacity(2);
    let mut requests = Vec::with_capacity(2);
    let mut signed_extensions = Vec::with_capacity(2);
    let mut original_policies = Vec::with_capacity(2);
    for owner in &born[1..] {
        check_scenario(scenario_deadline)?;
        let (intent, request, signed_extension, original_policy) = publish_roster_member(
            &host,
            witnesses.for_original(owner)?,
            &signers,
            owner,
            expiry_ms,
        )?;
        intents.push(intent);
        requests.push(request);
        signed_extensions.push(signed_extension);
        original_policies.push(original_policy);
    }
    // Read back the actual immutable Store roster through the genuine Engine
    // metadata owner. Success of a signer UI alone is not Host publication.
    mark(B::MetadataCheck);
    {
        let target = host
            .engine
            .manual_roster_intent_target(host.access()?, AGREEMENT)?;
        let members = target.members(host.access()?)?;
        if members.len() != 3
            || target.binding().roster_sequence != 4
            || born.iter().any(|owner| {
                !members.iter().any(|member| {
                    member.identity.account_id == owner.account_id
                        && member.identity.full_viewing_key_digest == owner.full_viewing_key_digest
                        && member.scope.participant_id == owner.participant_id
                        && member.scope.privacy_domain == owner.privacy_domain
                })
            })
        {
            return Err(Error::Authentication);
        }
        target.check_current(host.access()?)?;
    }
    // First publication is audit-only. It must not silently activate a generic
    // financial gate or create spendable/candidate inputs.
    mark(B::FinancialRefusal);
    if host.require_financial_generation_admission().is_ok() {
        return Err(Error::Authentication);
    }
    require_original_declared_policy(&host, &payment_receiver)?;
    check_scenario(scenario_deadline)?;
    Ok(FullJoinedV3 {
        signers,
        witnesses,
        host,
        born,
        roster_intents: intents.try_into().map_err(|_| Error::Invalid)?,
        roster_requests: requests.try_into().map_err(|_| Error::Invalid)?,
        roster_signed_extension_files: signed_extensions.try_into().map_err(|_| Error::Invalid)?,
        roster_original_policy_files: original_policies.try_into().map_err(|_| Error::Invalid)?,
        payment_recipient,
        expiry_ms,
        scenario_deadline,
        full_path_started: false,
        temporary,
    })
}

/// The SAME scenario's actual constructed/proved/carried owners plus disjoint
/// borrows of its original witnesses/worker/recipient. A parent full caller can
/// continue genuine enrollment/import/return/current/dispatch without moving a
/// Window across threads or recreating a source. No completion DTO can enter.
pub(super) struct FullProvedJoinedV1<'host> {
    pub(super) carried: CarriedJoinedStageV1<'host>,
    pub(super) witnesses: &'host mut OriginalJoinedWitnessSetV1,
    pub(super) signers: &'host JoinedSignerWorkerV1,
    pub(super) born: &'host [PublicJoinedBornV1; 3],
    pub(super) payment_recipient: &'host SyntheticBornPaymentRecipientV1,
    pub(super) temporary_root: &'host Path,
    pub(super) original_scenario_deadline: Instant,
}
impl FullJoinedV3 {
    /// Actual one-shot chain, not a component-only success. All real native
    /// approvals occur inside the existing retained/observed/constructor/proof
    /// and carrier producers. Any error is terminal, never automatically retried.
    pub(super) fn prove_originals(&mut self) -> Result<FullProvedJoinedV1<'_>> {
        if std::mem::replace(&mut self.full_path_started, true) {
            return Err(Error::Permission);
        }
        check_scenario(self.scenario_deadline)?;
        require_original_declared_policy(
            &self.host,
            self.payment_recipient.public_receive_address(),
        )?;
        let retained = super::retained_joined_v3::retain_two_with_original_witnesses(
            &self.host,
            &mut self.witnesses,
            &self.signers,
            &self.born,
            &self.roster_intents,
            &self.roster_requests,
            &self.roster_signed_extension_files,
            &self.roster_original_policy_files,
            self.expiry_ms,
            self.temporary.path(),
            self.scenario_deadline,
        )?;
        let observed = super::observed_joined_v3::observe_two_with_original_witnesses(
            &self.host,
            &mut self.witnesses,
            &self.signers,
            &self.born,
            &self.roster_intents,
            &self.roster_signed_extension_files,
            self.temporary.path(),
            self.scenario_deadline,
            retained,
        )?;
        let constructed = super::constructed_joined_v3::construct_two_with_original_witnesses(
            &self.host,
            &mut self.witnesses,
            &self.signers,
            &self.born,
            self.temporary.path(),
            self.scenario_deadline,
            observed,
        )?;
        let carried = constructed.prove_and_prepare_carriers_with_original_witnesses_v1(
            &mut self.witnesses,
            &self.signers,
            &self.born,
            self.temporary.path(),
            self.scenario_deadline,
        )?;
        check_scenario(self.scenario_deadline)?;
        Ok(FullProvedJoinedV1 {
            carried,
            witnesses: &mut self.witnesses,
            signers: &self.signers,
            born: &self.born,
            payment_recipient: &self.payment_recipient,
            temporary_root: self.temporary.path(),
            original_scenario_deadline: self.scenario_deadline,
        })
    }
}

#[test]
fn pure_original_pin_restriction_rejects_duplicate_endpoints_and_any_certificate_role() {
    // Public synthetic strings only. No witness, native owner, key, history or
    // completed claim is constructed by this pure restriction test.
    let rows = [
        ["e0", "w0", "s0", "o0", "r0"],
        ["e1", "w1", "s1", "o1", "r1"],
        ["e2", "w2", "s2", "o2", "r2"],
    ];
    assert!(distinct_original_pins(&rows));
    for column in 0..5 {
        let mut duplicate = rows;
        duplicate[2][column] = rows[0][column];
        assert!(!distinct_original_pins(&duplicate));
    }
    let mut cross_role = rows;
    cross_role[1][4] = rows[0][2];
    assert!(!distinct_original_pins(&cross_role));
    let mut empty = rows;
    empty[2][3] = "";
    assert!(!distinct_original_pins(&empty));
}
