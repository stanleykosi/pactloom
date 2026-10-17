//! STAGED, UNCOMPILED. V2 roster source adapted from the frozen V1 local attempt protocol.
//! Immutable local continuation proposals. The local index is independent of
//! witness attempt sequence: an expired proposal whose absence is authenticated
//! remains retained when a separately reviewed replacement is proposed.
use super::*;
use crate::native_ui::AuthenticatedPairing;
use std::collections::{BTreeMap, BTreeSet};
use wholepact_authority::manual_roster_continuation_signature_v2::{
    ManualRosterContinuationOwnerSignatureV2, verify_manual_roster_continuation_owner_signature_v2,
};
use wholepact_authority::manual_roster_witness_v2::{
    BornManualRosterAdmissionRecordV2, ManualRosterAttemptObservationV2,
    ManualRosterSessionContinuationV2,
};

mod preconstruction;

pub(crate) const MAX_LOCAL_PROPOSALS: usize = 32;
const PREFIX: &str = "born-manual-roster-continuation-v2-";
const MAX_RECORD: usize = 256 * 1024;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContinuationProposal {
    pub(crate) version: u16,
    pub(crate) local_index: u16,
    pub(crate) previous_local_digest: Option<String>,
    pub(crate) enrollment_ref: String,
    pub(crate) intent_digest: String,
    pub(crate) first_marker_digest: String,
    pub(crate) continuation: ManualRosterSessionContinuationV2,
    pub(crate) process: TransportIdentityBinding,
    pub(crate) native_principal: String,
    pub(crate) native_measurement: String,
    pub(crate) complete_history_digest: String,
}
#[derive(Serialize)]
struct ReviewBody<'a> {
    local_index: u16,
    previous_local_digest: &'a Option<String>,
    enrollment_ref: &'a str,
    intent_digest: &'a str,
    first_marker_digest: &'a str,
    extension_digest: &'a str,
    roster_extension_digest: &'a str,
    attempt_sequence: u64,
    previous_attempt_digest: &'a str,
    expected_snapshot: &'a wholepact_authority::AccountSnapshot,
    previous_admission_digest: &'a Option<String>,
    attempt_nonce: &'a str,
    issued_at_ms: u64,
    initial_commit_deadline_ms: u64,
    process: &'a TransportIdentityBinding,
    native_principal: &'a str,
    native_measurement: &'a str,
    complete_history_digest: &'a str,
}
impl ContinuationProposal {
    fn review_digest(&self) -> Result<String> {
        let c = &self.continuation.continuation;
        canonical(
            "wholepact:native-born-manual-roster-continuation-intent:v2",
            &ReviewBody {
                local_index: self.local_index,
                previous_local_digest: &self.previous_local_digest,
                enrollment_ref: &self.enrollment_ref,
                intent_digest: &self.intent_digest,
                first_marker_digest: &self.first_marker_digest,
                extension_digest: &c.extension_digest,
                roster_extension_digest: &self.continuation.roster_extension_digest,
                attempt_sequence: c.sequence,
                previous_attempt_digest: &c.previous_attempt_digest,
                expected_snapshot: &c.expected_snapshot,
                previous_admission_digest: &c.expected_previous_admission_digest,
                attempt_nonce: &c.attempt_nonce,
                issued_at_ms: c.issued_at_ms,
                initial_commit_deadline_ms: c.initial_commit_deadline_ms,
                process: &self.process,
                native_principal: &self.native_principal,
                native_measurement: &self.native_measurement,
                complete_history_digest: &self.complete_history_digest,
            },
        )
    }
    pub(crate) fn digest(&self) -> Result<String> {
        canonical(
            "wholepact:born-manual-roster-local-continuation-proposal:v2",
            self,
        )
    }
    fn validate(
        &self,
        record: &BornManualRosterEnrollmentRecordV2,
        intent: &str,
        first: &str,
    ) -> Result<()> {
        self.continuation
            .validate_for(&record.extension()?)
            .map_err(|_| Error::Authentication)?;
        if self.version != 2
            || self.local_index == 0
            || usize::from(self.local_index) > MAX_LOCAL_PROPOSALS
            || self.enrollment_ref != record.account_record.reference()?
            || self.intent_digest != intent
            || self.first_marker_digest != first
            || !is_hash(first)
            || self
                .previous_local_digest
                .as_ref()
                .is_some_and(|v| !is_hash(v))
            || (self.local_index == 1) != self.previous_local_digest.is_none()
            || !is_hash(&self.native_measurement)
            || !is_hash(&self.complete_history_digest)
            || self.native_principal.is_empty()
            || self.native_principal.len() > 128
            || self.continuation.continuation.fresh_signer_review_digest != self.review_digest()?
            || self.continuation.continuation.fresh_process_binding_digest
                != process_digest(&self.process)?
        {
            return Err(Error::Authentication);
        }
        require_process(&self.process, record)
    }
    fn filename(&self, kind: Kind) -> Result<String> {
        Ok(format!(
            "{PREFIX}{:04}-{}.{}.wp",
            self.local_index,
            self.digest()?,
            kind.name()
        ))
    }
}
fn process_digest(process: &TransportIdentityBinding) -> Result<String> {
    canonical(
        "wholepact:born-manual-roster-continuation-process:v2",
        process,
    )
}
fn require_process(
    process: &TransportIdentityBinding,
    record: &BornManualRosterEnrollmentRecordV2,
) -> Result<()> {
    match process {
        TransportIdentityBinding::LocalProcess {
            account_id,
            agreement_id,
            participant_id,
            pid,
            signer_generation,
            ..
        } if account_id == &record.account_record.terms.identity.account_id
            && agreement_id == &record.account_record.terms.scope.agreement_id
            && participant_id == &record.account_record.terms.scope.participant_id
            && *pid > 0
            && *signer_generation > 0 =>
        {
            Ok(())
        }
        _ => Err(Error::Authentication),
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    Proposal,
    Signature,
    Acquire,
    Admission,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Signature => "signature",
            Self::Acquire => "acquire",
            Self::Admission => "admission",
        }
    }
}
pub(crate) fn parse_name(name: &str) -> Option<(u16, String, Kind)> {
    let rest = name.strip_prefix(PREFIX)?.strip_suffix(".wp")?;
    let (stem, kind) = rest.rsplit_once('.')?;
    let kind = match kind {
        "proposal" => Kind::Proposal,
        "signature" => Kind::Signature,
        "acquire" => Kind::Acquire,
        "admission" => Kind::Admission,
        _ => return None,
    };
    let (index, digest) = stem.split_once('-')?;
    if index.len() != 4 || !index.bytes().all(|c| c.is_ascii_digit()) || !is_hash(digest) {
        return None;
    }
    let index: u16 = index.parse().ok()?;
    if index == 0 || usize::from(index) > MAX_LOCAL_PROPOSALS {
        return None;
    }
    Some((index, digest.into(), kind))
}
pub(crate) fn check_names(names: &BTreeSet<String>) -> Result<()> {
    let mut groups: BTreeMap<u16, (String, BTreeSet<Kind>)> = BTreeMap::new();
    for name in names {
        if let Some((index, digest, kind)) = parse_name(name) {
            let (old, kinds) = groups
                .entry(index)
                .or_insert_with(|| (digest.clone(), BTreeSet::new()));
            if old != &digest || !kinds.insert(kind) {
                return Err(Error::RecoveryRequired);
            }
        }
    }
    for (position, (index, (_, kinds))) in groups.iter().enumerate() {
        if usize::from(*index) != position + 1
            || !kinds.contains(&Kind::Proposal)
            || kinds.contains(&Kind::Acquire) && !kinds.contains(&Kind::Signature)
            || kinds.contains(&Kind::Admission) && !kinds.contains(&Kind::Acquire)
        {
            return Err(Error::RecoveryRequired);
        }
    }
    if !groups.is_empty() && (!names.contains(INTENT) || !names.contains(ROSTER_ACQUIRE)) {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContinuationAcquireAudit {
    pub(crate) version: u16,
    pub(crate) proposal_digest: String,
    pub(crate) acquire_operation_id: String,
    pub(crate) reentry_review_digest: String,
    pub(crate) acquire_review_digest: String,
    pub(crate) process: TransportIdentityBinding,
    pub(crate) native_principal: String,
    pub(crate) native_measurement: String,
}
impl ContinuationAcquireAudit {
    fn validate(
        &self,
        p: &ContinuationProposal,
        record: &BornManualRosterEnrollmentRecordV2,
    ) -> Result<()> {
        if self.version != 2
            || self.proposal_digest != p.digest()?
            || self.acquire_operation_id
                != p.continuation
                    .acquire_operation_id(&record.extension()?)
                    .map_err(|_| Error::InvalidData)?
            || !is_hash(&self.reentry_review_digest)
            || !is_hash(&self.acquire_review_digest)
            || !is_hash(&self.native_measurement)
            || self.native_principal.is_empty()
            || self.native_principal.len() > 128
            || self.reentry_review_digest
                != reentry_digest(
                    p,
                    &self.process,
                    &self.native_principal,
                    &self.native_measurement,
                )?
        {
            return Err(Error::Authentication);
        }
        require_process(&self.process, record)
    }
}
pub(crate) fn reentry_digest(
    p: &ContinuationProposal,
    process: &TransportIdentityBinding,
    principal: &str,
    measurement: &str,
) -> Result<String> {
    canonical(
        "wholepact:native-born-manual-roster-continuation-reentry:v2",
        &(p, process, principal, measurement),
    )
}
pub(crate) struct LocalContinuation {
    pub(crate) proposal: ContinuationProposal,
    pub(crate) signature: Option<ManualRosterContinuationOwnerSignatureV2>,
    pub(crate) acquire: Option<ContinuationAcquireAudit>,
    pub(crate) admission: Option<BornManualRosterAdmissionRecordV2>,
}
fn domain(record: &BornManualRosterEnrollmentRecordV2, name: &str) -> Result<Vec<u8>> {
    let mut d = b"wholepact:born-manual-roster-continuation-local-file:v2\0".to_vec();
    d.extend(record.reference()?.as_bytes());
    d.push(0);
    d.extend(name.as_bytes());
    Ok(d)
}
/// Pure authenticated parser also used by complete encrypted backup validation.
/// No parsed value is a live native or witness owner.
pub(crate) fn validate_files(
    record: &BornManualRosterEnrollmentRecordV2,
    intent: &str,
    key: &[u8; 32],
    first: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<LocalContinuation>> {
    let first_digest = hex::encode(Sha256::digest(first));
    acquisition::validate_acquire_attempt_bytes(record, intent, key, first)?;
    let mut all_names: BTreeSet<String> = files.keys().cloned().collect();
    all_names.insert(INTENT.into());
    all_names.insert(ROSTER_ACQUIRE.into());
    check_names(&all_names)?;
    let mut result: Vec<LocalContinuation> = Vec::new();
    let mut previous = None;
    for (name, bytes) in files {
        let Some((index, digest, Kind::Proposal)) = parse_name(name) else {
            continue;
        };
        let plain = vault::decrypt(key, &domain(record, name)?, bytes)?;
        let proposal: ContinuationProposal =
            serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
        proposal.validate(record, intent, &first_digest)?;
        if proposal.local_index != index
            || proposal.digest()? != digest
            || proposal.previous_local_digest != previous
        {
            return Err(Error::Authentication);
        }
        previous = Some(digest);
        let extension = record.extension()?;
        let read = |kind: Kind| -> Result<Option<Zeroizing<Vec<u8>>>> {
            let name = proposal.filename(kind)?;
            files
                .get(&name)
                .map(|bytes| vault::decrypt(key, &domain(record, &name)?, bytes))
                .transpose()
        };
        let signature: Option<ManualRosterContinuationOwnerSignatureV2> = read(Kind::Signature)?
            .map(|plain| serde_json::from_slice(&plain).map_err(|_| Error::InvalidData))
            .transpose()?;
        if let Some(s) = &signature {
            if s.extension != extension || s.continuation != proposal.continuation {
                return Err(Error::Authentication);
            }
            verify_manual_roster_continuation_owner_signature_v2(
                s,
                &record.account_record.terms.signer.owner_certificate_digest,
            )
            .map_err(|_| Error::Authentication)?;
        }
        let acquire: Option<ContinuationAcquireAudit> = read(Kind::Acquire)?
            .map(|plain| serde_json::from_slice(&plain).map_err(|_| Error::InvalidData))
            .transpose()?;
        if let Some(a) = &acquire {
            a.validate(&proposal, record)?;
        }
        let admission: Option<BornManualRosterAdmissionRecordV2> = read(Kind::Admission)?
            .map(|plain| serde_json::from_slice(&plain).map_err(|_| Error::InvalidData))
            .transpose()?;
        if let Some(a) = &admission {
            a.validate_for(&extension, Some(&proposal.continuation))
                .map_err(|_| Error::Authentication)?;
        }
        result.push(LocalContinuation {
            proposal,
            signature,
            acquire,
            admission,
        });
    }
    if result.len() > MAX_LOCAL_PROPOSALS {
        return Err(Error::Unavailable);
    }
    Ok(result)
}
pub(crate) fn read_files(directory: &PrivateDirectory) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(directory.root())? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        if parse_name(&name).is_some() {
            files.insert(name.clone(), directory.read(&name, MAX_RECORD)?);
        }
    }
    Ok(files)
}
pub(crate) fn load(
    retained: &RetainedBornManualRosterEnrollmentV2,
) -> Result<Vec<LocalContinuation>> {
    let files = read_files(&retained.account.directory)?;
    if files.is_empty() {
        return Ok(Vec::new());
    }
    validate_files(
        &retained.record,
        &retained.intent_digest,
        &retained.account.encryption_key,
        &retained
            .account
            .directory
            .read(ROSTER_ACQUIRE, MAX_INTENT)?,
        &files,
    )
}
fn write_once<T: Serialize + serde::de::DeserializeOwned>(
    retained: &RetainedBornManualRosterEnrollmentV2,
    name: &str,
    value: &T,
) -> Result<()> {
    if retained.account.directory.exists(name)? {
        let plain = vault::decrypt(
            &retained.account.encryption_key,
            &domain(&retained.record, name)?,
            &retained.account.directory.read(name, MAX_RECORD)?,
        )?;
        let existing: T = serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
        if serde_json::to_value(&existing).map_err(|_| Error::InvalidData)?
            != serde_json::to_value(value).map_err(|_| Error::InvalidData)?
        {
            return Err(Error::RecoveryRequired);
        }
    } else {
        let plain = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::InvalidData)?);
        if plain.len() > MAX_RECORD {
            return Err(Error::Unavailable);
        }
        let ciphertext = vault::encrypt(
            &retained.account.encryption_key,
            &domain(&retained.record, name)?,
            &plain,
        )?;
        retained.account.directory.write(name, &ciphertext)?;
        retained.account.directory.sync_all_files()?;
    }
    Ok(())
}
/// Owns an authenticated original vault and an immutable local proposal. This
/// is audit provenance only; every action needs its actual current native owner.
pub(crate) struct RetainedContinuation {
    pub(crate) retained: RetainedBornManualRosterEnrollmentV2,
    pub(crate) proposal: ContinuationProposal,
}
impl RetainedContinuation {
    pub(crate) fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.retained.check_current_source(owner)?;
        if !load(&self.retained)?
            .iter()
            .any(|p| p.proposal == self.proposal)
        {
            return Err(Error::RecoveryRequired);
        }
        Ok(())
    }
    pub(crate) fn signature(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Option<ManualRosterContinuationOwnerSignatureV2>> {
        self.check(owner)?;
        Ok(load(&self.retained)?
            .into_iter()
            .find(|p| p.proposal == self.proposal)
            .ok_or(Error::RecoveryRequired)?
            .signature)
    }
    pub(crate) fn retain_signature(
        &self,
        signature: &ManualRosterContinuationOwnerSignatureV2,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        if signature.extension != self.retained.record.extension()?
            || signature.continuation != self.proposal.continuation
        {
            return Err(Error::ReviewMismatch);
        }
        verify_manual_roster_continuation_owner_signature_v2(
            signature,
            &self
                .retained
                .record
                .account_record
                .terms
                .signer
                .owner_certificate_digest,
        )
        .map_err(|_| Error::Authentication)?;
        write_once(
            &self.retained,
            &self.proposal.filename(Kind::Signature)?,
            signature,
        )?;
        self.check(owner)
    }
    pub(crate) fn reopen(&self, owner: &PendingAccountNativeAuthority) -> Result<Self> {
        self.check(owner)?;
        Ok(Self {
            retained: self.retained.reopen_exact(owner)?,
            proposal: self.proposal.clone(),
        })
    }
}
pub(crate) struct PreparedContinuationProposal {
    retained: RetainedBornManualRosterEnrollmentV2,
    proposal: ContinuationProposal,
    source: NativeAuthorityBinding,
    peer: AuthenticatedPeer,
    display: Zeroizing<String>,
}
impl PreparedContinuationProposal {
    pub(crate) fn prepare(
        retained: RetainedBornManualRosterEnrollmentV2,
        history: &ReconciledAuthorityHistory,
        pairing: &AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        retained.check_current_source(owner)?;
        pairing.check_current()?;
        if pairing.native_origin() != &owner.native().binding() {
            return Err(Error::Authentication);
        }
        require_process(pairing.binding(), &retained.record)?;
        let pair = pairing.current_peer();
        let original_intent = retained.record.intent()?;
        if pair.scope.manifest_digest != original_intent.digest().map_err(|_| Error::InvalidData)?
            || pair.scope.history_read
            || pair.scope.authorization_export
            || pair.scope.preconstruction_export
        {
            return Err(Error::Authentication);
        }
        let first = retained
            .account
            .directory
            .read(ROSTER_ACQUIRE, MAX_INTENT)?;
        acquisition::validate_acquire_attempt_bytes(
            &retained.record,
            &retained.intent_digest,
            &retained.account.encryption_key,
            &first,
        )?;
        let origin = original(&retained.account)?;
        let audit = origin.anchor().audit_historical_witness_link(history)?;
        if audit.permanent_exclusion().is_some()
            || history.pending_birth_commit() != Some(origin.witness_commit())
        {
            return Err(Error::RecoveryRequired);
        }
        preconstruction::require_original(&retained, history)?;
        let extension = retained.record.extension()?;
        let observation: ManualRosterAttemptObservationV2 = history
            .latest_manual_roster_attempt_v2(&extension.account_extension.enrollment_ref)
            .map_err(|_| Error::RecoveryRequired)?;
        let now = now_ms()?;
        if observation.extension_digest != extension.digest().map_err(|_| Error::InvalidData)?
            || observation
                .last_publication_deadline_ms()
                .is_some_and(|deadline| now < deadline)
            || now >= retained.record.account_record.terms.scope.expires_at_ms
        {
            return Err(Error::RecoveryRequired);
        }
        let previous = load(&retained)?;
        if previous.len() >= MAX_LOCAL_PROPOSALS {
            return Err(Error::Unavailable);
        }
        for old in &previous {
            let digest = old
                .proposal
                .continuation
                .digest_for(&extension)
                .map_err(|_| Error::InvalidData)?;
            match history
                .manual_roster_session_continuation_v2(&digest)
                .map_err(|_| Error::Authentication)?
            {
                Some(actual) if actual == &old.proposal.continuation => {}
                Some(_) => return Err(Error::Authentication),
                None if now
                    >= old
                        .proposal
                        .continuation
                        .continuation
                        .initial_commit_deadline_ms
                    && old.acquire.is_none()
                    && old.admission.is_none() => {}
                None => return Err(Error::RecoveryRequired),
            }
        }
        let mut proposal = ContinuationProposal {
            version: 2,
            local_index: (previous.len() + 1)
                .try_into()
                .map_err(|_| Error::Unavailable)?,
            previous_local_digest: previous.last().map(|p| p.proposal.digest()).transpose()?,
            enrollment_ref: retained.record.account_record.reference()?,
            intent_digest: retained.intent_digest.clone(),
            first_marker_digest: hex::encode(Sha256::digest(&first)),
            continuation: ManualRosterSessionContinuationV2 {
                version: 2,
                roster_extension_digest: extension.digest().map_err(|_| Error::InvalidData)?,
                continuation: wholepact_authority::manual_session_continuation::ManualEnrollmentSessionContinuation {
                version: 1,
                extension_digest: extension.account_extension.digest().map_err(|_| Error::InvalidData)?,
                sequence: observation
                    .sequence
                    .checked_add(1)
                    .ok_or(Error::Unavailable)?,
                previous_attempt_digest: observation.attempt_digest.clone(),
                expected_snapshot: observation.snapshot.clone(),
                expected_previous_admission_digest: observation
                    .last_admission_digest(&extension)
                    .map_err(|_| Error::InvalidData)?,
                attempt_nonce: hex::encode(vault::random::<32>()?),
                fresh_process_binding_digest: process_digest(pairing.binding())?,
                fresh_signer_review_digest: String::new(),
                issued_at_ms: now,
                initial_commit_deadline_ms: now
                    .checked_add(120_000)
                    .ok_or(Error::InvalidData)?
                    .min(retained.record.account_record.terms.scope.expires_at_ms),
                },
            },
            process: pairing.binding().clone(),
            native_principal: owner.native().principal_id().into(),
            native_measurement: owner.native().measurement().into(),
            complete_history_digest: history.history_digest().map_err(|_| Error::InvalidData)?,
        };
        proposal
            .continuation
            .continuation
            .fresh_signer_review_digest = proposal.review_digest()?;
        proposal.validate(
            &retained.record,
            &retained.intent_digest,
            &hex::encode(Sha256::digest(&first)),
        )?;
        let display = Zeroizing::new(format!(
            "RETAIN ONE EXACT ORIGINAL-ACCOUNT SESSION CONTINUATION\n{}\n\nThis preserves the original intent, first acquire marker, enrollment, epoch, policy, lifetime budget and all old session/exposure records. The independent witness must separately approve this exact predecessor and head. Every earlier uncommitted local proposal is expired and absent from complete authenticated history. No key or current native authority is serialized. The original 120-second first witness commit window cannot be renewed. Local index is separate from witness attempt sequence. No financial action is authorized.",
            serde_json::to_string_pretty(&proposal).map_err(|_| Error::InvalidData)?
        ));
        Ok(Self {
            retained,
            proposal,
            source: owner.native().binding(),
            peer: pairing.current_peer(),
            display,
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self
            .proposal
            .continuation
            .continuation
            .fresh_signer_review_digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        self.peer.check_current()?;
        Ok(self.display.to_string())
    }
    pub(crate) fn approve_and_retain(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<RetainedContinuation> {
        self.retained.check_current_source(owner)?;
        self.peer.check_current()?;
        if self.source != owner.native().binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.reviewed_digest()
            || now_ms()?
                >= self
                    .proposal
                    .continuation
                    .continuation
                    .initial_commit_deadline_ms
        {
            return Err(Error::ReviewMismatch);
        }
        let existing = load(&self.retained)?;
        if existing.len() + 1 != usize::from(self.proposal.local_index)
            || existing.last().map(|p| p.proposal.digest()).transpose()?
                != self.proposal.previous_local_digest
        {
            return Err(Error::RecoveryRequired);
        }
        let _lease = self.source.publication_lease()?;
        self.retained.check_current_source(owner)?;
        self.peer.check_current()?;
        write_once(
            &self.retained,
            &self.proposal.filename(Kind::Proposal)?,
            &self.proposal,
        )?;
        let result = RetainedContinuation {
            retained: self.retained,
            proposal: self.proposal,
        };
        result.check(owner)?;
        Ok(result)
    }
}

pub(crate) fn select(
    retained: RetainedBornManualRosterEnrollmentV2,
    continuation_digest: &str,
    owner: &PendingAccountNativeAuthority,
) -> Result<RetainedContinuation> {
    retained.check_current_source(owner)?;
    let extension = retained.record.extension()?;
    let mut selected = None;
    for entry in load(&retained)? {
        if entry
            .proposal
            .continuation
            .digest_for(&extension)
            .map_err(|_| Error::InvalidData)?
            == continuation_digest
        {
            if selected.is_some() {
                return Err(Error::Authentication);
            }
            selected = Some(entry.proposal);
        }
    }
    Ok(RetainedContinuation {
        retained,
        proposal: selected.ok_or(Error::RecoveryRequired)?,
    })
}
pub(crate) struct PreparedContinuedReentry {
    retained: RetainedContinuation,
    source: NativeAuthorityBinding,
    peer: AuthenticatedPeer,
    process: TransportIdentityBinding,
    principal: String,
    measurement: String,
    digest: String,
    display: Zeroizing<String>,
}
pub(crate) struct ApprovedContinuedReentry(PreparedContinuedReentry);
impl PreparedContinuedReentry {
    pub(crate) fn prepare(
        retained: RetainedContinuation,
        request: &wholepact_signer_origin::manual_roster_v2::HostManualRosterPublicationRequestV2,
        history: &ReconciledAuthorityHistory,
        pairing: &AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        retained.check(owner)?;
        pairing.check_current()?;
        request.validate().map_err(|_| Error::InvalidData)?;
        let p = &retained.proposal;
        let record = &retained.retained.record;
        let peer = pairing.current_peer();
        let extension = record.extension()?;
        let observed = history
            .latest_manual_roster_attempt_v2(&record.account_record.reference()?)
            .map_err(|_| Error::RecoveryRequired)?;
        let own = load(&retained.retained)?
            .into_iter()
            .find(|item| item.proposal == *p)
            .ok_or(Error::RecoveryRequired)?;
        let audit = original(&retained.retained.account)?
            .anchor()
            .audit_historical_witness_link(history)?;
        let expected_attempt = wholepact_signer_origin::manual_roster_v2::ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest: p.continuation.digest_for(&extension).map_err(|_| Error::InvalidData)?,
            attempt_sequence: p.continuation.sequence(),
        };
        if request.enrollment.terms != record.account_record.terms
            || request.roster != record.roster
            || request.attempt != expected_attempt
            || request.digest().map_err(|_| Error::InvalidData)? != peer.scope.manifest_digest
            || observed.continuation.as_ref() != Some(&p.continuation)
            || observed.attempt_digest
                != p.continuation
                    .digest_for(&extension)
                    .map_err(|_| Error::InvalidData)?
            || observed.admission.is_some()
            || observed.snapshot.pending_writer_session.is_some()
            || observed.snapshot.active_writer_session.is_some()
            || own.signature.is_none()
            || own.acquire.is_some()
            || own.admission.is_some()
            || audit.permanent_exclusion().is_some()
            || now_ms()? >= record.account_record.terms.scope.expires_at_ms
            || pairing.native_origin() != &owner.native().binding()
            || peer.scope.history_read
            || peer.scope.authorization_export
            || peer.scope.preconstruction_export
        {
            return Err(Error::RecoveryRequired);
        }
        require_process(pairing.binding(), record)?;
        let process = pairing.binding().clone();
        let principal = owner.native().principal_id().to_owned();
        let measurement = owner.native().measurement().to_owned();
        let digest = reentry_digest(p, &process, &principal, &measurement)?;
        let display = Zeroizing::new(format!(
            "REENTER EXACT APPROVED CONTINUATION BEFORE SUCCESSOR ACQUIRE\n{}\n\nActual current paired process:\n{}\n\nThe continuation descriptor and its original signing transport/native review remain historical unchanged. Complete current witness history proves this exact successor approved and not yet acquired. The first witness-append deadline is historical after committed append; this native entry retains its own original cutoff. A new immutable acquire marker is written before send; losing this attempt requires another explicit continuation, never a local reset.\nExact review: {}",
            serde_json::to_string_pretty(p).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&process).map_err(|_| Error::InvalidData)?,
            digest
        ));
        Ok(Self {
            retained,
            source: owner.native().binding(),
            peer,
            process,
            principal,
            measurement,
            digest,
            display,
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        self.peer.check_current()?;
        Ok(self.display.to_string())
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ApprovedContinuedReentry> {
        self.retained.check(owner)?;
        self.peer.check_current()?;
        if self.source != owner.native().binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        if load(&self.retained.retained)?
            .into_iter()
            .find(|e| e.proposal == self.retained.proposal)
            .ok_or(Error::RecoveryRequired)?
            .acquire
            .is_some()
        {
            return Err(Error::RecoveryRequired);
        }
        Ok(ApprovedContinuedReentry(self))
    }
}
impl ApprovedContinuedReentry {
    pub(crate) fn check(
        &self,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.0.retained.check(owner)?;
        self.0.source.check_current()?;
        self.0.peer.check_current()?;
        peer.check_current()?;
        if self.0.source != owner.native().binding()
            || peer.native_origin != self.0.source
            || peer.grant_id != self.0.peer.grant_id
            || peer.scope != self.0.peer.scope
            || now_ms()?
                >= self
                    .0
                    .retained
                    .retained
                    .record
                    .account_record
                    .terms
                    .scope
                    .expires_at_ms
        {
            return Err(Error::ReviewMismatch);
        }
        peer.peer.same_live_process(&self.0.peer.peer)?;
        Ok(())
    }
    pub(crate) fn proposal(&self) -> &ContinuationProposal {
        &self.0.retained.proposal
    }
    pub(crate) fn persist_before_acquire(
        &self,
        approved: &crate::native_ui::NativeApprovedWriterSession,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(&self.0.peer, owner)?;
        let p = &self.0;
        let extension = p.retained.retained.record.extension()?;
        let acquire_review = approved.born_roster_continued_attempt_review_v2(
            &extension,
            &p.retained.proposal.continuation,
            &p.source,
        )?;
        let audit = ContinuationAcquireAudit {
            version: 2,
            proposal_digest: p.retained.proposal.digest()?,
            acquire_operation_id: p
                .retained
                .proposal
                .continuation
                .acquire_operation_id(&extension)
                .map_err(|_| Error::InvalidData)?,
            reentry_review_digest: p.digest.clone(),
            acquire_review_digest: acquire_review,
            process: p.process.clone(),
            native_principal: p.principal.clone(),
            native_measurement: p.measurement.clone(),
        };
        audit.validate(&p.retained.proposal, &p.retained.retained.record)?;
        let _lease = p.source.publication_lease()?;
        self.check(&p.peer, owner)?;
        write_once(
            &p.retained.retained,
            &p.retained.proposal.filename(Kind::Acquire)?,
            &audit,
        )?;
        let actual = load(&p.retained.retained)?
            .into_iter()
            .find(|e| e.proposal == p.retained.proposal)
            .ok_or(Error::RecoveryRequired)?;
        if actual.acquire.as_ref() != Some(&audit) {
            return Err(Error::Authentication);
        }
        self.check(&p.peer, owner)
    }
}
/// Called only with the actual finite V2 proof during native publication.
pub(crate) fn retain_admission(
    retained: &RetainedBornManualRosterEnrollmentV2,
    proof: &wholepact_authority::manual_roster_witness_v2::AuthenticatedBornManualRosterEnrollmentV2,
) -> Result<()> {
    proof.check_current().map_err(|_| Error::ReviewMismatch)?;
    let entry = load(retained)?
        .into_iter()
        .find(|e| Some(&e.proposal.continuation) == proof.continuation())
        .ok_or(Error::RecoveryRequired)?;
    if entry.signature.is_none()
        || entry.acquire.is_none()
        || proof.extension() != &retained.record.extension()?
    {
        return Err(Error::Authentication);
    }
    write_once(
        retained,
        &entry.proposal.filename(Kind::Admission)?,
        proof.record(),
    )?;
    let actual = load(retained)?
        .into_iter()
        .find(|e| Some(&e.proposal.continuation) == proof.continuation())
        .ok_or(Error::RecoveryRequired)?;
    if actual.admission.as_ref() != Some(proof.record()) {
        return Err(Error::Authentication);
    }
    Ok(())
}

pub(crate) fn require_attempted_source(
    retained: &RetainedBornManualRosterEnrollmentV2,
    owner: &PendingAccountNativeAuthority,
) -> Result<()> {
    retained.check_current_source(owner)?;
    acquisition::validate_acquire_attempt_bytes(
        &retained.record,
        &retained.intent_digest,
        &retained.account.encryption_key,
        &retained
            .account
            .directory
            .read(ROSTER_ACQUIRE, MAX_INTENT)?,
    )?;
    require_attempted_journal(retained)?;
    load(retained)?;
    retained.check_current_source(owner)
}
pub(crate) fn require_attempted_journal(
    retained: &RetainedBornManualRosterEnrollmentV2,
) -> Result<()> {
    if retained.account.directory.exists(JOURNAL)? {
        let path = retained.account.directory.root().join(JOURNAL);
        let key = DatabaseKey::from_bytes(*retained.journal_key);
        let namespace = retained
            .record
            .account_record
            .genesis
            .digest()
            .map_err(|_| Error::InvalidData)?;
        let plan = wholepact_storage_security::PlannedWitnessBirthInitialization::new(
            &namespace,
            &retained.intent_digest,
            &path,
            &key,
        )
        .map_err(|_| Error::RecoveryRequired)?;
        match plan
            .inspect(&path, &key, &namespace, &retained.intent_digest)
            .map_err(|_| Error::RecoveryRequired)?
        {
            wholepact_storage_security::PlannedWitnessBirthInspection::AuthenticatedEmpty => {
                if retained.account.directory.exists(ROSTER_COMMIT)? {
                    return Err(Error::RecoveryRequired);
                }
            }
            wholepact_storage_security::PlannedWitnessBirthInspection::Initialized(read) => {
                drop(read);
                SignerConsentJournal::verify_initial_born_history(
                    &path,
                    &key,
                    &retained.record.account_record.genesis,
                    retained.record.account_record.terms.signer.writer_epoch,
                )?;
                if retained.account.directory.exists(ROSTER_COMMIT)? {
                    publication::read_commit(retained)?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_retained_attempts(
    retained: &RetainedBornManualRosterEnrollmentV2,
) -> Result<()> {
    load(retained)?;
    Ok(())
}
