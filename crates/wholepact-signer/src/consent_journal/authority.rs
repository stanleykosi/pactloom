//! Sealed issuance boundary. A terminal challenge, imported manifest, native
//! preview acknowledgment or coordinator-provided verifier flag has no conversion
//! to these types. The private Linux native source retains its exact approved
//! local peer and rechecks process lifetime, grant revocation and expiry. Remote
//! key identity remains a separate issuer; tests use explicit synthetic fixtures.
use super::{types::*, *};
use crate::{
    account::DedicatedAccount,
    manifest::{AcceptedManifest, ReviewInputs},
};
use sha2::{Digest, Sha256};
use std::{
    sync::{Mutex, RwLock, RwLockReadGuard},
    time::{Duration, Instant},
};
use wholepact_core::Proposal;
use wholepact_protocol::review::verify_review;

/// A genuine measured launcher must own construction inside the signer. No
/// boolean, path, process name, PTY or deserialized attestation is accepted.
/// There is no public provenance constructor; the private native path requires
/// both its exact authority instance and a genuinely paired OS process.
pub struct TrustedSignerLaunch {
    pub(super) journal: SignerJournalBinding,
    pub(super) account_id: String,
    pub(super) principal_id: String,
    pub(super) writer_epoch: u64,
    pub(super) measurement: String,
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    native_origin: Option<crate::native_ui::NativeAuthorityBinding>,
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    native_peer: Option<crate::ipc::AuthenticatedPeer>,
}
/// Requires independently authenticated possession/association, not a displayed
/// public-key label. The production transport-key issuer is a separate gate.
pub struct AuthenticatedTransportIdentity {
    pub(super) account_id: String,
    pub(super) agreement_id: String,
    pub(super) participant_id: String,
    pub(super) binding: TransportIdentityBinding,
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    native_origin: crate::native_ui::NativeAuthorityBinding,
}
/// Issued only by a native decision route tied to the measured launch. Even a
/// correct displayed challenge cannot construct this type through public APIs.
pub struct NativeConsentDecision {
    pub(super) session_id: String,
    pub(super) permission_generation: u64,
    pub(super) reviewed_digest: String,
}
#[cfg(all(feature = "native-ui", target_os = "linux"))]
impl TrustedSignerLaunch {
    pub(crate) fn from_native(
        authority: &crate::native_ui::NativeAuthority,
        journal: &SignerConsentJournal,
        account: &DedicatedAccount,
        pairing: &crate::native_ui::AuthenticatedPairing,
    ) -> Result<Self> {
        authority
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        pairing
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        if pairing.native_origin() != &authority.binding() {
            return Err(JournalError::Permission);
        }
        let state = journal.account_state()?;
        let account_id = account
            .account_id()
            .map_err(|_| JournalError::InvalidBinding)?;
        if pairing.account_id() != account_id {
            return Err(JournalError::Permission);
        }
        if account.recovery_required() || state.recovery_required || state.account_id != account_id
        {
            return Err(JournalError::RecoveryRequired);
        }
        Ok(Self {
            journal: journal.binding(),
            account_id,
            principal_id: authority.principal_id().into(),
            writer_epoch: state.writer_epoch,
            measurement: authority.measurement().into(),
            native_origin: Some(authority.binding()),
            native_peer: Some(pairing.current_peer()),
        })
    }
}
#[cfg(all(feature = "native-ui", target_os = "linux"))]
impl AuthenticatedTransportIdentity {
    pub(crate) fn from_native(pairing: &crate::native_ui::AuthenticatedPairing) -> Result<Self> {
        pairing
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        if !matches!(
            pairing.binding(),
            TransportIdentityBinding::LocalProcess { .. }
        ) {
            return Err(JournalError::InvalidBinding);
        }
        pairing.binding().validate_scope(
            pairing.account_id(),
            pairing.agreement_id(),
            pairing.participant_id(),
            None,
        )?;
        Ok(Self {
            account_id: pairing.account_id().into(),
            agreement_id: pairing.agreement_id().into(),
            participant_id: pairing.participant_id().into(),
            binding: pairing.binding().clone(),
            native_origin: pairing.native_origin().clone(),
        })
    }
}
struct SessionState {
    current: bool,
    generation: u64,
}
struct SessionInner {
    journal: SignerJournalBinding,
    account_id: String,
    principal_id: String,
    writer_epoch: u64,
    measurement: String,
    session_id: String,
    created: Instant,
    issued_receipts: Mutex<std::collections::BTreeMap<String, Instant>>,
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    native_origin: Option<crate::native_ui::NativeAuthorityBinding>,
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    native_peer: Option<crate::ipc::AuthenticatedPeer>,
    state: RwLock<SessionState>,
}
/// Opaque owner/principal/source-bound native session. Revocation is serialized
/// with held journal leases, not implemented as a racy preflight boolean.
pub struct SignerConsentSession {
    inner: Arc<SessionInner>,
}
impl SignerConsentSession {
    pub fn from_trusted_launch(launch: TrustedSignerLaunch) -> Result<Self> {
        id(&launch.account_id)?;
        id(&launch.principal_id)?;
        hash(&launch.measurement)?;
        if launch.writer_epoch == 0 {
            return Err(JournalError::Permission);
        }
        #[cfg(all(feature = "native-ui", target_os = "linux"))]
        if let Some(origin) = &launch.native_origin {
            origin
                .check_current()
                .map_err(|_| JournalError::Permission)?;
        }
        #[cfg(all(feature = "native-ui", target_os = "linux"))]
        if let Some(peer) = &launch.native_peer {
            peer.check_current().map_err(|_| JournalError::Permission)?;
        }
        Ok(Self {
            inner: Arc::new(SessionInner {
                journal: launch.journal,
                account_id: launch.account_id,
                principal_id: launch.principal_id,
                writer_epoch: launch.writer_epoch,
                measurement: launch.measurement,
                session_id: random_id()?,
                created: Instant::now(),
                issued_receipts: Mutex::new(std::collections::BTreeMap::new()),
                #[cfg(all(feature = "native-ui", target_os = "linux"))]
                native_origin: launch.native_origin,
                #[cfg(all(feature = "native-ui", target_os = "linux"))]
                native_peer: launch.native_peer,
                state: RwLock::new(SessionState {
                    current: true,
                    generation: 1,
                }),
            }),
        })
    }
    /// Focus loss, Lock, close, navigation, app revocation and launch invalidation
    /// must call this. An invalidated session cannot be reactivated.
    pub fn invalidate(&self) -> Result<()> {
        let mut state = self
            .inner
            .state
            .write()
            .map_err(|_| JournalError::Permission)?;
        state.current = false;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(JournalError::Permission)?;
        Ok(())
    }
    fn receipt(&self) -> Result<NativeConsentReceipt> {
        let state = self.inner.read()?;
        let now = now_ms()?;
        let nonce = random_id()?;
        let mut issued = self
            .inner
            .issued_receipts
            .lock()
            .map_err(|_| JournalError::Permission)?;
        issued.retain(|_, instant| instant.elapsed() < Duration::from_secs(120));
        if issued.len() >= 4096 {
            return Err(JournalError::Limit);
        }
        issued.insert(nonce.clone(), Instant::now());
        Ok(NativeConsentReceipt {
            native_session_id: self.inner.session_id.clone(),
            trusted_launch_measurement: self.inner.measurement.clone(),
            permission_generation: state.generation,
            writer_epoch: self.inner.writer_epoch,
            nonce,
            reviewed_at_ms: now,
            expires_at_ms: now.checked_add(120_000).ok_or(JournalError::Expired)?,
        })
    }
    pub fn prepare_enrollment(
        &self,
        account: &DedicatedAccount,
        proposal: &Proposal,
        transport: AuthenticatedTransportIdentity,
        request: EnrollmentRequest,
    ) -> Result<PreparedEnrollment> {
        #[cfg(all(feature = "native-ui", target_os = "linux"))]
        if self.inner.native_origin.as_ref() != Some(&transport.native_origin) {
            return Err(JournalError::Permission);
        }
        let account_id = account
            .account_id()
            .map_err(|_| JournalError::InvalidBinding)?;
        let owner = proposal
            .manifest()
            .participants
            .iter()
            .find(|p| p.participant_id == request.participant_id && p.account_id == account_id)
            .ok_or(JournalError::InvalidBinding)?;
        if account.recovery_required()
            || account_id != self.inner.account_id
            || transport.account_id != account_id
            || transport.agreement_id != proposal.manifest().agreement.agreement_id
            || transport.participant_id != owner.participant_id
            || request.aggregate_budget_limit_zatoshis < owner.maximum_net_debit.as_zatoshis()
        {
            return Err(JournalError::InvalidBinding);
        }
        transport.binding.validate_scope(
            &account_id,
            &proposal.manifest().agreement.agreement_id,
            &request.participant_id,
            Some(proposal.manifest_digest()),
        )?;
        let record = AccountEnrollmentRecord::new(EnrollmentTerms {
            account_id,
            agreement_id: proposal.manifest().agreement.agreement_id.clone(),
            participant_id: request.participant_id,
            principal_id: self.inner.principal_id.clone(),
            network_profile_id: proposal.manifest().agreement.network_profile_id.clone(),
            privacy_domain: account.privacy_domain().into(),
            account_fvk_digest: hex::encode(Sha256::digest(
                account
                    .fvk()
                    .map_err(|_| JournalError::InvalidBinding)?
                    .to_bytes(),
            )),
            transport: transport.binding,
            aggregate_budget_limit_zatoshis: request.aggregate_budget_limit_zatoshis,
            receipt: self.receipt()?,
        })?;
        Ok(PreparedEnrollment(Pending::new(
            record.clone(),
            record.reference.clone(),
            &self.inner,
        )))
    }
    pub fn approve_enrollment(
        &self,
        prepared: PreparedEnrollment,
        decision: NativeConsentDecision,
    ) -> Result<ApprovedEnrollment> {
        Ok(ApprovedEnrollment(prepared.0.approve(self, decision)?))
    }
    pub fn prepare_manifest(
        &self,
        enrollment: &AccountEnrollmentRecord,
        proposal: &Proposal,
    ) -> Result<PreparedManifestAcceptance> {
        enrollment.validate()?;
        self.matches(enrollment)?;
        if enrollment.terms.agreement_id != proposal.manifest().agreement.agreement_id
            || enrollment.terms.network_profile_id
                != proposal.manifest().agreement.network_profile_id
            || !proposal.manifest().participants.iter().any(|p| {
                p.account_id == enrollment.terms.account_id
                    && p.participant_id == enrollment.terms.participant_id
            })
        {
            return Err(JournalError::InvalidBinding);
        }
        enrollment.transport().validate_scope(
            enrollment.account_id(),
            enrollment.agreement_id(),
            enrollment.participant_id(),
            Some(proposal.manifest_digest()),
        )?;
        let record = AcceptedManifestRecord::new(ManifestTerms {
            enrollment_ref: enrollment.reference.clone(),
            account_id: enrollment.terms.account_id.clone(),
            principal_id: enrollment.terms.principal_id.clone(),
            proposal: proposal.input().clone(),
            proposal_digest: proposal.proposal_digest().into(),
            manifest_digest: proposal.manifest_digest().into(),
            receipt: self.receipt()?,
        })?;
        Ok(PreparedManifestAcceptance(Pending::new(
            record.clone(),
            record.reference.clone(),
            &self.inner,
        )))
    }
    pub fn approve_manifest(
        &self,
        prepared: PreparedManifestAcceptance,
        decision: NativeConsentDecision,
    ) -> Result<ApprovedManifestAcceptance> {
        Ok(ApprovedManifestAcceptance(
            prepared.0.approve(self, decision)?,
        ))
    }
    /// Reconciles actual cryptographic effects and signer-derived account FVK with
    /// the retained manifest and maintained-wallet selection. Neither this review
    /// nor the original decision establishes current unspentness or writer fencing.
    pub fn prepare_spend(
        &self,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
        account: &DedicatedAccount,
        bytes: &[u8],
        inputs: &ReviewInputs,
        authorization_id: &str,
    ) -> Result<PreparedSpendConsent> {
        if account.recovery_required() {
            return Err(JournalError::RecoveryRequired);
        }
        let account_id = account
            .account_id()
            .map_err(|_| JournalError::InvalidBinding)?;
        let fvk = account.fvk().map_err(|_| JournalError::InvalidBinding)?;
        self.prepare_spend_for_account(
            enrollment,
            manifest,
            (&account_id, &fvk),
            bytes,
            inputs,
            authorization_id,
        )
    }
    fn prepare_spend_for_account(
        &self,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
        account: (&str, &orchard::keys::FullViewingKey),
        bytes: &[u8],
        inputs: &ReviewInputs,
        authorization_id: &str,
    ) -> Result<PreparedSpendConsent> {
        enrollment.validate()?;
        self.matches(enrollment)?;
        let proposal = manifest.proposal()?;
        if account.0 != enrollment.terms.account_id
            || manifest.terms.enrollment_ref != enrollment.reference
            || manifest.terms.account_id != enrollment.terms.account_id
            || manifest.terms.principal_id != enrollment.terms.principal_id
            || hex::encode(Sha256::digest(account.1.to_bytes()))
                != enrollment.terms.account_fvk_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        let accepted = AcceptedManifest { proposal };
        crate::manifest::reconcile(&accepted, inputs, &enrollment.terms.account_id, account.1)
            .map_err(|_| JournalError::InvalidBinding)?;
        let verified =
            verify_review(bytes, &inputs.policy).map_err(|_| JournalError::InvalidBinding)?;
        let owner = inputs
            .policy
            .participants
            .iter()
            .position(|p| p.account_id == enrollment.terms.account_id)
            .ok_or(JournalError::InvalidBinding)?;
        let mut input_bindings = Vec::new();
        for mapping in inputs
            .input_actions
            .iter()
            .filter(|m| m.account_id == enrollment.terms.account_id)
        {
            let input = inputs
                .policy
                .inputs
                .iter()
                .find(|i| i.action_index == mapping.action_index && i.participant_index == owner)
                .ok_or(JournalError::InvalidBinding)?;
            input_bindings.push(ConsentInputBinding {
                input_id: mapping.input_id.clone(),
                action_index: input
                    .action_index
                    .try_into()
                    .map_err(|_| JournalError::InvalidBinding)?,
                nullifier: hex::encode(input.nullifier),
                value_zatoshis: input.value_zatoshis,
            });
        }
        input_bindings.sort_by(|a, b| a.input_id.cmp(&b.input_id));
        let selection = &inputs.own_selection.context;
        let t = SpendConsentTerms {
            durable_born_policy_v1: None,
            automation: None,
            sponsor_policy: None,
            sponsor_owner_attestation_digest: None,
            authorization_id: authorization_id.into(),
            enrollment_ref: enrollment.reference.clone(),
            accepted_manifest_ref: manifest.reference.clone(),
            account_id: enrollment.terms.account_id.clone(),
            principal_id: enrollment.terms.principal_id.clone(),
            agreement_id: accepted.proposal.manifest().agreement.agreement_id.clone(),
            obligation_id: accepted.proposal.manifest().agreement.obligation_id.clone(),
            proposal_id: accepted.proposal.input().proposal_id.clone(),
            proposal_digest: accepted.proposal.proposal_digest().into(),
            manifest_digest: accepted.proposal.manifest_digest().into(),
            effects_digest: verified.shielded_sighash().into(),
            artifact_digest: hex::encode(Sha256::digest(bytes)),
            review_binding: verified.review_binding().into(),
            transport: enrollment.terms.transport.clone(),
            input_bindings,
            maximum_debit_zatoshis: verified.net_debits_zatoshis()[owner],
            fee_share_zatoshis: inputs.policy.participants[owner].fee_share_zatoshis,
            transaction_fee_zatoshis: verified.fee_zatoshis(),
            aggregate_budget_limit_zatoshis: enrollment.terms.aggregate_budget_limit_zatoshis,
            transaction_expiry_height: inputs.policy.expiry_height,
            wallet_key_use_policy: inputs.own_selection.key_use_policy.clone(),
            wallet_snapshot: WalletSnapshotBinding {
                tip_height: selection.tip_height,
                tip_hash: hex::encode(selection.tip_hash),
                anchor_height: selection.anchor_height,
                anchor_hash: hex::encode(selection.anchor_hash),
                anchor_root: hex::encode(selection.anchor_root),
            },
            receipt: self.receipt()?,
        };
        let record = OriginalSpendConsent::new(t)?;
        let pending = Pending::new(record.clone(), record.reference.clone(), &self.inner);
        let reviewed_owner_fvks = Some(
            inputs
                .policy
                .participants
                .iter()
                .map(|p| {
                    (
                        p.account_id.clone(),
                        hex::encode(Sha256::digest(p.fvk.to_bytes())),
                    )
                })
                .collect(),
        );
        Ok(PreparedSpendConsent(pending, reviewed_owner_fvks))
    }
    pub fn approve_spend(
        &self,
        prepared: PreparedSpendConsent,
        decision: NativeConsentDecision,
    ) -> Result<ApprovedSpendConsent> {
        Ok(ApprovedSpendConsent(prepared.0.approve(self, decision)?))
    }
    fn matches(&self, enrollment: &AccountEnrollmentRecord) -> Result<()> {
        if self.inner.account_id != enrollment.terms.account_id
            || self.inner.principal_id != enrollment.terms.principal_id
            || self.inner.writer_epoch != enrollment.terms.receipt.writer_epoch
            || self.inner.session_id != enrollment.terms.receipt.native_session_id
        {
            return Err(JournalError::Permission);
        }
        Ok(())
    }
    pub(super) fn read_lease(
        &self,
        journal: &SignerJournalBinding,
        account: &SignerAccountState,
    ) -> Result<ReadLease<'_>> {
        if self.inner.journal != *journal
            || self.inner.account_id != account.account_id
            || self.inner.writer_epoch != account.writer_epoch
        {
            return Err(JournalError::Permission);
        }
        Ok(ReadLease {
            _guard: self.inner.read()?,
            principal: &self.inner.principal_id,
            session: &self.inner,
        })
    }
}
#[cfg(all(feature = "native-ui", target_os = "linux"))]
impl SignerConsentSession {
    pub(crate) fn native_decision(
        &self,
        decision: crate::native_ui::NativeDecision,
    ) -> Result<NativeConsentDecision> {
        let state = self.inner.read()?;
        let origin = self
            .inner
            .native_origin
            .as_ref()
            .ok_or(JournalError::Permission)?;
        if origin != decision.binding() {
            return Err(JournalError::Permission);
        }
        hash(decision.reviewed_digest())?;
        Ok(NativeConsentDecision {
            session_id: self.inner.session_id.clone(),
            permission_generation: state.generation,
            reviewed_digest: decision.reviewed_digest().into(),
        })
    }
}
impl Drop for SignerConsentSession {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.write() {
            state.current = false;
        }
    }
}
impl SessionInner {
    fn read(&self) -> Result<RwLockReadGuard<'_, SessionState>> {
        let state = self.state.read().map_err(|_| JournalError::Permission)?;
        #[cfg(all(feature = "native-ui", target_os = "linux"))]
        if let Some(origin) = &self.native_origin {
            origin
                .check_current()
                .map_err(|_| JournalError::Permission)?;
        }
        #[cfg(all(feature = "native-ui", target_os = "linux"))]
        if let Some(peer) = &self.native_peer {
            peer.check_current().map_err(|_| JournalError::Permission)?;
        }
        if !state.current || self.created.elapsed() >= Duration::from_secs(15 * 60) {
            return Err(JournalError::Permission);
        }
        Ok(state)
    }
}
pub(super) struct ReadLease<'a> {
    _guard: RwLockReadGuard<'a, SessionState>,
    pub principal: &'a str,
    session: &'a SessionInner,
}
impl ReadLease<'_> {
    pub(super) fn check_current(&self) -> Result<()> {
        if !self._guard.current || self.session.created.elapsed() >= Duration::from_secs(15 * 60) {
            return Err(JournalError::Permission);
        }
        #[cfg(all(feature = "native-ui", target_os = "linux"))]
        if let Some(origin) = &self.session.native_origin {
            origin
                .check_current()
                .map_err(|_| JournalError::Permission)?;
        }
        #[cfg(all(feature = "native-ui", target_os = "linux"))]
        if let Some(peer) = &self.session.native_peer {
            peer.check_current().map_err(|_| JournalError::Permission)?;
        }
        Ok(())
    }
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    pub(super) fn require_native_origin(
        &self,
        origin: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<()> {
        self.check_current()?;
        if self.session.native_origin.as_ref() != Some(origin) {
            return Err(JournalError::Permission);
        }
        Ok(())
    }
    pub(super) fn require_spending_decision(&self, receipt: &NativeConsentReceipt) -> Result<()> {
        self.check_current()?;
        if receipt.native_session_id != self.session.session_id
            || receipt.permission_generation != self._guard.generation
            || receipt.writer_epoch != self.session.writer_epoch
            || receipt.trusted_launch_measurement != self.session.measurement
        {
            return Err(JournalError::Permission);
        }
        let now = now_ms()?;
        if now < receipt.reviewed_at_ms || now >= receipt.expires_at_ms {
            return Err(JournalError::Expired);
        }
        let issued = self
            .session
            .issued_receipts
            .lock()
            .map_err(|_| JournalError::Permission)?;
        // A database row and wall clock can never revive missing/expired live
        // native review. This provenance exists only in the originating session.
        let instant = issued.get(&receipt.nonce).ok_or(JournalError::Permission)?;
        if instant.elapsed() >= Duration::from_secs(120) {
            return Err(JournalError::Expired);
        }
        Ok(())
    }
}

pub struct EnrollmentRequest {
    pub participant_id: String,
    pub aggregate_budget_limit_zatoshis: u64,
}
struct Pending<T> {
    record: T,
    review_digest: String,
    session: Arc<SessionInner>,
    created: Instant,
}
impl<T> Pending<T> {
    fn new(record: T, review_digest: String, session: &Arc<SessionInner>) -> Self {
        Self {
            record,
            review_digest,
            session: Arc::clone(session),
            created: Instant::now(),
        }
    }
    fn approve(
        self,
        session: &SignerConsentSession,
        decision: NativeConsentDecision,
    ) -> Result<Approval<T>> {
        let state = self.session.read()?;
        if !Arc::ptr_eq(&self.session, &session.inner)
            || decision.session_id != self.session.session_id
            || decision.permission_generation != state.generation
            || decision.reviewed_digest != self.review_digest
        {
            return Err(JournalError::Permission);
        }
        if self.created.elapsed() >= Duration::from_secs(120) {
            return Err(JournalError::Expired);
        }
        drop(state);
        Ok(Approval {
            record: self.record,
            session: self.session,
            created: self.created,
        })
    }
}
pub(super) struct Approval<T> {
    pub record: T,
    session: Arc<SessionInner>,
    created: Instant,
}
impl<T> Approval<T> {
    pub fn lease(
        &self,
        journal: &SignerJournalBinding,
        account: &SignerAccountState,
        receipt: &NativeConsentReceipt,
    ) -> Result<ReadLease<'_>> {
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let state = self.session.read()?;
        let now = now_ms()?;
        if self.session.journal != *journal
            || self.session.account_id != account.account_id
            || self.session.writer_epoch != account.writer_epoch
            || receipt.native_session_id != self.session.session_id
            || receipt.trusted_launch_measurement != self.session.measurement
            || receipt.permission_generation != state.generation
            || receipt.writer_epoch != account.writer_epoch
        {
            return Err(JournalError::Permission);
        }
        if self.created.elapsed() >= Duration::from_secs(120)
            || now < receipt.reviewed_at_ms
            || now >= receipt.expires_at_ms
        {
            return Err(JournalError::Expired);
        }
        Ok(ReadLease {
            _guard: state,
            principal: &self.session.principal_id,
            session: &self.session,
        })
    }
}

pub struct PreparedEnrollment(Pending<AccountEnrollmentRecord>);
pub struct PreparedManifestAcceptance(Pending<AcceptedManifestRecord>);
pub struct PreparedSpendConsent(Pending<OriginalSpendConsent>, Option<Vec<(String, String)>>);
pub struct ApprovedEnrollment(pub(super) Approval<AccountEnrollmentRecord>);
pub struct ApprovedManifestAcceptance(pub(super) Approval<AcceptedManifestRecord>);
pub struct ApprovedSpendConsent(pub(super) Approval<OriginalSpendConsent>);
impl PreparedEnrollment {
    pub fn review_digest(&self) -> &str {
        &self.0.review_digest
    }
    pub fn record(&self) -> &AccountEnrollmentRecord {
        &self.0.record
    }
}
impl PreparedManifestAcceptance {
    pub fn review_digest(&self) -> &str {
        &self.0.review_digest
    }
    pub fn record(&self) -> &AcceptedManifestRecord {
        &self.0.record
    }
}
impl PreparedSpendConsent {
    /// Pre-decision binding only. This changes the exact native review hash;
    /// neither an existing approval nor an old original release can be remapped.
    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn with_durable_born_policy_v1(
        mut self,
        binding: DurableBornPolicyBindingV1,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
    ) -> Result<Self> {
        if self.0.record.terms.durable_born_policy_v1.is_some() {
            return Err(JournalError::Conflict);
        }
        binding.validate_consent(&self.0.record.terms, enrollment, manifest)?;
        binding.require_current_time(now_ms()?)?;
        self.0.record.terms.durable_born_policy_v1 = Some(binding);
        self.0.record = OriginalSpendConsent::new(self.0.record.terms)?;
        self.0.review_digest = self.0.record.reference.clone();
        Ok(self)
    }
    pub(super) fn reviewed_owner_fvks(&self) -> Result<&[(String, String)]> {
        self.1.as_deref().ok_or(JournalError::Permission)
    }

    pub(super) fn with_sponsor_binding(
        mut self,
        binding: Option<SponsorPolicyBinding>,
        attestation_digest: Option<String>,
    ) -> Result<Self> {
        self.0.record.terms.sponsor_policy = binding;
        self.0.record.terms.sponsor_owner_attestation_digest = attestation_digest;
        self.0.record = OriginalSpendConsent::new(self.0.record.terms)?;
        self.0.review_digest = self.0.record.reference.clone();
        Ok(self)
    }

    pub fn review_digest(&self) -> &str {
        &self.0.review_digest
    }
    pub fn record(&self) -> &OriginalSpendConsent {
        &self.0.record
    }
}

#[cfg(test)]
pub(super) mod fixture {
    use super::*;
    pub fn session(journal: &SignerConsentJournal, principal: &str) -> SignerConsentSession {
        let state = journal.account_state().unwrap();
        SignerConsentSession::from_trusted_launch(TrustedSignerLaunch {
            journal: journal.binding(),
            account_id: state.account_id,
            principal_id: principal.into(),
            writer_epoch: state.writer_epoch,
            measurement: "ab".repeat(32),
            #[cfg(all(feature = "native-ui", target_os = "linux"))]
            native_origin: None,
            #[cfg(all(feature = "native-ui", target_os = "linux"))]
            native_peer: None,
        })
        .unwrap()
    }
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    pub fn native_session(
        journal: &SignerConsentJournal,
        origin: crate::native_ui::NativeAuthorityBinding,
        principal: &str,
        measurement: &str,
    ) -> SignerConsentSession {
        let state = journal.account_state().unwrap();
        SignerConsentSession::from_trusted_launch(TrustedSignerLaunch {
            journal: journal.binding(),
            account_id: state.account_id,
            principal_id: principal.into(),
            writer_epoch: state.writer_epoch,
            measurement: measurement.into(),
            native_origin: Some(origin),
            native_peer: None,
        })
        .unwrap()
    }
    pub fn decision(session: &SignerConsentSession, digest: &str) -> NativeConsentDecision {
        NativeConsentDecision {
            session_id: session.inner.session_id.clone(),
            permission_generation: session.inner.state.read().unwrap().generation,
            reviewed_digest: digest.into(),
        }
    }
    pub fn approve_redelivery(
        session: &SignerConsentSession,
        record: ResultRedeliveryRecord,
    ) -> ApprovedResultRedelivery {
        redelivery_authority::fixture_approval(session, record)
    }
    pub fn approve_enrollment(
        session: &SignerConsentSession,
        terms: EnrollmentTerms,
    ) -> ApprovedEnrollment {
        let record = AccountEnrollmentRecord::new(EnrollmentTerms {
            receipt: session.receipt().unwrap(),
            ..terms
        })
        .unwrap();
        let prepared = PreparedEnrollment(Pending::new(
            record.clone(),
            record.reference.clone(),
            &session.inner,
        ));
        let decision = decision(session, prepared.review_digest());
        session.approve_enrollment(prepared, decision).unwrap()
    }
    pub fn approve_spend(
        session: &SignerConsentSession,
        terms: SpendConsentTerms,
    ) -> ApprovedSpendConsent {
        let record = OriginalSpendConsent::new(SpendConsentTerms {
            receipt: session.receipt().unwrap(),
            ..terms
        })
        .unwrap();
        let prepared = PreparedSpendConsent(
            Pending::new(record.clone(), record.reference.clone(), &session.inner),
            None,
        );
        let decision = decision(session, prepared.review_digest());
        session.approve_spend(prepared, decision).unwrap()
    }
    pub fn exact_spend(
        session: &SignerConsentSession,
        record: OriginalSpendConsent,
    ) -> ApprovedSpendConsent {
        let prepared = PreparedSpendConsent(
            Pending::new(record.clone(), record.reference.clone(), &session.inner),
            None,
        );
        let decision = decision(session, prepared.review_digest());
        session.approve_spend(prepared, decision).unwrap()
    }
    #[cfg(feature = "synthetic-qualification")]
    pub fn prepare_synthetic_spend(
        session: &SignerConsentSession,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
        bytes: &[u8],
        inputs: ReviewInputs,
    ) -> Result<PreparedSpendConsent> {
        let fvk = inputs.policy.participants[0].fvk.clone();
        session.prepare_spend_for_account(
            enrollment,
            manifest,
            (enrollment.account_id(), &fvk),
            bytes,
            &inputs,
            "synthetic-verified-authorization",
        )
    }
    pub fn exercise_held_lease_revocation(
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        approval: &ApprovedSpendConsent,
    ) {
        let state = journal.account_state().unwrap();
        let lease = approval
            .0
            .lease(&journal.binding(), &state, &approval.0.record.terms.receipt)
            .unwrap();
        // Deterministic lock-contention assertion, independent of scheduling.
        assert!(matches!(
            session.inner.state.try_write(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        std::thread::scope(|threads| {
            threads.spawn(|| {
                started_tx.send(()).unwrap();
                session.invalidate().unwrap();
                finished_tx.send(()).unwrap();
            });
            started_rx.recv().unwrap();
            assert!(matches!(
                finished_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            drop(lease);
            finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
    }
    pub fn expire_receipt_monotonically(session: &SignerConsentSession, nonce: &str) {
        *session
            .inner
            .issued_receipts
            .lock()
            .unwrap()
            .get_mut(nonce)
            .unwrap() = Instant::now() - Duration::from_secs(121);
    }
    pub fn receipt(session: &SignerConsentSession) -> NativeConsentReceipt {
        session.receipt().unwrap()
    }
}

/// Test-only inspection of a held lease using an actual IPC-issued peer. The
/// callback can only make its permission less current; no issuer is exposed.
#[cfg(all(test, feature = "native-ui", target_os = "linux"))]
pub(crate) fn assert_native_peer_revocation(
    journal: &SignerConsentJournal,
    origin: crate::native_ui::NativeAuthorityBinding,
    principal: &str,
    measurement: &str,
    peer: crate::ipc::AuthenticatedPeer,
    revoke: impl FnOnce(),
) {
    let mut session = fixture::native_session(journal, origin, principal, measurement);
    Arc::get_mut(&mut session.inner).unwrap().native_peer = Some(peer);
    let state = journal.account_state().unwrap();
    let lease = session.read_lease(&journal.binding(), &state).unwrap();
    lease.check_current().unwrap();
    revoke();
    assert!(matches!(
        lease.check_current(),
        Err(JournalError::Permission)
    ));
    drop(lease);
    assert!(session.inner.read().is_err());
}

#[path = "writer_reconciliation.rs"]
mod writer_reconciliation;
pub use writer_reconciliation::*;
// The always-compiled typed writer kernel also preserves online exposure.
pub(super) use writer_reconciliation::retain_remote_exposure;

#[path = "durable_payment_admission_intent_v1.rs"]
pub(crate) mod durable_payment_admission_intent_v1;

#[path = "redelivery_authority.rs"]
mod redelivery_authority;
pub use redelivery_authority::*;

#[cfg(feature = "authority-signing")]
#[path = "settlement_source.rs"]
mod settlement_source;
#[cfg(feature = "authority-signing")]
pub use settlement_source::*;

#[path = "automation_authority.rs"]
mod automation_authority;
pub use automation_authority::*;

#[path = "durable_delivery_admission_intent_v2.rs"]
pub(crate) mod durable_delivery_admission_intent_v2;

// V3 is purpose-distinct from the generic session/receipt issuer above.
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
#[path = "durable_delivery_admission_intent_v3.rs"]
pub(crate) mod durable_delivery_admission_intent_v3;
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub(crate) use durable_delivery_admission_intent_v3::{
    PreparedDurableDeliveryAdmissionIntentV3, RetainedDurableDeliveryAdmissionIntentV3,
};
