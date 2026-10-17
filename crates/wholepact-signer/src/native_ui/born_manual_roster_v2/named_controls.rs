//! Native continuation of the actual consumed source. Each local enrollment,
//! manifest, profile and original-owner signature has its own exact decision.
//! Historical Host channels never occupy the foreground job slot.
use super::*;
use crate::consent_journal::{PreparedEnrollment, PreparedManifestAcceptance};
use named_continuation::ConsumedBornNamedOwnerV1;

pub(super) enum NamedStep {
    #[cfg(feature = "offline-review-foundation")]
    Verifier(Box<super::named_verifier_disclosure::Prepared>),
    #[cfg(feature = "offline-review-foundation")]
    Bridge(Box<super::named_bridge::Prepared>),
    #[cfg(feature = "offline-review-foundation")]
    OwnerEnrollment(Box<crate::consent_journal::PreparedBornOfflineOwnerEnrollmentV1>),
    #[cfg(feature = "offline-review-foundation")]
    Export(Box<super::named_enrollment_export::PreparedBornEnrollmentExportV1>),
    Enrollment(Box<PreparedEnrollment>),
    Manifest(Box<PreparedManifestAcceptance>),
}
impl NamedStep {
    pub(super) fn display(&self) -> Result<(String, String)> {
        #[cfg(feature = "offline-review-foundation")]
        match self {
            Self::Verifier(p) => return p.display(),
            Self::Bridge(p) => return p.display(),
            Self::OwnerEnrollment(p) => return Ok((p.digest().into(), p.display().into())),
            Self::Export(p) => return Ok((p.digest().into(), p.display().into())),
            _ => {}
        }
        let (digest, body, label) = match self {
            Self::Enrollment(p) => (
                p.review_digest(),
                serde_json::to_string_pretty(p.record()),
                "ACCEPT EXACT LOCAL BORN PARTICIPATION ENROLLMENT",
            ),
            #[cfg(feature = "offline-review-foundation")]
            Self::OwnerEnrollment(_) | Self::Export(_) | Self::Bridge(_) | Self::Verifier(_) => {
                return Err(Error::Unavailable);
            }
            Self::Manifest(p) => (
                p.review_digest(),
                serde_json::to_string_pretty(p.record()),
                "ACCEPT EXACT ORIGINAL CONSUMED CONSTRUCTION MANIFEST",
            ),
        };
        Ok((
            digest.into(),
            format!(
                "{label}\n{}\n\nThis binds a distinct local native consent record to the original consumed construction and paired Host. It does not renew the original witness session, undo its permanent transport fence, select new inputs, duplicate reserved exposure, or authorize a transaction signature. Named-verifier setup and final signing each need a separate exact review.",
                body.map_err(|_| Error::InvalidData)?
            ),
        ))
    }
}
pub(super) enum NamedWork {
    #[cfg(feature = "offline-review-foundation")]
    PrepareVerifier(Box<ConsumedBornNamedOwnerV1>, Box<super::named_verifier_disclosure::Input>),
    #[cfg(feature = "offline-review-foundation")]
    PrepareBridge(Box<ConsumedBornNamedOwnerV1>, Box<super::named_bridge::Input>),
    #[cfg(feature="offline-review-foundation")]
    PrepareOwnerEnrollment(Box<ConsumedBornNamedOwnerV1>,crate::consent_journal::LiveNamedRecipientProfile,wholepact_authority::born_offline_enrollment_v1::BornOfflineEnrollmentV1,crate::consent_journal::NamedRecipientOperation),
    #[cfg(feature="offline-review-foundation")]
    PrepareExport(Box<ConsumedBornNamedOwnerV1>,wholepact_authority::born_offline_enrollment_signature_v1::BornOfflineEnrollmentOwnerSignatureV1,PathBuf),
    PrepareEnrollment(Box<ConsumedBornNamedOwnerV1>, AuthenticatedPairing),
    Commit(Box<ConsumedBornNamedOwnerV1>, NamedStep, NativeDecision),
}
pub(super) struct NamedOutput {
    #[cfg(feature = "offline-review-foundation")]
    verifier: Option<super::named_verifier_disclosure::Outcome>,
    actual: Box<ConsumedBornNamedOwnerV1>,
    next: Option<NamedStep>,
    #[cfg(feature = "offline-review-foundation")]
    bridge: Option<super::named_bridge::Approved>,
    #[cfg(feature="offline-review-foundation")]
    signed: Option<wholepact_authority::born_offline_enrollment_signature_v1::BornOfflineEnrollmentOwnerSignatureV1>,
}
pub(super) fn run(work: NamedWork, owner: &PendingAccountNativeAuthority) -> Result<NamedOutput> {
    #[cfg(feature = "offline-review-foundation")]
    let mut signed = None;
    #[cfg(feature = "offline-review-foundation")]
    let mut verifier = None;
    #[cfg(feature = "offline-review-foundation")]
    let mut bridge = None;
    let (actual, next) = match work {
        #[cfg(feature = "offline-review-foundation")]
        NamedWork::PrepareVerifier(actual, input) => {
            let prepared = input.prepare(&actual, owner)?;
            (actual, Some(NamedStep::Verifier(Box::new(prepared))))
        }
        #[cfg(feature = "offline-review-foundation")]
        NamedWork::Commit(actual, NamedStep::Verifier(prepared), decision) => {
            verifier = Some(prepared.approve(decision, &actual, owner)?);
            (actual, None)
        }
        #[cfg(feature = "offline-review-foundation")]
        NamedWork::PrepareBridge(actual, input) => {
            let prepared = input.prepare(&actual)?;
            (actual, Some(NamedStep::Bridge(Box::new(prepared))))
        }
        #[cfg(feature = "offline-review-foundation")]
        NamedWork::Commit(actual, NamedStep::Bridge(prepared), decision) => {
            bridge = Some(prepared.approve(decision, &actual, owner)?);
            (actual, None)
        }
        #[cfg(feature = "offline-review-foundation")]
        NamedWork::PrepareOwnerEnrollment(actual, profile, proposal, operation) => {
            let prepared = crate::consent_journal::PreparedBornOfflineOwnerEnrollmentV1::prepare(
                &profile,
                actual.source(),
                owner,
                actual.session()?,
                actual.client(),
                proposal,
                operation,
            )?;
            (actual, Some(NamedStep::OwnerEnrollment(Box::new(prepared))))
        }
        #[cfg(feature = "offline-review-foundation")]
        NamedWork::PrepareExport(actual, envelope, path) => {
            let prepared = super::named_enrollment_export::PreparedBornEnrollmentExportV1::prepare(
                actual.source(),
                envelope,
                &path,
                owner,
            )?;
            (actual, Some(NamedStep::Export(Box::new(prepared))))
        }
        #[cfg(feature = "offline-review-foundation")]
        NamedWork::Commit(actual, NamedStep::OwnerEnrollment(p), decision) => {
            signed = Some(
                actual
                    .signer()
                    .sign_born_enrollment(*p, decision, &actual, owner)?,
            );
            (actual, None)
        }
        #[cfg(feature = "offline-review-foundation")]
        NamedWork::Commit(actual, NamedStep::Export(p), decision) => {
            p.publish(decision, actual.source(), owner)?;
            (actual, None)
        }
        NamedWork::PrepareEnrollment(mut actual, pairing) => {
            let prepared = actual.prepare_enrollment(&pairing, owner)?;
            (actual, prepared.map(|p| NamedStep::Enrollment(Box::new(p))))
        }
        NamedWork::Commit(mut actual, NamedStep::Enrollment(prepared), decision) => {
            let prepared = actual.approve_enrollment(*prepared, decision, owner)?;
            (actual, Some(NamedStep::Manifest(Box::new(prepared))))
        }
        NamedWork::Commit(mut actual, NamedStep::Manifest(prepared), decision) => {
            actual.approve_manifest(*prepared, decision, owner)?;
            (actual, None)
        }
    };
    actual.check(owner)?;
    Ok(NamedOutput {
        #[cfg(feature = "offline-review-foundation")]
        verifier,
        actual,
        next,
        #[cfg(feature = "offline-review-foundation")]
        bridge,
        #[cfg(feature = "offline-review-foundation")]
        signed,
    })
}
#[derive(Default)]
pub(super) struct NamedControls {
    #[cfg(feature = "offline-review-foundation")]
    verifier: super::named_verifier_disclosure::State,
    #[cfg(feature = "offline-review-foundation")]
    verifier_scope: Zeroizing<String>,
    #[cfg(feature = "offline-review-foundation")]
    bridge: super::named_bridge::State,
    #[cfg(feature="offline-review-foundation")]
    proposal:Zeroizing<String>,
    #[cfg(feature="offline-review-foundation")]
    destination:Zeroizing<String>,
    #[cfg(feature="offline-review-foundation")]
    operation:Option<crate::consent_journal::NamedRecipientOperation>,
    #[cfg(feature="offline-review-foundation")]
    signed:Option<wholepact_authority::born_offline_enrollment_signature_v1::BornOfflineEnrollmentOwnerSignatureV1>,
    #[cfg(feature = "offline-review-foundation")]
    workspace: super::super::named_recipient::NamedRecipientWorkspace,
}
impl NamedControls {
    pub(super) fn clear(&mut self) -> Vec<JoinHandle<()>> {
        #[cfg(feature = "offline-review-foundation")]
        {
            self.workspace.clear();
            if let Some(operation) = self.operation.take() {
                operation.revoke();
            }
            self.signed = None;
            self.proposal.zeroize();
            self.destination.zeroize();
            self.verifier_scope.zeroize();
            let mut cleanup = self.bridge.cancel_and_drain();
            if let Some(thread) = self.verifier.clear() {
                cleanup.push(thread);
            }
            return cleanup;
        }
        #[cfg(not(feature = "offline-review-foundation"))]
        Vec::new()
    }
    pub(super) fn reap_cancelled(&mut self) {
        #[cfg(feature = "offline-review-foundation")]
        self.workspace.reap_cancelled();
    }
    pub(super) fn active(&self) -> bool {
        #[cfg(feature = "offline-review-foundation")]
        {
            self.workspace.final_active()
        }
        #[cfg(not(feature = "offline-review-foundation"))]
        {
            false
        }
    }
}
impl BornManualRosterUiV2 {
    pub(super) fn accept_named_output(&mut self, output: NamedOutput, epoch: u64) -> Result<()> {
        self.named_continuation = Some(output.actual);
        #[cfg(feature = "offline-review-foundation")]
        if let Some(outcome) = output.verifier {
            if let Some(thread) = self
                .named_controls
                .verifier
                .adopt(outcome, self.owner.as_deref())?
            {
                self.cleanup.push(thread);
            }
        }
        #[cfg(feature = "offline-review-foundation")]
        if let Some(approved) = output.bridge {
            let owner = self.owner(epoch)?;
            self.named_controls.bridge.adopt(approved, &owner)?;
        }
        #[cfg(feature = "offline-review-foundation")]
        if let Some(signed) = output.signed {
            self.named_controls.signed = Some(signed);
        }
        if let Some(next) = output.next {
            let (digest, display) = next.display()?;
            self.review = Some(Review {
                step: Step::Named(Box::new(next)),
                exact: ExactNativeReview::stage(
                    self.owner(epoch)?.native(),
                    &digest,
                    display,
                    epoch,
                )?,
                displayed_to_end: false,
            });
        } else {
            self.message = "Exact local enrollment and original manifest retained. Separately review named-verifier profile, original-owner witness enrollment and every final signature. The old writer transport remains permanently fenced.";
        }
        Ok(())
    }
    pub(super) fn poll_named_event(&mut self, epoch: u64) -> Result<()> {
        #[cfg(feature = "offline-review-foundation")]
        self.named_controls.bridge.poll();
        if self.named_controls.active() {
            return Ok(());
        }
        let owner = self.owner(epoch)?;
        #[cfg(feature = "offline-review-foundation")]
        if self.named_controls.verifier.engaged() {
            if let Some(input) = self.named_controls.verifier.poll()? {
                let actual = self.named_continuation.take().ok_or(Error::Locked)?;
                self.start(
                    Work::Named(Box::new(NamedWork::PrepareVerifier(
                        actual,
                        Box::new(input),
                    ))),
                    epoch,
                )?;
            }
            return Ok(());
        }
        let event = self
            .completion_opened
            .as_ref()
            .and_then(|o| o.ipc.try_lock().ok().and_then(|ipc| ipc.next_event()));
        match event {
            #[cfg(feature = "offline-review-foundation")]
            Some(
                event @ (LocalEvent::BornOriginalHistoryV1 { .. }
                | LocalEvent::BornDispatchV1 { .. }),
            ) => {
                let profile = self
                    .named_controls
                    .workspace
                    .live_profile()
                    .ok_or(Error::Locked)?;
                let grant = self
                    .peer
                    .as_ref()
                    .ok_or(Error::Authentication)?
                    .grant_id
                    .clone();
                let input = self
                    .named_controls
                    .bridge
                    .queue(event, profile, owner, &grant)?;
                let actual = self.named_continuation.take().ok_or(Error::Locked)?;
                self.start(
                    Work::Named(Box::new(NamedWork::PrepareBridge(actual, Box::new(input)))),
                    epoch,
                )?;
            }
            Some(LocalEvent::Pairing(pair)) => {
                #[cfg(feature = "offline-review-foundation")]
                if self.named_controls.bridge.held() {
                    return Err(Error::Locked);
                }
                let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
                actual.source().check_pending_pairing(&pair, &owner)?;
                if self
                    .peer
                    .as_ref()
                    .is_some_and(|p| p.scope.manifest_digest == pair.scope.manifest_digest)
                {
                    return Err(Error::ReviewMismatch);
                }
                let generation = self
                    .completion_opened
                    .as_ref()
                    .ok_or(Error::Locked)?
                    .ipc
                    .lock()
                    .map_err(|_| Error::Locked)?
                    .generation();
                let digest = pair.review_digest(generation)?;
                let display = format!(
                    "PAIR SAME ORIGINAL HOST FOR EXACT BORN PAYMENT CONTINUATION\n{}\nActual UID/PID: {} / {}; process instance {}. This history-only grant does not authorize signing or dispatch. Those operations require separate purpose-specific native decisions. The original consumed construction and permanently fenced general writer transport remain unchanged.",
                    serde_json::to_string_pretty(&pair.scope).map_err(|_| Error::InvalidData)?,
                    pair.uid(),
                    pair.pid(),
                    pair.instance()
                );
                self.review = Some(Review {
                    step: Step::Pair(Box::new(pair)),
                    exact: ExactNativeReview::stage(owner.native(), &digest, display, epoch)?,
                    displayed_to_end: false,
                });
            }
            Some(LocalEvent::Request {
                peer,
                request: crate::ipc::AppRequest::Status {},
            }) => {
                let pairing = AuthenticatedPairing::from_authenticated_request(peer.clone())?;
                let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
                actual.source().check_pairing(&pairing, &owner)?;
                if self.peer.as_ref().is_some_and(|p| {
                    p.scope.manifest_digest == peer.scope.manifest_digest
                        && p.grant_id != peer.grant_id
                }) {
                    return Err(Error::ReviewMismatch);
                }
                self.peer = Some(peer);
                if actual.session().is_err() {
                    let actual = self.named_continuation.take().ok_or(Error::Locked)?;
                    self.start(
                        Work::Named(Box::new(NamedWork::PrepareEnrollment(actual, pairing))),
                        epoch,
                    )?;
                }
            }
            None => {}
            // Only the purpose-specific requests above can enter the bridge.
            // Generic authorization export is never enabled by history pairing.
            _ => return Err(Error::Unavailable),
        }
        Ok(())
    }
    pub(super) fn named_ui(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) -> Result<()> {
        let owner = self.owner(epoch)?;
        if !self.named_controls.active()
            && ui
                .button("Lock to key-free exact named-payment reentry")
                .clicked_by(egui::PointerButton::Primary)
        {
            return self.park_named();
        }
        let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
        ui.label("Original consumed born construction. No general writer key is restored; every local/native/witness approval remains distinct.");
        if actual.session().is_err() || actual.local_records().is_err() {
            ui.label("The same original Host must pair this exact proposal manifest using the displayed original endpoint. Then review the distinct local enrollment and exact manifest.");
            return Ok(());
        }
        #[cfg(feature = "offline-review-foundation")]
        {
            if self.named_controls.bridge.held() {
                ui.label("Exact born Host channels remain held. Only a separately reviewed dispatch for the same original may join its history channel; other profile, signing and local writes remain excluded. Lock or blur closes new admission immediately; an already admitted outcome may remain uncertain.");
                ui.ctx().request_repaint_after(Duration::from_millis(50));
                return Ok(());
            }
            if self.named_controls.verifier.engaged() {
                ui.label("Separate exact verifier disclosure lane. All profile, original, signing and Host-channel admissions are excluded until it closes. The original Host pairing is unchanged.");
                if let Some(endpoint) = self.named_controls.verifier.endpoint() {
                    ui.label(format!("Exact verifier endpoint: {}", endpoint.display()));
                }
                if ui
                    .button("Cancel verifier lane and lock named payment")
                    .clicked_by(egui::PointerButton::Primary)
                {
                    self.clear();
                }
                return Ok(());
            }
            let context = actual.context(&owner)?;
            if self.named_controls.workspace.final_active() {
                self.named_controls.workspace.final_ui(
                    ui,
                    &context,
                    None,
                    Some(actual.witness()),
                    focused,
                    epoch,
                );
            } else {
                self.named_controls.workspace.ui(
                    ui,
                    &context,
                    None,
                    Some(actual.witness()),
                    focused,
                    epoch,
                );
            }
        }
        #[cfg(feature = "offline-review-foundation")]
        if !self.named_controls.workspace.final_active() {
            if let Some(profile) = self.named_controls.workspace.live_profile() {
                ui.separator();
                ui.label("Exact named-verifier policy scope JSON. The verifier signing key must match this retained profile; the actual consumed proposal and local record references are independently checked. This does not reuse the original Host pairing.");
                ui.add(
                    egui::TextEdit::multiline(&mut *self.named_controls.verifier_scope)
                        .char_limit(128 * 1024),
                );
                if ui
                    .button("Review separate exact verifier disclosure lane")
                    .clicked_by(egui::PointerButton::Primary)
                {
                    if self.named_controls.verifier_scope.len() > 128 * 1024 {
                        return Err(Error::InvalidData);
                    }
                    let scope = wholepact_core::parse_typed_json(
                        self.named_controls.verifier_scope.as_bytes(),
                    )
                    .map_err(|_| Error::InvalidData)?;
                    self.named_controls.verifier_scope.zeroize();
                    self.named_controls.verifier.begin()?;
                    let input =
                        super::named_verifier_disclosure::Input::Select(profile.clone(), scope);
                    let actual = self.named_continuation.take().ok_or(Error::Locked)?;
                    self.start(
                        Work::Named(Box::new(NamedWork::PrepareVerifier(
                            actual,
                            Box::new(input),
                        ))),
                        epoch,
                    )?;
                    return Ok(());
                }
                ui.separator();
                ui.label("Exact original-owner born enrollment proposal JSON. This separately authorizes only the unchanged consumed construction, existing original owner identity and reviewed profile pins.");
                ui.add(
                    egui::TextEdit::multiline(&mut *self.named_controls.proposal)
                        .char_limit(256 * 1024),
                );
                if ui
                    .button("Review original-owner born enrollment signature")
                    .clicked_by(egui::PointerButton::Primary)
                {
                    let proposal =
                        wholepact_core::parse_typed_json(self.named_controls.proposal.as_bytes())
                            .map_err(|_| Error::InvalidData)?;
                    self.named_controls.proposal.zeroize();
                    let operation = crate::consent_journal::NamedRecipientOperation::new();
                    self.named_controls.operation = Some(operation.clone());
                    let actual = self.named_continuation.take().ok_or(Error::Locked)?;
                    self.start(
                        Work::Named(Box::new(NamedWork::PrepareOwnerEnrollment(
                            actual, profile, proposal, operation,
                        ))),
                        epoch,
                    )?;
                    return Ok(());
                }
            }
            if self.named_controls.signed.is_some() {
                ui.label("Already-existing private standalone export directory");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.named_controls.destination)
                        .char_limit(4096),
                );
                if ui
                    .button("Review exact signed born enrollment export")
                    .clicked_by(egui::PointerButton::Primary)
                {
                    let actual = self.named_continuation.take().ok_or(Error::Locked)?;
                    let signed = self
                        .named_controls
                        .signed
                        .as_ref()
                        .ok_or(Error::Locked)?
                        .clone();
                    let path = PathBuf::from(&*self.named_controls.destination);
                    self.start(
                        Work::Named(Box::new(NamedWork::PrepareExport(actual, signed, path))),
                        epoch,
                    )?;
                    return Ok(());
                }
            }
        }
        #[cfg(not(feature = "offline-review-foundation"))]
        {
            let _ = (focused, epoch);
            ui.label("The named-verifier continuation requires the qualified offline-review foundation build.");
        }
        Ok(())
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
mod synthetic_profile;
#[cfg(feature = "synthetic-born-joined-qualification")]
mod synthetic_verifier;

#[cfg(feature = "synthetic-born-joined-qualification")]
mod synthetic_enrollment;

#[cfg(feature = "synthetic-born-joined-qualification")]
mod synthetic_payment;
