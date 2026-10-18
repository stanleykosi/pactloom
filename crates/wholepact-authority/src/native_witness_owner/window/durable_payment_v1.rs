//! Production native review and finite listener custody for ONE exact record.
//! No synthetic issuer, credential generator, serialized approval or generic work.
use super::*;
use crate::durable_payment_owner_v1::{
    arm_durable_payment_admission_v1, prepare_durable_payment_admission_v1,
    DurablePaymentAdmissionProposalV1,
};
use crate::transport::{AuthorityServer, ServerTls};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    net::{SocketAddr, TcpListener},
    path::Path,
};
use wholepact_storage_security::witness_namespace_fs::read_existing_private_file;

#[derive(Default)]
pub(super) struct InputsV1 {
    request_json: Zeroizing<String>,
    server_certificate_der: String,
    server_private_key_pkcs8_der: String,
    trusted_client_root_der: String,
}
impl InputsV1 {
    // Ordinary form data only. Preparation, exact review, final primary click
    // and native authority construction remain in the unchanged Window path.
    #[cfg(feature = "synthetic-qualification")]
    pub(super) fn set_synthetic_form_data(
        &mut self,
        request_json: String,
        server_certificate_der: String,
        server_private_key_pkcs8_der: String,
        trusted_client_root_der: String,
    ) {
        self.discard();
        self.request_json = Zeroizing::new(request_json);
        self.server_certificate_der = server_certificate_der;
        self.server_private_key_pkcs8_der = server_private_key_pkcs8_der;
        self.trusted_client_root_der = trusted_client_root_der;
    }
    pub(super) fn discard(&mut self) {
        self.request_json.zeroize();
        self.server_certificate_der.zeroize();
        self.server_private_key_pkcs8_der.zeroize();
        self.trusted_client_root_der.zeroize();
    }
}
pub(super) struct PreparedNativeV1 {
    pub(super) proposal: DurablePaymentAdmissionProposalV1,
    pub(super) tls: ServerTls,
    pub(super) listener: TcpListener,
}
/// Fields are visible only to this actual Window module. Its focused primary
/// branch constructs the decision; an ordinary request cannot manufacture one.
pub(crate) struct NativeDurablePaymentAdmissionDecisionV1 {
    pub(super) proposal: DurablePaymentAdmissionProposalV1,
    pub(super) lease: NativeWorkerLease,
}
impl NativeDurablePaymentAdmissionDecisionV1 {
    pub(crate) fn into_parts(self) -> (DurablePaymentAdmissionProposalV1, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}
pub(super) enum WorkV1 {
    Prepare {
        input: NamespaceOpenInput,
        fields: InputsV1,
    },
    Admit {
        decision: NativeDurablePaymentAdmissionDecisionV1,
        tls: ServerTls,
        listener: TcpListener,
        clock: ReviewClock,
        #[cfg(feature = "synthetic-qualification")]
        observer: Option<crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1>,
    },
}
pub(super) fn execute(work: WorkV1) -> Result<WorkResult> {
    match work {
        WorkV1::Prepare { input, fields } => {
            let prepared = prepare(input, fields)?;
            let digest = prepared.proposal.review_digest()?;
            let display = prepared.proposal.display()?;
            let deadline = prepared.proposal.first_commit_deadline_ms();
            Prepared::new(
                Proposal::DurablePaymentV1(Box::new(prepared)),
                display,
                digest,
                deadline,
            )
            .map(WorkResult::Prepared)
        }
        WorkV1::Admit {
            decision,
            tls,
            listener,
            clock,
            #[cfg(feature = "synthetic-qualification")]
            observer,
        } => {
            // The guard holds only inert measurements. Do not put this branch
            // in a consuming closure: original owner drop order must stay intact.
            #[cfg(feature = "synthetic-qualification")]
            let _worker_span = observer.as_ref().map(|observer| {
                observer.start_span(
                    crate::transport::admission_diagnostics_v1::AdmissionWitnessSpanV1::Worker,
                )
            });
            crate::transport::admission_stage!(observer.as_ref(), ServerCreate);
            let listen = crate::transport::admission_result!(
                observer.as_ref(),
                observe_worker_failure,
                listener.local_addr().map_err(|_| AuthorityError::Storage)
            )?
            .to_string();
            crate::transport::admission_stage!(observer.as_ref(), SourceArm);
            let source = crate::transport::admission_result!(
                observer.as_ref(),
                observe_worker_failure,
                crate::transport::admission_result!(
                    observer.as_ref(),
                    observe_semantic,
                    crate::transport::admission_measure!(
                        observer.as_ref(),
                        SourceArm,
                        arm_durable_payment_admission_v1(decision)
                    )
                )
            )?;
            #[cfg(feature = "synthetic-qualification")]
            let source = {
                let mut source = source;
                source.set_admission_observer(observer.clone());
                source
            };
            crate::transport::admission_stage!(observer.as_ref(), ServerCreate);
            let server = crate::transport::admission_result!(
                observer.as_ref(),
                observe_worker_failure,
                crate::transport::admission_result!(
                    observer.as_ref(),
                    observe_semantic,
                    crate::transport::admission_measure!(
                        observer.as_ref(),
                        ServerCreate,
                        AuthorityServer::from_durable_payment_admission_v1(source, tls, &listen)
                    )
                )
            )?;
            // No eight-worker generic serving loop and no detached source clones.
            // The retained same listener stays nonblocking; every socket receives
            // the maintained ten-second TLS bound and OPEN checks. Closing or
            // blur revokes OPEN. Once publication wins it can only drain exactly
            // this append; the GUI must report a committed/uncertain outcome.
            let snapshot = loop {
                crate::transport::admission_stage!(observer.as_ref(), ResultLookup);
                if let Some(snapshot) = crate::transport::admission_result!(
                    observer.as_ref(),
                    observe_worker_failure,
                    crate::transport::admission_result!(
                        observer.as_ref(),
                        observe_semantic,
                        server.durable_payment_admission_result_v1()
                    )
                )? {
                    break snapshot;
                }
                crate::transport::admission_stage!(observer.as_ref(), ListenerAccept);
                match crate::transport::admission_measure!(
                    observer.as_ref(),
                    Accept,
                    listener.accept()
                ) {
                    Ok((socket, _)) => {
                        let outcome = server.serve_connection(socket);
                        crate::transport::admission_stage!(observer.as_ref(), ResultLookup);
                        if let Some(snapshot) = crate::transport::admission_result!(
                            observer.as_ref(),
                            observe_worker_failure,
                            crate::transport::admission_result!(
                                observer.as_ref(),
                                observe_semantic,
                                server.durable_payment_admission_result_v1()
                            )
                            .map_err(|_| AuthorityError::Uncertain)
                        )? {
                            break snapshot;
                        }
                        if outcome.is_err() {
                            crate::transport::admission_stage!(observer.as_ref(), WaitCurrent);
                            crate::transport::admission_result!(
                                observer.as_ref(),
                                observe_worker_failure,
                                clock.check()
                            )?;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        crate::transport::admission_stage!(observer.as_ref(), WaitCurrent);
                        crate::transport::admission_result!(
                            observer.as_ref(),
                            observe_worker_failure,
                            clock.check()
                        )?;
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => {
                        #[cfg(feature = "synthetic-qualification")]
                        if let Some(observer) = &observer {
                            let _ = observer.observe_io::<()>(Err(error));
                        }
                        #[cfg(not(feature = "synthetic-qualification"))]
                        let _ = error;
                        return crate::transport::admission_result!(
                            observer.as_ref(),
                            observe_worker_failure,
                            crate::transport::admission_result!(
                                observer.as_ref(),
                                observe_connection,
                                Err(AuthorityError::Uncertain)
                            )
                        );
                    }
                }
            };
            // Drain the one synchronous socket, then drop every namespace/source
            // and listener owner BEFORE returning. Reopening is separate, never
            // a competing lock, implicit server transition or lease extension.
            drop(server);
            drop(listener);
            crate::transport::admission_stage!(observer.as_ref(), WorkerDisplay);
            let result = private_display(&serde_json::json!({
                "kind": "durable_payment_admission_v1_committed",
                "committed_head": snapshot.head,
                "notice": "The one reviewed financial admission is committed. This listener and namespace owner are closed. Later serving requires selecting the same immutable record in the original namespace. Closing the UI does not revoke this record; its explicit interval and existing account exclusions still apply. No financial reserve, signature, release or dispatch occurred here.",
            })).map(|display| WorkResult::DurablePaymentAdmittedV1 { display, clock });
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = &observer {
                observer.worker_result(&result);
            }
            result
        }
    }
}
// The original receipt-only short circuit, with each predicate and clock invoked
// at most once in the original order. This cannot create a native decision.
pub(super) fn retain_receipt_v1(
    focused: bool,
    epoch_matches: impl FnOnce() -> bool,
    not_revoked: impl FnOnce() -> bool,
    not_closing: impl FnOnce() -> bool,
    clock_accepted: impl FnOnce() -> bool,
    #[cfg(feature = "synthetic-qualification")] observer: Option<
        &crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1,
    >,
) -> bool {
    macro_rules! gate {
        ($gate:ident, $retained:expr) => {{
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.receipt_gate(crate::transport::admission_diagnostics_v1::AdmissionWitnessReceiptGateV1::$gate);
            }
            $retained
        }};
    }
    if !focused {
        gate!(Unfocused, false)
    } else if !epoch_matches() {
        gate!(EpochMismatch, false)
    } else if !not_revoked() {
        gate!(Revoked, false)
    } else if !not_closing() {
        gate!(Closing, false)
    } else if !clock_accepted() {
        gate!(ClockRejected, false)
    } else {
        gate!(Retained, true)
    }
}

fn prepare(input: NamespaceOpenInput, fields: InputsV1) -> Result<PreparedNativeV1> {
    if fields.request_json.is_empty() || fields.request_json.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    let expected: crate::OwnerControlRequest =
        wholepact_core::parse_typed_json(fields.request_json.as_bytes())
            .map_err(|_| AuthorityError::InvalidBinding)?;
    let address: SocketAddr = input
        .endpoint
        .parse()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    if address.to_string() != input.endpoint
        || address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let read = |name: &str| {
        let path = Path::new(name);
        if !path.is_absolute() || name.len() > 4096 || name.contains('\0') {
            return Err(AuthorityError::InvalidBinding);
        }
        read_existing_private_file(path, 65_536).map_err(|_| AuthorityError::Permission)
    };
    // Existing protected DER inputs only, using the maintained nofollow/private
    // owner file reader. Key bytes never enter a DTO, native display or log.
    let certificate = CertificateDer::from(read(&fields.server_certificate_der)?.to_vec());
    let name = rustls::pki_types::ServerName::try_from(input.server_name.clone())
        .map_err(|_| AuthorityError::InvalidBinding)?;
    webpki::EndEntityCert::try_from(&certificate)
        .map_err(|_| AuthorityError::Authentication)?
        .verify_is_valid_for_subject_name(&name)
        .map_err(|_| AuthorityError::Authentication)?;
    let pin = crate::transport::certificate_digest(&certificate);
    let root = CertificateDer::from(read(&fields.trusted_client_root_der)?.to_vec());
    let key = read(&fields.server_private_key_pkcs8_der)?;
    let tls = ServerTls::new(
        vec![root],
        vec![certificate],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
    )?;
    let proposal = prepare_durable_payment_admission_v1(input, expected)?;
    proposal.require_endpoint(&pin, &address.to_string())?;
    let listener = TcpListener::bind(address).map_err(|_| AuthorityError::Permission)?;
    if listener.local_addr().map_err(|_| AuthorityError::Storage)? != address {
        return Err(AuthorityError::Authentication);
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| AuthorityError::Storage)?;
    proposal.check_current()?;
    Ok(PreparedNativeV1 {
        proposal,
        tls,
        listener,
    })
}
pub(super) fn input_ui(window: &mut Window, ui: &mut egui::Ui, focused: bool) -> bool {
    ui.separator();
    ui.heading("ONE exact durable payment admission");
    ui.label("Original owner mTLS and this independent native review are both mandatory. Enter the exact candidate record and existing protected TLS files. Preparing binds the original endpoint but cannot append. After final approval the listener accepts only this exact admission, then closes. The committed interval outlives this window; cancellation after commit does not revoke it. No signature, release or dispatch is performed here.");
    ui.label("Existing server certificate DER file");
    ui.add(
        egui::TextEdit::singleline(&mut window.input.durable_payment_v1.server_certificate_der)
            .char_limit(4096),
    );
    ui.label("Existing server private key PKCS#8 DER file (path only)");
    ui.add(
        egui::TextEdit::singleline(
            &mut window.input.durable_payment_v1.server_private_key_pkcs8_der,
        )
        .char_limit(4096),
    );
    ui.label("Existing trusted client root DER file");
    ui.add(
        egui::TextEdit::singleline(&mut window.input.durable_payment_v1.trusted_client_root_der)
            .char_limit(4096),
    );
    ui.label("Exact durable admission request JSON (no private signer material)");
    ui.add(
        egui::TextEdit::multiline(&mut *window.input.durable_payment_v1.request_json)
            .desired_rows(6)
            .char_limit(crate::MAX_FRAME_BYTES),
    );
    if ui
        .add_enabled(
            focused,
            egui::Button::new("Prepare original TLS listener and exact durable record for review"),
        )
        .clicked_by(egui::PointerButton::Primary)
    {
        let launched = (|| {
            let input = window.input.enrollment_input()?;
            let fields = std::mem::take(&mut window.input.durable_payment_v1);
            launch_work(
                Work::DurablePaymentV1(WorkV1::Prepare { input, fields }),
                NativeOwner::entered_window(),
                window.focus_epoch,
                ui.ctx(),
            )
        })();
        window.accept_launch(launched);
        return true;
    }
    false
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod admission_observation_tests {
    use super::*;
    use crate::transport::admission_diagnostics_v1::{
        AdmissionWitnessObserverV1, AdmissionWitnessReceiptGateV1,
    };
    use std::cell::RefCell;

    #[test]
    fn pure_admission_receipt_gates_preserve_original_short_circuit_and_clock_count() {
        use AdmissionWitnessReceiptGateV1::*;
        for (reject, expected) in [
            (0, Unfocused),
            (1, EpochMismatch),
            (2, Revoked),
            (3, Closing),
            (4, ClockRejected),
            (5, Retained),
        ] {
            let original_trace = RefCell::new(Vec::new());
            let original_check = |index| {
                original_trace.borrow_mut().push(index);
                reject != index
            };
            let original = reject != 0
                && original_check(1)
                && original_check(2)
                && original_check(3)
                && original_check(4);
            for observed in [false, true] {
                let observer = AdmissionWitnessObserverV1::new();
                let trace = RefCell::new(Vec::new());
                let check = |index| {
                    trace.borrow_mut().push(index);
                    reject != index
                };
                let retained = retain_receipt_v1(
                    reject != 0,
                    || check(1),
                    || check(2),
                    || check(3),
                    || check(4),
                    observed.then_some(&observer),
                );
                assert_eq!(retained, original);
                assert_eq!(*trace.borrow(), *original_trace.borrow());
                assert_eq!(
                    trace.borrow().iter().filter(|&&index| index == 4).count(),
                    if reject >= 4 { 1 } else { 0 }
                );
                if observed {
                    assert!(observer.snapshot().receipt_gate() == expected);
                } else {
                    assert!(observer.snapshot().receipt_gate() == NotObserved);
                }
            }
        }
    }
}
