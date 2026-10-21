//! Production native review and finite listener custody for ONE exact record.
//! No synthetic issuer, credential generator, serialized approval or generic work.
use super::*;
use crate::durable_delivery_admission_owner_v2::{
    arm_durable_delivery_admission_v2,
    DurableDeliveryAdmissionProposalV2,
};
use crate::transport::{AuthorityServer, ServerTls};
use std::net::TcpListener;

pub(super) use super::super::delivery_preparation_v2::{InputsV2, PreparedNativeV2};
use super::super::delivery_preparation_v2::prepare;

/// Fields are visible only to this actual Window module. Its focused primary
/// branch constructs the decision; an ordinary request cannot manufacture one.
pub(crate) struct NativeDurableDeliveryAdmissionDecisionV2 {
    pub(super) proposal: DurableDeliveryAdmissionProposalV2,
    pub(super) lease: NativeWorkerLease,
}
impl NativeDurableDeliveryAdmissionDecisionV2 {
    pub(crate) fn into_parts(self) -> (DurableDeliveryAdmissionProposalV2, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}
pub(super) enum WorkV2 {
    Prepare {
        input: NamespaceOpenInput,
        fields: InputsV2,
    },
    Admit {
        decision: NativeDurableDeliveryAdmissionDecisionV2,
        tls: ServerTls,
        listener: TcpListener,
        clock: ReviewClock,
        #[cfg(feature = "synthetic-qualification")]
        observer: Option<crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1>,
    },
}
pub(super) fn execute(work: WorkV2) -> Result<WorkResult> {
    match work {
        WorkV2::Prepare { input, fields } => {
            let prepared = prepare(input, fields)?;
            let digest = prepared.proposal.review_digest()?;
            let display = prepared.proposal.display()?;
            let deadline = prepared.proposal.first_commit_deadline_ms();
            Prepared::new(
                Proposal::DurableDeliveryV2(Box::new(prepared)),
                display,
                digest,
                deadline,
            )
            .map(WorkResult::Prepared)
        }
        WorkV2::Admit {
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
                        arm_durable_delivery_admission_v2(decision)
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
                        AuthorityServer::from_durable_delivery_admission_v2(source, tls, &listen)
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
                        server.durable_delivery_admission_result_v2()
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
                                server.durable_delivery_admission_result_v2()
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
                "kind": "durable_delivery_admission_v2_committed",
                "committed_head": snapshot.head,
                "notice": "The whole reviewed prospective delivery scope is retained. This listener and namespace owner are closed. Only exact historical reading is supported. Acquire, Activate, Reserve, signing, extraction, final-byte release and dispatch remain denied. Closing the UI does not erase admission.",
            })).map(|display| WorkResult::DurableDeliveryAdmittedV2 { display, clock });
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = &observer {
                observer.worker_result(&result);
            }
            result
        }
    }
}
pub(super) fn input_ui(window: &mut Window, ui: &mut egui::Ui, focused: bool) -> bool {
    ui.separator();
    ui.heading("ONE prospective durable delivery admission");
    ui.label("Original owner mTLS and independent native review are mandatory. Review the whole exact scope, dispatcher custody, fixed proposal, both owners, original Host/submission binding, provider route and original ceilings. The listener accepts one exact prospective admission only, then closes. No Acquire, Activate, Reserve, signing, extraction, final-byte delivery or dispatch is supported.");
    ui.label("Existing server certificate DER file");
    ui.add(
        egui::TextEdit::singleline(
            &mut window
                .input
                .durable_delivery_admission_v2
                .server_certificate_der,
        )
        .char_limit(4096),
    );
    ui.label("Existing server private key PKCS#8 DER file (path only)");
    ui.add(
        egui::TextEdit::singleline(
            &mut window
                .input
                .durable_delivery_admission_v2
                .server_private_key_pkcs8_der,
        )
        .char_limit(4096),
    );
    ui.label("Existing trusted client root DER file");
    ui.add(
        egui::TextEdit::singleline(
            &mut window
                .input
                .durable_delivery_admission_v2
                .trusted_client_root_der,
        )
        .char_limit(4096),
    );
    ui.label("Exact durable admission request JSON (no private signer material)");
    ui.add(
        egui::TextEdit::multiline(&mut *window.input.durable_delivery_admission_v2.request_json)
            .desired_rows(6)
            .char_limit(crate::MAX_FRAME_BYTES),
    );
    if ui
        .add_enabled(
            focused,
            egui::Button::new("Prepare original TLS listener and exact delivery scope for review"),
        )
        .clicked_by(egui::PointerButton::Primary)
    {
        let launched = (|| {
            let input = window.input.enrollment_input()?;
            let fields = std::mem::take(&mut window.input.durable_delivery_admission_v2);
            launch_work(
                Work::DurableDeliveryV2(WorkV2::Prepare { input, fields }),
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
