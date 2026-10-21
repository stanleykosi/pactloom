//! Production native review and finite listener custody for ONE exact record.
//! No synthetic issuer, credential generator, serialized approval or generic work.
use super::*;
use crate::durable_financial_continuation_owner_v1::{
    arm_financial_continuation_v1,
    FinancialContinuationProposalV1,
};
use crate::transport::{AuthorityServer, ServerTls};
use std::net::TcpListener;

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
pub(super) use super::super::financial_continuation_preparation_v1::PreparedNativeV1;
/// Fields are visible only to this actual Window module. Its focused primary
/// branch constructs the decision; an ordinary request cannot manufacture one.
pub(crate) struct NativeFinancialContinuationDecisionV1 {
    pub(super) proposal: FinancialContinuationProposalV1,
    pub(super) lease: NativeWorkerLease,
}
impl NativeFinancialContinuationDecisionV1 {
    pub(crate) fn into_parts(self) -> (FinancialContinuationProposalV1, NativeWorkerLease) {
        (self.proposal, self.lease)
    }
}
pub(super) enum WorkV1 {
    Prepare {
        input: NamespaceOpenInput,
        fields: InputsV1,
    },
    Admit {
        decision: NativeFinancialContinuationDecisionV1,
        tls: ServerTls,
        listener: TcpListener,
        clock: ReviewClock,
    },
}
pub(super) fn execute(work: WorkV1) -> Result<WorkResult> {
    match work {
        WorkV1::Prepare { input, fields } => {
            let prepared = prepare(input, fields)?;
            let digest = prepared.proposal.review_digest()?;
            let display = prepared.proposal.display()?;
            let deadline = prepared.proposal.first_commit_deadline_ms();
            Prepared::new(Proposal::FinancialContinuationV1(Box::new(prepared)), display, digest, deadline)
                .map(WorkResult::Prepared)
        }
        WorkV1::Admit { decision, tls, listener, clock } => {
            let listen = listener.local_addr().map_err(|_| AuthorityError::Storage)?.to_string();
            let source = arm_financial_continuation_v1(decision)?;
            let server = AuthorityServer::from_financial_continuation_v1(source, tls, &listen)?;
            let snapshot = loop {
                if let Some(snapshot) = server.financial_continuation_result_v1()? { break snapshot; }
                match listener.accept() {
                    Ok((socket, _)) => {
                        let outcome = server.serve_connection(socket);
                        // A failed return cannot establish non-commit. Inspect the
                        // actual original operation before classifying the outcome.
                        if let Some(snapshot) = server.financial_continuation_result_v1()
                            .map_err(|_| AuthorityError::Uncertain)? { break snapshot; }
                        if outcome.is_err() { clock.check()?; }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        clock.check()?;
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return Err(AuthorityError::Uncertain),
                }
            };
            drop(server);
            drop(listener);
            let display = private_display(&serde_json::json!({
                "kind": "financial_continuation_v1_committed",
                "committed_head": snapshot.head,
                "notice": "This exact original financial continuation is committed. The listener is closed. Fresh signing decisions are still required. Only completed original signatures may enable the separately approved exact-byte dispatcher before the original ceilings. No signing, extraction or dispatch occurred in this operation."
            }))?;
            Ok(WorkResult::FinancialContinuationAdmittedV1 { display, clock })
        }
    }
}
fn prepare(input: NamespaceOpenInput, fields: InputsV1) -> Result<PreparedNativeV1> {
    super::super::financial_continuation_preparation_v1::prepare(
        input,
        &fields.request_json,
        &fields.server_certificate_der,
        &fields.server_private_key_pkcs8_der,
        &fields.trusted_client_root_der,
    )
}
pub(super) fn input_ui(window: &mut Window, ui: &mut egui::Ui, focused: bool) -> bool {
    ui.separator();
    ui.heading("ONE exact original financial continuation");
    ui.label("Original owner mTLS and independent native review are mandatory. This explicitly authorizes the exact original payment and bounded future dispatch after original signer restart. Review both owners, fixed proposal, original sources, named dispatcher, provider route, expiry and attempt limit. The listener commits only this exact continuation, then closes. It cannot sign or send a transaction.");
    ui.label("Existing server certificate DER file");
    ui.add(
        egui::TextEdit::singleline(
            &mut window
                .input
                .financial_continuation_v1
                .server_certificate_der,
        )
        .char_limit(4096),
    );
    ui.label("Existing server private key PKCS#8 DER file (path only)");
    ui.add(
        egui::TextEdit::singleline(
            &mut window
                .input
                .financial_continuation_v1
                .server_private_key_pkcs8_der,
        )
        .char_limit(4096),
    );
    ui.label("Existing trusted client root DER file");
    ui.add(
        egui::TextEdit::singleline(
            &mut window
                .input
                .financial_continuation_v1
                .trusted_client_root_der,
        )
        .char_limit(4096),
    );
    ui.label("Exact financial continuation request JSON (no private signer material)");
    ui.add(
        egui::TextEdit::multiline(&mut *window.input.financial_continuation_v1.request_json)
            .desired_rows(6)
            .char_limit(crate::MAX_FRAME_BYTES),
    );
    if ui
        .add_enabled(
            focused,
            egui::Button::new("Prepare original TLS listener and exact financial continuation for review"),
        )
        .clicked_by(egui::PointerButton::Primary)
    {
        let launched = (|| {
            let input = window.input.enrollment_input()?;
            let fields = std::mem::take(&mut window.input.financial_continuation_v1);
            launch_work(
                Work::FinancialContinuationV1(WorkV1::Prepare { input, fields }),
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
