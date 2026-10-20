//! Production native review and finite listener custody for ONE exact record.
//! No synthetic issuer, credential generator, serialized approval or generic work.
use super::*;
use crate::durable_financial_continuation_owner_v1::{
    arm_financial_continuation_v1, prepare_financial_continuation_v1,
    FinancialContinuationProposalV1,
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
    pub(super) proposal: FinancialContinuationProposalV1,
    pub(super) tls: ServerTls,
    pub(super) listener: TcpListener,
}
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
    let proposal = prepare_financial_continuation_v1(input, expected)?;
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
