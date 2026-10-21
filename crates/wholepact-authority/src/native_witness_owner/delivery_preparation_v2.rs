//! Exact existing delivery preparation, shared only inside the Witness owner.
//! Preparation holds real source/TLS/listener custody but grants no approval.
use crate::{
    durable_delivery_admission_owner_v2::{prepare_durable_delivery_admission_v2, DurableDeliveryAdmissionProposalV2},
    transport::ServerTls,
    witness_locator::NamespaceOpenInput,
    AuthorityError, Result,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{net::{SocketAddr, TcpListener}, path::Path};
use wholepact_storage_security::witness_namespace_fs::read_existing_private_file;
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
pub(super) struct InputsV2 {
    pub(super) request_json: Zeroizing<String>,
    pub(super) server_certificate_der: String,
    pub(super) server_private_key_pkcs8_der: String,
    pub(super) trusted_client_root_der: String,
}
impl InputsV2 {
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
pub(super) struct PreparedNativeV2 {
    pub(super) proposal: DurableDeliveryAdmissionProposalV2,
    pub(super) tls: ServerTls,
    pub(super) listener: TcpListener,
}
pub(super) fn prepare(input: NamespaceOpenInput, fields: InputsV2) -> Result<PreparedNativeV2> {
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
    let proposal = prepare_durable_delivery_admission_v2(input, expected)?;
    proposal.require_endpoint(&pin, &address.to_string())?;
    let listener = TcpListener::bind(address).map_err(|_| AuthorityError::Permission)?;
    if listener.local_addr().map_err(|_| AuthorityError::Storage)? != address {
        return Err(AuthorityError::Authentication);
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| AuthorityError::Storage)?;
    proposal.check_current()?;
    Ok(PreparedNativeV2 {
        proposal,
        tls,
        listener,
    })
}
