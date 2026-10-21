//! Shared private preparation only. No native decision or permission constructor.
//! The legacy Window and coordinated role use the same original-source checks.
use crate::{AuthorityError, Result};
use crate::witness_locator::NamespaceOpenInput;
use crate::durable_financial_continuation_owner_v1::{prepare_financial_continuation_v1, FinancialContinuationProposalV1};
use crate::transport::ServerTls;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{net::{SocketAddr, TcpListener}, path::Path};
use wholepact_storage_security::witness_namespace_fs::read_existing_private_file;

pub(super) struct PreparedNativeV1 {
    pub(super) proposal: FinancialContinuationProposalV1,
    pub(super) tls: ServerTls,
    pub(super) listener: TcpListener,
}

pub(super) fn prepare(
    input: NamespaceOpenInput,
    request_json: &str,
    server_certificate_der: &str,
    server_private_key_pkcs8_der: &str,
    trusted_client_root_der: &str,
) -> Result<PreparedNativeV1> {
    if request_json.is_empty() || request_json.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    let expected: crate::OwnerControlRequest =
        wholepact_core::parse_typed_json(request_json.as_bytes())
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
    let certificate = CertificateDer::from(read(server_certificate_der)?.to_vec());
    let name = rustls::pki_types::ServerName::try_from(input.server_name.clone())
        .map_err(|_| AuthorityError::InvalidBinding)?;
    webpki::EndEntityCert::try_from(&certificate)
        .map_err(|_| AuthorityError::Authentication)?
        .verify_is_valid_for_subject_name(&name)
        .map_err(|_| AuthorityError::Authentication)?;
    let pin = crate::transport::certificate_digest(&certificate);
    let root = CertificateDer::from(read(trusted_client_root_der)?.to_vec());
    let key = read(server_private_key_pkcs8_der)?;
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
