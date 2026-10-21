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

/// Actual fixed-role setup only. Every protected file acquisition and backend
/// preparation is surrounded by the same nonrefreshing nominal Setup token.
/// The legacy Window path above remains byte-for-byte unchanged.
#[cfg(feature = "coordinated-witness-financial-continuation")]
pub(super) fn prepare_coordinated(
    setup: &wholepact_financial_coordinator_origin::WitnessFinancialContinuationSetupV1,
    first: &mut super::coordinated_financial_continuation_v1::observation::FirstFailureV1,
) -> Result<PreparedNativeV1> {
    use super::coordinated_financial_continuation_v1::observation::Stage;
    let mut stage = Stage::InputValidation;
    let result = (|| {
    setup.check_current().map_err(|_| AuthorityError::Permission)?;
    let fields = setup.inputs();
    fields.validate().map_err(|_| AuthorityError::InvalidBinding)?;
    setup.continuation().validate().map_err(|_| AuthorityError::InvalidBinding)?;
    if fields.request_json != setup.continuation().request_json {
        return Err(AuthorityError::Authentication);
    }
    let owner_der = zeroize::Zeroizing::new(hex::decode(&fields.owner_certificate_der_hex)
        .map_err(|_| AuthorityError::InvalidBinding)?);
    let owner_certificate = CertificateDer::from(owner_der.as_slice());
    webpki::EndEntityCert::try_from(&owner_certificate).map_err(|_| AuthorityError::Authentication)?;
    let input = NamespaceOpenInput {
        #[cfg(feature = "synthetic-qualification")]
        synthetic_installation: None,
        endpoint: fields.endpoint.clone(), server_name: fields.server_name.clone(),
        witness_id: fields.witness_id.clone(),
        pinned_server_certificate_digest: fields.pinned_server_certificate_digest.clone(),
        owner_certificate_digest: crate::transport::certificate_digest(&owner_certificate),
        network_profile_id: fields.network_profile_id.clone(),
        storage_key_file: fields.storage_key_file.clone(),
        expected_account_id: fields.expected_account_id.clone(),
    };
    let request_json = fields.request_json.as_str();
    let server_certificate_der = fields.server_certificate_der.as_str();
    let server_private_key_pkcs8_der = fields.server_private_key_pkcs8_der.as_str();
    let trusted_client_root_der = fields.trusted_client_root_der.as_str();
    if request_json.is_empty() || request_json.len() > crate::MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    stage = Stage::RequestDecode;
    let expected: crate::OwnerControlRequest =
        wholepact_core::parse_typed_json(request_json.as_bytes())
            .map_err(|_| AuthorityError::InvalidBinding)?;
    let crate::OwnerControl::AdmitFinancialContinuationV1 { record } = &expected.control else {
        return Err(AuthorityError::Permission);
    };
    record.validate_request(&expected, &record.terms.scope.witness)?;
    if expected.account_id != fields.expected_account_id
        || expected.network_profile_id != fields.network_profile_id
        || record.terms.valid_until_ms > setup.continuation().source_expires_at_ms
    {
        return Err(AuthorityError::Authentication);
    }
    record.terms.require_live(crate::now_ms()?)?;
    setup.check_current().map_err(|_| AuthorityError::Permission)?;
    stage = Stage::EndpointValidation;
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
        setup.check_current().map_err(|_| AuthorityError::Permission)?;
        let path = Path::new(name);
        if !path.is_absolute() || name.len() > 4096 || name.contains('\0') {
            return Err(AuthorityError::InvalidBinding);
        }
        let bytes = super::financial_setup_guard_v1::FinancialSetupGuardV1::Coordinated(setup).read(path, 65_536)?;
        setup.check_current().map_err(|_| AuthorityError::Permission)?;
        Ok(bytes)
    };
    // Existing protected DER inputs only, using the maintained nofollow/private
    // owner file reader. Key bytes never enter a DTO, native display or log.
    stage = Stage::ServerCertificateRead;
    let certificate = CertificateDer::from(read(server_certificate_der)?.to_vec());
    stage = Stage::ServerCertificateValidation;
    let name = rustls::pki_types::ServerName::try_from(input.server_name.clone())
        .map_err(|_| AuthorityError::InvalidBinding)?;
    webpki::EndEntityCert::try_from(&certificate)
        .map_err(|_| AuthorityError::Authentication)?
        .verify_is_valid_for_subject_name(&name)
        .map_err(|_| AuthorityError::Authentication)?;
    let pin = crate::transport::certificate_digest(&certificate);
    stage = Stage::TrustedClientRootRead;
    let root = CertificateDer::from(read(trusted_client_root_der)?.to_vec());
    stage = Stage::ServerPrivateKeyRead;
    let key = read(server_private_key_pkcs8_der)?;
    setup.check_current().map_err(|_| AuthorityError::Permission)?;
    stage = Stage::TlsConfiguration;
    let tls = ServerTls::new(
        vec![root],
        vec![certificate],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
    )?;
    setup.check_current().map_err(|_| AuthorityError::Permission)?;
    stage = Stage::ProtectedNamespaceOpen;
    let proposal = crate::durable_financial_continuation_owner_v1::prepare_coordinated_financial_continuation_v1(input, expected, setup)?;
    setup.check_current().map_err(|_| AuthorityError::Permission)?;
    proposal.require_endpoint(&pin, &address.to_string())?;
    setup.check_current().map_err(|_| AuthorityError::Permission)?;
    stage = Stage::ListenerBind;
    let listener = TcpListener::bind(address).map_err(|_| AuthorityError::Permission)?;
    if listener.local_addr().map_err(|_| AuthorityError::Storage)? != address {
        return Err(AuthorityError::Authentication);
    }
    stage = Stage::ListenerConfiguration;
    listener
        .set_nonblocking(true)
        .map_err(|_| AuthorityError::Storage)?;
    setup.check_current().map_err(|_| AuthorityError::Permission)?;
    stage = Stage::PreparedSourceCurrentness;
    proposal.coordinated_setup_current_v1(setup)?;
    setup.check_current().map_err(|_| AuthorityError::Permission)?;
    Ok(PreparedNativeV1 {
        proposal,
        tls,
        listener,
    })
    })();
    if let Err(error) = result.as_ref() { first.note(stage, *error); }
    result
}
