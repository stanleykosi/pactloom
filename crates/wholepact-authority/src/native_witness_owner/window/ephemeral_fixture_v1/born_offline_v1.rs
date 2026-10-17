//! Finite temporary born-offline controller phases. Ordinary signed inputs and
//! the exact existing protected key file enter the SAME Window review path.
//! No NativeDecision, namespace owner, journal row or runtime admission is made.
#![cfg(all(
    feature = "synthetic-qualification",
    feature = "born-offline-witness-owner"
))]
use super::*;
use crate::{
    born_offline_artifacts_v1::BornOfflineArtifactRecordV1,
    born_offline_enrollment_v1::BornOfflineEnrollmentV1, offline_witness_transport_v1 as hpke,
};

const ENROLL_OFFLINE: &str = "Authenticate exact born offline enrollment for review";
const IMPORT_ARTIFACTS: &str = "Review exact persistent transport import";

/// The key remains below the exact concrete temporary installation. The owner
/// is neither Clone nor serializable, accepts no path/key/pin from a caller,
/// and exports only its maintained HPKE public identity.
pub struct EphemeralBornTransportKeyV1 {
    installation: Arc<EphemeralWitnessInstallation>,
    account_id: String,
    file: PathBuf,
    public_hex: String,
    fingerprint: String,
}
/// Authenticated ORIGINAL public provenance captured on the actual witness
/// thread. This is historical public evidence, not present key-file liveness,
/// native approval, a transport admission, or a transferable namespace owner.
/// No secret, key path, file checker or Window is stored or exposed. The retained
/// installation keeps the temporary source lifetime; later actual enrollment
/// and artifact import must independently revalidate the real key owner.
pub struct EphemeralBornTransportPublicPinV1 {
    account_id: String,
    public_key: [u8; 32],
    server_certificate_digest: String,
    _installation: Arc<EphemeralWitnessInstallation>,
}
impl EphemeralBornTransportPublicPinV1 {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    /// Checks only exact ORIGINAL account correlation. Success says nothing
    /// about present installation/key-file/native liveness or authority.
    pub fn original_public_key_for_account(&self, account_id: &str) -> Result<[u8; 32]> {
        if self.account_id != account_id {
            return Err(AuthorityError::Permission);
        }
        Ok(self.public_key)
    }
    pub fn original_server_certificate_digest(&self) -> &str {
        &self.server_certificate_digest
    }
}

impl EphemeralBornTransportKeyV1 {
    pub fn public_key_hex(&self) -> &str {
        &self.public_hex
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    /// Public-only projection for this concrete retained account/installation.
    /// Rechecks the actual protected key file; grants no native or journal
    /// permission and never exports the secret or a reconstructible key owner.
    pub fn public_key_for_original(
        &self,
        witness: &EphemeralNativeWitnessV1,
        account_id: &str,
    ) -> Result<[u8; 32]> {
        if self.account_id != account_id {
            return Err(AuthorityError::Permission);
        }
        self.check_original(witness)?;
        let public: [u8; 32] = hex::decode(&self.public_hex)
            .map_err(|_| AuthorityError::CorruptHistory)?
            .try_into()
            .map_err(|_| AuthorityError::CorruptHistory)?;
        if hex::encode(public) != self.public_hex {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(public)
    }
    /// Capture public evidence on the real witness's owning thread. Checks the
    /// actual same installation/account/protected key before creating the only
    /// nominal snapshot constructor; it grants no permission on either thread.
    pub fn snapshot_for_original(
        &self,
        witness: &EphemeralNativeWitnessV1,
        account_id: &str,
    ) -> Result<EphemeralBornTransportPublicPinV1> {
        let public_key = self.public_key_for_original(witness, account_id)?;
        crate::hash(&witness.server_certificate_digest)?;
        Ok(EphemeralBornTransportPublicPinV1 {
            account_id: self.account_id.clone(),
            public_key,
            server_certificate_digest: witness.server_certificate_digest.clone(),
            _installation: self.installation.clone(),
        })
    }
    fn check_original(&self, witness: &EphemeralNativeWitnessV1) -> Result<()> {
        if !Arc::ptr_eq(&self.installation, &witness.installation)
            || self.file
                != witness
                    .root
                    .join(format!("synthetic-born-offline-{}.key", self.account_id))
        {
            return Err(AuthorityError::Permission);
        }
        self.installation
            .probe()?
            .open_existing()?
            .check_current()?;
        let secret = wholepact_storage_security::witness_namespace_fs::read_existing_storage_key(
            &self.file,
        )?;
        let public = hpke::TransportSecret::from_bytes(*secret)
            .and_then(|key| key.public_key())
            .map_err(|_| AuthorityError::Authentication)?;
        if hex::encode(public.as_bytes()) != self.public_hex
            || public.fingerprint() != self.fingerprint
        {
            return Err(AuthorityError::Conflict);
        }
        Ok(())
    }
}

impl EphemeralNativeWitnessV1 {
    /// Prepare ONCE before the signer independently reviews its immutable
    /// enrollment policy. No import, enrollment or financial decision follows.
    pub fn prepare_original_born_transport_v1(
        &mut self,
        account_id: &str,
    ) -> Result<EphemeralBornTransportKeyV1> {
        crate::hash(account_id)?;
        let original =
            crate::witness_locator::open_born_history(self.original_namespace_input(account_id)?)?;
        original.require_born_read_current()?;
        drop(original);
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *secret).map_err(|_| AuthorityError::Storage)?;
        let public = hpke::TransportSecret::from_bytes(*secret)
            .and_then(|key| key.public_key())
            .map_err(|_| AuthorityError::Authentication)?;
        let file = self
            .root
            .join(format!("synthetic-born-offline-{account_id}.key"));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file)
            .map_err(|_| AuthorityError::Storage)?;
        output
            .write_all(secret.as_slice())
            .map_err(|_| AuthorityError::Storage)?;
        output.sync_all().map_err(|_| AuthorityError::Storage)?;
        drop(output);
        drop(secret);
        let key = EphemeralBornTransportKeyV1 {
            installation: self.installation.clone(),
            account_id: account_id.into(),
            file,
            public_hex: hex::encode(public.as_bytes()),
            fingerprint: public.fingerprint(),
        };
        key.check_original(self)?;
        Ok(key)
    }

    pub fn review_original_born_offline_enrollment_v1(
        &mut self,
        key: &EphemeralBornTransportKeyV1,
        signed_envelope: &[u8],
    ) -> Result<BornOfflineEnrollmentV1> {
        key.check_original(self)?;
        self.select_original_signed_form(&key.account_id, signed_envelope)?;
        let text =
            std::str::from_utf8(signed_envelope).map_err(|_| AuthorityError::InvalidBinding)?;
        let expected = parse_born_offline_enrollment_envelope_v1(text)?;
        if expected.enrollment.policy.account_id != key.account_id
            || expected.enrollment.policy.witness_transport_key_digest != key.fingerprint
        {
            return Err(AuthorityError::InvalidBinding);
        }
        self.window.input.signed_born_offline_enrollment_json = Zeroizing::new(text.into());
        self.click(ENROLL_OFFLINE)?;
        self.drain()?;
        if !matches!(
            self.window.pending.as_ref().map(|p| &p.prepared.proposal),
            Some(Proposal::BornOfflineEnrollmentV1(_))
        ) {
            return Err(AuthorityError::Permission);
        }
        self.approve_exact()?;
        self.completed_native_receipt()?;
        let actual = self.original_born_offline_enrollment_v1(&key.account_id)?;
        if actual != expected.enrollment {
            return Err(AuthorityError::CorruptHistory);
        }
        key.check_original(self)?;
        Ok(actual)
    }

    pub fn install_original_born_artifacts_v1(
        &mut self,
        key: &EphemeralBornTransportKeyV1,
        actual_signer_public_key: &[u8; 32],
    ) -> Result<BornOfflineArtifactRecordV1> {
        key.check_original(self)?;
        let actual = self.original_born_offline_enrollment_v1(&key.account_id)?;
        let signer = hpke::TransportPublicKey::from_bytes(*actual_signer_public_key)
            .map_err(|_| AuthorityError::Authentication)?;
        if actual.policy.witness_transport_key_digest != key.fingerprint
            || actual.policy.offline_signer_key_digest != signer.fingerprint()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        self.original_namespace_input(&key.account_id)?;
        self.window.input.born_transport_key_file = key
            .file
            .to_str()
            .ok_or(AuthorityError::InvalidBinding)?
            .into();
        self.window.input.born_signer_public_key_hex = hex::encode(signer.as_bytes());
        self.click(IMPORT_ARTIFACTS)?;
        self.drain()?;
        if !matches!(
            self.window.pending.as_ref().map(|p| &p.prepared.proposal),
            Some(Proposal::BornOfflineArtifactsV1(_))
        ) {
            return Err(AuthorityError::Permission);
        }
        self.approve_exact()?;
        self.completed_native_receipt()?;
        let journal = crate::witness_locator::open_born_history(
            self.original_namespace_input(&key.account_id)?,
        )?;
        let (record, retained_secret) = journal.born_offline_artifacts_v1()?;
        let retained_public = hpke::TransportSecret::from_bytes(*retained_secret)
            .and_then(|value| value.public_key())
            .map_err(|_| AuthorityError::Authentication)?;
        if record.binding.witness_public_key_hex != key.public_hex
            || record.binding.offline_signer_public_key_hex != hex::encode(signer.as_bytes())
            || retained_public.fingerprint() != key.fingerprint
        {
            return Err(AuthorityError::CorruptHistory);
        }
        record.binding.validate_enrollment(&actual)?;
        key.check_original(self)?;
        Ok(record)
    }

    fn original_born_offline_enrollment_v1(
        &mut self,
        account_id: &str,
    ) -> Result<BornOfflineEnrollmentV1> {
        let journal =
            crate::witness_locator::open_born_history(self.original_namespace_input(account_id)?)?;
        journal.require_born_read_current()?;
        let connection = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(connection.connection())?;
        let enrollment = ledger
            .born_offline_enrollment_v1()?
            .ok_or(AuthorityError::Permission)?
            .enrollment
            .clone();
        journal.require_born_read_current()?;
        Ok(enrollment)
    }

    /// Serve the actual native-installed enrollment/artifacts in this exact
    /// concrete installation. Correlation comes from authenticated journal rows,
    /// not caller configuration, and every runtime request keeps its own gates.
    pub fn serve_original_born_offline_v1(
        &mut self,
        key: &EphemeralBornTransportKeyV1,
    ) -> Result<EphemeralHistoryServerV1> {
        key.check_original(self)?;
        let enrollment = self.original_born_offline_enrollment_v1(&key.account_id)?;
        let input = self.original_namespace_input(&key.account_id)?;
        let journal = crate::witness_locator::open_born_history(input.clone())?;
        let (artifacts, _) = journal.born_offline_artifacts_v1()?;
        if artifacts.binding.witness_public_key_hex != key.public_hex {
            return Err(AuthorityError::Conflict);
        }
        artifacts.binding.validate_enrollment(&enrollment)?;
        drop(journal);
        let owner = crate::born_offline_retry_v1::configured_born_witness::ConfiguredBornOfflineWitnessV1::configure_from_original_namespace(
            input, enrollment.digest()?, artifacts.binding.digest()?, &self.server_certificate_digest,
        )?;
        let server = AuthorityServer::from_configured_born_offline_v1(owner, self.tls.clone())?;
        self.serve_exact_server(server)
    }
}
