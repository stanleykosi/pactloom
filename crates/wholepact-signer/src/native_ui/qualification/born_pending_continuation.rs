//! Synthetic event delivery through the real pending continuation controller.
//! Compile only behind the dedicated synthetic-born-joined-qualification feature.
//! No native owner, approval, witness history, or born record is fabricated.

use super::*;
use crate::native_ui::birth_workspace::born_roster_v3::{
    ProducedPendingBirth, SYNTHETIC_PENDING_PASSWORD,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(in crate::native_ui) struct EphemeralOwnerCredentials {
    origin: Arc<wholepact_authority::native_witness_owner::EphemeralWitnessOriginV1>,
    pub(in crate::native_ui) certificate_der: PathBuf,
    pub(in crate::native_ui) private_key_pkcs8_der: PathBuf,
    pub(in crate::native_ui) trusted_server_root_der: PathBuf,
}
impl EphemeralOwnerCredentials {
    pub(in crate::native_ui) fn from_origin(
        origin: wholepact_authority::native_witness_owner::EphemeralWitnessOriginV1,
    ) -> Result<Self> {
        // The nominal authority fixture retains its actual temporary installation.
        // Public metadata cannot redirect credentials to an arbitrary filesystem root.
        let root = origin.credential_root();
        if origin.owner_certificate_file != root.join("owner.der")
            || origin.owner_key_file != root.join("owner.pk8")
            || origin.trusted_server_root_file != root.join("ca.der")
            || origin.writer_certificate_file != root.join("writer.der")
            || origin.writer_key_file != root.join("writer.pk8")
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(Self {
            certificate_der: origin.owner_certificate_file.clone(),
            private_key_pkcs8_der: origin.owner_key_file.clone(),
            trusted_server_root_der: origin.trusted_server_root_file.clone(),
            origin: Arc::new(origin),
        })
    }
    pub(in crate::native_ui) fn origin(
        &self,
    ) -> &wholepact_authority::native_witness_owner::EphemeralWitnessOriginV1 {
        &self.origin
    }
    pub(in crate::native_ui) fn roster_setup_json(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(serde_json::to_string(&serde_json::json!({
            "trusted_server_root_der": self.trusted_server_root_der,
            "writer_certificate_der": self.origin.writer_certificate_file,
            "writer_private_key_pkcs8_der": self.origin.writer_key_file,
            "owner_certificate_der": self.certificate_der,
            "owner_private_key_pkcs8_der": self.private_key_pkcs8_der,
            "operator_name": "Explicit synthetic never-funded ephemeral witness",
            "retention_statement": "Only the concrete private temporary qualification installation",
        })).map_err(|_| Error::InvalidData)?))
    }
}

/// The exact reviewed public export, together with the same bounded controller.
/// Dropping this value closes that owner; no caller can renew its deadline.
pub(in crate::native_ui) struct ExportedPendingBirth {
    ui: DrainingPendingController,
    pending: ProducedPendingBirth,
    credentials: EphemeralOwnerCredentials,
    pub(in crate::native_ui) exported_file: PathBuf,
}

pub(in crate::native_ui) struct AcknowledgedBornFixture {
    pub(in crate::native_ui) temporary: Arc<tempfile::TempDir>,
    pub(in crate::native_ui) root: PathBuf,
    pub(in crate::native_ui) account_id: String,
    pub(in crate::native_ui) birth_digest: String,
    pub(in crate::native_ui) public_receive_address: String,
    pub(in crate::native_ui) privacy_domain: String,
    pub(in crate::native_ui) credentials: EphemeralOwnerCredentials,
}

struct DrainingPendingController(
    PendingEnrollmentUi,
    Arc<tempfile::TempDir>,
    EphemeralOwnerCredentials,
);
impl std::ops::Deref for DrainingPendingController {
    type Target = PendingEnrollmentUi;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for DrainingPendingController {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for DrainingPendingController {
    fn drop(&mut self) {
        self.0.clear();
        if let Some(job) = self.0.job.take() {
            drop(job.finish());
        }
        self.0.clear();
    }
}

fn drain(ui: &mut PendingEnrollmentUi, epoch: u64) -> Result<()> {
    // The real owner deadline, not this wait ceiling, controls every admission.
    let limit = Instant::now() + Duration::from_secs(120);
    while ui.job.is_some() {
        if Instant::now() >= limit {
            ui.clear();
            return Err(Error::Uncertain);
        }
        ui.poll_lifecycle(true, epoch);
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

fn approve_current(ui: &mut PendingEnrollmentUi, epoch: u64) -> Result<()> {
    ui.current_owner(epoch)?;
    let review = ui.review.as_mut().ok_or(Error::ReviewMismatch)?;
    if review.exact.display().is_empty() || review.exact.confirming() {
        return Err(Error::ReviewMismatch);
    }
    // Explicit synthetic scroll and click delivery, not human/native-attestation
    // evidence. The existing exact machine still creates and consumes approval.
    review.displayed_to_end = true;
    if review
        .exact
        .continue_from_native_click(false, epoch)
        .is_ok()
        || review
            .exact
            .continue_from_native_click(true, epoch.wrapping_add(1))
            .is_ok()
    {
        return Err(Error::ReviewMismatch);
    }
    review.exact.continue_from_native_click(true, epoch)?;
    ui.confirmation = Zeroizing::new(format!("AUTHORIZE {}", &review.exact.digest()[..12]));
    ui.consume_review(true, epoch)?;
    drain(ui, epoch)
}

/// Caller must obtain `ui` from the actual runtime pending-reopen controller.
/// TLS/key files retain the nominal authority fixture; the export belongs only
/// to this actual account fixture. Neither accepts an arbitrary credential root.
/// Request, signature and disclosure each consume their own exact review.
pub(in crate::native_ui) fn retain_sign_and_export(
    ui: PendingEnrollmentUi,
    pending: ProducedPendingBirth,
    credentials: &EphemeralOwnerCredentials,
    destination: &Path,
) -> Result<ExportedPendingBirth> {
    let mut ui = DrainingPendingController(ui, pending.temporary.clone(), credentials.clone());
    if !pending.root.starts_with(pending.temporary.path())
        || !destination.starts_with(pending.temporary.path())
    {
        return Err(Error::ReviewMismatch);
    }
    let epoch = ui.owner.as_ref().ok_or(Error::Locked)?.focus_epoch();
    drain(&mut ui, epoch)?;
    ui.current_owner(epoch)?;
    let opened = ui.opened.as_ref().ok_or(Error::Locked)?;
    if opened.retained
        || opened.staged
        || opened.pending.anchor().identity() != &pending.identity
        || opened.pending.anchor().birth_digest() != pending.birth_digest
    {
        return Err(Error::ReviewMismatch);
    }
    ui.prepare_action(Action::Request, epoch)?;
    drain(&mut ui, epoch)?;
    if !matches!(ui.review.as_ref().map(|r| &r.step), Some(Step::Retain(_))) {
        return Err(Error::ReviewMismatch);
    }
    approve_current(&mut ui, epoch)?;
    if !ui.opened.as_ref().is_some_and(|opened| opened.retained) {
        return Err(Error::ReviewMismatch);
    }

    ui.certificate = Zeroizing::new(
        credentials
            .certificate_der
            .to_str()
            .ok_or(Error::InvalidData)?
            .to_owned(),
    );
    ui.key = Zeroizing::new(
        credentials
            .private_key_pkcs8_der
            .to_str()
            .ok_or(Error::InvalidData)?
            .to_owned(),
    );
    ui.prepare_action(Action::Sign, epoch)?;
    drain(&mut ui, epoch)?;
    if !matches!(ui.review.as_ref().map(|r| &r.step), Some(Step::Sign(_))) {
        return Err(Error::ReviewMismatch);
    }
    approve_current(&mut ui, epoch)?;
    let envelope = ui.envelope.as_ref().ok_or(Error::ReviewMismatch)?;
    let expected =
        Zeroizing::new(serde_json::to_vec_pretty(&**envelope).map_err(|_| Error::InvalidData)?);
    let content_digest = hex::encode(Sha256::digest(expected.as_slice()));
    let exported_file = destination.join(format!("pending-owner-request-{content_digest}.json"));
    ui.destination = Zeroizing::new(destination.to_str().ok_or(Error::InvalidData)?.to_owned());
    ui.prepare_action(Action::Export, epoch)?;
    drain(&mut ui, epoch)?;
    if !matches!(ui.review.as_ref().map(|r| &r.step), Some(Step::Export(_))) {
        return Err(Error::ReviewMismatch);
    }
    approve_current(&mut ui, epoch)?;
    ui.current_owner(epoch)?;
    let exported = Zeroizing::new(std::fs::read(&exported_file)?);
    if exported.as_slice() != expected.as_slice() {
        return Err(Error::ReviewMismatch);
    }
    Ok(ExportedPendingBirth {
        ui,
        pending,
        credentials: credentials.clone(),
        exported_file,
    })
}

impl ExportedPendingBirth {
    /// Invoke only after the independently reviewed witness owner committed the
    /// exported request and started the original pinned mutual-TLS endpoint.
    /// This makes the production history request; no supplied history is accepted.
    pub(in crate::native_ui) fn acknowledge_original_witness(
        mut self,
    ) -> Result<AcknowledgedBornFixture> {
        let credentials = &self.credentials;
        let epoch = self.ui.owner.as_ref().ok_or(Error::Locked)?.focus_epoch();
        self.ui.current_owner(epoch)?;
        self.ui.history_setup = Zeroizing::new(
            serde_json::to_string(&serde_json::json!({
                "trusted_server_root_der": credentials.trusted_server_root_der,
                "owner_certificate_der": credentials.certificate_der,
                "owner_private_key_pkcs8_der": credentials.private_key_pkcs8_der,
                "operator_name": "Explicit synthetic never-funded ephemeral witness",
                "retention_statement": "Only this private temporary qualification tree",
            }))
            .map_err(|_| Error::InvalidData)?,
        );
        self.ui.prepare_action(Action::History, epoch)?;
        drain(&mut self.ui, epoch)?;
        if !matches!(
            self.ui.review.as_ref().map(|r| &r.step),
            Some(Step::History(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve_current(&mut self.ui, epoch)?;
        if !matches!(
            self.ui.review.as_ref().map(|r| &r.step),
            Some(Step::Acknowledge(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve_current(&mut self.ui, epoch)?;
        if self.ui.owner.is_some() || self.ui.opened.is_some() || self.ui.review.is_some() {
            return Err(Error::ReviewMismatch);
        }
        // Decode the actual acknowledged envelope and its preserved anchor.
        // It remains audit-only: ordinary authority-journal creation is denied.
        let mut vault = crate::account::AccountVault::unlock(
            &self.pending.root,
            SYNTHETIC_PENDING_PASSWORD.as_bytes(),
        )?;
        if vault.account_id()? != self.pending.identity.account_id()
            || vault.historical_birth_anchor()?.anchor().birth_digest() != self.pending.birth_digest
            || vault.create_authority_journal().is_ok()
        {
            return Err(Error::ReviewMismatch);
        }
        let public_receive_address = wholepact_protocol::review::encode_testnet_receiver(
            &vault
                .account()
                .fvk()?
                .address_at(0u32, orchard::keys::Scope::External),
        );
        let privacy_domain = vault.account().privacy_domain().to_owned();
        drop(vault);
        Ok(AcknowledgedBornFixture {
            temporary: self.pending.temporary,
            root: self.pending.root,
            account_id: self.pending.identity.account_id().to_owned(),
            birth_digest: self.pending.birth_digest,
            public_receive_address,
            privacy_domain,
            credentials: self.credentials,
        })
    }
}
