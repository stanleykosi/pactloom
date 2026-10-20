//! Native-reviewed, read-only-selected witness configuration. No credential
//! generation, installation, remote setup or silent enrollment is performed.
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::{account::AccountVault, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use wholepact_authority::{
    AuthorityClient, AuthorityHead, CertificateDer, ClientTls, PrivateKeyDer, PrivatePkcs8KeyDer,
    WitnessDisclosureDescriptor, WriterStatus,
};
use zeroize::Zeroizing;

#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
mod durable_payment_v1;

const MAX_CONFIG: usize = 16 * 1024;
const MAX_CREDENTIAL: usize = 16 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessSetup {
    schema_version: u16,
    endpoint: SocketAddr,
    server_name: String,
    witness_id: String,
    account_id: String,
    network_profile_id: String,
    policy_digest: String,
    pinned_server_certificate_digest: String,
    trusted_server_root_der: PathBuf,
    client_certificate_der: PathBuf,
    client_private_key_pkcs8_der: PathBuf,
    operator_name: String,
    retention_statement: String,
}

/// Frozen selection only: no connection is opened and no native permission is
/// issued. Shared by separate, non-convertible ordinary and informational
/// owners so both use the same maintained credential/TLS validation path.
pub(super) struct SelectedWitnessConfiguration {
    pub(super) account_id: String,
    pub(super) digest: String,
    pub(super) display: Zeroizing<String>,
    pub(super) client: AuthorityClient,
    pub(super) writer_certificate_digest: String,
}
pub(super) fn prepare_selected_witness_configuration(
    json: &str,
    expected_account_id: &str,
    expected_network_profile_id: Option<&str>,
) -> Result<SelectedWitnessConfiguration> {
    if json.len() > MAX_CONFIG {
        return Err(Error::InvalidData);
    }
    let setup: WitnessSetup = serde_json::from_str(json).map_err(|_| Error::InvalidData)?;
    if setup.schema_version != 1
        || setup.account_id != expected_account_id
        || expected_network_profile_id.is_some_and(|network| setup.network_profile_id != network)
    {
        return Err(Error::ReviewMismatch);
    }
    for text in [&setup.operator_name, &setup.retention_statement] {
        if text.is_empty() || text.len() > 2048 || text.chars().any(|c| c.is_control() && c != '\n')
        {
            return Err(Error::InvalidData);
        }
    }
    let root = read_private_credential(&setup.trusted_server_root_der)?;
    let certificate = read_private_credential(&setup.client_certificate_der)?;
    let key = read_private_credential(&setup.client_private_key_pkcs8_der)?;
    let writer_certificate_digest = hex::encode(Sha256::digest(&*certificate));
    let root_digest = hex::encode(Sha256::digest(&*root));
    // Maintained TLS verifies the selected certificate/key match. No socket,
    // writer session or credential generation occurs during preparation.
    let tls = ClientTls::new(
        setup.server_name.clone(),
        setup.pinned_server_certificate_digest.clone(),
        vec![CertificateDer::from(root.to_vec())],
        vec![CertificateDer::from(certificate.to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
    )
    .map_err(|_| Error::Authentication)?;
    let client = AuthorityClient::new(
        setup.endpoint,
        tls,
        setup.witness_id.clone(),
        setup.account_id.clone(),
        setup.network_profile_id.clone(),
        setup.policy_digest.clone(),
    )
    .map_err(|_| Error::InvalidData)?;
    let digest = wholepact_core::proposal::canonical_digest(
        "wholepact:native-witness-setup:v1",
        &(
            &setup,
            &writer_certificate_digest,
            &root_digest,
            client.disclosure_descriptor(),
        ),
    )
    .map_err(|_| Error::InvalidData)?;
    let display = Zeroizing::new(format!(
        "Operator: {}\nEndpoint: {}\nTLS server name: {}\nPinned server certificate: {}\nWitness: {}\nAccount: {}\nNetwork: {}\nOwner policy digest: {}\nClient certificate fingerprint: {}\nTrusted root fingerprint: {}\nSelected root file: {}\nSelected client certificate: {}\nSelected private credential file: {}\n\nOperator retention statement (owner-supplied; not independently verified):\n{}",
        setup.operator_name,
        setup.endpoint,
        setup.server_name,
        setup.pinned_server_certificate_digest,
        setup.witness_id,
        setup.account_id,
        setup.network_profile_id,
        setup.policy_digest,
        writer_certificate_digest,
        root_digest,
        setup.trusted_server_root_der.display(),
        setup.client_certificate_der.display(),
        setup.client_private_key_pkcs8_der.display(),
        setup.retention_statement
    ));
    Ok(SelectedWitnessConfiguration {
        account_id: setup.account_id,
        digest,
        display,
        client,
        writer_certificate_digest,
    })
}

pub(super) struct PreparedWitnessSetup {
    source: NativeAuthorityBinding,
    account_id: String,
    digest: String,
    display: Zeroizing<String>,
    client: AuthorityClient,
    writer_certificate_digest: String,
}
impl PreparedWitnessSetup {
    pub(super) fn prepare(
        json: &str,
        vault: &AccountVault,
        authority: &NativeAuthority,
    ) -> Result<Self> {
        authority.check_current()?;
        let selected = prepare_selected_witness_configuration(json, &vault.account_id()?, None)?;
        let display = Zeroizing::new(format!(
            "Independent authority witness setup\n\n{}\n\nThis permits authenticated witness inspection and later explicitly approved setup/session actions. Each reservation still needs separate exact disclosure and spending approval. A reservation discloses sensitive account/agreement/input linkage, selected input identifiers/nullifiers/values, debit/fees, expiry, recipient-scope and consent/review/artifact commitments to this operator. No spend keys, viewing keys, note plaintext, note witnesses, memos or PCZTs are sent. The witness must be independently administered and must not be restored with this signer. Pausing/revoking never cancels already issued permits. Certificate selection does not establish a fresh writer session or reconcile restored authority. No credentials are generated or installed here.",
            selected.display.as_str(),
        ));
        Ok(Self {
            source: authority.binding(),
            account_id: selected.account_id,
            digest: selected.digest,
            display,
            client: selected.client,
            writer_certificate_digest: selected.writer_certificate_digest,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<NativeWitnessWorkspace> {
        authority.check_current()?;
        self.source.check_current()?;
        if decision.binding() != &self.source
            || authority.binding() != self.source
            || decision.reviewed_digest() != self.digest
            || vault.account_id()? != self.account_id
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(NativeWitnessWorkspace {
            instance: std::sync::Arc::new(()),
            source: self.source,
            account_id: self.account_id,
            client: self.client,
            writer_certificate_digest: self.writer_certificate_digest,
        })
    }
}

pub(super) struct NativeWitnessWorkspace {
    instance: std::sync::Arc<()>,
    source: NativeAuthorityBinding,
    account_id: String,
    client: AuthorityClient,
    writer_certificate_digest: String,
}
impl NativeWitnessWorkspace {
    pub(super) fn writer_certificate_digest(&self) -> &str {
        &self.writer_certificate_digest
    }
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()
    }
    pub(super) fn client(&self) -> &AuthorityClient {
        &self.client
    }
    pub(super) fn disclosure(&self) -> WitnessDisclosureDescriptor {
        self.client.disclosure_descriptor()
    }
    pub(super) fn snapshot_head(&self) -> Result<AuthorityHead> {
        self.source.check_current()?;
        let snapshot = self.client.snapshot().map_err(|_| Error::Uncertain)?;
        self.source.check_current()?;
        if snapshot.account_id != self.account_id
            || snapshot.writer_certificate_digest != self.writer_certificate_digest
        {
            return Err(Error::Authentication);
        }
        if snapshot.writer_status == WriterStatus::Quarantined {
            return Err(Error::RecoveryRequired);
        }
        if snapshot.writer_status != WriterStatus::Active {
            return Err(Error::Locked);
        }
        Ok(snapshot.head)
    }
}

pub(super) fn read_private_credential(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::InvalidData);
    }
    let parent = path.parent().ok_or(Error::InvalidData)?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| Error::InvalidData)?;
    let uid = unsafe { libc::geteuid() };
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != uid
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err(Error::InvalidData);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::InvalidData)?;
    let metadata = file.metadata().map_err(|_| Error::InvalidData)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_CREDENTIAL as u64
    {
        return Err(Error::InvalidData);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_CREDENTIAL as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidData)?;
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL {
        return Err(Error::InvalidData);
    }
    Ok(bytes)
}

/// A complete history review is prepared before creating session access. Native
/// approval and retries are separate so an uncertain response retains the exact
/// operation and ephemeral client key without a new operation or silent takeover.
pub(super) struct PreparedWriterSession {
    source: NativeAuthorityBinding,
    history: wholepact_authority::ReconciledAuthorityHistory,
    operation_id: String,
    digest: String,
    display: Zeroizing<String>,
    client_certificate_digest: String,
}
pub(crate) struct ApprovedWriterSession(PreparedWriterSession, std::time::Instant);
impl PreparedWriterSession {
    pub(super) fn prepare(workspace: &NativeWitnessWorkspace) -> Result<Self> {
        Self::prepare_operation(workspace, None)
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(super) fn prepare_born(
        workspace: &NativeWitnessWorkspace,
        extension: &wholepact_authority::manual_enrollment::ManualEnrollmentExtension,
    ) -> Result<Self> {
        let prepared = Self::prepare_operation(
            workspace,
            Some(
                extension
                    .acquire_operation_id()
                    .map_err(|_| Error::InvalidData)?,
            ),
        )?;
        if prepared
            .history
            .manual_enrollment_extension(&extension.enrollment_ref)
            .map_err(|_| Error::Authentication)?
            != Some(extension)
            || prepared.history.snapshot().head.sequence != 1
            || prepared.history.contains_operation(
                &extension
                    .acquire_operation_id()
                    .map_err(|_| Error::InvalidData)?,
            )
            || prepared.history.contains_operation(
                &extension
                    .admission_operation_id()
                    .map_err(|_| Error::InvalidData)?,
            )
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(prepared)
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(super) fn prepare_born_continued(
        workspace: &NativeWitnessWorkspace,
        extension: &wholepact_authority::manual_enrollment::ManualEnrollmentExtension,
        continuation: &wholepact_authority::manual_session_continuation::ManualEnrollmentSessionContinuation,
    ) -> Result<Self> {
        let prepared = Self::prepare_operation(
            workspace,
            Some(
                continuation
                    .acquire_operation_id(extension)
                    .map_err(|_| Error::InvalidData)?,
            ),
        )?;
        let attempt = prepared
            .history
            .latest_manual_attempt(&extension.enrollment_ref)
            .map_err(|_| Error::RecoveryRequired)?;
        if attempt.continuation.as_ref() != Some(continuation)
            || attempt.admission.is_some()
            || prepared.history.contains_operation(
                &continuation
                    .acquire_operation_id(extension)
                    .map_err(|_| Error::InvalidData)?,
            )
            || prepared.history.contains_operation(
                &continuation
                    .admission_operation_id(extension)
                    .map_err(|_| Error::InvalidData)?,
            )
        {
            return Err(Error::RecoveryRequired);
        }
        Ok(prepared)
    }
    fn prepare_operation(
        workspace: &NativeWitnessWorkspace,
        operation: Option<String>,
    ) -> Result<Self> {
        workspace.check_current()?;
        let history = if operation.is_some() {
            workspace.client.reconcile_history_checked(|| {
                workspace
                    .check_current()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
        } else {
            workspace.client.reconcile_history()
        }
        .map_err(|_| Error::Uncertain)?;
        workspace.check_current()?;
        let snapshot = history.snapshot();
        if snapshot.account_id != workspace.account_id
            || snapshot.writer_certificate_digest != workspace.writer_certificate_digest
        {
            return Err(Error::Authentication);
        }
        if snapshot.writer_status == WriterStatus::Quarantined {
            return Err(Error::RecoveryRequired);
        }
        if snapshot.writer_status == WriterStatus::Revoked
            || snapshot.active_writer_session.is_some()
            || snapshot.pending_writer_session.is_some()
        {
            return Err(Error::Locked);
        }
        let operation_id = match operation {
            Some(value) => value,
            None => hex::encode(crate::vault::random::<32>()?),
        };
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-witness-session-request:v2",
            &(
                snapshot,
                history.history_digest().map_err(|_| Error::InvalidData)?,
                &operation_id,
                workspace.disclosure(),
                &workspace.writer_certificate_digest,
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "Request a fresh independent writer session\n\nWitness: {}\nEndpoint: {}\nAccount: {}\nNetwork: {}\nWriter certificate: {}\nWriter epoch: {}\nComplete reconciled history head: {} / {}\nOriginal outstanding permits: {}\nOutstanding maximum debit: {} zatoshis\nReserved selected input value: {} zatoshis\n\nEvery history page and exact original permit was verified. All existing exposure remains counted. This creates a pending short-lived session tied to this process's authenticated TLS channel. It is unusable until the independent owner approves this exact session. A saved certificate or restored ledger alone cannot resume authorization. The session key stays only in this process and the witness's encrypted state; it is not written into signer backups. Canceling or losing this process does not erase any permit or reservation.",
            snapshot.witness_id,
            workspace.disclosure().endpoint,
            snapshot.account_id,
            snapshot.network_profile_id,
            snapshot.writer_certificate_digest,
            snapshot.writer_epoch,
            snapshot.head.sequence,
            snapshot.head.digest,
            snapshot.outstanding_reservations,
            snapshot.outstanding_debit_zatoshis,
            snapshot.reserved_input_value_zatoshis
        ));
        Ok(Self {
            source: workspace.source.clone(),
            history,
            operation_id,
            digest,
            display,
            client_certificate_digest: workspace.writer_certificate_digest.clone(),
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        workspace: &NativeWitnessWorkspace,
    ) -> Result<ApprovedWriterSession> {
        authority.check_current()?;
        workspace.check_current()?;
        if decision.binding() != &self.source
            || authority.binding() != self.source
            || workspace.source != self.source
            || decision.reviewed_digest() != self.digest
            || workspace.writer_certificate_digest != self.client_certificate_digest
            || workspace.disclosure() != *self.history.disclosure()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedWriterSession(self, std::time::Instant::now()))
    }
}
impl ApprovedWriterSession {
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn born_attempt_review(
        &self,
        extension: &wholepact_authority::manual_enrollment::ManualEnrollmentExtension,
        source: &NativeAuthorityBinding,
    ) -> Result<String> {
        self.0.source.check_current()?;
        if &self.0.source != source
            || self.1.elapsed() >= std::time::Duration::from_secs(120)
            || self.0.operation_id
                != extension
                    .acquire_operation_id()
                    .map_err(|_| Error::InvalidData)?
            || self.0.history.snapshot().head.sequence != 1
            || self.0.client_certificate_digest != extension.terms.signer.writer_certificate_digest
            || self.0.history.snapshot().writer_epoch != extension.terms.signer.writer_epoch
            || self
                .0
                .history
                .manual_enrollment_extension(&extension.enrollment_ref)
                .map_err(|_| Error::Authentication)?
                != Some(extension)
            || self.0.history.snapshot().pending_writer_session.is_some()
            || self.0.history.snapshot().active_writer_session.is_some()
        {
            return Err(Error::RecoveryRequired);
        }
        Ok(self.0.digest.clone())
    }

    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn born_continued_attempt_review(
        &self,
        extension: &wholepact_authority::manual_enrollment::ManualEnrollmentExtension,
        continuation: &wholepact_authority::manual_session_continuation::ManualEnrollmentSessionContinuation,
        source: &NativeAuthorityBinding,
    ) -> Result<String> {
        self.0.source.check_current()?;
        let attempt = self
            .0
            .history
            .latest_manual_attempt(&extension.enrollment_ref)
            .map_err(|_| Error::RecoveryRequired)?;
        if &self.0.source != source
            || self.1.elapsed() >= std::time::Duration::from_secs(120)
            || self.0.operation_id
                != continuation
                    .acquire_operation_id(extension)
                    .map_err(|_| Error::InvalidData)?
            || attempt.continuation.as_ref() != Some(continuation)
            || attempt.admission.is_some()
            || attempt.snapshot.pending_writer_session.is_some()
            || attempt.snapshot.active_writer_session.is_some()
            || self.0.client_certificate_digest != extension.terms.signer.writer_certificate_digest
            || attempt.snapshot.writer_epoch != extension.terms.signer.writer_epoch
        {
            return Err(Error::RecoveryRequired);
        }
        Ok(self.0.digest.clone())
    }

    pub(super) fn acquire(
        &self,
        workspace: &NativeWitnessWorkspace,
    ) -> Result<wholepact_authority::WriterSessionReceipt> {
        self.0.source.check_current()?;
        // A decision permits only this exact operation and bounded retry window.
        // Monotonic time prevents wall-clock rollback from extending approval.
        if self.1.elapsed() > std::time::Duration::from_secs(120) {
            return Err(Error::ReviewMismatch);
        }
        workspace.check_current()?;
        if workspace.source != self.0.source
            || workspace.writer_certificate_digest != self.0.client_certificate_digest
            || workspace.disclosure() != *self.0.history.disclosure()
        {
            return Err(Error::ReviewMismatch);
        }
        let result = workspace
            .client
            .acquire_writer(&self.0.history, &self.0.operation_id)
            .map_err(|_| Error::Uncertain)?;
        self.0.source.check_current()?;
        if self.1.elapsed() > std::time::Duration::from_secs(120) {
            return Err(Error::ReviewMismatch);
        }
        Ok(result)
    }
}

pub(super) struct PreparedWriterActivation {
    source: NativeAuthorityBinding,
    request: wholepact_authority::OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
    client_certificate_digest: String,
    digest: String,
    display: Zeroizing<String>,
}
pub(super) struct ApprovedWriterActivation(PreparedWriterActivation, std::time::Instant);
impl PreparedWriterActivation {
    pub(super) fn prepare(
        owner_workspace: &NativeWitnessWorkspace,
        receipt: wholepact_authority::WriterSessionReceipt,
    ) -> Result<Self> {
        owner_workspace.check_current()?;
        let snapshot = owner_workspace
            .client
            .snapshot()
            .map_err(|_| Error::Uncertain)?;
        owner_workspace.check_current()?;
        // Snapshot access admits only owner/current writer. A different selected
        // client certificate that successfully read it is the authenticated owner.
        if snapshot.writer_certificate_digest == owner_workspace.writer_certificate_digest
            || snapshot.account_id != owner_workspace.account_id
            || receipt.disclosure != owner_workspace.disclosure()
            || snapshot.pending_writer_session.as_ref() != Some(&receipt)
            || snapshot.head != receipt.acquired_head
        {
            return Err(Error::Authentication);
        }
        if snapshot.writer_status == WriterStatus::Quarantined {
            return Err(Error::RecoveryRequired);
        }
        let request = wholepact_authority::OwnerControlRequest {
            operation_id: hex::encode(crate::vault::random::<32>()?),
            account_id: snapshot.account_id.clone(),
            network_profile_id: snapshot.network_profile_id.clone(),
            expected_head: snapshot.head.clone(),
            writer_epoch: snapshot.writer_epoch,
            control: wholepact_authority::OwnerControl::ActivateWriter {
                session_id: receipt.session_id.clone(),
            },
        };
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-owner-writer-activation:v2",
            &(
                &request,
                &receipt,
                &snapshot,
                &owner_workspace.writer_certificate_digest,
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "Independent owner approval: activate this exact writer session\n\nWitness: {}\nEndpoint: {}\nAccount: {}\nNetwork: {}\nSelected owner certificate: {}\nWriter certificate: {}\nWriter epoch: {}\nFresh writer session: {}\nReconciled head: {} / {}\nActivation precondition: {} / {}\nSession expires at Unix milliseconds: {}\nOutstanding original permits: {}\nOutstanding maximum debit: {} zatoshis\nReserved selected input value: {} zatoshis\n\nCompare this exact session with the writer you intend to activate. Approval grants only this fresh session permission to compete for exact future reservations under the unchanged witness policy. It does not sign a transaction, increase the budget, erase history, clear exposure or cancel previously issued permits. A materially different session/head requires a new review.",
            snapshot.witness_id,
            owner_workspace.disclosure().endpoint,
            snapshot.account_id,
            snapshot.network_profile_id,
            owner_workspace.writer_certificate_digest,
            receipt.writer_certificate_digest,
            receipt.writer_epoch,
            receipt.session_id,
            receipt.reconciled_head.sequence,
            receipt.reconciled_head.digest,
            snapshot.head.sequence,
            snapshot.head.digest,
            receipt.expires_at_ms,
            snapshot.outstanding_reservations,
            snapshot.outstanding_debit_zatoshis,
            snapshot.reserved_input_value_zatoshis
        ));
        Ok(Self {
            source: owner_workspace.source.clone(),
            request,
            disclosure: owner_workspace.disclosure(),
            client_certificate_digest: owner_workspace.writer_certificate_digest.clone(),
            digest,
            display,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        workspace: &NativeWitnessWorkspace,
    ) -> Result<ApprovedWriterActivation> {
        authority.check_current()?;
        workspace.check_current()?;
        if decision.binding() != &self.source
            || authority.binding() != self.source
            || workspace.source != self.source
            || decision.reviewed_digest() != self.digest
            || workspace.disclosure() != self.disclosure
            || workspace.writer_certificate_digest != self.client_certificate_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedWriterActivation(self, std::time::Instant::now()))
    }
}
impl ApprovedWriterActivation {
    pub(super) fn activate(
        &self,
        workspace: &NativeWitnessWorkspace,
    ) -> Result<wholepact_authority::AccountSnapshot> {
        self.0.source.check_current()?;
        // A decision permits only this exact operation and bounded retry window.
        // Monotonic time prevents wall-clock rollback from extending approval.
        if self.1.elapsed() > std::time::Duration::from_secs(120) {
            return Err(Error::ReviewMismatch);
        }
        workspace.check_current()?;
        if workspace.source != self.0.source
            || workspace.disclosure() != self.0.disclosure
            || workspace.writer_certificate_digest != self.0.client_certificate_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let result = workspace
            .client
            .control(self.0.request.clone())
            .map_err(|_| Error::Uncertain)?;
        self.0.source.check_current()?;
        if self.1.elapsed() > std::time::Duration::from_secs(120) {
            return Err(Error::ReviewMismatch);
        }
        Ok(result)
    }
}

#[cfg(feature = "pending-birth-owner-signing")]
impl NativeWitnessWorkspace {
    pub(super) fn from_born_manual(
        approved: super::born_manual::witness::ApprovedManualWitnessSetup,
    ) -> (Self, Self) {
        let (source, account_id, writer, owner, writer_pin, owner_pin) = approved.into_parts();
        (
            Self {
                instance: std::sync::Arc::new(()),
                source: source.clone(),
                account_id: account_id.clone(),
                client: writer,
                writer_certificate_digest: writer_pin,
            },
            Self {
                instance: std::sync::Arc::new(()),
                source,
                account_id,
                client: owner,
                writer_certificate_digest: owner_pin,
            },
        )
    }
}

#[cfg(feature = "pending-birth-owner-signing")]
mod roster_v2;

impl NativeWitnessWorkspace {
    /// Informational recovery stays inside the same genuine native lifetime.
    pub(super) fn require_native_origin(&self, source: &NativeAuthorityBinding) -> Result<()> {
        self.check_current()?;
        source.check_current()?;
        if &self.source != source {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}

#[cfg(feature = "pending-birth-owner-signing")]
impl NativeWitnessWorkspace {
    /// Retains the original-owner TLS client selected by the genuine reentry
    /// ceremony. No request is made and no writer-session MAC is installed.
    /// Every subsequent purpose-specific action needs its own native review.
    pub(in crate::native_ui) fn from_consumed_born_named(
        actual: &crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::ConsumedBornNamedSourceV1,
        owner: &super::PendingAccountNativeAuthority,
        client: AuthorityClient,
    ) -> Result<Self> {
        actual.check(owner)?;
        let terms = &actual.construction().extension.account_extension.terms;
        let disclosure = client.disclosure_descriptor();
        if disclosure.account_id != terms.identity.account_id
            || disclosure.policy_digest != terms.original_policy_digest
            || disclosure != actual.construction().reservation.session.disclosure
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(Self {
            instance: std::sync::Arc::new(()),
            source: owner.native().binding(),
            account_id: terms.identity.account_id.clone(),
            client,
            writer_certificate_digest: terms.signer.owner_certificate_digest.clone(),
        })
    }
}

#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
mod durable_delivery_admission_v2;

#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
pub(in crate::native_ui) mod durable_delivery_v3;

#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
pub(in crate::native_ui) mod financial_continuation_v1;
