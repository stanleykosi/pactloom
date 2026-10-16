//! Evidence-only encrypted assertion import. Application-owned recipient keys,
//! explicit verifier selection and retained local expectations remain prerequisites.
//! This module cannot establish setup, consent, current time or financial authority.
use crate::{
    NamedVerifierExpectedContext, NamedVerifierPackageInspection, Result,
    inspect_named_verifier_package,
};
use sha2::{Digest, Sha256};
use wholepact_authority::offline::OfflineAuthorizationTerms;
use wholepact_protocol::own_effects::OwnEffectsPolicy;
use wholepact_transport::{
    ArtifactKind, EncryptedEnvelope, MessageContext, ReceivedArtifact, ReplayLedger,
    RetainedEnvelope, Timestamp, TransportError, TransportPublicKey, TransportSecret,
    open_envelope_checked, recover_received,
};

/// Local expectations, never a remotely asserted approval or an opaque capability.
/// The native owner must supply its retained context, own-account policy and
/// independently selected verifier key. A caller can inspect evidence but cannot
/// turn these inputs into an offline reservation or key-use permit.
pub struct NamedVerifierEnvelopeExpectation<'a> {
    pub context: &'a MessageContext,
    pub original_terms: &'a OfflineAuthorizationTerms,
    pub own_policy: &'a OwnEffectsPolicy,
    pub selected_verifier: &'a [u8; 32],
    pub assertion: &'a NamedVerifierExpectedContext<'a>,
}

pub struct ReceivedNamedVerifierAssertion {
    artifact: ReceivedArtifact,
    inspection: NamedVerifierPackageInspection,
    historical: bool,
}
impl ReceivedNamedVerifierAssertion {
    pub fn is_new_delivery(&self) -> bool {
        !self.historical
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
    pub fn artifact(&self) -> &ReceivedArtifact {
        &self.artifact
    }
    pub fn inspection(&self) -> &NamedVerifierPackageInspection {
        &self.inspection
    }
}

/// Authenticate and check the exact assertion and independent selected-own
/// effects BEFORE durable inbox acceptance. The timestamp is supplied by the
/// actual owner; this function does not establish a trusted clock. Domain errors
/// consume no sequence. A commit error remains an uncertain import outcome and
/// must be recovered from the original inbox, never retried under a new identity.
#[allow(clippy::too_many_arguments)]
pub fn open_named_verifier_assertion(
    envelope: &EncryptedEnvelope,
    recipient: &TransportSecret,
    pinned_sender: &TransportPublicKey,
    expected: &NamedVerifierEnvelopeExpectation<'_>,
    now: &Timestamp,
    ledger: &mut impl ReplayLedger,
    mut check_current: impl FnMut() -> Result<()>,
) -> Result<ReceivedNamedVerifierAssertion> {
    check_current()?;
    check_expectation(expected)?;
    if recipient.public_key()?.fingerprint() != expected.original_terms.offline_signer_key_digest {
        return Err(TransportError::WrongRecipient);
    }
    let mut inspection = None;
    let artifact = open_envelope_checked(
        envelope,
        recipient,
        pinned_sender,
        expected.context,
        now,
        ledger,
        |artifact| {
            check_current()?;
            inspection = Some(inspect_artifact(artifact, expected)?);
            check_current()
        },
    )?;
    // No authority escapes if the owner's lifetime ends during durable import.
    // The exact accepted ciphertext remains recoverable in the original inbox.
    check_current().map_err(|_| TransportError::ImportCommittedButUnavailable)?;
    Ok(ReceivedNamedVerifierAssertion {
        artifact,
        inspection: inspection.ok_or(TransportError::Authentication)?,
        historical: false,
    })
}

fn check_expectation(expected: &NamedVerifierEnvelopeExpectation<'_>) -> Result<()> {
    let terms = expected.original_terms;
    terms.validate().map_err(|_| TransportError::WrongContext)?;
    if crate::named_verifier_original_context_digest(terms)?
        != expected.assertion.original_context_digest
        || terms.account_id != expected.assertion.own_account_id
        || terms.artifact_digest != expected.assertion.original_artifact_digest
        || terms.manifest_digest != expected.assertion.manifest_digest
        || terms.transaction_expiry_height != expected.assertion.transaction_expiry_height
        || expected.context.network_profile_id != terms.network_profile_id
        || expected.context.agreement_id != terms.agreement_id
        || expected.context.proposal_id != terms.proposal_id
        || expected.context.proposal_revision != terms.proposal_revision
        || expected.own_policy.expiry_height != terms.transaction_expiry_height
        || hex::encode(expected.own_policy.anchor) != terms.snapshot.anchor_root
        || hex::encode(expected.own_policy.manifest_digest) != terms.manifest_digest
        || expected.own_policy.maximum_selected_net_debit_zatoshis != terms.maximum_debit_zatoshis
        || expected.own_policy.declared_fee_share_zatoshis != terms.fee_share_zatoshis
        || expected.own_policy.exact_transaction_fee_zatoshis != terms.transaction_fee_zatoshis
        || expected.own_policy.own_inputs.len() != terms.inputs.len()
        || expected.own_policy.own_inputs.iter().any(|own| {
            !terms.inputs.iter().any(|input| {
                input.action_index == own.action_index as u64
                    && input.nullifier == hex::encode(own.nullifier)
                    && input.value_zatoshis == own.value_zatoshis
            })
        })
        || expected.context.artifact_kind != ArtifactKind::NamedVerifierAssertion
        || expected.context.recipient_id != expected.assertion.own_account_id
        || expected.own_policy.account_id != expected.assertion.own_account_id
        || expected.context.sender_id != hex::encode(Sha256::digest(expected.selected_verifier))
    {
        return Err(TransportError::WrongContext);
    }
    Ok(())
}

fn inspect_artifact(
    artifact: &ReceivedArtifact,
    expected: &NamedVerifierEnvelopeExpectation<'_>,
) -> Result<NamedVerifierPackageInspection> {
    let order = &artifact.preview().order;
    let start = i64::try_from(expected.assertion.validity_not_before_ms.div_ceil(1000))
        .map_err(|_| TransportError::InvalidTime)?;
    let end = i64::try_from(expected.assertion.validity_expires_ms / 1000)
        .map_err(|_| TransportError::InvalidTime)?;
    if order.issued_at.unix_seconds() != start || order.expires_at.unix_seconds() != end {
        return Err(TransportError::WrongContext);
    }
    let fields = artifact.fields();
    if fields.len() != 1 || fields[0].name() != "named-verifier-assertion-v1" {
        return Err(TransportError::WrongContext);
    }
    let inspected = inspect_named_verifier_package(
        fields[0].bytes(),
        expected.own_policy,
        expected.selected_verifier,
        expected.assertion,
    )?;
    if inspected.own().inspection().shielded_sighash() != expected.original_terms.effects_digest {
        return Err(TransportError::WrongContext);
    }
    Ok(inspected)
}

/// Exact receipt-backed historical reopening, including expired original content.
/// This performs no inbox mutation and confers neither a new delivery nor current
/// time, consent or key-use authority. It is the only retry path after a committed
/// import whose caller lost its current owner before receiving the result.
pub fn recover_named_verifier_assertion(
    record: &RetainedEnvelope,
    recipient: &TransportSecret,
    pinned_sender: &TransportPublicKey,
    expected: &NamedVerifierEnvelopeExpectation<'_>,
    mut check_current: impl FnMut() -> Result<()>,
) -> Result<ReceivedNamedVerifierAssertion> {
    check_current()?;
    check_expectation(expected)?;
    if recipient.public_key()?.fingerprint() != expected.original_terms.offline_signer_key_digest {
        return Err(TransportError::WrongRecipient);
    }
    let artifact =
        recover_received(record, recipient, pinned_sender, expected.context)?.into_artifact();
    let inspection = inspect_artifact(&artifact, expected)?;
    check_current()?;
    Ok(ReceivedNamedVerifierAssertion {
        artifact,
        inspection,
        historical: true,
    })
}
