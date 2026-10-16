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

/// Additional exact locally retained evidence commitments. Public data is not
/// provenance or authorization: the native owner must load these from its own
/// immutable original. This type cannot create a receipt, admission or permit.
pub struct NamedVerifierRetainedPackageBinding<'a> {
    pub package_digest: &'a str,
    pub canonical_artifact_digest: &'a str,
    pub assertion_digest: &'a str,
    pub own_policy_digest: &'a str,
}
impl NamedVerifierRetainedPackageBinding<'_> {
    fn check(&self, inspection: &NamedVerifierPackageInspection) -> Result<()> {
        self.check_digests([
            inspection.package_digest(),
            inspection.own().inspection().artifact_digest(),
            inspection.assertion().statement_digest(),
            inspection.own().inspection().policy_digest(),
        ])
    }
    fn check_digests(&self, observed: [&str; 4]) -> Result<()> {
        let expected = [
            self.package_digest,
            self.canonical_artifact_digest,
            self.assertion_digest,
            self.own_policy_digest,
        ];
        if expected != observed
            || expected.iter().any(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }
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
    check_current: impl FnMut() -> Result<()>,
) -> Result<ReceivedNamedVerifierAssertion> {
    open_named_verifier_assertion_inner(
        envelope,
        recipient,
        pinned_sender,
        expected,
        None,
        now,
        ledger,
        check_current,
    )
}

/// Exact retained binding is checked inside the authenticated artifact callback,
/// after all package/own-effects checks and before any durable receipt is offered.
#[allow(clippy::too_many_arguments)]
pub fn open_named_verifier_assertion_bound(
    envelope: &EncryptedEnvelope,
    recipient: &TransportSecret,
    pinned_sender: &TransportPublicKey,
    expected: &NamedVerifierEnvelopeExpectation<'_>,
    binding: &NamedVerifierRetainedPackageBinding<'_>,
    now: &Timestamp,
    ledger: &mut impl ReplayLedger,
    check_current: impl FnMut() -> Result<()>,
) -> Result<ReceivedNamedVerifierAssertion> {
    open_named_verifier_assertion_inner(
        envelope,
        recipient,
        pinned_sender,
        expected,
        Some(binding),
        now,
        ledger,
        check_current,
    )
}

#[allow(clippy::too_many_arguments)]
fn open_named_verifier_assertion_inner(
    envelope: &EncryptedEnvelope,
    recipient: &TransportSecret,
    pinned_sender: &TransportPublicKey,
    expected: &NamedVerifierEnvelopeExpectation<'_>,
    binding: Option<&NamedVerifierRetainedPackageBinding<'_>>,
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
            let checked = inspect_artifact(artifact, expected)?;
            if let Some(binding) = binding {
                binding.check(&checked)?;
            }
            inspection = Some(checked);
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
    check_exact_debit_reservation(
        expected.own_policy.maximum_selected_net_debit_zatoshis,
        expected.own_policy.exact_selected_net_debit_zatoshis,
        terms.maximum_debit_zatoshis,
    )?;
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

/// The witness reservation covers this exact transaction debit. The independently
/// retained accepted cap remains unchanged and may be larger. The full package
/// inspection still commits both values in its maintained own-policy digest.
fn check_exact_debit_reservation(
    accepted_cap: u64,
    exact_debit: u64,
    reserved_debit: u64,
) -> Result<()> {
    if exact_debit != reserved_debit || accepted_cap < exact_debit {
        return Err(TransportError::WrongContext);
    }
    Ok(())
}

#[cfg(test)]
mod exact_debit_reservation_tests {
    use super::*;
    #[test]
    fn greater_accepted_cap_preserves_exact_transaction_reservation() {
        assert!(check_exact_debit_reservation(100, 70, 70).is_ok());
        assert!(check_exact_debit_reservation(70, 70, 70).is_ok());
        assert_eq!(
            check_exact_debit_reservation(100, 71, 70),
            Err(TransportError::WrongContext)
        );
        assert_eq!(
            check_exact_debit_reservation(69, 70, 70),
            Err(TransportError::WrongContext)
        );
        assert_eq!(
            check_exact_debit_reservation(100, 70, 71),
            Err(TransportError::WrongContext)
        );
    }
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

/// Historical counterpart for concrete owners that retain exact commitments.
/// The receipt-backed constructor remains transport-private; arbitrary imported
/// profile/original bytes cannot construct a RetainedEnvelope.
pub fn recover_named_verifier_assertion_bound(
    record: &RetainedEnvelope,
    recipient: &TransportSecret,
    pinned_sender: &TransportPublicKey,
    expected: &NamedVerifierEnvelopeExpectation<'_>,
    binding: &NamedVerifierRetainedPackageBinding<'_>,
    mut check_current: impl FnMut() -> Result<()>,
) -> Result<ReceivedNamedVerifierAssertion> {
    let recovered = recover_named_verifier_assertion(
        record,
        recipient,
        pinned_sender,
        expected,
        &mut check_current,
    )?;
    binding.check(recovered.inspection())?;
    check_current()?;
    Ok(recovered)
}

#[cfg(test)]
mod retained_binding_tests {
    use super::*;
    #[test]
    fn every_exact_commitment_mismatch_stops_before_receipt_acceptance() {
        let values = [
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
        ];
        let binding = NamedVerifierRetainedPackageBinding {
            package_digest: &values[0],
            canonical_artifact_digest: &values[1],
            assertion_digest: &values[2],
            own_policy_digest: &values[3],
        };
        let expected = values.each_ref().map(String::as_str);
        assert!(binding.check_digests(expected).is_ok());
        for changed in 0..4 {
            let mut observed = expected;
            observed[changed] = &values[(changed + 1) % 4];
            // This is a pure ordering test, not a forged AuthenticatedReceipt.
            let mut accepted = false;
            let result = binding.check_digests(observed).map(|()| accepted = true);
            assert_eq!(result, Err(TransportError::WrongContext));
            assert!(!accepted);
        }
    }
}
