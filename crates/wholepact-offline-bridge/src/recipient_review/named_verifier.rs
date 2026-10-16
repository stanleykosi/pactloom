//! Producer side: all viewing authority is already retained locally. No imported
//! account label can supply a policy association. Existing setup/retention types
//! have no factory, so this does not open an issuer or grant verifier credentials.
use super::*;
use crate::named_verifier::*;
use wholepact_protocol::{
    canonical_role_layout::{produce_canonical_layout, CanonicalLayoutArtifact},
    own_effects::*,
};

/// Durable pre-package request identity. Only the forthcoming concrete owner
/// journal adapter can construct this; no wire conversion or expiry reset.
pub struct OriginalNamedVerifierRequest {
    request_digest: String,
    original_context_digest: String,
    validity_not_before_ms: u64,
    validity_expires_ms: u64,
}
/// Package-independent original economic context. The sole omitted field is the
/// package digest, which necessarily includes the later statement. Final witness
/// intent separately binds the completed exact package and assertion.
pub fn named_verifier_original_context_digest(terms: &OfflineAuthorizationTerms) -> Result<String> {
    terms.validate().map_err(|_| TransportError::WrongContext)?;
    let mut value = serde_json::to_value(terms).map_err(|_| TransportError::Malformed)?;
    value
        .as_object_mut()
        .ok_or(TransportError::Malformed)?
        .remove("review_package_digest")
        .ok_or(TransportError::Malformed)?;
    let bytes = serde_json::to_vec(&value).map_err(|_| TransportError::Malformed)?;
    Ok(hash(
        b"wholepact:named-verifier-original-context:v1\0",
        &bytes,
    ))
}

pub struct PreparedNamedVerifierAssertion {
    statement: NamedVerifierStatementV1,
    layout: CanonicalLayoutArtifact,
}
impl PreparedNamedVerifierAssertion {
    pub fn statement(&self) -> &NamedVerifierStatementV1 {
        &self.statement
    }
    pub fn recipient_artifact(&self) -> &CanonicalLayoutArtifact {
        &self.layout
    }
    /// Bytes to be signed by a separately established verifier owner. This
    /// function creates no signature, credential, enrollment or disclosure grant.
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        self.statement.signing_message()
    }
}
/// Source-supported producer boundary, currently unavailable to runtime because
/// authenticated retained inputs/reservation have no public production factory.
fn prepare_named_verifier_assertion(
    original: &[u8],
    retained: &RetainedOfflineReviewInputs,
    request: &OriginalNamedVerifierRequest,
    verifier_public_key: &[u8; 32],
) -> Result<PreparedNamedVerifierAssertion> {
    retained
        .terms
        .validate()
        .map_err(|_| TransportError::WrongContext)?;
    if request.original_context_digest != named_verifier_original_context_digest(&retained.terms)?
        || request.validity_not_before_ms >= request.validity_expires_ms
    {
        return Err(TransportError::WrongContext);
    }
    // Re-executes exact manifest policy, full economic review and maintained proof
    // verification; neither a caller's proof flag nor a precomputed DTO is accepted.
    verify_exact(
        &retained.terms,
        &retained.proposal,
        &retained.policy,
        &retained.input_actions,
        &retained.output_actions,
        original,
        retained.maximum_actions,
    )?;
    let layout = produce_canonical_layout(original, &retained.policy)
        .map_err(|_| TransportError::Authentication)?;
    let policy = &retained.policy;
    let mut participants = Vec::new();
    for (owner, p) in policy.participants.iter().enumerate() {
        let own = OwnEffectsPolicy {
            account_id: p.account_id.clone(),
            own_fvk: p.fvk.clone(),
            manifest_digest: policy.manifest_digest,
            anchor: policy.anchor,
            expiry_height: policy.expiry_height,
            maximum_selected_net_debit_zatoshis: p.maximum_net_debit_zatoshis,
            exact_selected_net_debit_zatoshis: p
                .contribution_zatoshis
                .checked_add(p.fee_share_zatoshis)
                .ok_or(TransportError::WrongContext)?,
            declared_fee_share_zatoshis: p.fee_share_zatoshis,
            exact_transaction_fee_zatoshis: policy.exact_fee_zatoshis,
            own_inputs: policy
                .inputs
                .iter()
                .filter(|i| i.participant_index == owner)
                .map(|i| OwnInputExpectation {
                    action_index: i.action_index,
                    nullifier: i.nullifier,
                    value_zatoshis: i.value_zatoshis,
                })
                .collect(),
            outputs: policy
                .outputs
                .iter()
                .map(|o| OwnOutputExpectation {
                    action_index: o.action_index,
                    receiver: o.receiver,
                    value_zatoshis: o.value_zatoshis,
                    memo: o.memo,
                    purpose: match o.purpose {
                        OutputPurpose::Return { participant_index }
                            if participant_index == owner =>
                        {
                            OwnOutputPurpose::OwnReturn
                        }
                        OutputPurpose::Return { .. } => OwnOutputPurpose::PeerReturnUnverified,
                        OutputPurpose::Recipient => OwnOutputPurpose::Recipient,
                    },
                })
                .collect(),
        };
        let inspection =
            verify_own_effects(layout.bytes(), &own).map_err(|_| TransportError::Authentication)?;
        if inspection.shielded_sighash() != retained.terms.effects_digest {
            return Err(TransportError::WrongContext);
        }
        participants.push(NamedParticipantAllocationV1 {
            account_id: p.account_id.clone(),
            contribution_zatoshis: p.contribution_zatoshis,
            fee_share_zatoshis: p.fee_share_zatoshis,
            maximum_debit_zatoshis: p.maximum_net_debit_zatoshis,
            selected_own_policy_digest: inspection.policy_digest().into(),
        });
    }
    let mut inputs = policy
        .inputs
        .iter()
        .map(|i| {
            Ok(NamedInputAllocationV1 {
                action_index: u32::try_from(i.action_index)
                    .map_err(|_| TransportError::ResourceLimit)?,
                participant_index: u32::try_from(i.participant_index)
                    .map_err(|_| TransportError::ResourceLimit)?,
                nullifier: hex::encode(i.nullifier),
                value_zatoshis: i.value_zatoshis,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    inputs.sort_by_key(|i| i.action_index);
    let mut outputs = policy
        .outputs
        .iter()
        .map(|o| {
            Ok(NamedOutputAllocationV1 {
                action_index: u32::try_from(o.action_index)
                    .map_err(|_| TransportError::ResourceLimit)?,
                return_participant_index: match o.purpose {
                    OutputPurpose::Recipient => None,
                    OutputPurpose::Return { participant_index } => Some(
                        u32::try_from(participant_index)
                            .map_err(|_| TransportError::ResourceLimit)?,
                    ),
                },
                receiver: hex::encode(o.receiver.to_raw_address_bytes()),
                value_zatoshis: o.value_zatoshis,
                memo_digest: hex::encode(Sha256::digest(o.memo)),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    outputs.sort_by_key(|o| o.action_index);
    let statement = NamedVerifierStatementV1 {
        schema_version: 1,
        verifier_key_digest: hex::encode(Sha256::digest(verifier_public_key)),
        recipient_account_id: retained.terms.account_id.clone(),
        original_artifact_digest: layout.transformation().original_digest().into(),
        recipient_artifact_digest: layout.transformation().redacted_digest().into(),
        transformation_commitment: layout.transformation().commitment().into(),
        effects_digest: retained.terms.effects_digest.clone(),
        manifest_digest: retained.terms.manifest_digest.clone(),
        original_context_digest: request.original_context_digest.clone(),
        original_request_digest: request.request_digest.clone(),
        validity_not_before_ms: request.validity_not_before_ms,
        validity_expires_ms: request.validity_expires_ms,
        transaction_expiry_height: policy.expiry_height,
        transaction_fee_zatoshis: policy.exact_fee_zatoshis,
        participants,
        inputs,
        outputs,
    };
    statement.validate()?;
    Ok(PreparedNamedVerifierAssertion { statement, layout })
}

/// Complete current native-approved account associations. This factory consumes
/// only genuine installed-signer purpose leases, never an imported trust flag.
#[cfg(target_os = "linux")]
pub struct RetainedNamedVerifierOwner<'a, 'client> {
    leases: &'a [wholepact_signer_origin::NamedVerifierPolicyLease<'client>],
    retained: RetainedOfflineReviewInputs,
    request: OriginalNamedVerifierRequest,
    verifier_key_digest: String,
}
#[cfg(target_os = "linux")]
pub struct CurrentPreparedNamedVerifierAssertion<'owner, 'a, 'client> {
    owner: &'owner RetainedNamedVerifierOwner<'a, 'client>,
    prepared: PreparedNamedVerifierAssertion,
}
/// Untrusted retained inputs. These fields alone confer no authority; the
/// factory verifies them against every genuine current account-policy lease.
#[cfg(target_os = "linux")]
pub struct NamedVerifierRetainedInputs {
    pub terms: OfflineAuthorizationTerms,
    pub proposal: Proposal,
    pub policy: ReviewPolicy,
    pub input_actions: Vec<InputActionMapping>,
    pub output_actions: Vec<OutputActionMapping>,
    pub maximum_actions: usize,
}
#[cfg(target_os = "linux")]
impl<'a, 'client> RetainedNamedVerifierOwner<'a, 'client> {
    pub fn from_current_policy_leases(
        leases: &'a [wholepact_signer_origin::NamedVerifierPolicyLease<'client>],
        inputs: NamedVerifierRetainedInputs,
        verifier_public_key: &[u8; 32],
    ) -> Result<Self> {
        let NamedVerifierRetainedInputs {
            terms,
            proposal,
            policy,
            input_actions,
            output_actions,
            maximum_actions,
        } = inputs;
        terms.validate().map_err(|_| TransportError::WrongContext)?;
        if leases.len() != policy.participants.len() || !(2..=32).contains(&leases.len()) {
            return Err(TransportError::WrongContext);
        }
        verify_manifest_policy(&proposal, &policy, &input_actions, &output_actions)
            .map_err(|_| TransportError::WrongContext)?;
        let key_digest = hex::encode(Sha256::digest(verifier_public_key));
        let first = &leases[0].request().scope;
        let request_digest = first.original_request_digest.clone();
        let destination = first.verifier_destination.clone();
        let mut accounts = std::collections::BTreeSet::new();
        let not_before = first.original_validity_not_before_ms;
        let expires = first.original_validity_expires_ms;
        for lease in leases {
            lease
                .check_current()
                .map_err(|_| TransportError::AuthorityUnavailable)?;
            let scope = &lease.request().scope;
            let p = scope.validate().map_err(|_| TransportError::WrongContext)?;
            let participant = policy
                .participants
                .iter()
                .find(|p| p.account_id == scope.account_id)
                .ok_or(TransportError::WrongContext)?;
            if !accounts.insert(scope.account_id.clone())
                || p.input() != proposal.input()
                || scope.original_request_digest != request_digest
                || scope.original_artifact_digest != terms.artifact_digest
                || scope.verifier_key_digest != key_digest
                || scope.verifier_destination != destination
                || scope.original_validity_not_before_ms != not_before
                || scope.original_validity_expires_ms != expires
                || lease
                    .full_viewing_key_bytes()
                    .map_err(|_| TransportError::AuthorityUnavailable)?
                    != &participant.fvk.to_bytes()
            {
                return Err(TransportError::WrongContext);
            }
        }
        if not_before >= expires {
            return Err(TransportError::InvalidTime);
        }
        let original_context_digest = named_verifier_original_context_digest(&terms)?;
        Ok(Self {
            leases,
            retained: RetainedOfflineReviewInputs {
                terms,
                proposal,
                policy,
                input_actions,
                output_actions,
                maximum_actions,
            },
            request: OriginalNamedVerifierRequest {
                request_digest,
                original_context_digest,
                validity_not_before_ms: not_before,
                validity_expires_ms: expires,
            },
            verifier_key_digest: key_digest,
        })
    }
    pub fn check_current(&self) -> Result<()> {
        for lease in self.leases {
            lease
                .check_current()
                .map_err(|_| TransportError::AuthorityUnavailable)?;
        }
        Ok(())
    }
    fn check_local_current(&self) -> Result<()> {
        for lease in self.leases {
            lease
                .check_local_current()
                .map_err(|_| TransportError::AuthorityUnavailable)?;
        }
        Ok(())
    }
    pub fn prepare<'owner>(
        &'owner self,
        original: &[u8],
        key: &[u8; 32],
    ) -> Result<CurrentPreparedNamedVerifierAssertion<'owner, 'a, 'client>> {
        self.check_current()?;
        if hex::encode(Sha256::digest(key)) != self.verifier_key_digest {
            return Err(TransportError::WrongContext);
        }
        let prepared =
            prepare_named_verifier_assertion(original, &self.retained, &self.request, key)?;
        self.check_current()?;
        Ok(CurrentPreparedNamedVerifierAssertion {
            owner: self,
            prepared,
        })
    }
}
#[cfg(target_os = "linux")]
impl CurrentPreparedNamedVerifierAssertion<'_, '_, '_> {
    pub fn check_current(&self) -> Result<()> {
        self.owner.check_current()
    }
    pub fn check_local_current(&self) -> Result<()> {
        self.owner.check_local_current()
    }
    pub fn statement(&self) -> &NamedVerifierStatementV1 {
        self.prepared.statement()
    }
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        self.check_current()?;
        self.prepared.signing_message()
    }
    pub fn recipient_artifact(&self) -> Result<&CanonicalLayoutArtifact> {
        self.check_current()?;
        Ok(self.prepared.recipient_artifact())
    }
}
