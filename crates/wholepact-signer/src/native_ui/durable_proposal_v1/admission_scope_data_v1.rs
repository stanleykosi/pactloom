//! Pure exact-scope data projection shared by separately authorized consumers.
//! No source read, grant, history access, journal mutation or completion owner.
use super::*;
use wholepact_authority::durable_payment_v1::DurableFixedCandidateBindingV1;

pub(crate) fn fixed_inputs(
    economics: &VerifiedDurableEconomicsV1,
    account: &str,
) -> Result<(
    DurableFixedCandidateBindingV1,
    Vec<wholepact_authority::InputReservation>,
)> {
    let fixed = economics.verified();
    let fixed_binding: DurableFixedCandidateBindingV1 = wholepact_core::parse_typed_json(
        &serde_json::to_vec(fixed.identity()).map_err(|_| Error::InvalidData)?,
    )
    .map_err(|_| Error::InvalidData)?;
    let inputs = economics
        .input_actions()
        .iter()
        .filter(|i| i.account_id == account)
        .map(|map| {
            let input = fixed
                .private_review_policy()
                .inputs
                .iter()
                .find(|i| i.action_index == map.action_index)
                .ok_or(Error::ReviewMismatch)?;
            Ok(wholepact_authority::InputReservation {
                input_id: map.input_id.clone(),
                nullifier: hex::encode(input.nullifier),
                action_index: map.action_index as u64,
                value_zatoshis: input.value_zatoshis,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((fixed_binding, inputs))
}

/// Maintained pure scope assembly and full original-claim equality. Callers
/// authenticate source/history independently before supplying these values.
#[allow(clippy::too_many_arguments)]
pub(crate) fn scope(
    terms: wholepact_authority::durable_payment_v1::DurablePaymentAdmissionTermsV1,
    extension: &wholepact_authority::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    history: &wholepact_authority::ReconciledAuthorityHistory,
    economics: &VerifiedDurableEconomicsV1,
    fixed_binding: &DurableFixedCandidateBindingV1,
    inputs: &[wholepact_authority::InputReservation],
    manifest_ref: &str,
    witness: &wholepact_authority::WitnessDisclosureDescriptor,
    delivery: &wholepact_authority::durable_delivery_scope_v2::DurableDeliveryPlanV2,
    materials: &[wholepact_authority::durable_delivery_scope_v2::DurableDeliveryMaterialScopeRefV2],
) -> Result<wholepact_authority::durable_delivery_scope_v2::DurableDeliveryScopeV2> {
    use wholepact_authority::durable_delivery_scope_v2::*;
    let old = &extension.account_extension;
    let scope = DurableDeliveryScopeV2 {
        version: 2, accepted_manifest_ref: manifest_ref.into(),
        original_writer_epoch: old.terms.signer.writer_epoch,
        original_ceilings: DurableDeliveryOriginalCeilingsV2 {
            payment_valid_from_ms: terms.valid_from_ms,
            payment_valid_until_ms: terms.valid_until_ms,
            enrollment_expires_at_ms: old.terms.scope.expires_at_ms,
            policy_expires_at_ms: history.account_policy().policy_expires_at_ms,
            material_scopes: materials.to_vec(),
        },
        authorization: terms, delivery: delivery.clone(), witness: witness.clone(),
        disclosure_rule: DurableDeliveryDisclosureRuleV2::WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness,
    };
    scope
        .matches_original_claims(
            history.account_policy(),
            extension,
            economics.proposal(),
            fixed_binding,
            manifest_ref,
            old.terms.signer.writer_epoch,
            witness,
            inputs,
            materials,
        )
        .map_err(|_| Error::ReviewMismatch)?;
    Ok(scope)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn terms(
    extension: &wholepact_authority::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    economics: &VerifiedDurableEconomicsV1,
    account: &str,
    genesis_digest: String,
    recipient_policy_scope_digest: String,
    fixed_binding: &DurableFixedCandidateBindingV1,
    inputs: &[wholepact_authority::InputReservation],
    delivery: &wholepact_authority::durable_delivery_scope_v2::DurableDeliveryPlanV2,
) -> Result<wholepact_authority::durable_payment_v1::DurablePaymentAdmissionTermsV1> {
    use wholepact_authority::durable_payment_v1::DurablePaymentAdmissionTermsV1;
    let old = &extension.account_extension;
    let fixed = economics.verified();
    let proposal = economics.proposal();
    let owner = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == account)
        .ok_or(Error::ReviewMismatch)?;
    let terms = DurablePaymentAdmissionTermsV1 {
        version: 1,
        identity: old.terms.identity.clone(),
        original_policy_digest: old.terms.original_policy_digest.clone(),
        original_genesis_digest: genesis_digest,
        original_birth_commit_digest: old.terms.birth_commit_digest.clone(),
        original_roster_extension_digest: extension.digest().map_err(|_| Error::ReviewMismatch)?,
        original_enrollment_ref: old.enrollment_ref.clone(),
        writer_certificate_digest: old.terms.signer.writer_certificate_digest.clone(),
        fixed: fixed_binding.clone(),
        authorization_id: crate::authority_bridge::durable_proposal_v1::manual_authorization_id(
            fixed.identity(),
            &account,
        )
        .map_err(|_| Error::ReviewMismatch)?,
        recipient_policy_scope_digest,
        concrete_recipient_scope_digest:
            wholepact_core::manual_construction::construction_recipient_scope_digest(proposal)
                .map_err(|_| Error::ReviewMismatch)?,
        inputs: inputs.to_vec(),
        maximum_debit_zatoshis: proposal
            .accounting()
            .participant_net_debits
            .get(&owner.participant_id)
            .ok_or(Error::ReviewMismatch)?
            .as_zatoshis(),
        fee_share_zatoshis: owner.fee_share.as_zatoshis(),
        transaction_fee_zatoshis: proposal.manifest().transaction_fee.as_zatoshis(),
        valid_from_ms: delivery.valid_from_ms,
        valid_until_ms: delivery.valid_until_ms,
    };
    terms.validate().map_err(|_| Error::ReviewMismatch)?;
    Ok(terms)
}
