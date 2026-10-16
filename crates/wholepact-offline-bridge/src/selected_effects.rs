//! Connected evidence-only inspection/report path. No offline setup or issuer
//! factory is opened. An attested assurance choice is neither inferred nor made.
use wholepact_protocol::own_effects::{OwnEffectsInspection, OwnEffectsPolicy, verify_own_effects};
use wholepact_transport::TransportError;

/// Opaque local inspection and fixed fact classification, not native consent.
pub struct SelectedOfflineEffectsReport {
    inspection: OwnEffectsInspection,
    display: String,
}
impl SelectedOfflineEffectsReport {
    pub fn inspection(&self) -> &OwnEffectsInspection {
        &self.inspection
    }
    pub fn display(&self) -> &str {
        &self.display
    }
}
fn display(inspection: &OwnEffectsInspection) -> String {
    format!(
        "SELECTED OWN EFFECTS ONLY — NO SPENDING AUTHORITY\nIndependently checked against retained local expectations:\nExact artifact: {}\nPolicy commitment: {}\nEffects sighash: {}\nSelected own inputs: {}\nSelected own net debit: {} zatoshis\nOwn return: {} zatoshis\nTransaction fee arithmetic: {} zatoshis\nDeclared only: fee allocation {} zatoshis (not independently attributed across owners).\nAttested facts: none; no named-verifier assurance mode is active.\nUnknown: peer input ownership, peer return ownership/allocation, matching eligibility, completeness of own-controlled inputs, full-account exposure, transaction proof validity, canonical chain/anchor, current unspentness/mempool, chain-context age, remote revocation, disconnected clone activity and globally unique key use.\nThis report authenticates no enrollment, person, source, reservation or consent. Do not sign, release exposure or dispatch based on this report.\n",
        inspection.artifact_digest(),
        inspection.policy_digest(),
        inspection.shielded_sighash(),
        inspection.own_action_indices().len(),
        inspection.selected_net_debit_zatoshis(),
        inspection.own_return_zatoshis(),
        inspection.transaction_fee_zatoshis(),
        inspection.declared_fee_share_zatoshis()
    )
}
/// Actual selected-effects verifier produces the report; caller booleans or
/// imported success/attestation DTOs cannot populate independently checked facts.
pub fn inspect_selected_offline_effects(
    bytes: &[u8],
    policy: &OwnEffectsPolicy,
) -> Result<SelectedOfflineEffectsReport, TransportError> {
    let inspection =
        verify_own_effects(bytes, policy).map_err(|_| TransportError::Authentication)?;
    let display = display(&inspection);
    Ok(SelectedOfflineEffectsReport {
        inspection,
        display,
    })
}

/// Verify a returned artifact against the exact locally inspected bytes and
/// retained producer transformation. This is evidence only; current online
/// authority, proof validity, consent and complete ownership remain separate.
pub fn inspect_selected_offline_return(
    reviewed: &[u8],
    returned: &[u8],
    report: &SelectedOfflineEffectsReport,
    transformation: &wholepact_protocol::canonical_role_layout::LayoutTransformation,
) -> Result<wholepact_protocol::offline_return::OpaqueVerifiedReturn, TransportError> {
    wholepact_protocol::offline_return::inspect_exact_own_signature_return_with_layout(
        reviewed,
        returned,
        report.inspection(),
        transformation,
    )
    .map_err(|_| TransportError::Authentication)
}
