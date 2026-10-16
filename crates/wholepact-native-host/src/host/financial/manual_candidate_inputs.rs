//! Actual maintained-wallet input evidence for the candidate preparation phase.
//! This private owner retains source lifetime; it grants no builder, key-use,
//! witness reservation, transport or financial authority.
use crate::{Error, Result};
use std::collections::BTreeSet;
use wholepact_core::manual_construction::{ManualConstructionInput, ManualSelectionContext};
use wholepact_signer::authority_bridge::manual_candidate_selection::SignerCandidateSelectionLease;
use wholepact_wallet::wallet::protected_sync::ProtectedContribution;

/// Not Clone/Deserialize. No raw contribution escape is provided. The parent
/// selection module may create this only after its exact native selection gate.
pub(in crate::host) struct SelectedCandidateInputs {
    selected: ProtectedContribution,
    selection_request_digest: String,
    account_id: String,
    requested_debit_zatoshis: u64,
    selected_zatoshis: u64,
    change_address: String,
    inputs: Vec<ManualConstructionInput>,
    context: ManualSelectionContext,
}
impl SelectedCandidateInputs {
    // Only the parent selection composition may mint this owner, immediately
    // after the genuine bridge's one-attempt selection and internal-change check.
    pub(super) fn capture(
        selected: ProtectedContribution,
        lease: &SignerCandidateSelectionLease<'_>,
        local_exclusions: &wholepact_store::financial_preflight::RetainedInputExclusions,
    ) -> Result<Self> {
        lease.check_current().map_err(|_| Error::Permission)?;
        let request = lease.request().map_err(|_| Error::Permission)?;
        let selection_request_digest = request.digest().map_err(|_| Error::Invalid)?;
        let account_id = request
            .scope
            .inventory
            .enrollment
            .identity
            .account_id
            .as_str();
        let requested_debit_zatoshis = lease
            .requested_debit_zatoshis()
            .map_err(|_| Error::Permission)?;
        let anchor_height = request.scope.inventory.anchor_height;
        selected.check_current().map_err(|_| Error::Permission)?;
        let wallet = selected.selection();
        if wallet.account_id() != account_id
            || wallet.requested_debit_zatoshis() != requested_debit_zatoshis
            || requested_debit_zatoshis == 0
            || wallet.context().anchor_height != anchor_height
            || wallet.fvk().to_bytes() != lease.fvk().map_err(|_| Error::Permission)?.to_bytes()
        {
            return Err(Error::Permission);
        }
        let observed = wallet.evidence();
        if observed.account_id() != account_id
            || observed.inputs().len() != wallet.local_note_refs().len()
        {
            return Err(Error::Permission);
        }
        // Actual local snapshot only; absence is not complete external history.
        // The final witness reservation must independently union/recheck all
        // current and inherited obligations on the original account ledger.
        if local_exclusions.account_id() != account_id
            || observed.inputs().iter().any(|input| {
                local_exclusions.excludes(input.input_id(), &hex::encode(input.nullifier()))
            })
        {
            return Err(Error::Permission);
        }
        let mut inputs: Vec<_> = observed
            .inputs()
            .iter()
            .map(|input| ManualConstructionInput {
                input_id: input.input_id().to_owned(),
                nullifier: hex::encode(input.nullifier()),
                value_zatoshis: input.value_zatoshis(),
            })
            .collect();
        inputs.sort_by(|a, b| a.input_id.cmp(&b.input_id));
        let total = validate_observed_inputs(&inputs, requested_debit_zatoshis)?;
        if total != wallet.selected_zatoshis() {
            return Err(Error::Permission);
        }
        let actual = observed.context();
        if actual != wallet.context() || actual.tip_height < actual.anchor_height {
            return Err(Error::Permission);
        }
        let context = ManualSelectionContext {
            tip_height: actual.tip_height,
            tip_hash_protocol: hex::encode(actual.tip_hash_protocol),
            anchor_height: actual.anchor_height,
            anchor_hash_protocol: hex::encode(actual.anchor_hash_protocol),
            anchor_root: hex::encode(actual.anchor_root),
        };
        // This address comes from the maintained selection, whose same-account
        // Internal scope the bridge checked against its authenticated FVK. Never
        // substitute caller text, a claimed return or a freshly guessed address.
        let change_address =
            wholepact_protocol::review::encode_testnet_receiver(&wallet.change_address());
        selected.check_current().map_err(|_| Error::Permission)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        Ok(Self {
            selected,
            selection_request_digest,
            account_id: account_id.into(),
            requested_debit_zatoshis,
            selected_zatoshis: total,
            change_address,
            inputs,
            context,
        })
    }
    /// Private metadata remains gated by the same actual native selection lease.
    /// This cannot authorize later construction or renew the original cutoff.
    pub(in crate::host) fn current_evidence(
        &self,
        lease: &SignerCandidateSelectionLease<'_>,
    ) -> Result<CurrentCandidateInputEvidence<'_>> {
        lease.check_current().map_err(|_| Error::Permission)?;
        if lease
            .request()
            .map_err(|_| Error::Permission)?
            .digest()
            .map_err(|_| Error::Invalid)?
            != self.selection_request_digest
        {
            return Err(Error::Permission);
        }
        self.selected
            .check_current()
            .map_err(|_| Error::Permission)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        Ok(CurrentCandidateInputEvidence {
            account_id: &self.account_id,
            requested_debit_zatoshis: self.requested_debit_zatoshis,
            selected_zatoshis: self.selected_zatoshis,
            change_address: &self.change_address,
            inputs: &self.inputs,
            context: &self.context,
        })
    }
}
/// Borrowed inert metadata only. Its producer always checks both the original
/// native lease and the maintained source lifetime. This is neither an input
/// reservation nor any authority to construct, retain witnesses or spend.
pub(in crate::host) struct CurrentCandidateInputEvidence<'a> {
    pub(in crate::host) account_id: &'a str,
    pub(in crate::host) requested_debit_zatoshis: u64,
    pub(in crate::host) selected_zatoshis: u64,
    pub(in crate::host) change_address: &'a str,
    pub(in crate::host) inputs: &'a [ManualConstructionInput],
    pub(in crate::host) context: &'a ManualSelectionContext,
}
fn validate_observed_inputs(inputs: &[ManualConstructionInput], debit: u64) -> Result<u64> {
    if inputs.is_empty() || inputs.len() > 256 || debit == 0 || debit > wholepact_core::MAX_MONEY {
        return Err(Error::Invalid);
    }
    let mut previous = None;
    let mut nullifiers = BTreeSet::new();
    let mut total = 0u64;
    for input in inputs {
        if input.input_id.is_empty()
            || input.input_id.len() > 256
            || input.input_id.chars().any(char::is_control)
            || previous.is_some_and(|old: &str| old >= input.input_id.as_str())
            || input.nullifier.len() != 64
            || !input
                .nullifier
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !nullifiers.insert(input.nullifier.as_str())
            || input.value_zatoshis == 0
        {
            return Err(Error::Invalid);
        }
        total = total
            .checked_add(input.value_zatoshis)
            .filter(|v| *v <= wholepact_core::MAX_MONEY)
            .ok_or(Error::Invalid)?;
        previous = Some(input.input_id.as_str());
    }
    if total < debit {
        return Err(Error::Invalid);
    }
    Ok(total)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input(id: &str, nullifier: char, value: u64) -> ManualConstructionInput {
        ManualConstructionInput {
            input_id: id.into(),
            nullifier: nullifier.to_string().repeat(64),
            value_zatoshis: value,
        }
    }
    #[test]
    fn observed_input_arithmetic_rejects_duplicates_and_shortfall() {
        let inputs = vec![input("a", 'a', 60), input("b", 'b', 40)];
        assert_eq!(validate_observed_inputs(&inputs, 90).unwrap(), 100);
        assert!(validate_observed_inputs(&inputs, 101).is_err());
        assert!(validate_observed_inputs(&[input("a", 'a', 60), input("a", 'b', 40)], 90).is_err());
        assert!(validate_observed_inputs(&[input("a", 'a', 60), input("b", 'a', 40)], 90).is_err());
    }
    #[test]
    fn observed_input_validation_rejects_noncanonical_and_overflow() {
        assert!(validate_observed_inputs(&[input("a", 'A', 60)], 40).is_err());
        assert!(
            validate_observed_inputs(
                &[
                    input("a", 'a', wholepact_core::MAX_MONEY),
                    input("b", 'b', 1)
                ],
                1
            )
            .is_err()
        );
        assert!(validate_observed_inputs(&[], 1).is_err());
    }
}
