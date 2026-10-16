//! Actual maintained-wallet input evidence for the candidate preparation phase.
//! This private owner retains source lifetime; it grants no builder, key-use,
//! witness reservation, transport or financial authority.
use super::{CommittedRosterImportTarget, FreshRosterPreliminaryWalletV2, Host};
use crate::{Error, Result};
use std::collections::BTreeSet;
use wholepact_core::manual_construction::{ManualConstructionInput, ManualSelectionContext};
use wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryScopeV2;
use wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerRosterCandidateSelectionLeaseV2;
use wholepact_store::manual_enrollment::ManualRosterCandidateLocalExclusionsV2;
use wholepact_wallet::wallet::protected_sync::ProtectedContribution;

/// Not Clone/Deserialize. No raw contribution escape is provided. The parent
/// selection module may create this only after its exact native selection gate.
pub(in crate::host) struct SelectedRosterCandidateInputsV2<'source, 'audit, 'host, 'store> {
    host: &'source Host,
    admission_deadline: std::time::Instant,
    fresh: &'source FreshRosterPreliminaryWalletV2,
    target: &'source CommittedRosterImportTarget<'audit, 'host>,
    inventory_scope: ManualRosterInventoryScopeV2,
    local_exclusions: &'source ManualRosterCandidateLocalExclusionsV2<'store>,
    selected: ProtectedContribution,
    selection_request_digest: String,
    account_id: String,
    requested_debit_zatoshis: u64,
    selected_zatoshis: u64,
    change_address: String,
    inputs: Vec<ManualConstructionInput>,
    context: ManualSelectionContext,
}
impl<'source, 'audit, 'host, 'store>
    SelectedRosterCandidateInputsV2<'source, 'audit, 'host, 'store>
{
    // Only the parent selection composition may mint this owner, immediately
    // after the genuine bridge's one-attempt selection and internal-change check.
    pub(super) fn capture(
        selected: ProtectedContribution,
        lease: &SignerRosterCandidateSelectionLeaseV2<'_>,
        source: super::RosterCandidateSourceV2<'source, 'audit, 'host, 'store>,
    ) -> Result<Self> {
        let super::RosterCandidateSourceV2 {
            host,
            admission_deadline,
            fresh,
            target,
            inventory_scope,
            local_exclusions: snapshot,
        } = source;
        fresh.check_current(host, &inventory_scope, target)?;
        let local_exclusions = host.engine.manual_roster_candidate_current_exclusions_v2(
            host.access()?,
            lease.request().map_err(|_| Error::Permission)?,
            snapshot,
        )?;
        lease.check_current().map_err(|_| Error::Permission)?;
        let request = lease.request().map_err(|_| Error::Permission)?;
        let selection_request_digest = request.digest().map_err(|_| Error::Invalid)?;
        let account_id = request
            .scope
            .selection
            .inventory
            .enrollment
            .identity
            .account_id
            .as_str();
        let requested_debit_zatoshis = lease
            .requested_debit_zatoshis()
            .map_err(|_| Error::Permission)?;
        let anchor_height = request.scope.selection.inventory.anchor_height;
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
        let result = Self {
            host,
            admission_deadline,
            fresh,
            target,
            inventory_scope,
            local_exclusions: snapshot,
            selected,
            selection_request_digest,
            account_id: account_id.into(),
            requested_debit_zatoshis,
            selected_zatoshis: total,
            change_address,
            inputs,
            context,
        };
        result.current_evidence(lease)?;
        Ok(result)
    }
    /// Exact native retention runs on this SAME live stream while every
    /// original Host/selection deadline still holds. The private handoff owns
    /// the actual selected contribution; no selected-data DTO becomes authority.
    pub(in crate::host) fn retain_for_sequential_collection<'retained>(
        self,
        host: &'retained Host,
        lease: SignerRosterCandidateSelectionLeaseV2<'_>,
        admission: super::super::retained_inputs::RosterContributionRetentionAdmissionV2,
    ) -> Result<super::super::retained_inputs::RetainedRosterInputHandoffV2<'retained>> {
        use super::super::retained_inputs::{
            RetainedRosterInputHandoffV2, RetainedRosterLocalOwnersV2, now_ms,
        };
        self.require_host(host)?;
        self.current_evidence(&lease)?;
        let request = lease.request().map_err(|_| Error::Permission)?;
        admission.check_selection(&request.scope)?;
        let local = RetainedRosterLocalOwnersV2::capture(
            host,
            self.target,
            &self.inventory_scope,
            &admission,
        )?;
        let exclusion_digest = self
            .host
            .engine
            .manual_roster_candidate_current_exclusions_v2(
                self.host.access()?,
                request,
                self.local_exclusions,
            )?
            .snapshot_digest()?;
        let now = now_ms()?;
        let remaining = admission
            .admission_deadline()
            .checked_duration_since(std::time::Instant::now())
            .ok_or(Error::Permission)?;
        let host_end = now
            .checked_add(u64::try_from(remaining.as_millis()).map_err(|_| Error::Invalid)?)
            .ok_or(Error::Invalid)?;
        let end = host_end.min(request.disclosure_expires_at_ms);
        let operation_id = admission.operation_id().to_owned();
        self.current_evidence(&lease)?;
        let pending = lease
            .begin_retention(
                self.selected,
                operation_id,
                exclusion_digest,
                now,
                end,
                admission.completion_deadline(),
            )
            .map_err(|_| Error::Permission)?;
        let retained = pending.finish().map_err(|_| Error::Permission)?;
        // The original live target is checked one last time at transition. Once
        // this succeeds, ONLY the explicit new retained owner may be used.
        self.fresh
            .check_current(self.host, &self.inventory_scope, self.target)?;
        self.host
            .engine
            .manual_roster_candidate_current_exclusions_v2(
                self.host.access()?,
                &retained.request().map_err(|_| Error::Permission)?.selection,
                self.local_exclusions,
            )?;
        RetainedRosterInputHandoffV2::finish(retained, local, admission)
    }

    pub(in crate::host::financial::manual_roster_inventory_setup_v2) fn require_host(
        &self,
        host: &Host,
    ) -> Result<()> {
        if !std::ptr::eq(host, self.host) {
            return Err(Error::Permission);
        }
        Ok(())
    }
    /// Fixed local display only. Every private field comes from the actual
    /// maintained selection and remains gated by the complete V2 request,
    /// original Host/native deadlines, real source, target and exclusion owner.
    /// No naked metadata DTO is exposed to the command layer.
    pub(in crate::host) fn display_current_evidence(
        &self,
        lease: &SignerRosterCandidateSelectionLeaseV2<'_>,
    ) -> Result<()> {
        let actual = self.current_evidence(lease)?;
        let value = serde_json::json!({
            "status": "unreviewed_actual_input_selection",
            "meaning": "One exact private contribution selection only. Single-provider observation is not independently verified unspentness or complete history. No full candidate, construction, reservation, proof, signature, release or spending authority exists. Exact inputs and authenticated same-account return still require later separate native construction review.",
            "account_id": actual.account_id,
            "requested_debit_zatoshis": actual.requested_debit_zatoshis,
            "selected_zatoshis": actual.selected_zatoshis,
            "same_account_return_address": actual.change_address,
            "inputs": actual.inputs,
            "selection_context": actual.context,
        });
        self.current_evidence(lease)?;
        self.host.terminal.json(&value)?;
        self.current_evidence(lease)?;
        Ok(())
    }
    /// Private metadata remains gated by the same actual native selection lease.
    /// This cannot authorize later construction or renew the original cutoff.
    pub(in crate::host::financial::manual_roster_inventory_setup_v2) fn current_evidence(
        &self,
        lease: &SignerRosterCandidateSelectionLeaseV2<'_>,
    ) -> Result<CurrentRosterCandidateInputEvidenceV2<'_>> {
        if std::time::Instant::now() >= self.admission_deadline {
            return Err(Error::Permission);
        }
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
        self.fresh
            .check_current(self.host, &self.inventory_scope, self.target)?;
        self.host
            .authority
            .check_financial_principal(&self.host.access()?.principal_id)?;
        self.host
            .engine
            .manual_roster_candidate_current_exclusions_v2(
                self.host.access()?,
                lease.request().map_err(|_| Error::Permission)?,
                self.local_exclusions,
            )?;
        self.selected
            .check_current()
            .map_err(|_| Error::Permission)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        Ok(CurrentRosterCandidateInputEvidenceV2 {
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
pub(in crate::host::financial::manual_roster_inventory_setup_v2) struct CurrentRosterCandidateInputEvidenceV2<
    'a,
> {
    pub(in crate::host::financial::manual_roster_inventory_setup_v2) account_id: &'a str,
    pub(in crate::host::financial::manual_roster_inventory_setup_v2) requested_debit_zatoshis: u64,
    pub(in crate::host::financial::manual_roster_inventory_setup_v2) selected_zatoshis: u64,
    pub(in crate::host::financial::manual_roster_inventory_setup_v2) change_address: &'a str,
    pub(in crate::host::financial::manual_roster_inventory_setup_v2) inputs:
        &'a [ManualConstructionInput],
    pub(in crate::host::financial::manual_roster_inventory_setup_v2) context:
        &'a ManualSelectionContext,
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
