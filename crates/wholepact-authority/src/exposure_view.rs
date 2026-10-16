//! Accounting-only projection across purpose-distinct reservation origins.
//! This is not a financial permit view and never grants dispatch, resolution,
//! authorization or key use. Construction inputs have no fabricated action index.
use crate::{InputReservation, MutationResult, reservation_view::ReservationView};
use wholepact_core::manual_construction::ManualConstructionInput;
pub(crate) struct ExposureInput<'a> {
    pub(crate) input_id: &'a str,
    pub(crate) nullifier: &'a str,
    pub(crate) value_zatoshis: u64,
}
#[derive(Clone, Copy)]
enum Inputs<'a> {
    Financial(&'a [InputReservation]),
    Construction(&'a [ManualConstructionInput]),
}
pub(crate) struct ExposureView<'a> {
    pub(crate) obligation_id: &'a str,
    pub(crate) maximum_debit_zatoshis: u64,
    pub(crate) financial_resolution_allowed: bool,
    inputs: Inputs<'a>,
}
impl<'a> ExposureView<'a> {
    pub(crate) fn from_result(result: &'a MutationResult) -> Option<Self> {
        if let MutationResult::ConstructionTransportReservedV1(record) = result {
            return Some(Self {
                obligation_id: &record.original.request.enrollment().scope.obligation_id,
                maximum_debit_zatoshis: record.original.reserved_debit_zatoshis,
                financial_resolution_allowed: false,
                inputs: Inputs::Construction(record.original.request.selected_inputs()),
            });
        }
        if let MutationResult::ManualRosterConstructionReservedV3(record) = result {
            return Some(Self {
                obligation_id: &record.request.enrollment().scope.obligation_id,
                maximum_debit_zatoshis: record.reserved_debit_zatoshis,
                financial_resolution_allowed: false,
                inputs: Inputs::Construction(record.request.selected_inputs()),
            });
        }
        if let MutationResult::ManualRosterConstructionReservedV2(record) = result {
            return Some(Self {
                obligation_id: &record.request.enrollment().scope.obligation_id,
                maximum_debit_zatoshis: record.reserved_debit_zatoshis,
                financial_resolution_allowed: false,
                inputs: Inputs::Construction(record.request.selected_inputs()),
            });
        }
        ReservationView::from_result(result).map(|p| Self {
            obligation_id: p.obligation_id,
            maximum_debit_zatoshis: p.maximum_debit_zatoshis,
            financial_resolution_allowed: true,
            inputs: Inputs::Financial(p.inputs),
        })
    }
    pub(crate) fn inputs(&self) -> impl Iterator<Item = ExposureInput<'a>> {
        let (financial, construction) = match self.inputs {
            Inputs::Financial(v) => (v, &[][..]),
            Inputs::Construction(v) => (&[][..], v),
        };
        financial
            .iter()
            .map(|i| ExposureInput {
                input_id: &i.input_id,
                nullifier: &i.nullifier,
                value_zatoshis: i.value_zatoshis,
            })
            .chain(construction.iter().map(|i| ExposureInput {
                input_id: &i.input_id,
                nullifier: &i.nullifier,
                value_zatoshis: i.value_zatoshis,
            }))
    }
}

impl crate::policy::Ledger {
    /// Shared by online, offline (including automated origins) and construction
    /// reservation. This is pure data validation, not a grant or native issuer.
    pub(crate) fn check_input_obligation_exclusions<'a>(
        &self,
        obligation: &str,
        inputs: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> crate::Result<()> {
        if self.obligations.contains(obligation) {
            return Err(crate::AuthorityError::ObligationReserved);
        }
        for (id, nullifier) in inputs {
            if self.input_ids.contains(id) || self.nullifiers.contains(nullifier) {
                return Err(crate::AuthorityError::InputReserved);
            }
        }
        Ok(())
    }
}
