//! Private whole-image entry composition. The origin crate owns all actual
//! forks, exact lifetimes and finite frames; GUI/source adapters remain in this
//! pinned binary. The positive native issuer is private to this whole pinned image; nothing
//! here is a public role entry or caller-claimed origin.
use crate::Result;
use wholepact_financial_coordinator_origin::{bootstrap_common_image_v1, BootstrappedRoleV1};
#[cfg(feature = "cancel-only-witness-review")]
pub(super) use wholepact_financial_coordinator_origin::CoordinatorCancelOriginV1 as InertTreeV1;

#[cfg(feature = "coordinated-financial-runtime")]
type Completion = bool;
#[cfg(not(feature = "coordinated-financial-runtime"))]
type Completion = ();
// Existing construction result only; owned failure cleanup already returned.
// No new input, retry, original-actor discovery, or authority is introduced.
fn observed_initialization<T>(result: Result<T>) -> Result<T> {
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    if let Err(error)=&result {
        use wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::{work_fallback,DriverStage};
        work_fallback(DriverStage::Initialization,error);
        wholepact_financial_coordinator_origin::financial_ci_flush_actor_diagnostics();
    }
    result
}
pub(super) fn run_before_runtime() -> Result<Completion> {
    match observed_initialization(bootstrap_common_image_v1())? {
        BootstrappedRoleV1::Coordinator(origin) => {
            #[cfg(feature = "cancel-only-witness-review")]
            {
                let tree = origin.into_cancel_review()?;
                let deadline = tree.session_deadline();
                crate::native_ui::run(tree, deadline)
            }
            #[cfg(feature = "coordinated-witness-delivery-append")]
            {
                let (native, endpoint) = origin.into_delivery_review()?;
                crate::delivery_ui::run(native, endpoint)
            }
            #[cfg(feature = "coordinated-financial-runtime")]
            {
                let (native, endpoint) = observed_initialization(origin.into_financial_workflow())?;
                let result = crate::financial_source_ui::run(native, endpoint);
                #[cfg(wholepact_financial_rendered_host_semantic_ci)]
                {
                    wholepact_financial_coordinator_origin::financial_ci_flush_failure_boundaries();
                    wholepact_financial_coordinator_origin::financial_ci_flush_host_diagnostics();
                    if let Err(error) = &result {
                        use wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::{work_fallback,DriverStage};
                        work_fallback(DriverStage::WorkUnclassified,error);
                    }
                    wholepact_financial_coordinator_origin::financial_ci_flush_actor_diagnostics();
                }
                result
            }
            #[cfg(not(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append", feature = "coordinated-financial-runtime")))]
            { origin.finish_inert() }
        }
        #[cfg(feature = "coordinated-witness-delivery-append")]
        BootstrappedRoleV1::WitnessDelivery(origin) => wholepact_authority::native_witness_owner::coordinated_delivery_append_v1::run_witness_delivery_once_v1(origin),
        #[cfg(feature = "coordinated-financial-runtime")]
        BootstrappedRoleV1::Host(origin) => {
            let result=wholepact_native_host::run_coordinated_financial_host_v1(origin);
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            {
                if let Err(error)=&result {
                    use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::{latch_failure,Stage,classify_io};
                    // Only a truthful fallback if the finer native stage did not latch.
                    latch_failure(Stage::RunnerReturn,classify_io(error.kind()));
                }
                wholepact_financial_coordinator_origin::financial_ci_flush_host_diagnostics();
                if let Err(error) = &result {
                    use wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::{work_fallback,DriverStage};
                    work_fallback(DriverStage::WorkUnclassified,error);
                }
                wholepact_financial_coordinator_origin::financial_ci_flush_actor_diagnostics();
            }
            result.map(|()|true)
        },
        #[cfg(not(feature = "coordinated-financial-runtime"))]
        BootstrappedRoleV1::Host(origin) => origin.run_until_stop(),
        #[cfg(feature = "coordinated-financial-runtime")]
        BootstrappedRoleV1::Signer(origin) => wholepact_signer::native_ui::run_coordinated_financial_signer_v1(origin),
        #[cfg(not(feature = "coordinated-financial-runtime"))]
        BootstrappedRoleV1::Signer(origin) => origin.run_until_stop(),
        #[cfg(feature = "coordinated-financial-runtime")]
        BootstrappedRoleV1::InertWitness(origin) => {
            use wholepact_financial_coordinator_origin::FinancialWitnessPurposeV1 as Purpose;
            match observed_initialization(origin.into_financial_purpose())? {
                Purpose::RetainedInert(owner) => owner.run_until_stop(),
                Purpose::InitialHistory(owner) => wholepact_authority::transport::run_coordinated_initial_history_v1(owner),
                Purpose::Continuation(owner) => wholepact_authority::native_witness_owner::coordinated_financial_continuation_v1::run_witness_financial_continuation_once_v1(owner),
                Purpose::Signing(owner) => wholepact_authority::transport::run_coordinated_financial_signing_v1(owner),
                Purpose::CompletedPair(owner) => wholepact_authority::transport::run_coordinated_completed_pair_v1(owner),
            }
        }
        #[cfg(not(feature = "coordinated-financial-runtime"))]
        BootstrappedRoleV1::InertWitness(origin) => origin.run_until_stop(),
        #[cfg(feature = "cancel-only-witness-review")]
        BootstrappedRoleV1::CancelOnlyWitness(origin) => {
            let deadline = origin.session_deadline();
            let result = crate::witness_role::run_cancel_only(&origin, deadline);
            origin.complete(result)
        }
    }
}
