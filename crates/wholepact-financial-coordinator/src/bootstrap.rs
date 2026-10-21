//! Private whole-image entry composition. The origin crate owns all actual
//! forks, exact lifetimes and finite frames; GUI/source adapters remain in this
//! pinned binary. The positive native issuer is private to this whole pinned image; nothing
//! here is a public role entry or caller-claimed origin.
use crate::Result;
use wholepact_financial_coordinator_origin::{bootstrap_common_image_v1, BootstrappedRoleV1};
#[cfg(feature = "cancel-only-witness-review")]
pub(super) use wholepact_financial_coordinator_origin::CoordinatorCancelOriginV1 as InertTreeV1;

pub(super) fn run_before_runtime() -> Result<()> {
    match bootstrap_common_image_v1()? {
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
            #[cfg(not(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append")))]
            { origin.finish_inert() }
        }
        #[cfg(feature = "coordinated-witness-delivery-append")]
        BootstrappedRoleV1::WitnessDelivery(origin) => wholepact_authority::native_witness_owner::coordinated_delivery_append_v1::run_witness_delivery_once_v1(origin),
        BootstrappedRoleV1::Host(origin) => origin.run_until_stop(),
        BootstrappedRoleV1::Signer(origin) => origin.run_until_stop(),
        BootstrappedRoleV1::InertWitness(origin) => origin.run_until_stop(),
        #[cfg(feature = "cancel-only-witness-review")]
        BootstrappedRoleV1::CancelOnlyWitness(origin) => {
            let deadline = origin.session_deadline();
            let result = crate::witness_role::run_cancel_only(&origin, deadline);
            origin.complete(result)
        }
    }
}
