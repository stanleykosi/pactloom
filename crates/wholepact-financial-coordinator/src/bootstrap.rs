//! Private whole-image entry composition. The origin crate owns all actual
//! forks, exact lifetimes and finite frames; GUI/source adapters remain in this
//! pinned binary. Nothing here is a public role entry or financial issuer.
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
            #[cfg(not(feature = "cancel-only-witness-review"))]
            { origin.finish_inert() }
        }
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
