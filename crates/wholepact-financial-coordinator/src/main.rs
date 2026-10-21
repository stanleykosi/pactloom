//! Private exact-image fixed-fork entry. Separate closed profiles provide inert
//! bootstrap, cancel-only preparation, or one exact source-backed delivery append.
//! Initial launch is trusted, credential-free and uninjected; no public worker
//! entry, source factory or reusable financial approval is accepted.
#![forbid(unsafe_code)]
#[cfg(all(wholepact_bootstrap_ci, any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append")))]
compile_error!("Bootstrap-only CI instrumentation cannot select the source-opening UI profile");

#[cfg(all(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
compile_error!("Cancel-only and one-exact-append are separate common-image profiles");
#[cfg(all(feature = "coordinated-financial-runtime", any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append", wholepact_bootstrap_ci, wholepact_delivery_ci)))]
compile_error!("Financial runtime is separate from narrow and instrumented qualification profiles");
#[cfg(target_os = "linux")]
mod bootstrap;
#[cfg(all(target_os = "linux", feature = "coordinated-witness-delivery-append"))]
mod delivery_driver;
#[cfg(all(target_os = "linux", feature = "coordinated-witness-delivery-append"))]
mod delivery_ui;
#[cfg(all(target_os = "linux", feature = "coordinated-financial-source-ui"))]
mod financial_source_driver;
#[cfg(all(target_os = "linux", feature = "coordinated-financial-source-ui"))]
mod financial_source_ui;
#[cfg(all(target_os = "linux", feature = "coordinated-financial-source-ui"))]
mod financial_completed_pair_ui;
#[cfg(all(target_os = "linux", feature = "coordinated-financial-source-ui"))]
mod host_line_input;
#[cfg(all(target_os = "linux", feature = "coordinated-financial-source-ui"))]
mod host_output_text;
#[cfg(all(target_os = "linux", feature = "cancel-only-witness-review"))]
mod native_ui;
#[cfg(all(target_os = "linux", feature = "cancel-only-witness-review"))]
mod review_channel;
#[cfg(all(target_os = "linux", feature = "cancel-only-witness-review"))]
mod review_driver;
#[cfg(all(target_os = "linux", feature = "coordinator-transient-password-input"))]
mod secret_input;
#[cfg(all(target_os = "linux", feature = "cancel-only-witness-review"))]
mod witness_role;

#[cfg(target_os = "linux")]
type Result<T> = std::io::Result<T>;
#[cfg(target_os = "linux")]
fn rejected(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

fn main() {
    // This private main invokes the argument-free whole-image kernel before
    // any thread-capable initialization. No public worker/role entry exists.
    #[cfg(target_os = "linux")]
    let code = match bootstrap::run_before_runtime() {
        Ok(()) => {
            #[cfg(feature = "coordinated-witness-delivery-append")] { 0 }
            #[cfg(not(feature = "coordinated-witness-delivery-append"))] { 78 }
        },
        Err(_) => 1,
    };
    #[cfg(not(target_os = "linux"))]
    let code = 78;
    #[cfg(all(target_os = "linux", wholepact_bootstrap_ci))]
    wholepact_financial_coordinator_origin::record_process_exit_for_ci(code);
    #[cfg(all(target_os = "linux", wholepact_delivery_ci))]
    wholepact_financial_coordinator_origin::finish_delivery_observation_for_ci(code);
    std::process::exit(code);
}
