//! Private fixed-fork entry: the bootstrap profile is inert; the separate opt-in
//! profile adds actual Witness preparation and C-only display/disposal, never
//! financial approval. Neither has a public worker entry. Initial native launch
//! must be trusted, credential-free and uninjected; image checks cannot undo
//! earlier loader injection.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(all(wholepact_bootstrap_ci, feature = "cancel-only-witness-review"))]
compile_error!("Bootstrap-only CI instrumentation cannot select the source-opening UI profile");

#[cfg(all(target_os = "linux", wholepact_bootstrap_ci))]
mod ci;
#[cfg(target_os = "linux")]
mod bootstrap;
#[cfg(target_os = "linux")]
mod channel;
#[cfg(target_os = "linux")]
mod image;
#[cfg(target_os = "linux")]
mod process;
#[cfg(all(target_os = "linux", feature = "cancel-only-witness-review"))]
mod desktop_launch;
#[cfg(all(target_os = "linux", feature = "cancel-only-witness-review"))]
mod native_ui;
#[cfg(all(target_os = "linux", feature = "cancel-only-witness-review"))]
mod review_channel;
#[cfg(all(target_os = "linux", feature = "cancel-only-witness-review"))]
mod review_driver;
#[cfg(all(target_os = "linux", feature = "cancel-only-witness-review"))]
mod witness_role;

#[cfg(target_os = "linux")]
type Result<T> = std::io::Result<T>;
#[cfg(target_os = "linux")]
fn rejected(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

fn main() {
    // Do not move this into a library callable after threads or a GUI/runtime
    // have started. There is deliberately no externally selectable worker mode.
    #[cfg(target_os = "linux")]
    let code = match bootstrap::run_before_runtime() {
        Ok(()) => 78, // Bootstrap completed, but financial activation unavailable.
        Err(_) => 1,
    };
    #[cfg(not(target_os = "linux"))]
    let code = 78;
    #[cfg(all(target_os = "linux", wholepact_bootstrap_ci))]
    ci::finished(code);
    std::process::exit(code);
}
