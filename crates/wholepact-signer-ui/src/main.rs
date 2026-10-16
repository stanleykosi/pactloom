//! No IPC, CLI argument, stdin, browser event or exported action approves anything.
fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("Wholepact signer stopped. Pending approvals were discarded.");
    }));
    #[cfg(target_os = "linux")]
    if let Err(error) = wholepact_signer::native_ui::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "This signer window profile requires Linux Wayland; this platform is not qualified."
        );
        std::process::exit(1);
    }
}
