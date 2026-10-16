//! Separate no-argument owner launcher; not an authority-server or signer mode.
fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("Witness owner review stopped. Pending local approval was discarded.");
    }));
    #[cfg(target_os = "linux")]
    if let Err(error) = wholepact_authority::native_witness_owner::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("The independent witness-owner review requires Linux Wayland.");
        std::process::exit(1);
    }
}
