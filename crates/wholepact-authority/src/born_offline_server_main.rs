//! Operator launch only. No setup, persistent credential generation or fallback.
fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!(
            "Born witness stopped. No successful mutation is implied; recover exact originals."
        )
    }));
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!(
            "Usage: wholepact-born-offline-witness --check CONFIG.json\n       wholepact-born-offline-witness --serve CONFIG.json\nExisting native schema7 namespace and protected TLS/keys only. No setup or generation.\nConfig and TLS inputs require private regular single-link files under private directories.\nDefault listener: 127.0.0.1:18556; explicit bind must match the retained namespace exactly.\nTLS1.3 mutual authentication is mandatory. Stop the foreground process to stop serving."
        );
        return;
    }
    if args.len() != 2 || (args[0] != "--check" && args[0] != "--serve") {
        eprintln!(
            "Use --help. Only an explicit --check or --serve with one protected config file is supported."
        );
        std::process::exit(2);
    }
    #[cfg(target_os = "linux")]
    {
        let result = if args[0] == "--check" {
            wholepact_authority::born_offline_server_launcher_v1::check_existing_born_offline_server_v1(std::path::Path::new(&args[1]))
        } else {
            wholepact_authority::born_offline_server_launcher_v1::serve_existing_born_offline_server_v1(std::path::Path::new(&args[1]))
        };
        if result.is_err() {
            eprintln!(
                "Born witness unavailable: existing protected files, exact native namespace/pins, supported schema and mTLS configuration are required. No replacement or reset was attempted."
            );
            std::process::exit(1);
        }
        if args[0] == "--check" {
            println!(
                "Existing protected born witness configuration validated. No listener started and no setup performed."
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Born witness execution requires the supported Linux native namespace owner.");
        std::process::exit(2);
    }
}
