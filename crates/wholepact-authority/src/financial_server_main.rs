//! Foreground existing-only financial Witness operator entrypoint.
fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!(
            "Financial witness stopped. No successful mutation is implied; reconcile exact originals."
        )
    }));
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!(
            "Usage: wholepact-financial-witness --check MODE CONFIG.json\n       wholepact-financial-witness --serve MODE CONFIG.json\nModes: financial-signing-v1, completed-dispatch-v1, completed-dispatch-pair-v1.\n--check validates protected configuration, TLS and selector shape only. It does not authenticate committed state or establish availability/eligibility.\n--serve opens the exact existing native namespace and committed continuation before binding its exact retained endpoint.\nConfig: version=1, explicit listen, originals=[{{namespace_file, continuation_operation_id}}], tls={{trusted_client_roots_der, server_chain_der, server_private_key_pkcs8_der}}.\nSingle modes require one original; completed-dispatch-pair-v1 requires two distinct original accounts in the same original namespace at the same endpoint.\nConfig, namespace JSON, storage key and TLS inputs must be existing protected files at absolute paths. TLS1.3 mutual authentication is mandatory.\nThe installation belongs to the actual OS user; HOME/XDG overrides cannot select another installation.\nRun initial owner admission/signing services sequentially. Resolve outstanding requests, then stop and reap the previous foreground process before reopening this OS user's installation. No automatic mode switch or graceful-drain signal is provided.\nThere is no setup, credential generation, fallback, reset, renewal, new continuation admission or replacement namespace."
        );
        return;
    }
    if args.len() != 3 || (args[0] != "--check" && args[0] != "--serve") {
        eprintln!("Use --help. An explicit --check or --serve, one mode and one protected config file are required.");
        std::process::exit(2);
    }
    #[cfg(target_os = "linux")]
    {
        use wholepact_authority::financial_server_launcher_v1::{
            check_existing_financial_server_v1, serve_existing_financial_server_v1,
            FinancialWitnessServiceV1,
        };
        let mode = args[1]
            .to_str()
            .and_then(|value| FinancialWitnessServiceV1::try_from(value).ok());
        let Some(mode) = mode else {
            eprintln!("Unsupported service mode. Use --help; no fallback service is available.");
            std::process::exit(2);
        };
        let result = if args[0] == "--check" {
            check_existing_financial_server_v1(mode, std::path::Path::new(&args[2]))
        } else {
            serve_existing_financial_server_v1(mode, std::path::Path::new(&args[2]))
        };
        if result.is_err() {
            eprintln!(
                "Financial witness unavailable. Exact protected inputs, committed original continuation, retained TLS pins, native installation and exclusive ownership are required for serving. No replacement, reset or renewal was attempted."
            );
            std::process::exit(1);
        }
        if args[0] == "--check" {
            println!(
                "Protected configuration, TLS and selector shape validated only. No original-state opener or listener ran. Committed state, namespace availability and financial eligibility were not authenticated."
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "Financial witness execution requires the supported Linux native namespace owner."
        );
        std::process::exit(2);
    }
}
