fn main() {
    if let Err(error) = wholepact_native_host::run() {
        eprintln!("wholepact-native-host: {error}");
        std::process::exit(1);
    }
}
