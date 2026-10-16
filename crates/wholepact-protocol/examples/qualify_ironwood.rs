fn main() {
    match wholepact_protocol::synthetic::run_two_owner_fixture() {
        Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
        Err(error) => {
            eprintln!("Synthetic qualification failed: {error}");
            std::process::exit(1);
        }
    }
}
