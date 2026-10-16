#[cfg(feature = "synthetic-qualification")]
use std::io::{self, BufRead, Write};

fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("signer stopped safely; review outstanding exposure")
    }));
    if wholepact_signer::harden_process().is_err() {
        eprintln!("signer platform hardening unavailable");
        std::process::exit(1);
    }
    let args: Vec<String> = std::env::args().collect();
    #[cfg(feature = "synthetic-qualification")]
    if args.get(1).map(String::as_str) == Some("--synthetic-terminal-probe") {
        let result=wholepact_signer::terminal::TrustedTerminal::open().map(|mut terminal| {
            serde_json::json!({"controlling_tty":true,"human_origin_authenticated":terminal.user_origin_authenticated(),"provisioning_consent":terminal.approve_new_account("synthetic-pty-probe",0).is_ok()})
        });
        match result {Ok(value)=>println!("{value}"),Err(_)=>println!("{{\"controlling_tty\":false,\"human_origin_authenticated\":false,\"provisioning_consent\":false}}")}
        return;
    }
    #[cfg(feature = "synthetic-qualification")]
    if args.get(1).map(String::as_str) == Some("--synthetic-stdio") {
        if let Err(error) = synthetic_stdio(&args) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() > 1 && args[1] != "capabilities" {
        eprintln!("live signer operations unavailable; use capabilities");
        std::process::exit(2);
    }
    println!("{{\"live_signing\":false,\"persistent_user_setup\":false,\"automation\":false,\"reason\":\"chain_encrypted_journal_and_restore_authority_qualification_required\"}}");
}

#[cfg(feature = "synthetic-qualification")]
fn synthetic_stdio(args: &[String]) -> wholepact_signer::Result<()> {
    use wholepact_signer::{
        synthetic::{Command, CrashAt, Session},
        Error,
    };
    use zeroize::Zeroizing;
    if args.len() != 3 && args.len() != 5 {
        return Err(Error::InvalidData);
    }
    let fault = if args.len() == 5 {
        if args[3] != "--crash-at" {
            return Err(Error::InvalidData);
        }
        Some(match args[4].as_str() {
            "before-intent" => CrashAt::BeforeIntent,
            "after-intent" => CrashAt::AfterIntent,
            "after-sign" => CrashAt::AfterSign,
            "after-result" => CrashAt::AfterResult,
            "before-export" => CrashAt::BeforeExport,
            _ => return Err(Error::InvalidData),
        })
    } else {
        None
    };
    let mut session = Session::new(std::path::Path::new(&args[2]), fault);
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        let mut line = Zeroizing::new(Vec::new());
        // Stop before unbounded allocation. One line = one request, no paths or
        // passwords in argv, and no TCP, HTTP, browser or remote listening surface.
        loop {
            let buffer = input.fill_buf()?;
            if buffer.is_empty() {
                if line.is_empty() {
                    return Ok(());
                }
                return Err(Error::InvalidData);
            }
            let count = buffer
                .iter()
                .position(|&b| b == b'\n')
                .map(|n| n + 1)
                .unwrap_or(buffer.len());
            if line.len() + count > 2_200_000 {
                return Err(Error::InvalidData);
            }
            line.extend_from_slice(&buffer[..count]);
            let complete = line.last() == Some(&b'\n');
            input.consume(count);
            if complete {
                break;
            }
        }
        let result = serde_json::from_slice::<Command>(&line)
            .map_err(|_| Error::InvalidData)
            .and_then(|command| session.execute(command));
        let response = SensitiveResponse(match result {
            Ok(value) => serde_json::json!({"ok":true,"result":value}),
            Err(error) => serde_json::json!({"ok":false,"error":error.to_string()}),
        });
        serde_json::to_writer(&mut output, &response.0).map_err(|_| Error::InvalidData)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}

#[cfg(feature = "synthetic-qualification")]
struct SensitiveResponse(serde_json::Value);
#[cfg(feature = "synthetic-qualification")]
impl Drop for SensitiveResponse {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        fn wipe(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(s) => s.zeroize(),
                serde_json::Value::Array(items) => items.iter_mut().for_each(wipe),
                serde_json::Value::Object(items) => items.values_mut().for_each(wipe),
                _ => (),
            }
        }
        wipe(&mut self.0);
    }
}
