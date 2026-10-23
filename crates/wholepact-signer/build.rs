//! Crate-local financial observation configuration; absent mode is production.
//! Identical reviewed scripts are used only by the three financial cfg consumers.
use std::env;
use std::ffi::OsStr;

const MODE_ENV: &str = "WHOLEPACT_FINANCIAL_BUILD_MODE";
const CFGS: [&str; 3] = [
    "wholepact_financial_ci",
    "wholepact_financial_external_ci",
    "wholepact_financial_rendered_host_semantic_ci",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode { Production, ObservedPixel, ObservedSemantic }

fn select_mode(value: Option<&OsStr>) -> Result<Mode, &'static str> {
    match value {
        // Ordinary builds must remain observation-free without an opt-in.
        None => Ok(Mode::Production),
        Some(v) => match v.to_str() {
            Some("production") => Ok(Mode::Production),
            Some("observed-pixel") => Ok(Mode::ObservedPixel),
            Some("observed-semantic") => Ok(Mode::ObservedSemantic),
            _ => Err("financial_build_mode_invalid"),
        },
    }
}

fn reject_legacy_cfg(value: Option<&OsStr>) -> Result<(), &'static str> {
    let Some(value) = value else { return Ok(()) };
    let text = value.to_str().ok_or("financial_global_flags_invalid")?;
    if CFGS.iter().any(|cfg| text.contains(cfg)) {
        return Err("financial_global_cfg_forbidden");
    }
    Ok(())
}

fn cfgs(mode: Mode) -> &'static [&'static str] {
    match mode {
        Mode::Production => &CFGS[..0],
        Mode::ObservedPixel => &CFGS[..2],
        Mode::ObservedSemantic => &CFGS[..3],
    }
}

fn instructions(mode: Mode) -> Vec<String> {
    let mut lines = vec![
        "cargo::rerun-if-changed=build.rs".to_owned(),
        format!("cargo::rerun-if-env-changed={MODE_ENV}"),
        "cargo::rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS".to_owned(),
        "cargo::rerun-if-env-changed=RUSTFLAGS".to_owned(),
    ];
    for cfg in CFGS { lines.push(format!("cargo::rustc-check-cfg=cfg({cfg})")); }
    for cfg in cfgs(mode) { lines.push(format!("cargo::rustc-cfg={cfg}")); }
    lines
}

fn main() {
    let result = (|| {
        let mode = select_mode(env::var_os(MODE_ENV).as_deref())?;
        reject_legacy_cfg(env::var_os("CARGO_ENCODED_RUSTFLAGS").as_deref())?;
        reject_legacy_cfg(env::var_os("RUSTFLAGS").as_deref())?;
        Ok::<_, &'static str>(instructions(mode))
    })();
    match result {
        Ok(lines) => for line in lines { println!("{line}"); },
        Err(code) => {
            // Never interpolate a rejected environment value into output.
            eprintln!("{code}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_modes_and_absent_are_safe() {
        assert_eq!(select_mode(None), Ok(Mode::Production));
        for (value, expected) in [("production", Mode::Production),
            ("observed-pixel", Mode::ObservedPixel),
            ("observed-semantic", Mode::ObservedSemantic)] {
            assert_eq!(select_mode(Some(OsStr::new(value))), Ok(expected));
        }
    }

    #[test]
    fn malformed_modes_fail_closed() {
        for value in ["", "semantic", "PRODUCTION", "production\n", "observed-semantic ",
            "observed-pixel\0suffix", "private-input"] {
            assert_eq!(select_mode(Some(OsStr::new(value))), Err("financial_build_mode_invalid"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_mode_is_rejected() {
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(select_mode(Some(OsStr::from_bytes(&[0xff]))),
            Err("financial_build_mode_invalid"));
    }

    #[test]
    fn exact_cfgs_and_rerun_tracking() {
        for mode in [Mode::Production, Mode::ObservedPixel, Mode::ObservedSemantic] {
            let lines = instructions(mode);
            let expected: Vec<_> = cfgs(mode).iter().map(|c| format!("cargo::rustc-cfg={c}")).collect();
            let actual: Vec<_> = lines.iter().filter(|s| s.starts_with("cargo::rustc-cfg=")).cloned().collect();
            assert_eq!(actual, expected);
            assert!(lines.contains(&format!("cargo::rerun-if-env-changed={MODE_ENV}")));
            assert_eq!(lines.len(), 7 + cfgs(mode).len());
        }
    }

    #[test]
    fn mixed_global_channels_rejected() {
        for cfg in CFGS {
            for value in [format!("--cfg {cfg}"), format!("--cfg={cfg}"),
                format!("--cfg\x1f{cfg}"), format!("--cfg={cfg}=\"x\"")] {
                assert_eq!(reject_legacy_cfg(Some(OsStr::new(&value))),
                    Err("financial_global_cfg_forbidden"));
            }
        }
        assert_eq!(reject_legacy_cfg(None), Ok(()));
        assert_eq!(reject_legacy_cfg(Some(OsStr::new(""))), Ok(()));
        // Preserve unrelated ordinary developer flags; the CI selector is stricter.
        assert_eq!(reject_legacy_cfg(Some(OsStr::new("-Dwarnings"))), Ok(()));
    }
}
