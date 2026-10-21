//! Nonsecret display coordinates, never a display FD or proof of human origin.
//! Captured before clearenv, dropped in every child before READY, restored only
//! by C after all forks and before either the driver or GUI starts threads.
use crate::{rejected, Result};
use std::{os::unix::fs::MetadataExt, path::Path};

pub(super) struct DesktopLaunchV1 { runtime: String, display: String }
impl DesktopLaunchV1 {
    pub(super) fn capture() -> Result<Self> {
        for name in ["WAYLAND_SOCKET", "EGUI_INSPECTION", "EGUI_INSPECTION_ADDR", "EFRAME_SCREENSHOT_TO"] {
            if std::env::var_os(name).is_some() { return Err(rejected("unsupported display input")); }
        }
        let value = Self {
            runtime: std::env::var("XDG_RUNTIME_DIR").map_err(|_| rejected("missing private runtime directory"))?,
            display: std::env::var("WAYLAND_DISPLAY").map_err(|_| rejected("missing Wayland display name"))?,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        validate_coordinates(&self.runtime, &self.display)?;
        let metadata = std::fs::symlink_metadata(&self.runtime)?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o700
        { return Err(rejected("runtime directory is not private to this user")); }
        // No inherited WAYLAND_SOCKET and no endpoint is accepted as authority.
        // The trusted OS/compositor/initial launcher assumption remains explicit.
        Ok(())
    }
    pub(super) fn restore_in_coordinator(self) -> Result<()> {
        crate::process::require_single_thread()?;
        self.validate()?;
        // This is the only restoration, after the fixed forks. EGL/driver,
        // inspection, HOME and arbitrary launch variables remain absent.
        let runtime = std::ffi::CString::new(self.runtime).map_err(|_| rejected("runtime directory NUL"))?;
        let display = std::ffi::CString::new(self.display).map_err(|_| rejected("display name NUL"))?;
        if unsafe { libc::setenv(c"XDG_RUNTIME_DIR".as_ptr(), runtime.as_ptr(), 1) } != 0
            || unsafe { libc::setenv(c"WAYLAND_DISPLAY".as_ptr(), display.as_ptr(), 1) } != 0
        { return Err(std::io::Error::last_os_error()); }
        Ok(())
    }
}

fn validate_coordinates(runtime: &str, display: &str) -> Result<()> {
    if runtime.is_empty() || runtime.len() > 4096 || !Path::new(runtime).is_absolute()
        || runtime.bytes().any(|b| b.is_ascii_control()) || runtime[1..].split('/').any(|p| p.is_empty() || matches!(p, "." | ".."))
        || display.is_empty() || display.len() > 100 || display.contains('/')
        || matches!(display, "." | "..") || !display.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || runtime.len() + 1 + display.len() >= 108
    { return Err(rejected("invalid finite Wayland coordinates")); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display_coordinates_are_only_finite_nonsecret_names() {
        assert!(validate_coordinates("/run/user/10001", "wayland-0").is_ok());
        for name in ["", "../socket", "/socket", ".", "..", "socket\0", "socket\n"] {
            assert!(validate_coordinates("/run/user/10001", name).is_err());
        }
        assert!(validate_coordinates("/run/../tmp", "wayland-0").is_err());
        assert!(validate_coordinates("relative", "wayland-0").is_err());
    }
}
