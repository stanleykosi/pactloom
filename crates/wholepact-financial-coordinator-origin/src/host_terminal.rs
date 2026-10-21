//! Genuine C-master/H-slave terminal custody for the fixed common-image tree.
//! Registered only for the fixed full-workflow profile. Bound close/error/Drop
//! publishes restriction through the original Core; this supplies no native
//! consent, action admission, shell, or descriptor/path importer.
//! Bootstrap must drop the inherited pair in every S/W branch before role work.
use crate::{
    bootstrap::PhaseDeadlinesV1,
    channel::require_time,
    process::{DirectChild, ForkOriginV1, PeerLifetime, Role},
    rejected, Result,
};
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::FileTypeExt,
    },
    sync::Arc,
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_INPUT_LINE: usize = 8192;
const OUTPUT_CHUNK: usize = 4096;

/// Born only after ambient-descriptor disposal, before the fixed forks. This
/// value is neither Clone nor reconstructible from a path or a supplied FD.
/// An inherited S/W copy has no special Drop action: it only closes both FDs.
pub(super) struct CreatedHostTerminalV1 {
    master: File,
    slave: File,
    creator_pid: libc::pid_t,
    creator_uid: libc::uid_t,
    clocks: PhaseDeadlinesV1,
}

impl CreatedHostTerminalV1 {
    pub(super) fn create(clocks: PhaseDeadlinesV1) -> Result<Self> {
        crate::process::require_single_thread()?;
        require_time(clocks.workflow().startup())?;
        // SAFETY: this opens a fresh kernel PTY, not an inherited/caller FD.
        let raw = unsafe {
            libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK)
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Own immediately so every later failure closes the fresh descriptor.
        let master = unsafe { File::from_raw_fd(raw) };
        if unsafe { libc::grantpt(master.as_raw_fd()) } != 0
            || unsafe { libc::unlockpt(master.as_raw_fd()) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // TIOCGPTPEER binds the slave to THIS master without a ptsname/path race.
        // No fallback to opening a named device is permitted.
        let raw = unsafe {
            libc::ioctl(
                master.as_raw_fd(),
                libc::TIOCGPTPEER,
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let slave = unsafe { File::from_raw_fd(raw) };
        if !slave.metadata()?.file_type().is_char_device()
            || unsafe { libc::isatty(slave.as_raw_fd()) } != 1
        {
            return Err(rejected("fresh Host slave is not a terminal"));
        }
        set_raw_no_echo(&slave)?;
        require_time(clocks.workflow().startup())?;
        Ok(Self {
            master,
            slave,
            creator_pid: unsafe { libc::getpid() },
            creator_uid: unsafe { libc::geteuid() },
            clocks,
        })
    }

    /// C keeps only its master and a check-only handle to its actual H child.
    /// The original tree, not this endpoint, continues to own H's sole reaper.
    pub(super) fn into_coordinator(
        self,
        host: &DirectChild,
    ) -> Result<CoordinatorHostTerminalEndpointV1> {
        require_local(self.creator_pid, self.creator_uid, self.clocks.session)?;
        if host.role() != Role::Host {
            return Err(rejected("terminal requires the original Host child"));
        }
        let host_lifetime = host.continue_pidfd()?;
        let Self { master, slave, creator_pid, creator_uid, clocks } = self;
        drop(slave);
        let endpoint = CoordinatorHostTerminalEndpointV1 {
            owner_pid: creator_pid,
            owner_uid: creator_uid,
            deadline: clocks.session,
            io: Some(CoordinatorTerminalIo { master, host_lifetime }),
            input: None,
            workflow: None,
        };
        endpoint.check_transport()?;
        Ok(endpoint)
    }

    /// The actual fixed S1/S2 owners prove that both Signer forks already
    /// happened. They never inherit H's newly established controlling terminal.
    /// A setup error is terminal for this H branch; setsid cannot be rolled back.
    pub(super) fn into_host_after_signer_forks(
        self,
        origin: &ForkOriginV1,
        signers: &[Option<DirectChild>; 2],
    ) -> Result<HostControllingTerminalV1> {
        crate::process::require_single_thread()?;
        require_time(self.clocks.workflow().startup())?;
        let coordinator = origin.retain_host_coordinator_lifetime()?;
        if coordinator.pid() != self.creator_pid
            || coordinator.uid() != self.creator_uid
            || unsafe { libc::geteuid() } != self.creator_uid
            || unsafe { libc::getpid() } == self.creator_pid
        {
            return Err(rejected("terminal is not inherited by the original Host"));
        }
        for (signer, expected) in signers.iter().zip([Role::Signer1, Role::Signer2]) {
            let signer = signer.as_ref().ok_or_else(|| rejected("fixed Signer not forked"))?;
            if signer.role() != expected {
                return Err(rejected("terminal requires exact fixed Signer order"));
            }
            signer.check_alive()?;
        }
        let Self { master, slave, creator_pid: _, creator_uid, clocks } = self;
        drop(master);
        let owner_pid = unsafe { libc::getpid() };
        // No stealing another session's terminal, inherited /dev/tty fallback,
        // stdio replacement, shell, or post-bootstrap child creation occurs.
        if unsafe { libc::setsid() } != owner_pid
            || unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY, 0) } != 0
            || unsafe { libc::tcsetpgrp(slave.as_raw_fd(), owner_pid) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let terminal = HostControllingTerminalV1 {
            slave,
            coordinator,
            owner_pid,
            owner_uid: creator_uid,
            deadline: clocks.session,
        };
        terminal.check_current()?;
        Ok(terminal)
    }
}

struct CoordinatorTerminalIo {
    master: File,
    host_lifetime: OwnedFd,
}
struct PendingUserLine {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}

/// Exact bounded byte transport only. The future native panel must display raw
/// Host output as text, never execute terminal escapes or log submitted input.
/// Every line must come from explicit user entry; no prompt recognition,
/// auto-answer, APPROVE completion, or input-derived transcript is provided.
pub struct CoordinatorHostTerminalEndpointV1 {
    owner_pid: libc::pid_t,
    owner_uid: libc::uid_t,
    deadline: Instant,
    io: Option<CoordinatorTerminalIo>,
    input: Option<PendingUserLine>,
    workflow: Option<Arc<crate::signer_continue_state::Core>>,
}
impl CoordinatorHostTerminalEndpointV1 {
    /// Only the original coordinator endpoint may bind its same retained Core,
    /// before handing out this endpoint once. No public importer or rebinding.
    pub(super) fn bind_workflow(mut self, core: Arc<crate::signer_continue_state::Core>) -> Result<Self> {
        if self.workflow.is_some() {
            core.phase.revoke();
            return self.close_with(rejected("Host terminal workflow already bound"));
        }
        let matches = core.owner_pid == self.owner_pid
            && core.owner_uid == self.owner_uid && core.session == self.deadline;
        // Install before a fallible check, so all ensuing errors revoke THIS
        // actual Core before transient input or master custody is discarded.
        self.workflow = Some(core);
        if !matches {
            return self.close_with(rejected("Host terminal original workflow mismatch"));
        }
        self.check_or_close()?;
        Ok(self)
    }

    /// Queue exactly one user-completed line. All input is transient/protected,
    /// whether or not the Host prompt is secret. The only added byte is Enter.
    pub fn queue_user_line(&mut self, line: Zeroizing<String>) -> Result<()> {
        self.check_or_close()?;
        if self.input.is_some() || !valid_line(&line) {
            return self.close_with(rejected("invalid or already pending Host input"));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(line.len() + 1));
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        self.input = Some(PendingUserLine { bytes, offset: 0 });
        Ok(())
    }

    /// At most one nonblocking write. A short write advances its exact offset;
    /// accepted prefixes are zeroed and are NEVER resent. A later error closes
    /// the endpoint; it cannot establish that earlier input was not consumed.
    pub fn pump_user_input(&mut self) -> Result<bool> {
        self.check_or_close()?;
        let Some(input) = self.input.as_mut() else { return Ok(true); };
        let io = self.io.as_mut().ok_or_else(|| rejected("Host terminal closed"))?;
        match io.master.write(&input.bytes[input.offset..]) {
            Ok(0) => return self.close_with(rejected("Host terminal input ended")),
            Ok(count) => {
                let end = input.offset + count;
                input.bytes[input.offset..end].zeroize();
                input.offset = end;
            }
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {}
            Err(error) => return self.close_with(error),
        }
        self.check_or_close()?;
        let complete = self.input.as_ref().is_some_and(|input| input.offset == input.bytes.len());
        if complete {
            self.input.take();
        }
        Ok(complete)
    }

    /// At most one nonblocking bounded read, with no interpretation, hiding,
    /// CR/LF rewrite or escape execution. The raw slave has OPOST disabled.
    /// The caller must retain incomplete UTF-8 across chunks for lossless text.
    pub fn try_read_output(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.check_or_close()?;
        let mut bytes = Zeroizing::new(vec![0u8; OUTPUT_CHUNK]);
        let io = self.io.as_mut().ok_or_else(|| rejected("Host terminal closed"))?;
        let count = match io.master.read(&mut bytes) {
            Ok(0) => return self.close_with(rejected("Host terminal output ended")),
            Ok(count) => count,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => 0,
            Err(error) => return self.close_with(error),
        };
        self.check_or_close()?;
        if count == 0 {
            return Ok(None);
        }
        bytes.truncate(count);
        Ok(Some(bytes))
    }

    /// Restrict the bound original workflow before closing transport/input.
    /// This cannot recall an admitted effect, reap a child, or prove that a
    /// partially accepted input or operation did not run.
    pub fn close(&mut self) {
        if let Some(core) = &self.workflow { core.phase.revoke(); }
        self.input.take();
        self.io.take();
    }
    fn close_with<T>(&mut self, error: std::io::Error) -> Result<T> {
        self.close();
        Err(error)
    }
    fn check_or_close(&mut self) -> Result<()> {
        let checked = (|| {
            let core = self.workflow.as_ref().ok_or_else(|| rejected("Host terminal workflow unbound"))?;
            core.check()?;
            require_time(core.session)?;
            if core.phase.revoked() { return Err(rejected("Host terminal workflow restricted")); }
            self.check_transport()
        })();
        if let Err(error) = checked {
            return self.close_with(error);
        }
        Ok(())
    }
    // Constructor-only checks must work before the actual Core exists. Public
    // transport methods always go through the bound-workflow check above.
    fn check_transport(&self) -> Result<()> {
        require_local(self.owner_pid, self.owner_uid, self.deadline)?;
        let io = self.io.as_ref().ok_or_else(|| rejected("Host terminal closed"))?;
        check_pidfd(&io.host_lifetime)?;
        check_raw_no_echo(&io.master)
    }
}
impl Drop for CoordinatorHostTerminalEndpointV1 {
    fn drop(&mut self) { self.close(); }
}

/// Holds the exact fresh slave and actual original C lifetime. No raw FD,
/// path, permission, fork constructor or secret-entry replacement is exposed.
/// The native Host still opens /dev/tty and must use its genuine approvals.
pub struct HostControllingTerminalV1 {
    slave: File,
    coordinator: PeerLifetime,
    owner_pid: libc::pid_t,
    owner_uid: libc::uid_t,
    deadline: Instant,
}
impl HostControllingTerminalV1 {
    pub fn deadline(&self) -> Instant { self.deadline }

    /// Check a separately opened /dev/tty against the retained actual slave.
    /// A supplied File is only compared; it cannot construct or replace custody.
    pub fn check_controlling_file(&self, file: &File) -> Result<()> {
        self.check_current()?;
        let observed = file.metadata()?;
        if !observed.file_type().is_char_device()
            // fstat(/dev/tty) describes its (5,0) alias, not /dev/pts/N.
            // TIOCGDEV compares the actual retained kernel terminal instead.
            || terminal_device(&self.slave)? != terminal_device(file)?
            || unsafe { libc::tcgetpgrp(file.as_raw_fd()) } != self.owner_pid
            || unsafe { libc::tcgetsid(file.as_raw_fd()) } != self.owner_pid
        {
            return Err(rejected("Host controlling terminal changed"));
        }
        self.check_current()
    }

    pub fn check_current(&self) -> Result<()> {
        require_local(self.owner_pid, self.owner_uid, self.deadline)?;
        self.coordinator.check_alive()?;
        if unsafe { libc::getsid(0) } != self.owner_pid
            || unsafe { libc::getpgrp() } != self.owner_pid
            || unsafe { libc::tcgetpgrp(self.slave.as_raw_fd()) } != self.owner_pid
            || unsafe { libc::tcgetsid(self.slave.as_raw_fd()) } != self.owner_pid
        {
            return Err(rejected("original Host terminal session lost"));
        }
        check_raw_no_echo(&self.slave)
    }
}

fn require_local(pid: libc::pid_t, uid: libc::uid_t, deadline: Instant) -> Result<()> {
    if unsafe { libc::getpid() } != pid || unsafe { libc::geteuid() } != uid {
        return Err(rejected("Host terminal used outside original actor"));
    }
    require_time(deadline)
}
fn check_pidfd(fd: &OwnedFd) -> Result<()> {
    let mut poll = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 || poll.revents != 0 {
        return Err(rejected("original Host terminal peer lost"));
    }
    Ok(())
}
fn valid_line(line: &str) -> bool {
    line.len() <= MAX_INPUT_LINE && !line.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
}
fn terminal_device(file: &File) -> Result<libc::c_uint> {
    let mut device = 0;
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCGDEV, &mut device) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(device)
}
fn set_raw_no_echo(slave: &File) -> Result<()> {
    let mut mode: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut mode) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // C edits each transient user line, not the kernel. Secret/nonsecret mode is
    // never inferred from prompt text. Disable all kernel echo and CR/LF output
    // projection throughout; the panel receives precisely Host-written bytes.
    unsafe { libc::cfmakeraw(&mut mode) };
    mode.c_lflag &= !(libc::ECHO | libc::ECHONL);
    mode.c_oflag &= !libc::OPOST;
    mode.c_cc[libc::VMIN] = 1;
    mode.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &mode) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    check_raw_no_echo(slave)
}
fn check_raw_no_echo(file: &File) -> Result<()> {
    let mut observed: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(file.as_raw_fd(), &mut observed) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if !raw_no_echo_mode(&observed) {
        return Err(rejected("fresh Host terminal mode not installed"));
    }
    Ok(())
}
fn raw_no_echo_mode(mode: &libc::termios) -> bool {
    mode.c_iflag
        & (libc::IGNBRK | libc::BRKINT | libc::PARMRK | libc::ISTRIP
            | libc::INLCR | libc::IGNCR | libc::ICRNL | libc::IXON) == 0
        && mode.c_lflag
            & (libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN) == 0
        && mode.c_oflag & libc::OPOST == 0
        && mode.c_cflag & libc::CSIZE == libc::CS8
        && mode.c_cflag & libc::PARENB == 0
        && mode.c_cc[libc::VMIN] == 1
        && mode.c_cc[libc::VTIME] == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_user_line_is_bounded_and_never_contains_a_second_enter() {
        assert!(valid_line(""));
        assert!(valid_line("user supplied text"));
        assert!(valid_line(&"x".repeat(MAX_INPUT_LINE)));
        assert!(!valid_line(&"x".repeat(MAX_INPUT_LINE + 1)));
        for invalid in ["line\n", "line\r", "line\0", "first\nsecond"] {
            assert!(!valid_line(invalid));
        }
        // Bounds are UTF-8 bytes, matching the actual Host line reader.
        assert!(valid_line(&"é".repeat(MAX_INPUT_LINE / 2)));
        assert!(!valid_line(&"é".repeat(MAX_INPUT_LINE / 2 + 1)));
    }
    #[test]
    fn exact_terminal_mode_rejects_every_maintained_raw_transform() {
        // Pure data predicate only. No terminal, syscall or native authority.
        let mut baseline: libc::termios = unsafe { std::mem::zeroed() };
        baseline.c_cflag = libc::CS8;
        baseline.c_cc[libc::VMIN] = 1;
        assert!(raw_no_echo_mode(&baseline));
        for flag in [libc::IGNBRK, libc::BRKINT, libc::PARMRK, libc::ISTRIP,
            libc::INLCR, libc::IGNCR, libc::ICRNL, libc::IXON] {
            let mut mode = baseline;
            mode.c_iflag |= flag;
            assert!(!raw_no_echo_mode(&mode));
        }
        for flag in [libc::ECHO, libc::ECHONL, libc::ICANON, libc::ISIG, libc::IEXTEN] {
            let mut mode = baseline;
            mode.c_lflag |= flag;
            assert!(!raw_no_echo_mode(&mode));
        }
        let mut mode = baseline;
        mode.c_oflag |= libc::OPOST;
        assert!(!raw_no_echo_mode(&mode));
        mode = baseline;
        mode.c_cflag |= libc::PARENB;
        assert!(!raw_no_echo_mode(&mode));
        mode = baseline;
        mode.c_cflag = (mode.c_cflag & !libc::CSIZE) | libc::CS7;
        assert!(!raw_no_echo_mode(&mode));
        mode = baseline;
        mode.c_cc[libc::VMIN] = 0;
        assert!(!raw_no_echo_mode(&mode));
        mode = baseline;
        mode.c_cc[libc::VTIME] = 1;
        assert!(!raw_no_echo_mode(&mode));
    }
}
