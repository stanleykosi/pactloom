//! Read-only Linux process observations for explicitly synthetic qualification.
//! No PID-taking, spawn, signal, process-policy setter or authority constructor.
//! Callers must retain exclusive wait ownership and forbid concurrent SIGCHLD
//! policy writers. An observation is not a portable or durable capability.
use std::process::Child;

fn policy_preserves_child(handler: libc::sighandler_t, flags: libc::c_int) -> bool {
    handler == libc::SIG_DFL && flags & libc::SA_NOCLDWAIT == 0
}
pub fn default_child_wait_policy() -> bool {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
    // Null input observes the disposition; it never installs one.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) } != 0 {
        return false;
    }
    let action = unsafe { action.assume_init() };
    policy_preserves_child(action.sa_sigaction, action.sa_flags)
}
pub fn exact_child_still_owned(child: &Child) -> bool {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    if unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        return false;
    }
    let info = unsafe { info.assume_init() };
    let observed = unsafe { info.si_pid() };
    observed == 0
        || (observed > 0
            && observed as u32 == child.id()
            && matches!(
                info.si_code,
                libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
            ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tls_generator_policy_refuses_auto_reap_and_custom_handlers() {
        assert!(policy_preserves_child(libc::SIG_DFL, 0));
        assert!(!policy_preserves_child(libc::SIG_IGN, 0));
        assert!(!policy_preserves_child(libc::SIG_DFL, libc::SA_NOCLDWAIT));
        assert!(!policy_preserves_child(123usize, 0));
    }
}
