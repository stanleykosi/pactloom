//! Distinct fixed initial-history C/W grammar. No append or writer command.
use crate::{
    channel::inspect_ancillary,
    financial_history_data::{
        FinancialHistoryInputsV1, FinancialHistoryPresentationV1, FinancialHistoryReadBindingV1,
    },
    financial_workflow_clock::PROFILE,
    process::{PeerLifetime, Role},
    rejected,
    signer_continue_state::hash,
    Result,
};
use serde::{Deserialize, Serialize};
use std::os::fd::RawFd;
use zeroize::Zeroizing;
const MAX_PACKET: usize = 65_536;
const PREFIX: [u8; 5] = *b"WPFH\x01";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Setup {
    pub inputs: FinancialHistoryInputsV1,
    pub read_binding: FinancialHistoryReadBindingV1,
    pub setup_challenge: String,
    pub setup_ceiling_ms: u64,
}
impl Setup {
    pub(super) fn validate(&self) -> Result<()> {
        self.inputs.validate()?;
        self.read_binding.validate()?;
        let r = &self.read_binding.read;
        if r.actor.profile != PROFILE
            || !hash(&self.setup_challenge)
            || self.setup_ceiling_ms == 0
            || self.setup_ceiling_ms > r.read_ceiling_ms
            || self.inputs.expected_account_id != r.facts.account_id
        {
            return Err(rejected("initial history setup binding"));
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Packet {
    PrepareOnce {
        setup: Setup,
    },
    Display {
        setup_challenge: String,
        witness_instance: String,
        serve_challenge: String,
        read_ceiling_ms: u64,
        data: FinancialHistoryPresentationV1,
    },
    Serve {
        setup_challenge: String,
        witness_instance: String,
        serve_challenge: String,
        presentation_digest: String,
    },
    Serving {
        setup_challenge: String,
        witness_instance: String,
        serve_challenge: String,
        presentation_digest: String,
    },
    FinishRead {
        setup_challenge: String,
        witness_instance: String,
        presentation_digest: String,
        read_presentation_digest: String,
    },
    Cancel {
        coordinator: String,
        session: String,
    },
    PreparationFailed {
        setup_challenge: String,
    },
    ServiceFailed {
        setup_challenge: String,
        witness_instance: String,
        presentation_digest: String,
    },
    Disposed {
        coordinator: String,
        session: String,
        cleanup_ceiling_ms: u64,
    },
    ClosePurpose {
        coordinator: String,
        session: String,
    },
    PurposeClosed {
        coordinator: String,
        session: String,
    },
}
pub(super) fn is_history_witness(role: Role) -> bool {
    matches!(
        role,
        Role::Owner1FinancialReadHistory | Role::Owner2FinancialReadHistory
    )
}
pub(super) fn role_for(role: crate::SignerContinueRoleV1) -> Role {
    match role {
        crate::SignerContinueRoleV1::Signer1 => Role::Owner1FinancialReadHistory,
        crate::SignerContinueRoleV1::Signer2 => Role::Owner2FinancialReadHistory,
    }
}
pub(super) fn send(fd: RawFd, local: Role, peer: &PeerLifetime, packet: &Packet) -> Result<()> {
    check_direction(local, peer.role(), packet)?;
    peer.check_alive()?;
    let payload = Zeroizing::new(
        serde_json::to_vec(packet).map_err(|_| rejected("initial history Witness encode"))?,
    );
    if payload.len() > MAX_PACKET - 8 {
        return Err(rejected("initial history Witness packet too large"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(payload.len() + 8));
    bytes.extend_from_slice(&PREFIX);
    bytes.extend_from_slice(&[local as u8, 0, 0]);
    bytes.extend_from_slice(&payload);
    // One nonblocking attempt, never a retry or an unbounded UI/role wait.
    let sent = unsafe {
        libc::send(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    };
    if sent != bytes.len() as isize {
        return Err(rejected("initial history Witness send unavailable"));
    }
    peer.check_alive()
}

pub(super) fn try_receive(fd: RawFd, local: Role, peer: &PeerLifetime) -> Result<Option<Packet>> {
    peer.check_alive()?;
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(rejected("initial history Witness channel lost"));
    }
    if result == 0 || poll.revents & libc::POLLIN == 0 {
        return Ok(None);
    }
    let mut bytes = Zeroizing::new(vec![0u8; MAX_PACKET]);
    let mut control = [0usize; 64];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = std::mem::size_of_val(&control);
    let read =
        unsafe { libc::recvmsg(fd, &mut header, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // This always closes any installed SCM_RIGHTS before the error escapes.
    let cred = inspect_ancillary(&header, &control)?
        .ok_or_else(|| rejected("initial history Witness missing sender"))?;
    if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || read < 9
        || cred.pid != peer.pid()
        || cred.uid != peer.uid()
        || bytes[..5] != PREFIX
        || bytes[5] != peer.role() as u8
        || bytes[6..8] != [0, 0]
    {
        return Err(rejected("initial history Witness frame or sender rejected"));
    }
    let packet: Packet = serde_json::from_slice(&bytes[8..read as usize])
        .map_err(|_| rejected("initial history Witness grammar rejected"))?;
    check_direction(peer.role(), local, &packet)?;
    peer.check_alive()?;
    Ok(Some(packet))
}

fn check_direction(sender: Role, recipient: Role, packet: &Packet) -> Result<()> {
    let from_c = matches!(
        packet,
        Packet::PrepareOnce { .. }
            | Packet::Serve { .. }
            | Packet::FinishRead { .. }
            | Packet::Cancel { .. }
            | Packet::ClosePurpose { .. }
    );
    if (from_c && sender == Role::Coordinator && is_history_witness(recipient))
        || (!from_c && is_history_witness(sender) && recipient == Role::Coordinator)
    {
        Ok(())
    } else {
        Err(rejected("initial history Witness role mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_grammar_rejects_unknown_duplicate_and_append_commands() {
        let p = r#"{"kind":"Cancel","coordinator":"public","session":"public"}"#;
        assert!(serde_json::from_str::<Packet>(p).is_ok());
        assert!(serde_json::from_str::<Packet>(&p.replacen('{', "{\"unknown\":1,", 1)).is_err());
        assert!(
            serde_json::from_str::<Packet>(&p.replacen('{', "{\"session\":\"duplicate\",", 1))
                .is_err()
        );
        assert!(serde_json::from_str::<Packet>(r#"{"kind":"FinalAdmit"}"#).is_err());
    }
    #[test]
    fn history_grammar_only_fixed_read_roles_and_direction() {
        let p = Packet::Cancel {
            coordinator: String::new(),
            session: String::new(),
        };
        assert!(check_direction(Role::Coordinator, Role::Owner1FinancialReadHistory, &p).is_ok());
        assert!(check_direction(Role::Coordinator, Role::Owner2FinancialReadHistory, &p).is_ok());
        assert!(check_direction(
            Role::Coordinator,
            Role::Owner1FinancialContinuationAdmission,
            &p
        )
        .is_err());
        assert!(check_direction(Role::Owner1FinancialReadHistory, Role::Coordinator, &p).is_err());
        let p = Packet::PurposeClosed {
            coordinator: String::new(),
            session: String::new(),
        };
        assert!(check_direction(Role::Owner1FinancialReadHistory, Role::Coordinator, &p).is_ok());
        assert!(check_direction(Role::Coordinator, Role::Owner1FinancialReadHistory, &p).is_err());
    }
}
