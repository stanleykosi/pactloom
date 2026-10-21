//! One fixed cancel-only C/W grammar on the original private fork edge. No
//! positive operation, descriptor import, listener, reconnect or generic RPC.
use crate::{channel::inspect_ancillary, process::{PeerLifetime, Role}, rejected, Result};
use serde::{Deserialize, Serialize};
use std::os::fd::RawFd;
use wholepact_authority::native_witness_owner::cancel_delivery_review_v1::{CancelOnlyDeliveryInputsV1, CancelOnlyDeliveryPresentationV1};
use zeroize::Zeroizing;

const MAX_PACKET: usize = 65_536;
const PREFIX: [u8; 5] = *b"WPCR\x01";
pub(super) const WITNESS: Role = Role::Owner1V3DeliveryAdmission;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub(super) enum Packet {
    PrepareOnce(CancelOnlyDeliveryInputsV1),
    PreparedDisplay(CancelOnlyDeliveryPresentationV1),
    Cancel,
    Disposed,
    PreparationFailed,
}

pub(super) fn send(fd: RawFd, local: Role, peer: &PeerLifetime, packet: &Packet) -> Result<()> {
    check_direction(local, peer.role(), packet)?;
    peer.check_alive()?;
    let payload = Zeroizing::new(serde_json::to_vec(packet).map_err(|_| rejected("cancel review encode"))?);
    if payload.len() > MAX_PACKET - 8 { return Err(rejected("cancel review packet too large")); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(payload.len() + 8));
    bytes.extend_from_slice(&PREFIX);
    bytes.extend_from_slice(&[local as u8, 0, 0]);
    bytes.extend_from_slice(&payload);
    // One nonblocking attempt, never a retry or an unbounded UI/role wait.
    let sent = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent != bytes.len() as isize { return Err(rejected("cancel review send unavailable")); }
    peer.check_alive()
}

pub(super) fn try_receive(fd: RawFd, local: Role, peer: &PeerLifetime) -> Result<Option<Packet>> {
    peer.check_alive()?;
    let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 { return Err(std::io::Error::last_os_error()); }
    if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 { return Err(rejected("cancel review channel lost")); }
    if result == 0 || poll.revents & libc::POLLIN == 0 { return Ok(None); }
    let mut bytes = Zeroizing::new(vec![0u8; MAX_PACKET]);
    let mut control = [0usize; 64];
    let mut iov = libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = std::mem::size_of_val(&control);
    let read = unsafe { libc::recvmsg(fd, &mut header, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
    if read < 0 { return Err(std::io::Error::last_os_error()); }
    // This always closes any installed SCM_RIGHTS before the error escapes.
    let cred = inspect_ancillary(&header, &control)?.ok_or_else(|| rejected("cancel review missing sender"))?;
    if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || read < 9
        || cred.pid != peer.pid() || cred.uid != peer.uid()
        || bytes[..5] != PREFIX || bytes[5] != peer.role() as u8 || bytes[6..8] != [0, 0]
    { return Err(rejected("cancel review frame or sender rejected")); }
    let packet: Packet = serde_json::from_slice(&bytes[8..read as usize]).map_err(|_| rejected("cancel review grammar rejected"))?;
    check_direction(peer.role(), local, &packet)?;
    peer.check_alive()?;
    Ok(Some(packet))
}

fn check_direction(sender: Role, recipient: Role, packet: &Packet) -> Result<()> {
    let allowed = match packet {
        Packet::PrepareOnce(_) | Packet::Cancel => sender == Role::Coordinator && recipient == WITNESS,
        Packet::PreparedDisplay(_) | Packet::Disposed | Packet::PreparationFailed => sender == WITNESS && recipient == Role::Coordinator,
    };
    if !allowed { return Err(rejected("cancel review role mismatch")); }
    Ok(())
}

pub(super) fn validate_presentation(p: &CancelOnlyDeliveryPresentationV1) -> Result<()> {
    p.validate().map_err(|_| rejected("invalid complete cancel-only presentation"))?;
    if p.display.len() > MAX_PACKET - 1024 { return Err(rejected("cancel-only presentation too large")); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grammar_has_no_approval_or_foreign_role_entry() {
        for text in [r#"{"kind":"Approve"}"#, r#"{"kind":"Cancel","approved":true}"#,
            r#"{"kind":"Cancel","kind":"Cancel"}"#, r#"{"kind":"Cancel","data":{"fd":3}}"#]
        { assert!(serde_json::from_str::<Packet>(text).is_err()); }
        assert!(serde_json::from_str::<Packet>(r#"{"kind":"Cancel"}"#).is_ok());
        assert!(check_direction(Role::Coordinator, WITNESS, &Packet::Cancel).is_ok());
        assert!(check_direction(Role::Coordinator, Role::Host, &Packet::Cancel).is_err());
        assert!(check_direction(WITNESS, Role::Coordinator, &Packet::Cancel).is_err());
        assert!(check_direction(WITNESS, Role::Coordinator, &Packet::Disposed).is_ok());
    }
}
