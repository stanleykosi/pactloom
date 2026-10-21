//! Distinct one-exact-delivery grammar. Wire data alone is never a capability;
//! only the retained original edge receiver can construct opaque origin tickets.
use crate::{channel::inspect_ancillary, process::{PeerLifetime, Role}, rejected, Result, DeliveryFailureV1};
use serde::{Deserialize, Serialize};
use std::os::fd::RawFd;
use zeroize::Zeroizing;
const MAX_PACKET: usize = 65_536;
const PREFIX: [u8; 5] = *b"WPDL\x01";
const WITNESS: Role = Role::Owner1V3DeliveryAdmission;

/// Ordinary bounded public facts only; no source owner, consent or permit.
#[derive(Default, Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReviewInputsV1 {
    pub endpoint: String,
    pub server_name: String,
    pub witness_id: String,
    pub pinned_server_certificate_digest: String,
    pub network_profile_id: String,
    pub expected_account_id: String,
    pub owner_certificate_der_hex: String,
    pub storage_key_file: String,
    pub server_certificate_der: String,
    pub server_private_key_pkcs8_der: String,
    pub trusted_client_root_der: String,
    pub request_json: String,
}

/// Ordinary bounded public facts only; no source owner, consent or permit.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReviewPresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub mode: String,
    pub display: String,
    pub backend_review_digest: String,
    pub presentation_digest: String,
    pub prepared_at_ms: u64,
    pub expires_at_ms: u64,
    pub account_id: String,
    pub operation_id: String,
    pub request_commitment: String,
    pub source_commitment: String,
    pub owner_certificate_digest: String,
    pub expected_head_sequence: u64,
    pub expected_head_digest: String,
}

/// Ordinary bounded public facts only; no source owner, consent or permit.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReadyV1 {
    pub presentation_digest: String,
    pub effect_commitment: String,
    pub request_commitment: String,
    pub source_commitment: String,
    pub owner_certificate_digest: String,
    pub expected_head_sequence: u64,
    pub expected_head_digest: String,
    pub preparation_nonce: String,
    pub accepted_at_ms: u64,
    pub accepted_tls_expires_at_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(tag = "outcome", deny_unknown_fields)]
pub enum DeliveryOutcomeV1 {
    Committed { presentation_digest: String, effect_commitment: String, head_sequence: u64, head_digest: String },
    KnownNoEffect { presentation_digest: String, effect_commitment: Option<String> },
    Uncertain { presentation_digest: String, effect_commitment: Option<String> },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Packet {
    PrepareOnce { session: String, input: DeliveryReviewInputsV1 },
    PreparedDisplay { session: String, review_nonce: String, data: DeliveryReviewPresentationV1 },
    Arm { session: String, review_nonce: String, presentation_digest: String },
    Ready { session: String, review_nonce: String, ready_nonce: String, data: DeliveryReadyV1 },
    FinalAdmit { session: String, review_nonce: String, ready_nonce: String, effect_commitment: String },
    Cancel { session: String },
    Outcome { session: String, review_nonce: String, data: DeliveryOutcomeV1 },
    Disposed { session: String },
    PreparationFailed { session: String },
    FirstFailure { session: String, data: DeliveryFailureV1 },
}

pub(super) fn send(fd: RawFd, local: Role, peer: &PeerLifetime, packet: &Packet) -> Result<()> {
    check_direction(local, peer.role(), packet)?;
    peer.check_alive()?;
    let payload = Zeroizing::new(serde_json::to_vec(packet).map_err(|_| rejected("delivery review encode"))?);
    if payload.len() > MAX_PACKET - 8 { return Err(rejected("delivery review packet too large")); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(payload.len() + 8));
    bytes.extend_from_slice(&PREFIX);
    bytes.extend_from_slice(&[local as u8, 0, 0]);
    bytes.extend_from_slice(&payload);
    // One nonblocking attempt, never a retry or an unbounded UI/role wait.
    let sent = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent != bytes.len() as isize { return Err(rejected("delivery review send unavailable")); }
    peer.check_alive()
}

pub(super) fn try_receive(fd: RawFd, local: Role, peer: &PeerLifetime) -> Result<Option<Packet>> {
    peer.check_alive()?;
    let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 { return Err(std::io::Error::last_os_error()); }
    if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 { return Err(rejected("delivery review channel lost")); }
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
    let cred = inspect_ancillary(&header, &control)?.ok_or_else(|| rejected("delivery review missing sender"))?;
    if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || read < 9
        || cred.pid != peer.pid() || cred.uid != peer.uid()
        || bytes[..5] != PREFIX || bytes[5] != peer.role() as u8 || bytes[6..8] != [0, 0]
    { return Err(rejected("delivery review frame or sender rejected")); }
    let packet: Packet = serde_json::from_slice(&bytes[8..read as usize]).map_err(|_| rejected("delivery review grammar rejected"))?;
    check_direction(peer.role(), local, &packet)?;
    peer.check_alive()?;
    Ok(Some(packet))
}

fn check_direction(sender: Role, recipient: Role, packet: &Packet) -> Result<()> {
    let from_c = matches!(packet, Packet::PrepareOnce { .. } | Packet::Arm { .. } | Packet::FinalAdmit { .. } | Packet::Cancel { .. });
    if (from_c && sender == Role::Coordinator && recipient == WITNESS)
        || (!from_c && sender == WITNESS && recipient == Role::Coordinator) { Ok(()) }
    else { Err(rejected("delivery role mismatch")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn positive_wire_is_closed_and_not_cancel_only_or_claimed_origin() {
        for text in [r#"{"kind":"Approve","approved":true}"#, r#"{"kind":"Cancel"}"#,
            r#"{"kind":"Cancel","session":"one","session":"two"}"#,
            r#"{"kind":"Cancel","session":"one","fd":3}"#] {
            assert!(serde_json::from_str::<Packet>(text).is_err());
        }
        let cancel = Packet::Cancel { session: "one".into() };
        assert!(check_direction(Role::Coordinator, WITNESS, &cancel).is_ok());
        assert!(check_direction(Role::Host, WITNESS, &cancel).is_err());
        assert!(check_direction(WITNESS, Role::Coordinator, &cancel).is_err());
    }
}
