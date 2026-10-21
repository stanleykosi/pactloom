//! Closed Continue-only data grammar. H is the trusted relay; S authenticates H,
//! not a fictional direct C socket. None of these serializable facts is a permit.
use crate::{channel::inspect_ancillary, process::{PeerLifetime, Role}, rejected, Result};
use super::signer_continue_state::hash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::fd::RawFd;
use zeroize::Zeroizing;
const MAX_PACKET: usize = 65_536;
const PREFIX: [u8; 5] = *b"WPSC\x01";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerContinueRoleV1 { Signer1, Signer2 }
impl SignerContinueRoleV1 {
    pub(super) fn index(self) -> usize { match self { Self::Signer1 => 0, Self::Signer2 => 1 } }
    pub(super) fn role(self) -> Role { match self { Self::Signer1 => Role::Signer1, Self::Signer2 => Role::Signer2 } }
    pub(super) fn from_role(role: Role) -> Result<Self> { match role { Role::Signer1 => Ok(Self::Signer1), Role::Signer2 => Ok(Self::Signer2), _ => Err(rejected("not original Signer role")) } }
}

/// Caller-supplied source observations remain ordinary data. The Signer source
/// independently matches these to its retained owner/history/actual Host peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerContinueSourceFactsV1 {
    pub original_host_process_instance: String,
    pub signer_principal_id: String,
    pub source_identity_digest: String,
    pub terms_digest: String,
    pub session_digest: String,
    pub review_digest: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub session_expires_at_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerContinueReviewDataV1 {
    pub coordinator_process_instance: String,
    pub coordinator_focus_epoch: u64,
    pub signer_role: SignerContinueRoleV1,
    pub signer_process_instance: String,
    pub original_host_process_instance: String,
    pub signer_principal_id: String,
    pub signer_image_measurement: String,
    pub source_identity_digest: String,
    pub terms_digest: String,
    pub session_digest: String,
    pub review_challenge: String,
    pub review_digest: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub session_expires_at_ms: u64,
}
impl SignerContinueReviewDataV1 {
    pub fn validate(&self) -> Result<()> {
        if self.coordinator_focus_epoch != 1 || ![&self.coordinator_process_instance, &self.signer_process_instance,
            &self.original_host_process_instance, &self.signer_image_measurement, &self.source_identity_digest,
            &self.terms_digest, &self.session_digest, &self.review_challenge, &self.review_digest].iter().all(|x| hash(x))
            || !identifier(&self.signer_principal_id) || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms || self.expires_at_ms - self.reviewed_at_ms > 120_000
            || self.expires_at_ms > self.session_expires_at_ms
        { return Err(rejected("Continue review data rejected")); }
        Ok(())
    }
}
fn identifier(s: &str) -> bool { !s.is_empty() && s.len() <= 128 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c)) }

/// Full immutable source-backed presentation, separate from the semantic review
/// digest inside the frozen request preimage, so there is no circular hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerContinuePresentationV1 {
    pub review: SignerContinueReviewDataV1,
    pub display: String,
    pub request_json: String,
    pub request_digest: String,
    pub prepared_digest: String,
    pub presentation_digest: String,
}
impl SignerContinuePresentationV1 {
    pub fn calculate_request_digest(request_json: &str) -> String {
        let mut h = Sha256::new(); h.update(b"wholepact:coordinated-signer-continue:request-bytes:v1\0"); h.update(request_json.as_bytes()); hex::encode(h.finalize())
    }
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&(&self.review, &self.display, &self.request_json, &self.request_digest, &self.prepared_digest))
            .map_err(|_| rejected("Continue presentation encoding"))?;
        let mut h = Sha256::new(); h.update(b"wholepact:coordinated-signer-continue:presentation:v1\0"); h.update(bytes); Ok(hex::encode(h.finalize()))
    }
    pub fn validate(&self) -> Result<()> {
        self.review.validate()?;
        if self.display.is_empty() || self.display.len() > 32_768 || self.request_json.is_empty() || self.request_json.len() > 32_768
            || !self.display.bytes().all(|b| b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b))
            || !hash(&self.request_digest) || !hash(&self.prepared_digest) || !hash(&self.presentation_digest)
            || self.request_digest != Self::calculate_request_digest(&self.request_json)
            || self.presentation_digest != self.calculate_presentation_digest()?
        { return Err(rejected("Continue complete presentation rejected")); }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", deny_unknown_fields)]
pub enum SignerContinueOutcomeV1 {
    Continued { presentation_digest: String, prepared_digest: String },
    KnownNoEffect { presentation_digest: String, prepared_digest: String },
    Uncertain { presentation_digest: String, prepared_digest: String },
}
impl SignerContinueOutcomeV1 {
    pub(super) fn matches(&self, data: &SignerContinuePresentationV1) -> bool {
        let (p, e) = match self { Self::Continued { presentation_digest, prepared_digest } | Self::KnownNoEffect { presentation_digest, prepared_digest } | Self::Uncertain { presentation_digest, prepared_digest } => (presentation_digest, prepared_digest) };
        p == &data.presentation_digest && e == &data.prepared_digest
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context { pub coordinator: String, pub role: SignerContinueRoleV1, pub slot_challenge: String, pub native_deadline_ms: u64 }
impl Context { pub(super) fn validate(&self) -> Result<()> {
    if !hash(&self.coordinator) || !hash(&self.slot_challenge) || self.native_deadline_ms == 0 || self.native_deadline_ms > 300_000 { Err(rejected("Continue context rejected")) } else { Ok(()) }
} }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding { pub context: Context, pub presentation: SignerContinuePresentationV1, pub source_deadline_ms: u64, pub review_deadline_ms: u64 }
impl Binding { pub(super) fn validate(&self) -> Result<()> {
    self.context.validate()?; self.presentation.validate()?;
    if self.presentation.review.coordinator_process_instance != self.context.coordinator || self.presentation.review.signer_role != self.context.role
        || self.source_deadline_ms == 0 || self.source_deadline_ms > 300_000 || self.review_deadline_ms == 0 || self.review_deadline_ms > 300_000
    { return Err(rejected("Continue original binding rejected")); } Ok(())
} }
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Packet {
    PrepareOnce { context: Context },
    Display { binding: Binding },
    Arm { context: Context, presentation_digest: String, prepared_digest: String },
    Ready { context: Context, presentation_digest: String, prepared_digest: String, ready_challenge: String },
    Final { context: Context, presentation_digest: String, prepared_digest: String, ready_challenge: String },
    Cancel { coordinator: String },
    Outcome { context: Context, data: SignerContinueOutcomeV1 },
    PreparationFailed { context: Context },
    Disposed { coordinator: String, role: SignerContinueRoleV1 },
}
impl Packet {
    pub(super) fn target(&self) -> Option<SignerContinueRoleV1> { match self {
        Self::PrepareOnce{context} | Self::Arm{context,..} | Self::Ready{context,..} | Self::Final{context,..} | Self::Outcome{context,..} | Self::PreparationFailed{context} => Some(context.role),
        Self::Display{binding} => Some(binding.context.role), Self::Disposed{role,..} => Some(*role), Self::Cancel{..} => None,
    } }
}

pub(super) fn send(fd: RawFd, local: Role, peer: &PeerLifetime, packet: &Packet) -> Result<()> {
    check_direction(local, peer.role(), packet)?;
    peer.check_alive()?;
    let payload = Zeroizing::new(serde_json::to_vec(packet).map_err(|_| rejected("Continue relay encode"))?);
    if payload.len() > MAX_PACKET - 8 { return Err(rejected("Continue relay packet too large")); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(payload.len() + 8));
    bytes.extend_from_slice(&PREFIX);
    bytes.extend_from_slice(&[local as u8, 0, 0]);
    bytes.extend_from_slice(&payload);
    // One nonblocking attempt, never a retry or an unbounded UI/role wait.
    let sent = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent != bytes.len() as isize { return Err(rejected("Continue relay send unavailable")); }
    peer.check_alive()
}

pub(super) fn try_receive(fd: RawFd, local: Role, peer: &PeerLifetime) -> Result<Option<Packet>> {
    peer.check_alive()?;
    let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 { return Err(std::io::Error::last_os_error()); }
    if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 { return Err(rejected("Continue relay channel lost")); }
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
    let cred = inspect_ancillary(&header, &control)?.ok_or_else(|| rejected("Continue relay missing sender"))?;
    if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || read < 9
        || cred.pid != peer.pid() || cred.uid != peer.uid()
        || bytes[..5] != PREFIX || bytes[5] != peer.role() as u8 || bytes[6..8] != [0, 0]
    { return Err(rejected("Continue relay frame or sender rejected")); }
    let packet: Packet = serde_json::from_slice(&bytes[8..read as usize]).map_err(|_| rejected("Continue relay grammar rejected"))?;
    check_direction(peer.role(), local, &packet)?;
    peer.check_alive()?;
    Ok(Some(packet))
}

fn check_direction(sender: Role, recipient: Role, packet: &Packet) -> Result<()> {
    let down = matches!(packet, Packet::PrepareOnce{..}|Packet::Arm{..}|Packet::Final{..}|Packet::Cancel{..});
    let edge = if down { (sender == Role::Coordinator && recipient == Role::Host)
        || (sender == Role::Host && matches!(recipient, Role::Signer1|Role::Signer2)) }
        else { (recipient == Role::Coordinator && sender == Role::Host)
        || (recipient == Role::Host && matches!(sender, Role::Signer1|Role::Signer2)) };
    let actual_s = if matches!(sender, Role::Signer1|Role::Signer2) { Some(sender) }
        else if matches!(recipient, Role::Signer1|Role::Signer2) { Some(recipient) } else { None };
    if !edge || actual_s.zip(packet.target()).is_some_and(|(actual, claimed)| actual != claimed.role()) {
        Err(rejected("Continue original relay direction rejected"))
    } else { Ok(()) }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn continue_grammar_has_no_direct_coordinator_signer_or_claimed_grant_import() {
        let p = Packet::Cancel{coordinator:"a".repeat(64)};
        assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());
        assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());
        assert!(check_direction(Role::Coordinator,Role::Signer1,&p).is_err());
        for text in [r#"{"kind":"Approve","approved":true}"#, r#"{"kind":"Cancel","coordinator":"a","coordinator":"b"}"#, r#"{"kind":"Cancel","coordinator":"a","fd":3}"#] { assert!(serde_json::from_str::<Packet>(text).is_err()); }
    }
}

#[cfg(test)] pub(super) fn sample_binding() -> Binding {
    let review=SignerContinueReviewDataV1{coordinator_process_instance:"a".repeat(64),coordinator_focus_epoch:1,signer_role:SignerContinueRoleV1::Signer1,
        signer_process_instance:"b".repeat(64),original_host_process_instance:"c".repeat(64),signer_principal_id:"signer-1".into(),signer_image_measurement:"d".repeat(64),
        source_identity_digest:"e".repeat(64),terms_digest:"f".repeat(64),session_digest:"1".repeat(64),review_challenge:"2".repeat(64),review_digest:"3".repeat(64),
        reviewed_at_ms:1000,expires_at_ms:121000,session_expires_at_ms:200000};
    let mut presentation=SignerContinuePresentationV1{review,display:"Exact source facts and request, conditional Continue only".into(),request_json:"{\"frozen\":true}".into(),request_digest:String::new(),prepared_digest:"4".repeat(64),presentation_digest:String::new()};
    presentation.request_digest=SignerContinuePresentationV1::calculate_request_digest(&presentation.request_json);
    presentation.presentation_digest=presentation.calculate_presentation_digest().unwrap();
    Binding{context:Context{coordinator:"a".repeat(64),role:SignerContinueRoleV1::Signer1,slot_challenge:"5".repeat(64),native_deadline_ms:120000},presentation,source_deadline_ms:240000,review_deadline_ms:120000}
}
#[cfg(test)] mod binding_tests {
    use super::*;
    #[test] fn full_presentation_commits_exact_request_review_source_role_and_prepared_ticket() {
        let b=sample_binding();b.validate().unwrap();
        for n in 0..9 {let mut x=b.clone();match n {
            0=>x.presentation.request_json.push(' '),1=>x.presentation.display.push('!'),2=>x.presentation.review.source_identity_digest="0".repeat(64),
            3=>x.presentation.review.signer_role=SignerContinueRoleV1::Signer2,4=>x.presentation.prepared_digest="0".repeat(64),
            5=>x.presentation.review.original_host_process_instance="0".repeat(64),6=>x.presentation.review.coordinator_focus_epoch=2,
            7=>x.presentation.review.expires_at_ms+=1,_=>x.presentation.review.review_challenge="0".repeat(64),}
            assert!(x.validate().is_err());}
        let bytes=serde_json::to_vec(&b).unwrap();assert_eq!(serde_json::from_slice::<Binding>(&bytes).unwrap(),b);
    }
    #[test] fn continued_outcome_cannot_substitute_another_prepared_effect_or_presentation() {
        let b=sample_binding();let mut outcome=SignerContinueOutcomeV1::Continued{presentation_digest:b.presentation.presentation_digest.clone(),prepared_digest:b.presentation.prepared_digest.clone()};
        assert!(outcome.matches(&b.presentation));
        if let SignerContinueOutcomeV1::Continued{prepared_digest,..}=&mut outcome{*prepared_digest="0".repeat(64);}assert!(!outcome.matches(&b.presentation));
    }
}
