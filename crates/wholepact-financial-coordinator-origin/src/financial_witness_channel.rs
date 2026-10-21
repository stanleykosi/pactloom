//! Closed original financial-continuation W grammar. Data alone is not authority.
use crate::{channel::inspect_ancillary,process::{PeerLifetime,Role},rejected,Result,
    FinancialActorContextV1,SignerContinuePresentationV1,DeliveryFailureV1,
    signer_continue_state::hash,financial_workflow_clock::{PROFILE,SUPERVISION_MS}};
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use std::os::fd::RawFd;
use zeroize::Zeroizing;
const MAX_PACKET:usize=65_536;
const PREFIX:[u8;5]=*b"WPFW\x01";
pub const FINANCIAL_WITNESS_PURPOSE:&str="original-financial-continuation-append";
pub const FINANCIAL_WITNESS_MODE:&str="one-exact-append";

#[derive(Default,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialWitnessInputsV1 {
    pub endpoint:String,pub server_name:String,pub witness_id:String,pub pinned_server_certificate_digest:String,
    pub network_profile_id:String,pub expected_account_id:String,pub owner_certificate_der_hex:String,
    pub storage_key_file:String,pub server_certificate_der:String,pub server_private_key_pkcs8_der:String,
    pub trusted_client_root_der:String,pub request_json:String,
}
impl FinancialWitnessInputsV1 {
    pub fn validate(&self)->Result<()> {
        if [&self.endpoint,&self.server_name,&self.witness_id,&self.network_profile_id].iter().any(|s|s.is_empty()||s.len()>4096||s.contains('\0'))
            || !hash(&self.pinned_server_certificate_digest)||!hash(&self.expected_account_id)
            ||self.owner_certificate_der_hex.is_empty()||self.owner_certificate_der_hex.len()>32768
            ||self.owner_certificate_der_hex.len()%2!=0||!self.owner_certificate_der_hex.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
            ||[&self.storage_key_file,&self.server_certificate_der,&self.server_private_key_pkcs8_der,&self.trusted_client_root_der].iter()
                .any(|s|!s.starts_with('/')||s.len()>4096||s.bytes().any(|b|b<0x20||b==0x7f))
            ||self.request_json.is_empty()||self.request_json.len()>32768
            ||serde_json::to_vec(self).map_err(|_|rejected("financial Witness input encoding"))?.len()>60*1024
        {return Err(rejected("financial Witness input shape"));}Ok(())
    }
}
#[derive(Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialWitnessContinuationV1 {
    pub actor:FinancialActorContextV1,pub continue_presentation_digest:String,pub prepared_digest:String,
    pub signer_source_identity_digest:String,pub admission_terms_digest:String,pub request_json:String,pub request_digest:String,
    pub source_ceiling_ms:u64,pub source_expires_at_ms:u64,
}
impl FinancialWitnessContinuationV1 {
    pub fn validate(&self)->Result<()> {
        self.actor.validate()?;
        if self.actor.profile!=PROFILE||![&self.continue_presentation_digest,&self.prepared_digest,&self.signer_source_identity_digest,
            &self.admission_terms_digest,&self.request_digest].iter().all(|v|hash(v))
            ||self.request_json.is_empty()||self.request_json.len()>32768
            ||self.request_digest!=SignerContinuePresentationV1::calculate_request_digest(&self.request_json)
            ||self.source_ceiling_ms==0||self.source_ceiling_ms>SUPERVISION_MS||self.source_expires_at_ms==0
        {return Err(rejected("financial Witness original continuation binding"));}Ok(())
    }
    pub fn commitment(&self)->Result<String>{digest(b"wholepact:financial-witness:continuation:v1\0",self)}
}
#[derive(Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialWitnessPresentationV1 {
    pub version:u16,pub purpose:String,pub mode:String,pub display:String,pub backend_review_digest:String,
    pub presentation_digest:String,pub prepared_at_ms:u64,pub expires_at_ms:u64,pub account_id:String,pub operation_id:String,
    pub request_commitment:String,pub source_commitment:String,pub owner_certificate_digest:String,
    pub expected_head_sequence:u64,pub expected_head_digest:String,pub continuation:FinancialWitnessContinuationV1,
}
impl FinancialWitnessPresentationV1 {
    pub fn calculate_presentation_digest(&self)->Result<String>{
        digest(b"wholepact:financial-witness:presentation:v1\0",&(&self.version,&self.purpose,&self.mode,&self.display,
            &self.backend_review_digest,self.prepared_at_ms,self.expires_at_ms,&self.account_id,&self.operation_id,
            &self.request_commitment,&self.source_commitment,&self.owner_certificate_digest,self.expected_head_sequence,
            &self.expected_head_digest,&self.continuation))
    }
    pub fn validate(&self)->Result<()> {
        self.continuation.validate()?;
        if self.version!=1||self.purpose!=FINANCIAL_WITNESS_PURPOSE||self.mode!=FINANCIAL_WITNESS_MODE
            ||self.display.is_empty()||self.display.len()>32768||!ascii_display(&self.display)
            ||![&self.backend_review_digest,&self.presentation_digest,&self.account_id,&self.request_commitment,
                &self.source_commitment,&self.owner_certificate_digest,&self.expected_head_digest].iter().all(|v|hash(v))
            ||!identifier(&self.operation_id)||self.expected_head_sequence==u64::MAX
            ||self.request_commitment!=self.continuation.request_digest
            ||self.expires_at_ms.checked_sub(self.prepared_at_ms).is_none_or(|n|n==0||n>120_000)
            ||self.expires_at_ms>self.continuation.source_expires_at_ms
            ||self.presentation_digest!=self.calculate_presentation_digest()?
            ||serde_json::to_vec(self).map_err(|_|rejected("financial Witness complete encoding"))?.len()>60*1024
        {return Err(rejected("financial Witness complete presentation"));}Ok(())
    }
}
#[derive(Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialWitnessReadyV1 {
    pub presentation_digest:String,pub effect_commitment:String,pub request_commitment:String,pub source_commitment:String,
    pub owner_certificate_digest:String,pub expected_head_sequence:u64,pub expected_head_digest:String,
    pub accepted_at_ms:u64,pub accepted_tls_expires_at_ms:u64,
}
impl FinancialWitnessReadyV1 {
    pub(super) fn matches(&self,p:&FinancialWitnessPresentationV1)->bool {
        self.presentation_digest==p.presentation_digest&&hash(&self.effect_commitment)&&self.request_commitment==p.request_commitment
            &&self.source_commitment==p.source_commitment&&self.owner_certificate_digest==p.owner_certificate_digest
            &&self.expected_head_sequence==p.expected_head_sequence&&self.expected_head_digest==p.expected_head_digest
            &&self.accepted_at_ms>=p.prepared_at_ms&&self.accepted_at_ms<p.expires_at_ms
            &&self.accepted_tls_expires_at_ms.checked_sub(self.accepted_at_ms)==Some(10_000)
    }
}
#[derive(Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(tag="outcome",deny_unknown_fields)]
pub enum FinancialWitnessOutcomeV1 {
    Committed{presentation_digest:String,effect_commitment:String,head_sequence:u64,head_digest:String},
    KnownNoEffect{presentation_digest:String,effect_commitment:Option<String>},
    Uncertain{presentation_digest:String,effect_commitment:Option<String>},
}
impl FinancialWitnessOutcomeV1 {
    pub(super) fn matches(&self,p:&FinancialWitnessPresentationV1,ready:Option<&FinancialWitnessReadyV1>)->bool{
        match self{
            Self::Committed{presentation_digest,effect_commitment,head_sequence,head_digest}=>presentation_digest==&p.presentation_digest
                &&ready.is_some_and(|r|&r.effect_commitment==effect_commitment)&&p.expected_head_sequence.checked_add(1)==Some(*head_sequence)&&hash(head_digest),
            Self::KnownNoEffect{presentation_digest,effect_commitment}|Self::Uncertain{presentation_digest,effect_commitment}=>
                presentation_digest==&p.presentation_digest&&effect_commitment.as_deref()==ready.map(|r|r.effect_commitment.as_str()),
        }
    }
}
#[derive(Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Setup {
    pub continuation:FinancialWitnessContinuationV1,pub inputs:FinancialWitnessInputsV1,
    pub setup_challenge:String,pub setup_ceiling_ms:u64,
}
impl Setup {
    pub(super) fn validate(&self)->Result<()>{self.continuation.validate()?;self.inputs.validate()?;
        if self.inputs.request_json!=self.continuation.request_json||!hash(&self.setup_challenge)
            ||self.setup_ceiling_ms==0||self.setup_ceiling_ms>self.continuation.source_ceiling_ms
        {return Err(rejected("financial Witness setup mismatch"));}Ok(())}
}
#[derive(Serialize,Deserialize)]
#[serde(tag="kind",deny_unknown_fields)]
pub(super) enum Packet {
    PrepareOnce{setup:Setup},
    Display{setup_challenge:String,witness_instance:String,review_challenge:String,review_ceiling_ms:u64,data:FinancialWitnessPresentationV1},
    Arm{setup_challenge:String,witness_instance:String,review_challenge:String,presentation_digest:String},
    Armed{setup_challenge:String,witness_instance:String,presentation_digest:String},
    Ready{setup_challenge:String,witness_instance:String,review_challenge:String,ready_challenge:String,accepted_ceiling_ms:u64,data:FinancialWitnessReadyV1},
    FinalAdmit{setup_challenge:String,witness_instance:String,review_challenge:String,ready_challenge:String,effect_commitment:String},
    Cancel{coordinator:String,session:String},
    Outcome{setup_challenge:String,witness_instance:String,data:FinancialWitnessOutcomeV1},
    FirstFailure{setup_challenge:String,data:DeliveryFailureV1},
    PreparationFailed{setup_challenge:String},
    Disposed{coordinator:String,session:String,cleanup_ceiling_ms:u64},
    ClosePurpose{coordinator:String,session:String},
    PurposeClosed{coordinator:String,session:String},
}
pub(super) fn is_financial_witness(role:Role)->bool{matches!(role,Role::Owner1FinancialContinuationAdmission|Role::Owner2FinancialContinuationAdmission)}
pub(super) fn role_for(target:crate::SignerContinueRoleV1)->Role{match target{crate::SignerContinueRoleV1::Signer1=>Role::Owner1FinancialContinuationAdmission,crate::SignerContinueRoleV1::Signer2=>Role::Owner2FinancialContinuationAdmission}}
fn identifier(s:&str)->bool{!s.is_empty()&&s.len()<=128&&s.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'-'|b'_'|b'.'|b':'))}
fn ascii_display(s:&str)->bool{s.bytes().all(|b|matches!(b,b'\n'|b'\t'|0x20..=0x7e))}
fn digest<T:Serialize>(domain:&[u8],value:&T)->Result<String>{let bytes=serde_json::to_vec(value).map_err(|_|rejected("financial Witness digest encode"))?;let mut h=Sha256::new();h.update(domain);h.update(bytes);Ok(hex::encode(h.finalize()))}

pub(super) fn send(fd: RawFd, local: Role, peer: &PeerLifetime, packet: &Packet) -> Result<()> {
    check_direction(local, peer.role(), packet)?;
    peer.check_alive()?;
    let payload = Zeroizing::new(serde_json::to_vec(packet).map_err(|_| rejected("financial Witness encode"))?);
    if payload.len() > MAX_PACKET - 8 { return Err(rejected("financial Witness packet too large")); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(payload.len() + 8));
    bytes.extend_from_slice(&PREFIX);
    bytes.extend_from_slice(&[local as u8, 0, 0]);
    bytes.extend_from_slice(&payload);
    // One nonblocking attempt, never a retry or an unbounded UI/role wait.
    let sent = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent != bytes.len() as isize { return Err(rejected("financial Witness send unavailable")); }
    peer.check_alive()
}

pub(super) fn send_positive(fd: RawFd, local: Role, peer: &PeerLifetime, packet: &Packet, phases: &crate::signer_continue_state::Phases, deadline: std::time::Instant) -> Result<crate::FinancialSendProgressV1> {
    if local != Role::Coordinator { return Err(rejected("positive sender is not original C")); }
    check_direction(local, peer.role(), packet)?;
    peer.check_alive()?;
    let payload = Zeroizing::new(serde_json::to_vec(packet).map_err(|_| rejected("financial Witness encode"))?);
    if payload.len() > MAX_PACKET - 8 { return Err(rejected("financial Witness packet too large")); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(payload.len() + 8));
    bytes.extend_from_slice(&PREFIX);
    bytes.extend_from_slice(&[local as u8, 0, 0]);
    bytes.extend_from_slice(&payload);
    // One nonblocking attempt, never a retry or an unbounded UI/role wait.
    // Encoding and original peer checks are complete. This exact retained cap
    // and SAME C atomic word are sampled immediately before the one syscall.
    peer.check_alive()?;crate::channel::require_time(deadline)?;
    if phases.positive_send_restricted()? { return Ok(crate::FinancialSendProgressV1::Restricted); }
    let sent = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent != bytes.len() as isize { return Err(rejected("financial Witness send unavailable")); }
    peer.check_alive()?;Ok(crate::FinancialSendProgressV1::Sent)
}

pub(super) fn try_receive(fd: RawFd, local: Role, peer: &PeerLifetime) -> Result<Option<Packet>> {
    peer.check_alive()?;
    let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 { return Err(std::io::Error::last_os_error()); }
    if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 { return Err(rejected("financial Witness channel lost")); }
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
    let cred = inspect_ancillary(&header, &control)?.ok_or_else(|| rejected("financial Witness missing sender"))?;
    if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || read < 9
        || cred.pid != peer.pid() || cred.uid != peer.uid()
        || bytes[..5] != PREFIX || bytes[5] != peer.role() as u8 || bytes[6..8] != [0, 0]
    { return Err(rejected("financial Witness frame or sender rejected")); }
    let packet: Packet = serde_json::from_slice(&bytes[8..read as usize]).map_err(|_| rejected("financial Witness grammar rejected"))?;
    check_direction(peer.role(), local, &packet)?;
    peer.check_alive()?;
    Ok(Some(packet))
}

fn check_direction(sender: Role, recipient: Role, packet: &Packet) -> Result<()> {
    let from_c = matches!(packet, Packet::PrepareOnce { .. } | Packet::Arm { .. } | Packet::FinalAdmit { .. } | Packet::Cancel { .. } | Packet::ClosePurpose { .. });
    if (from_c && sender == Role::Coordinator && is_financial_witness(recipient))
        || (!from_c && is_financial_witness(sender) && recipient == Role::Coordinator) { Ok(()) }
    else { Err(rejected("financial Witness role mismatch")) }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn presentation()->FinancialWitnessPresentationV1{
        let h="a".repeat(64);let request="{\"public_test\":1}".to_string();
        let continuation=FinancialWitnessContinuationV1{actor:crate::financial_workflow_channel::sample_entry().presentation.actor,
            continue_presentation_digest:h.clone(),prepared_digest:h.clone(),signer_source_identity_digest:h.clone(),admission_terms_digest:h.clone(),
            request_digest:SignerContinuePresentationV1::calculate_request_digest(&request),request_json:request,source_ceiling_ms:300000,source_expires_at_ms:300000};
        let mut p=FinancialWitnessPresentationV1{version:1,purpose:FINANCIAL_WITNESS_PURPOSE.into(),mode:FINANCIAL_WITNESS_MODE.into(),display:"Complete public test display".into(),
            backend_review_digest:h.clone(),presentation_digest:String::new(),prepared_at_ms:1000,expires_at_ms:121000,account_id:h.clone(),operation_id:"test-op".into(),
            request_commitment:continuation.request_digest.clone(),source_commitment:h.clone(),owner_certificate_digest:h.clone(),expected_head_sequence:4,expected_head_digest:h,continuation};
        p.presentation_digest=p.calculate_presentation_digest().unwrap();p
    }
    #[test]
    fn financial_witness_exact_public_schema_and_digest_are_closed(){
        let p=presentation();p.validate().unwrap();let bytes=serde_json::to_string(&p).unwrap();
        let copy:FinancialWitnessPresentationV1=serde_json::from_str(&bytes).unwrap();assert!(copy==p);
        assert!(serde_json::from_str::<FinancialWitnessPresentationV1>(&bytes.replacen('{',"{\"unknown\":1,",1)).is_err());
        assert!(serde_json::from_str::<FinancialWitnessPresentationV1>(&bytes.replacen('{',"{\"version\":1,",1)).is_err());
        for n in 0..6 {let mut q=p.clone();match n{0=>q.display.push('!'),1=>q.continuation.actor.signer_role=crate::SignerContinueRoleV1::Signer2,
            2=>q.continuation.request_json.push(' '),3=>q.expected_head_sequence+=1,4=>q.purpose="delivery-v3".into(),_=>q.expires_at_ms+=1}
            assert!(q.validate().is_err());}
    }
    #[test]
    fn financial_witness_ready_outcome_bind_original_source_peer_request_and_head(){
        let p=presentation();let r=FinancialWitnessReadyV1{presentation_digest:p.presentation_digest.clone(),effect_commitment:"b".repeat(64),request_commitment:p.request_commitment.clone(),
            source_commitment:p.source_commitment.clone(),owner_certificate_digest:p.owner_certificate_digest.clone(),expected_head_sequence:p.expected_head_sequence,expected_head_digest:p.expected_head_digest.clone(),accepted_at_ms:2000,accepted_tls_expires_at_ms:12000};
        assert!(r.matches(&p));for n in 0..5{let mut q=r.clone();match n{0=>q.source_commitment="c".repeat(64),1=>q.request_commitment="c".repeat(64),2=>q.owner_certificate_digest="c".repeat(64),3=>q.expected_head_sequence+=1,_=>q.accepted_tls_expires_at_ms+=1}assert!(!q.matches(&p));}
        let good=FinancialWitnessOutcomeV1::Committed{presentation_digest:p.presentation_digest.clone(),effect_commitment:r.effect_commitment.clone(),head_sequence:5,head_digest:"d".repeat(64)};
        assert!(good.matches(&p,Some(&r)));assert!(!good.matches(&p,None));
        let no=FinancialWitnessOutcomeV1::KnownNoEffect{presentation_digest:p.presentation_digest.clone(),effect_commitment:None};assert!(no.matches(&p,None));assert!(!no.matches(&p,Some(&r)));
    }
    #[test]
    fn financial_witness_complete_display_budget_rejects_without_truncation(){
        let mut p=presentation();p.display="x".repeat(32768);p.continuation.request_json="x".repeat(32768);
        p.continuation.request_digest=SignerContinuePresentationV1::calculate_request_digest(&p.continuation.request_json);p.request_commitment=p.continuation.request_digest.clone();
        p.presentation_digest=p.calculate_presentation_digest().unwrap();assert!(p.validate().is_err());
        let cancel=Packet::Cancel{coordinator:"a".repeat(64),session:"b".repeat(64)};
        assert!(check_direction(Role::Coordinator,Role::Owner1FinancialContinuationAdmission,&cancel).is_ok());
        assert!(check_direction(Role::Host,Role::Owner1FinancialContinuationAdmission,&cancel).is_err());
        assert!(check_direction(Role::Coordinator,Role::Owner1V3DeliveryAdmission,&cancel).is_err());
    }
}
