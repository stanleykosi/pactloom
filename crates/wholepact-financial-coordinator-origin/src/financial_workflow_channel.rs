//! Closed full-session SourceEntry/initial Read data. H is an explicitly trusted
//! relay; S authenticates H directly, not a fictional direct C/S channel.
use crate::{channel::inspect_ancillary, process::{PeerLifetime, Role}, rejected, Result,
    signer_continue_channel::SignerContinueRoleV1 as Target, signer_continue_state::hash,
    source_entry_envelope as envelope, financial_workflow_clock::{PROFILE, SUPERVISION_MS}};
use crate::financial_workflow_continue::{ContinueStart,ContinueWire,SignerContinuationSavedV1};
use crate::signer_continue_channel::SignerContinueOutcomeV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::fd::RawFd;
use zeroize::Zeroizing;
const MAX_PACKET: usize = 65_536;
const PREFIX: [u8; 5] = *b"WPFF\x01";
pub(super) const ENTRY_NOTICE: &str = "Unlock only this exact original Signer source. This does not authorize a history read, Continue or Admit. Cancel or loss of the original review remains restrictive through completion.";
pub(super) const READ_PURPOSE:&str="original-history-and-one-local-continue-preparation-v2";
pub(super) const READ_NOTICE: &str = "Read the complete original financial history from this exact selected owner and prepare exactly one immutable local Continue request from this same original Signer source. This does not authorize Continue, Admit or any mutation. Cancel remains restrictive through the history read and complete local preparation.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialActorContextV1 {
    pub profile: String,
    pub coordinator_process_instance: String,
    pub coordinator_focus_epoch: u64,
    pub signer_role: Target,
    pub signer_process_instance: String,
    pub common_image_measurement: String,
    pub session_challenge: String,
}
impl FinancialActorContextV1 {
    pub fn validate(&self) -> Result<()> {
        if self.profile != PROFILE || self.coordinator_focus_epoch != 1
            || ![&self.coordinator_process_instance, &self.signer_process_instance,
                &self.common_image_measurement, &self.session_challenge].iter().all(|v| hash(v))
        { return Err(rejected("full-workflow actor data rejected")); } Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSourceEntryFactsV1 {
    pub selection_digest: String,
    pub display: String,
    pub original_host_process_instance: String,
    pub account_id: String,
    pub owner_certificate_digest: String,
    pub disclosure_digest: String,
    pub terms_digest: String,
    pub session_digest: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerSourceEntryFactsV1 {
    pub fn validate(&self) -> Result<()> {
        if ![&self.selection_digest, &self.original_host_process_instance, &self.account_id,
            &self.owner_certificate_digest, &self.disclosure_digest, &self.terms_digest,
            &self.session_digest].iter().all(|v| hash(v)) || !display(&self.display)
        { return Err(rejected("source-entry facts rejected")); }
        wall_bounds(self.reviewed_at_ms, self.expires_at_ms, self.source_expires_at_ms)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSourceEntryPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerSourceEntryFactsV1,
    pub notice: String,
    pub sender_key_fingerprint: String,
    pub recipient_key_fingerprint: String,
    pub request_challenge: String,
    pub offer_challenge: String,
    pub native_ceiling_ms: u64,
    pub entry_ceiling_ms: u64,
    pub source_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerSourceEntryPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(b"wholepact:coordinated-source-entry:presentation:v1\0", &(
            &self.actor, &self.facts, &self.notice, &self.sender_key_fingerprint,
            &self.recipient_key_fingerprint, &self.request_challenge, &self.offer_challenge,
            self.native_ceiling_ms, self.entry_ceiling_ms, self.source_ceiling_ms))
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?; self.facts.validate()?;
        if self.notice != ENTRY_NOTICE || ![&self.sender_key_fingerprint, &self.recipient_key_fingerprint,
            &self.request_challenge, &self.offer_challenge, &self.presentation_digest].iter().all(|v|hash(v))
            || ![self.native_ceiling_ms, self.entry_ceiling_ms, self.source_ceiling_ms].iter().all(|v| offset(*v))
            || self.presentation_digest != self.calculate_presentation_digest()?
        { return Err(rejected("source-entry presentation rejected")); } Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFinancialReadFactsV1 {
    pub read_digest: String,
    pub display: String,
    pub source_identity_digest: String,
    pub original_journal_digest: String,
    pub terms_digest: String,
    pub original_delivery_operation_id: String,
    pub original_delivery_request_digest: String,
    pub original_delivery_head_sequence: u64,
    pub original_delivery_head_digest: String,
    pub original_host_process_instance: String,
    pub account_id: String,
    pub owner_certificate_digest: String,
    pub owner_selection_digest: String,
    pub disclosure_digest: String,
    pub session_digest: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerFinancialReadFactsV1 {
    pub fn calculate_read_digest(&self) -> Result<String> {
        // Nested tuples stay below serde's tuple arity limit; order is fixed.
        digest(b"wholepact:coordinated-initial-financial-history-read:facts:v2\0", &(2u16,READ_PURPOSE,
            (&self.display, &self.source_identity_digest, &self.original_journal_digest,
             &self.terms_digest, &self.original_delivery_operation_id, &self.original_delivery_request_digest,
             self.original_delivery_head_sequence, &self.original_delivery_head_digest),
            (&self.original_host_process_instance, &self.account_id, &self.owner_certificate_digest,
             &self.owner_selection_digest, &self.disclosure_digest, &self.session_digest,
             self.reviewed_at_ms, self.expires_at_ms, self.source_expires_at_ms)))
    }
    pub fn validate(&self) -> Result<()> {
        if !display(&self.display) || !identifier(&self.original_delivery_operation_id)
            || ![&self.read_digest, &self.source_identity_digest, &self.original_journal_digest,
                &self.terms_digest, &self.original_delivery_request_digest, &self.original_delivery_head_digest,
                &self.original_host_process_instance, &self.account_id, &self.owner_certificate_digest,
                &self.owner_selection_digest, &self.disclosure_digest, &self.session_digest].iter().all(|v|hash(v))
            || self.read_digest != self.calculate_read_digest()?
        { return Err(rejected("initial financial Read facts rejected")); }
        wall_bounds(self.reviewed_at_ms, self.expires_at_ms, self.source_expires_at_ms)
    }
    pub(super) fn matches_entry(&self, entry: &SignerSourceEntryFactsV1) -> bool {
        self.terms_digest == entry.terms_digest && self.original_host_process_instance == entry.original_host_process_instance
            && self.account_id == entry.account_id && self.owner_certificate_digest == entry.owner_certificate_digest
            && self.disclosure_digest == entry.disclosure_digest && self.session_digest == entry.session_digest
            && self.source_expires_at_ms == entry.source_expires_at_ms
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFinancialReadPresentationV1 {
    pub version:u16,
    pub purpose:String,
    pub actor: FinancialActorContextV1,
    pub facts: SignerFinancialReadFactsV1,
    pub notice: String,
    pub selection_digest: String,
    pub source_entry_presentation_digest: String,
    pub read_challenge: String,
    pub source_ceiling_ms: u64,
    pub read_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerFinancialReadPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(b"wholepact:coordinated-initial-financial-history-read:presentation:v2\0", &(
            self.version,&self.purpose,&self.actor, &self.facts, &self.notice, &self.selection_digest,
            &self.source_entry_presentation_digest, &self.read_challenge,
            self.source_ceiling_ms, self.read_ceiling_ms))
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?; self.facts.validate()?;
        if self.version!=2||self.purpose!=READ_PURPOSE||self.notice != READ_NOTICE || ![&self.selection_digest, &self.source_entry_presentation_digest,
            &self.read_challenge, &self.presentation_digest].iter().all(|v|hash(v))
            || !offset(self.source_ceiling_ms) || !offset(self.read_ceiling_ms)
            || self.presentation_digest != self.calculate_presentation_digest()?
        { return Err(rejected("initial financial Read presentation rejected")); } Ok(())
    }
    pub(super) fn matches_entry(&self, entry: &SignerSourceEntryPresentationV1) -> bool {
        self.actor == entry.actor && self.selection_digest == entry.facts.selection_digest
            && self.source_entry_presentation_digest == entry.presentation_digest
            && self.source_ceiling_ms == entry.source_ceiling_ms && self.facts.matches_entry(&entry.facts)
    }
}
fn digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_|rejected("workflow public encoding rejected"))?;
    let mut h=Sha256::new(); h.update(domain); h.update(bytes); Ok(hex::encode(h.finalize()))
}
fn display(s:&str)->bool { !s.is_empty() && s.len()<=32_768 && s.bytes().all(|b| b==b'\n'||b==b'\t'||(0x20..=0x7e).contains(&b)) }
fn identifier(s:&str)->bool { !s.is_empty() && s.len()<=128 && s.bytes().all(|b|b.is_ascii_alphanumeric()||b"-_.:".contains(&b)) }
fn offset(ms:u64)->bool {ms>0&&ms<=SUPERVISION_MS}
fn wall_bounds(start:u64,end:u64,source:u64)->Result<()> {
    if start==0||end<=start||end-start>120_000||end>source {Err(rejected("workflow original wall bounds rejected"))}else{Ok(())}
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Start {
    pub profile:String, pub coordinator:String, pub session:String, pub role:Target,
    pub request_challenge:String, pub native_ceiling_ms:u64, pub sender_public_key:String,
}
impl Start {
    pub(super) fn validate(&self)->Result<()> {
        if self.profile!=PROFILE || ![&self.coordinator,&self.session,&self.request_challenge,&self.sender_public_key].iter().all(|v|hash(v))
            || !offset(self.native_ceiling_ms) {Err(rejected("workflow start rejected"))}else{Ok(())}
    }
    fn matches_actor(&self,a:&FinancialActorContextV1)->bool {
        a.profile==self.profile&&a.coordinator_process_instance==self.coordinator&&a.session_challenge==self.session&&a.signer_role==self.role
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EntryOffer { pub start:Start, pub presentation:SignerSourceEntryPresentationV1, pub crypto:envelope::Binding }
impl EntryOffer {
    pub(super) fn validate(&self)->Result<()> {
        self.start.validate()?;self.presentation.validate()?;self.crypto.validate()?;
        let p=&self.presentation;let b=&self.crypto;
        let target=match p.actor.signer_role{Target::Signer1=>envelope::SourceEntryRole::Signer1,Target::Signer2=>envelope::SourceEntryRole::Signer2};
        if !self.start.matches_actor(&p.actor) || b.supervision_profile!=self.start.profile
            || b.coordinator_process_instance!=self.start.coordinator || b.session_challenge!=self.start.session
            || b.coordinator_focus_epoch!=p.actor.coordinator_focus_epoch || b.signer_role!=target
            || b.signer_process_instance!=p.actor.signer_process_instance || b.common_image_measurement!=p.actor.common_image_measurement
            || b.original_host_process_instance!=p.facts.original_host_process_instance
            || b.selection_digest!=p.facts.selection_digest || b.presentation_digest!=p.presentation_digest
            || b.account_id!=p.facts.account_id || b.owner_certificate_digest!=p.facts.owner_certificate_digest
            || b.disclosure_digest!=p.facts.disclosure_digest || b.terms_digest!=p.facts.terms_digest
            || b.request_challenge!=self.start.request_challenge || b.request_challenge!=p.request_challenge
            || b.offer_challenge!=p.offer_challenge || b.sender_public_key!=self.start.sender_public_key
            || b.sender_key_fingerprint!=p.sender_key_fingerprint || b.recipient_key_fingerprint!=p.recipient_key_fingerprint
            || b.native_ceiling_ms!=self.start.native_ceiling_ms || b.native_ceiling_ms!=p.native_ceiling_ms
            || b.entry_ceiling_ms!=p.entry_ceiling_ms || b.source_ceiling_ms!=p.source_ceiling_ms
            || b.reviewed_at_ms!=p.facts.reviewed_at_ms || b.expires_at_ms!=p.facts.expires_at_ms || b.source_expires_at_ms!=p.facts.source_expires_at_ms
        {return Err(rejected("workflow source-entry offer mismatch"));}Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinancialWorkflowStageV1 { SourceEntry, InitialRead, Continue }
#[derive(Serialize,Deserialize)]
#[serde(tag="kind",deny_unknown_fields)]
pub(super) enum Packet {
    CompletedPairServing{data:crate::CompletedPairPresentationV1,witness_instance:String,serve_challenge:String,service_ceiling_ms:u64},
    RetireRequest{request:crate::host_interstage::RetirementRequest},
    RetireQuiescent{request:crate::host_interstage::RetirementRequest},
    RetireResume{request:crate::host_interstage::RetirementRequest},
    RetireResumed{request:crate::host_interstage::RetirementRequest},
    OriginalHostPeer{role:Target,host_instance:String},
    StartEntry{start:Start}, EntryOffer{offer:EntryOffer},
    EntryCipher{envelope:String},
    SourceRetained{start:Start,presentation_digest:String},
    ReadOffer{start:Start,presentation:SignerFinancialReadPresentationV1},
    ReadFinal{start:Start,presentation_digest:String,read_digest:String,read_challenge:String},
    HistoryRetained{start:Start,presentation_digest:String,read_digest:String,continue_review_ceiling_ms:u64},
    ContinuePrepare{context:ContinueStart},
    ContinueDisplay{binding:ContinueWire},
    ContinueArm{context:ContinueStart,presentation_digest:String,prepared_digest:String},
    ContinueReady{context:ContinueStart,presentation_digest:String,prepared_digest:String,ready_challenge:String},
    ContinueFinal{context:ContinueStart,presentation_digest:String,prepared_digest:String,ready_challenge:String},
    ContinuationSaved{context:ContinueStart,data:SignerContinuationSavedV1},
    ContinueOutcome{context:ContinueStart,data:SignerContinueOutcomeV1},
    WriterReadDisplay{data:crate::SignerFinancialWriterReadPresentationV1},
    WriterReadFinal{actor:FinancialActorContextV1,presentation_digest:String,read_challenge:String,service:crate::FinancialSigningServiceV1},
    WriterReadFailed{actor:FinancialActorContextV1,presentation_digest:String},
    AcquireDisplay{data:crate::SignerAcquirePresentationV1},
    AcquireArm{actor:FinancialActorContextV1,presentation_digest:String,recipe_digest:String},
    AcquireReady{actor:FinancialActorContextV1,presentation_digest:String,recipe_digest:String,ready_challenge:String,acquire_ready_digest:String},
    AcquireFinal{actor:FinancialActorContextV1,presentation_digest:String,recipe_digest:String,ready_challenge:String,acquire_ready_digest:String,service:crate::FinancialSigningServiceV1},
    AcquireOutcome{actor:FinancialActorContextV1,data:crate::SignerAcquireOutcomeV1},
    Acquired{actor:FinancialActorContextV1,data:crate::SignerAcquireCommittedV1,writer_session_ceiling_ms:u64},
    ActivateReadDisplay{data:crate::SignerActivateReadPresentationV1},
    ActivateReadFinal{actor:FinancialActorContextV1,presentation_digest:String,read_challenge:String,service:crate::FinancialSigningServiceV1},
    ActivateReadFailed{actor:FinancialActorContextV1,presentation_digest:String},
    ActivateDisplay{data:crate::SignerActivatePresentationV1},
    ActivateArm{actor:FinancialActorContextV1,presentation_digest:String,recipe_digest:String},
    ActivateReady{actor:FinancialActorContextV1,presentation_digest:String,recipe_digest:String,ready_challenge:String,activate_ready_digest:String},
    ActivateFinal{actor:FinancialActorContextV1,presentation_digest:String,recipe_digest:String,ready_challenge:String,activate_ready_digest:String,service:crate::FinancialSigningServiceV1},
    ActivateOutcome{actor:FinancialActorContextV1,data:crate::SignerActivateOutcomeV1},
    Activated{actor:FinancialActorContextV1,data:crate::SignerActivateCommittedV1},
    AdmitDisplay{data:crate::SignerAdmitPresentationV1},
    AdmitArm{actor:FinancialActorContextV1,presentation_digest:String},
    AdmitReady{actor:FinancialActorContextV1,presentation_digest:String,ready_challenge:String,admission_ready_digest:String},
    AdmitFinal{actor:FinancialActorContextV1,presentation_digest:String,ready_challenge:String,admission_ready_digest:String,witness_presentation_digest:String},
    Admitted{actor:FinancialActorContextV1,data:crate::SignerAdmitCommittedV1},
    AdmitOutcome{actor:FinancialActorContextV1,data:crate::SignerAdmitOutcomeV1},
    Failed{start:Start,stage:FinancialWorkflowStageV1},
    Cancel{coordinator:String,session:String},
    Disposed{coordinator:String,session:String,role:Target},
}
impl Packet {
    pub(super) fn target(&self)->Result<Option<Target>> {Ok(match self {
        Self::OriginalHostPeer{role,host_instance}=>{if !hash(host_instance){return Err(rejected("original H handshake shape"));}Some(*role)},
        Self::CompletedPairServing{data,witness_instance,serve_challenge,service_ceiling_ms}=>{data.validate()?;
            if !hash(witness_instance)||!hash(serve_challenge)||*service_ceiling_ms==0||data.original.owners.iter().any(|o|*service_ceiling_ms>o.source_ceiling_ms){return Err(rejected("Pair service observation shape"));}None},
        Self::WriterReadDisplay{data}=>{data.validate()?;Some(data.actor.signer_role)},
        Self::AcquireDisplay{data}=>{data.validate()?;Some(data.actor.signer_role)},
        Self::WriterReadFinal{actor,presentation_digest,read_challenge,service}=>{
            actor.validate()?;service.validate()?;
            if !hash(presentation_digest)||!hash(read_challenge)||actor!=&service.original.actor{return Err(rejected("Writer Read Final shape"));}Some(actor.signer_role)},
        Self::WriterReadFailed{actor,presentation_digest}=>{actor.validate()?;if !hash(presentation_digest){return Err(rejected("Writer Read failure shape"));}Some(actor.signer_role)},
        Self::AcquireArm{actor,presentation_digest,recipe_digest}=>{actor.validate()?;
            if !hash(presentation_digest)||!hash(recipe_digest){return Err(rejected("Acquire Arm shape"));}Some(actor.signer_role)},
        Self::AcquireReady{actor,presentation_digest,recipe_digest,ready_challenge,acquire_ready_digest}=>{actor.validate()?;
            if ![presentation_digest,recipe_digest,ready_challenge,acquire_ready_digest].iter().all(|v|hash(v)){return Err(rejected("Acquire Ready shape"));}Some(actor.signer_role)},
        Self::AcquireFinal{actor,presentation_digest,recipe_digest,ready_challenge,acquire_ready_digest,service}=>{actor.validate()?;service.validate()?;
            if ![presentation_digest,recipe_digest,ready_challenge,acquire_ready_digest].iter().all(|v|hash(v))||actor!=&service.original.actor{return Err(rejected("Acquire Final shape"));}Some(actor.signer_role)},
        Self::AcquireOutcome{actor,data}=>{actor.validate()?;data.validate()?;Some(actor.signer_role)},
        Self::Acquired{actor,data,writer_session_ceiling_ms}=>{actor.validate()?;data.validate()?;
            if *writer_session_ceiling_ms==0||*writer_session_ceiling_ms>SUPERVISION_MS{return Err(rejected("Acquire original writer-session offset"));}Some(actor.signer_role)},
        Self::ActivateReadDisplay{data}=>{data.validate()?;Some(data.actor.signer_role)},
        Self::ActivateDisplay{data}=>{data.validate()?;Some(data.actor.signer_role)},
        Self::ActivateReadFinal{actor,presentation_digest,read_challenge,service}=>{
            actor.validate()?;service.validate()?;
            if !hash(presentation_digest)||!hash(read_challenge)||actor!=&service.original.actor{return Err(rejected("Activate Read Final shape"));}Some(actor.signer_role)},
        Self::ActivateReadFailed{actor,presentation_digest}=>{actor.validate()?;if !hash(presentation_digest){return Err(rejected("Activate Read failure shape"));}Some(actor.signer_role)},
        Self::ActivateArm{actor,presentation_digest,recipe_digest}=>{actor.validate()?;
            if !hash(presentation_digest)||!hash(recipe_digest){return Err(rejected("Activate Arm shape"));}Some(actor.signer_role)},
        Self::ActivateReady{actor,presentation_digest,recipe_digest,ready_challenge,activate_ready_digest}=>{actor.validate()?;
            if ![presentation_digest,recipe_digest,ready_challenge,activate_ready_digest].iter().all(|v|hash(v)){return Err(rejected("Activate Ready shape"));}Some(actor.signer_role)},
        Self::ActivateFinal{actor,presentation_digest,recipe_digest,ready_challenge,activate_ready_digest,service}=>{actor.validate()?;service.validate()?;
            if ![presentation_digest,recipe_digest,ready_challenge,activate_ready_digest].iter().all(|v|hash(v))||actor!=&service.original.actor{return Err(rejected("Activate Final shape"));}Some(actor.signer_role)},
        Self::ActivateOutcome{actor,data}=>{actor.validate()?;data.validate()?;Some(actor.signer_role)},
        Self::Activated{actor,data}=>{actor.validate()?;data.validate()?;Some(actor.signer_role)},
        Self::RetireRequest{..}|Self::RetireQuiescent{..}|Self::RetireResume{..}|Self::RetireResumed{..}=>None,
        Self::StartEntry{start}|Self::SourceRetained{start,..}|Self::ReadOffer{start,..}|Self::ReadFinal{start,..}|Self::HistoryRetained{start,..}|Self::Failed{start,..}=>Some(start.role),
        Self::ContinuePrepare{context}|Self::ContinueArm{context,..}|Self::ContinueReady{context,..}|Self::ContinueFinal{context,..}
            |Self::ContinuationSaved{context,..}|Self::ContinueOutcome{context,..}=>Some(context.start.role),
        Self::ContinueDisplay{binding}=>Some(binding.context.start.role),
        Self::AdmitDisplay{data}=>Some(data.actor.signer_role),
        Self::AdmitArm{actor,..}|Self::AdmitReady{actor,..}|Self::AdmitFinal{actor,..}|Self::Admitted{actor,..}|Self::AdmitOutcome{actor,..}=>Some(actor.signer_role),
        Self::EntryOffer{offer}=>Some(offer.start.role), Self::Disposed{role,..}=>Some(*role),Self::Cancel{..}=>None,
        Self::EntryCipher{envelope}=>Some(match crate::source_entry_envelope::Envelope::decode(envelope.as_bytes())?.binding().signer_role {
            crate::source_entry_envelope::SourceEntryRole::Signer1=>Target::Signer1,
            crate::source_entry_envelope::SourceEntryRole::Signer2=>Target::Signer2}),
    })}
}
fn payload(packet:&Packet)->Result<Vec<u8>> {
    let bytes=serde_json::to_vec(packet).map_err(|_|rejected("workflow packet encoding"))?;
    let limit=if matches!(packet,Packet::EntryCipher{..}){envelope::FRAME_LIMIT}else{MAX_PACKET};
    if bytes.len()>limit-8 {return Err(rejected("workflow packet oversized"));}Ok(bytes)
}
/// A consumed positive outbound was either sent once or restricted before any
/// transport attempt. Restricted is never a post-attempt/no-effect assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinancialSendProgressV1 { Sent, Restricted }
impl FinancialSendProgressV1 {
    pub(super) fn require_sent(self)->Result<()>{match self{Self::Sent=>Ok(()),Self::Restricted=>Err(rejected("positive workflow send restricted before attempt"))}}
}
pub(super) fn send(fd:RawFd,local:Role,peer:&PeerLifetime,packet:&Packet)->Result<()> {
    check_direction(local,peer.role(),packet)?;peer.check_alive()?;
    let body=Zeroizing::new(payload(packet)?);let mut bytes=Zeroizing::new(Vec::with_capacity(body.len()+8));
    bytes.extend_from_slice(&PREFIX);bytes.extend_from_slice(&[local as u8,0,0]);bytes.extend_from_slice(&body);
    let sent=unsafe{libc::send(fd,bytes.as_ptr().cast(),bytes.len(),libc::MSG_NOSIGNAL|libc::MSG_DONTWAIT)};
    if sent!=bytes.len() as isize{return Err(rejected("workflow send unavailable"));}peer.check_alive()
}
pub(super) fn send_positive(fd:RawFd,local:Role,peer:&PeerLifetime,packet:&Packet,phases:&crate::signer_continue_state::Phases,deadline:std::time::Instant)->Result<crate::FinancialSendProgressV1> {
    if local != Role::Coordinator { return Err(rejected("positive sender is not original C")); }
    check_direction(local,peer.role(),packet)?;peer.check_alive()?;
    let body=Zeroizing::new(payload(packet)?);let mut bytes=Zeroizing::new(Vec::with_capacity(body.len()+8));
    bytes.extend_from_slice(&PREFIX);bytes.extend_from_slice(&[local as u8,0,0]);bytes.extend_from_slice(&body);
    // Encoding and original peer checks are complete. This exact retained cap
    // and SAME C atomic word are sampled immediately before the one syscall.
    peer.check_alive()?;crate::channel::require_time(deadline)?;
    if phases.positive_send_restricted()? { return Ok(crate::FinancialSendProgressV1::Restricted); }
    let sent=unsafe{libc::send(fd,bytes.as_ptr().cast(),bytes.len(),libc::MSG_NOSIGNAL|libc::MSG_DONTWAIT)};
    if sent!=bytes.len() as isize{return Err(rejected("workflow send unavailable"));}peer.check_alive()?;Ok(crate::FinancialSendProgressV1::Sent)
}
pub(super) fn try_receive(fd:RawFd,local:Role,peer:&PeerLifetime)->Result<Option<Packet>> {
    peer.check_alive()?;let mut poll=libc::pollfd{fd,events:libc::POLLIN,revents:0};
    let status=unsafe{libc::poll(&mut poll,1,0)};
    if status<0{return Err(std::io::Error::last_os_error());}
    if poll.revents&(libc::POLLHUP|libc::POLLERR|libc::POLLNVAL)!=0{return Err(rejected("workflow edge lost"));}
    if status==0||poll.revents&libc::POLLIN==0{return Ok(None);}
    let mut bytes=Zeroizing::new(vec![0u8;MAX_PACKET]);let mut control=[0usize;64];
    let mut iov=libc::iovec{iov_base:bytes.as_mut_ptr().cast(),iov_len:bytes.len()};
    let mut h:libc::msghdr=unsafe{std::mem::zeroed()};h.msg_iov=&mut iov;h.msg_iovlen=1;
    h.msg_control=control.as_mut_ptr().cast();h.msg_controllen=std::mem::size_of_val(&control);
    let count=unsafe{libc::recvmsg(fd,&mut h,libc::MSG_CMSG_CLOEXEC|libc::MSG_DONTWAIT)};
    if count<0{return Err(std::io::Error::last_os_error());}
    let cred=inspect_ancillary(&h,&control)?.ok_or_else(||rejected("workflow sender missing"))?;
    if h.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)!=0||count<9||cred.pid!=peer.pid()||cred.uid!=peer.uid()
        ||bytes[..5]!=PREFIX||bytes[5]!=peer.role() as u8||bytes[6..8]!=[0,0]
    {return Err(rejected("workflow frame or original sender rejected"));}
    let packet:Packet=serde_json::from_slice(&bytes[8..count as usize]).map_err(|_|rejected("workflow grammar rejected"))?;
    if matches!(packet,Packet::EntryCipher{..})&&count as usize>envelope::FRAME_LIMIT{return Err(rejected("workflow ciphertext frame oversized"));}
    check_direction(peer.role(),local,&packet)?;peer.check_alive()?;Ok(Some(packet))
}
fn check_direction(sender:Role,recipient:Role,packet:&Packet)->Result<()> {
    if matches!(packet,Packet::CompletedPairServing{..}){
        packet.target()?;
        return if sender==Role::Coordinator&&recipient==Role::Host{Ok(())}else{Err(rejected("Pair service observation not original C/H"))};
    }
    if matches!(packet,Packet::RetireRequest{..}|Packet::RetireResume{..}){
        return if sender==Role::Coordinator&&recipient==Role::Host{Ok(())}else{Err(rejected("retirement control not original C/H"))};
    }
    if matches!(packet,Packet::RetireQuiescent{..}|Packet::RetireResumed{..}){
        return if sender==Role::Host&&recipient==Role::Coordinator{Ok(())}else{Err(rejected("retirement observation not original H/C"))};
    }

    if let Packet::OriginalHostPeer{role,host_instance}=packet {
        return if sender==Role::Host && recipient==role.role() && hash(host_instance){Ok(())}else{Err(rejected("original H handshake direction rejected"))};
    }
    let down=matches!(packet,Packet::ActivateReadFinal{..}|Packet::ActivateArm{..}|Packet::ActivateFinal{..}|Packet::WriterReadFinal{..}|Packet::AcquireArm{..}|Packet::AcquireFinal{..}|Packet::StartEntry{..}|Packet::EntryCipher{..}|Packet::ReadFinal{..}|Packet::ContinuePrepare{..}|Packet::ContinueArm{..}|Packet::ContinueFinal{..}|Packet::AdmitArm{..}|Packet::AdmitFinal{..}|Packet::Cancel{..});
    let edge=if down{sender==Role::Coordinator&&recipient==Role::Host||sender==Role::Host&&matches!(recipient,Role::Signer1|Role::Signer2)}
        else{recipient==Role::Coordinator&&sender==Role::Host||recipient==Role::Host&&matches!(sender,Role::Signer1|Role::Signer2)};
    let actual=if matches!(sender,Role::Signer1|Role::Signer2){Some(sender)}else if matches!(recipient,Role::Signer1|Role::Signer2){Some(recipient)}else{None};
    if !edge||actual.zip(packet.target()?).is_some_and(|(a,b)|a!=b.role()){Err(rejected("workflow direction rejected"))}else{Ok(())}
}

#[cfg(test)]
pub(super) fn sample_entry()->EntryOffer {
    let h="a".repeat(64);let sender=[1u8;32];let recipient=[2u8;32];
    let start=Start{profile:PROFILE.into(),coordinator:h.clone(),session:h.clone(),role:Target::Signer1,
        request_challenge:h.clone(),native_ceiling_ms:120000,sender_public_key:hex::encode(sender)};
    let actor=FinancialActorContextV1{profile:PROFILE.into(),coordinator_process_instance:h.clone(),coordinator_focus_epoch:1,signer_role:Target::Signer1,
        signer_process_instance:h.clone(),common_image_measurement:h.clone(),session_challenge:h.clone()};
    let facts=SignerSourceEntryFactsV1{selection_digest:h.clone(),display:"Full selected original source and disclosure".into(),original_host_process_instance:h.clone(),
        account_id:h.clone(),owner_certificate_digest:h.clone(),disclosure_digest:h.clone(),terms_digest:h.clone(),session_digest:h.clone(),reviewed_at_ms:1000,expires_at_ms:121000,source_expires_at_ms:300000};
    let mut presentation=SignerSourceEntryPresentationV1{actor,facts,notice:ENTRY_NOTICE.into(),sender_key_fingerprint:envelope::fingerprint(&sender),
        recipient_key_fingerprint:envelope::fingerprint(&recipient),request_challenge:h.clone(),offer_challenge:h.clone(),native_ceiling_ms:120000,entry_ceiling_ms:120000,source_ceiling_ms:300000,presentation_digest:String::new()};
    presentation.presentation_digest=presentation.calculate_presentation_digest().unwrap();
    let crypto=envelope::Binding{version:1,purpose:"original-signer-source-entry-unlock".into(),suite:"HPKE-Auth-X25519-HKDF-SHA256-ChaCha20Poly1305".into(),
        supervision_profile:PROFILE.into(),coordinator_process_instance:h.clone(),coordinator_focus_epoch:1,signer_role:envelope::SourceEntryRole::Signer1,
        signer_process_instance:h.clone(),original_host_process_instance:h.clone(),common_image_measurement:h.clone(),session_challenge:h.clone(),selection_digest:h.clone(),
        presentation_digest:presentation.presentation_digest.clone(),account_id:h.clone(),owner_certificate_digest:h.clone(),disclosure_digest:h.clone(),terms_digest:h.clone(),
        request_challenge:h.clone(),offer_challenge:h.clone(),sender_public_key:hex::encode(sender),sender_key_fingerprint:envelope::fingerprint(&sender),
        recipient_public_key:hex::encode(recipient),recipient_key_fingerprint:envelope::fingerprint(&recipient),reviewed_at_ms:1000,expires_at_ms:121000,source_expires_at_ms:300000,
        native_ceiling_ms:120000,entry_ceiling_ms:120000,source_ceiling_ms:300000,session_ceiling_ms:SUPERVISION_MS};
    EntryOffer{start,presentation,crypto}
}
#[cfg(test)]
pub(super) fn sample_read(entry:&EntryOffer)->SignerFinancialReadPresentationV1 {
    let h="a".repeat(64);let mut facts=SignerFinancialReadFactsV1{read_digest:String::new(),display:"Full exact owner and initial history reconciliation".into(),
        source_identity_digest:h.clone(),original_journal_digest:h.clone(),terms_digest:h.clone(),original_delivery_operation_id:"operation-1".into(),
        original_delivery_request_digest:h.clone(),original_delivery_head_sequence:1,original_delivery_head_digest:h.clone(),original_host_process_instance:h.clone(),
        account_id:h.clone(),owner_certificate_digest:h.clone(),owner_selection_digest:h.clone(),disclosure_digest:h.clone(),session_digest:h.clone(),
        reviewed_at_ms:130000,expires_at_ms:250000,source_expires_at_ms:300000};
    facts.read_digest=facts.calculate_read_digest().unwrap();
    let mut read=SignerFinancialReadPresentationV1{version:2,purpose:READ_PURPOSE.into(),actor:entry.presentation.actor.clone(),facts,notice:READ_NOTICE.into(),selection_digest:h.clone(),
        source_entry_presentation_digest:entry.presentation.presentation_digest.clone(),read_challenge:h,source_ceiling_ms:entry.presentation.source_ceiling_ms,
        read_ceiling_ms:250000,presentation_digest:String::new()};read.presentation_digest=read.calculate_presentation_digest().unwrap();read
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_entry_presentation_and_crypto_bind_exact_selection_role_keys_and_clocks(){
        let original=sample_entry();original.validate().unwrap();
        for n in 0..9 {let mut changed=original.clone();match n{
            0=>changed.presentation.facts.selection_digest="b".repeat(64),
            1=>changed.presentation.actor.signer_role=Target::Signer2,
            2=>changed.crypto.recipient_key_fingerprint="b".repeat(64),
            3=>changed.crypto.original_host_process_instance="b".repeat(64),
            4=>changed.presentation.facts.display.push('!'),
            5=>changed.crypto.entry_ceiling_ms+=1,
            6=>changed.start.native_ceiling_ms+=1,
            7=>changed.crypto.presentation_digest="b".repeat(64),
            _=>changed.presentation.notice="Continue automatically".into(),}
            assert!(changed.validate().is_err());}
        let bytes=serde_json::to_vec(&original).unwrap();let decoded:EntryOffer=serde_json::from_slice(&bytes).unwrap();
        assert!(decoded==original);
    }
    #[test]
    fn initial_read_digest_covers_every_frozen_nonself_fact(){
        let entry=sample_entry();let read=sample_read(&entry);read.validate().unwrap();assert!(read.matches_entry(&entry.presentation));
        for n in 0..17 {let mut f=read.facts.clone();match n{
            0=>f.display.push('!'),1=>f.source_identity_digest="b".repeat(64),2=>f.original_journal_digest="b".repeat(64),
            3=>f.terms_digest="b".repeat(64),4=>f.original_delivery_operation_id.push('2'),5=>f.original_delivery_request_digest="b".repeat(64),
            6=>f.original_delivery_head_sequence+=1,7=>f.original_delivery_head_digest="b".repeat(64),8=>f.original_host_process_instance="b".repeat(64),
            9=>f.account_id="b".repeat(64),10=>f.owner_certificate_digest="b".repeat(64),11=>f.owner_selection_digest="b".repeat(64),
            12=>f.disclosure_digest="b".repeat(64),13=>f.session_digest="b".repeat(64),14=>f.reviewed_at_ms+=1,
            15=>f.expires_at_ms-=1,_=>f.source_expires_at_ms+=1,}assert!(f.validate().is_err());}
    }
    #[test]
    fn read_presentation_cannot_switch_entry_source_selection_or_deadline(){
        let entry=sample_entry();let read=sample_read(&entry);
        for n in 0..5 {let mut changed=read.clone();match n{
            0=>changed.selection_digest="b".repeat(64),1=>changed.source_entry_presentation_digest="b".repeat(64),
            2=>changed.source_ceiling_ms+=1,3=>changed.facts.owner_certificate_digest="b".repeat(64),_=>changed.actor.signer_process_instance="b".repeat(64),}
            changed.facts.read_digest=changed.facts.calculate_read_digest().unwrap();changed.presentation_digest=changed.calculate_presentation_digest().unwrap();
            changed.validate().unwrap();assert!(!changed.matches_entry(&entry.presentation));}
    }
    #[test]
    fn full_workflow_grammar_rejects_imports_duplicates_and_direct_c_to_s(){
        let packet=Packet::Cancel{coordinator:"a".repeat(64),session:"b".repeat(64)};
        assert!(check_direction(Role::Coordinator,Role::Host,&packet).is_ok());
        assert!(check_direction(Role::Host,Role::Signer1,&packet).is_ok());
        assert!(check_direction(Role::Coordinator,Role::Signer1,&packet).is_err());
        for text in [r#"{"kind":"SourceEntryFinal","approved":true}"#,r#"{"kind":"Cancel","coordinator":"a","coordinator":"b","session":"c"}"#,
            r#"{"kind":"Cancel","coordinator":"a","session":"b","fd":3}"#]{assert!(serde_json::from_str::<Packet>(text).is_err());}
        let mut start=sample_entry().start;start.profile="coordinated-signer-continue".into();assert!(start.validate().is_err());
    }
    #[test]
    fn read_v2_scope_rejects_history_only_version_purpose_and_missing_discriminator(){
        let entry=sample_entry();let read=sample_read(&entry);read.validate().unwrap();
        let mut old=read.clone();old.version=1;old.presentation_digest=old.calculate_presentation_digest().unwrap();assert!(old.validate().is_err());
        let mut old=read.clone();old.purpose="original-financial-history-only-v1".into();old.presentation_digest=old.calculate_presentation_digest().unwrap();assert!(old.validate().is_err());
        let mut old=read.clone();old.notice="Read only history".into();old.presentation_digest=old.calculate_presentation_digest().unwrap();assert!(old.validate().is_err());
        let mut value=serde_json::to_value(read).unwrap();value.as_object_mut().unwrap().remove("version");assert!(serde_json::from_value::<SignerFinancialReadPresentationV1>(value).is_err());
    }
    #[test]
    fn full_display_and_ciphertext_packets_are_bounded_without_truncation(){
        let offer=sample_entry();assert!(payload(&Packet::EntryOffer{offer:offer.clone()}).is_ok());
        let mut oversized=offer;oversized.presentation.facts.display="x".repeat(32769);
        assert!(oversized.presentation.facts.validate().is_err());
        assert!(payload(&Packet::EntryCipher{envelope:"x".repeat(envelope::FRAME_LIMIT)}).is_err());
        let mut read=sample_read(&sample_entry());read.facts.original_delivery_operation_id="x".repeat(129);assert!(read.facts.validate().is_err());
    }
}

#[cfg(test)]mod writer_route_tests{
    use super::*;
    #[test]fn writer_acquire_packets_bind_fixed_actor_and_direction(){
        let actor=sample_entry().presentation.actor;let h="a".repeat(64);
        let p=Packet::AcquireArm{actor:actor.clone(),presentation_digest:h.clone(),recipe_digest:h};
        assert_eq!(p.target().unwrap(),Some(Target::Signer1));
        assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());
        assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());
        assert!(check_direction(Role::Host,Role::Signer2,&p).is_err());
        assert!(check_direction(Role::Signer1,Role::Host,&p).is_err());
        let p=Packet::WriterReadFailed{actor,presentation_digest:"not-a-digest".into()};
        assert!(p.target().is_err());
    }
    #[test]fn writer_final_grammar_requires_explicit_original_service_correlation(){
        assert!(serde_json::from_str::<Packet>(r#"{"kind":"WriterReadFinal","actor":{},"presentation_digest":"a","read_challenge":"b"}"#).is_err());
        assert!(serde_json::from_str::<Packet>(r#"{"kind":"AcquireFinal","signing_service_digest":"old-digest-only"}"#).is_err());
        assert!(serde_json::from_str::<Packet>(r#"{"kind":"Acquired","actor":{}}"#).is_err());
    }
}

#[cfg(test)]mod activate_route_tests{
    use super::*;
    #[test]fn activate_packets_bind_fixed_actor_and_direction(){
        let actor=sample_entry().presentation.actor;let h="a".repeat(64);
        let p=Packet::ActivateArm{actor:actor.clone(),presentation_digest:h.clone(),recipe_digest:h.clone()};
        assert_eq!(p.target().unwrap(),Some(Target::Signer1));
        assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());
        assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());
        assert!(check_direction(Role::Host,Role::Signer2,&p).is_err());
        assert!(check_direction(Role::Signer1,Role::Host,&p).is_err());
        let p=Packet::ActivateReadFailed{actor:actor.clone(),presentation_digest:h};
        assert!(check_direction(Role::Signer1,Role::Host,&p).is_ok());
        assert!(check_direction(Role::Host,Role::Coordinator,&p).is_ok());
        assert!(check_direction(Role::Coordinator,Role::Host,&p).is_err());
        let p=Packet::ActivateReadFailed{actor,presentation_digest:"not-a-digest".into()};
        assert!(p.target().is_err());
    }
    #[test]fn activate_final_grammar_requires_explicit_original_service_correlation(){
        assert!(serde_json::from_str::<Packet>(r#"{"kind":"ActivateReadFinal","actor":{},"presentation_digest":"a","read_challenge":"b"}"#).is_err());
        assert!(serde_json::from_str::<Packet>(r#"{"kind":"ActivateFinal","signing_service_digest":"old-digest-only"}"#).is_err());
        assert!(serde_json::from_str::<Packet>(r#"{"kind":"Activated","actor":{}}"#).is_err());
    }
}

#[cfg(test)]mod original_host_peer_route_tests {
    use super::*;
    #[test]fn host_peer_first_packet_only_original_host_to_exact_signer(){
        let p=Packet::OriginalHostPeer{role:Target::Signer1,host_instance:"ab".repeat(32)};
        assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());
        for (sender,recipient) in [(Role::Coordinator,Role::Host),(Role::Host,Role::Signer2),(Role::Signer1,Role::Host),(Role::Host,Role::Coordinator)] {
            assert!(check_direction(sender,recipient,&p).is_err());
        }
        let p=Packet::OriginalHostPeer{role:Target::Signer1,host_instance:"not-an-instance".into()};
        assert!(p.target().is_err());assert!(check_direction(Role::Host,Role::Signer1,&p).is_err());
    }
}
