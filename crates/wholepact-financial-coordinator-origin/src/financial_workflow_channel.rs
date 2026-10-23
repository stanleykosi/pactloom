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
    NormalCompletionNotice{notice:crate::FinancialNormalCompletionNoticeV1},
    NormalClose{context:crate::financial_normal_completion_data::FinancialNormalCloseContextV1},
    NormalDisposed{role:Target,challenge:String,notice_digest:String},
    NormalReady{challenge:String,notice_digest:String},
    FinancialResultSelector{role:Target,data:crate::SignerFinancialResultSelectorV1},
    CompletedPairServing{data:crate::CompletedPairPresentationV1,witness_instance:String,serve_challenge:String,service_ceiling_ms:u64},
    RetireRequest{request:crate::host_interstage::RetirementRequest},
    RetireQuiescent{request:crate::host_interstage::RetirementRequest},
    RetireResume{request:crate::host_interstage::RetirementRequest},
    RetireResumed{request:crate::host_interstage::RetirementRequest},
    OriginalHostPeer{role:Target,host_instance:String},
    V3EnrollmentDisplay{presentation:crate::SignerV3EnrollmentPresentationV1},
    V3EnrollmentFinal{role:Target,presentation_digest:String},
    V3Enrolled{role:Target,data:crate::SignerV3EnrollmentCommittedV1},
    V3ManifestDisplay{presentation:crate::SignerV3ManifestPresentationV1},
    V3ManifestFinal{role:Target,presentation_digest:String},
    V3ManifestAccepted{role:Target,data:crate::SignerV3ManifestCommittedV1},
    V3RedisclosureReadDisplay{presentation:crate::SignerV3RedisclosureReadPresentationV1},
    V3RedisclosureReadFinal{role:Target,presentation_digest:String},
    V3RedisclosurePrepared{role:Target,data:crate::SignerV3RedisclosurePreparedV1},
    V3AdmitDisplay{presentation:crate::SignerV3AdmitPresentationV1},
    V3AdmitArm{role:Target,presentation_digest:String},
    V3AdmitReady{role:Target,data:crate::SignerV3AdmitReadyV1,ready_challenge:String},
    V3AdmitFinal{role:Target,presentation_digest:String,ready_challenge:String,authenticated_ready_digest:String},
    V3Admitted{role:Target,data:crate::SignerV3AdmittedV1},
    V3AdmitReadDisplay{presentation:crate::SignerV3AdmitReadPresentationV1},
    V3AdmitReadFinal{role:Target,presentation_digest:String},
    V3AdmitReadRetained{role:Target,data:crate::SignerV3AdmitReadRetainedV1},
    ReturnReadDisplay{presentation:crate::SignerReturnReadPresentationV1},ReturnReadFinal{role:Target,presentation_digest:String},ReturnPrepared{role:Target,data:crate::SignerReturnPreparedV1},ReturnExactDisplay{presentation:crate::SignerReturnExactPresentationV1},ReturnExactFinal{role:Target,presentation_digest:String},ReturnCompleted{role:Target,data:crate::SignerReturnCompletedV1},ReturnFailed{role:Target,data:crate::SignerReturnFailureV1},
    SignReadDisplay{presentation:crate::SignerSignReadPresentationV1},SignReadFinal{role:Target,presentation_digest:String},SignPrepared{role:Target,data:crate::SignerSignPreparedV1},SignExactDisplay{presentation:crate::SignerSignExactPresentationV1},SignExactFinal{role:Target,presentation_digest:String},SignCommitted{role:Target,data:crate::SignerSignCommittedV1},SignFailed{role:Target,data:crate::SignerSignFailureV1},
    WalletPrepareDisplay{presentation:crate::SignerWalletPreparePresentationV1},
    WalletPrepareFinal{role:Target,presentation_digest:String},
    WalletPrepared{role:Target,data:crate::SignerWalletPreparedV1},
    WalletObserveDisplay{presentation:crate::SignerWalletObservePresentationV1},
    WalletObserveFinal{role:Target,presentation_digest:String},
    WalletObserved{role:Target,data:crate::SignerWalletObservedV1},
    WalletFailed{role:Target,data:crate::SignerWalletFailureV1},
    V3AuditDisplay{presentation:crate::SignerV3AuditPresentationV1},
    V3AuditFinal{role:Target,presentation_digest:String},
    V3Audited{role:Target,data:crate::SignerV3AuditedV1},
    FinancialSetupSelection{role:Target,selection:crate::SignerFinancialSetupSelectionV1},
    V3OwnerSelection{role:Target,source_identity_digest:String,redisclosure_presentation_digest:String,owner_setup_json:String,owner_selection_challenge:String},
    V3PrepareReadDisplay{presentation:crate::SignerV3PrepareReadPresentationV1},
    V3PrepareReadFinal{role:Target,presentation_digest:String},
    V3Prepared{role:Target,data:crate::SignerV3PreparedV1},
    V3ReceiveDisplay{presentation:crate::SignerV3ReceivePresentationV1},
    V3ReceiveFinal{role:Target,presentation_digest:String},
    V3Received{role:Target,data:crate::SignerV3ReceivedV1},
    V3RediscloseDisplay{presentation:crate::SignerV3RedisclosePresentationV1},
    V3RediscloseFinal{role:Target,presentation_digest:String},
    V3Redisclosed{role:Target,data:crate::SignerV3RedisclosedV1},
    V3PairEndpoint{role:Target,data:crate::SignerV3PairEndpointV1},
    V3PairDisplay{presentation:crate::SignerV3PairPresentationV1},
    V3PairFinal{role:Target,presentation_digest:String},
    V3Paired{role:Target,data:crate::SignerV3PairedV1},
    V3StartEntry{start:Start,selection:crate::SignerV3SourceEntrySelectionV1},
    V3EntryOffer{offer:crate::financial_workflow_origin::V3EntryOffer},
    V3EntryCipher{envelope:String},
    V3SourceOpened{start:Start,data:crate::SignerV3SourceOpenedV1},
    V3SourceFailed{start:Start,presentation_digest:Option<String>},
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
        Self::V3EnrollmentDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3Enrolled{role,data}=>{data.validate()?;Some(*role)},
        Self::V3EnrollmentFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("receipt Final digest"));}Some(*role)},
        Self::V3ManifestDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3ManifestAccepted{role,data}=>{data.validate()?;Some(*role)},
        Self::V3ManifestFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("receipt Final digest"));}Some(*role)},
        Self::V3RedisclosureReadDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3RedisclosurePrepared{role,data}=>{data.validate()?;Some(*role)},
        Self::V3RedisclosureReadFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("redisclosure Final digest"));}Some(*role)},
        Self::V3AdmitDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3Admitted{role,data}=>{data.validate()?;Some(*role)},
        Self::V3AdmitArm{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("admission Arm digest"));}Some(*role)},
        Self::V3AdmitReady{role,data,ready_challenge}=>{data.validate()?;if !hash(ready_challenge){return Err(rejected("admission READY challenge"));}Some(*role)},
        Self::V3AdmitFinal{role,presentation_digest,ready_challenge,authenticated_ready_digest}=>{if ![presentation_digest,ready_challenge,authenticated_ready_digest].iter().all(|v|hash(v)){return Err(rejected("admission Final binding"));}Some(*role)},
        Self::V3AdmitReadDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3AdmitReadRetained{role,data}=>{data.validate()?;Some(*role)},
        Self::V3AdmitReadFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("AdmitRead Final digest"));}Some(*role)},
        Self::ReturnReadDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},Self::ReturnExactDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},Self::ReturnReadFinal{role,presentation_digest}|Self::ReturnExactFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("Return Final digest"));}Some(*role)},Self::ReturnPrepared{role,data}=>{data.validate()?;Some(*role)},Self::ReturnCompleted{role,data}=>{data.validate()?;Some(*role)},Self::ReturnFailed{role,data}=>{data.validate()?;Some(*role)},
        Self::NormalCompletionNotice{notice}=>{notice.validate()?;None},
        Self::NormalClose{context}=>{context.validate()?;None},
        Self::NormalDisposed{role,challenge,notice_digest}=>{if !hash(challenge)||!hash(notice_digest){return Err(rejected("normal disposal metadata"));}Some(*role)},
        Self::NormalReady{challenge,notice_digest}=>{if !hash(challenge)||!hash(notice_digest){return Err(rejected("normal ready metadata"));}None},
        Self::FinancialResultSelector{role,data}=>{data.validate()?;if data.actor.signer_role!=*role{return Err(rejected("selector actor role"));}Some(*role)},
        Self::SignReadDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},Self::SignExactDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},Self::SignReadFinal{role,presentation_digest}|Self::SignExactFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("sign Final digest"));}Some(*role)},Self::SignPrepared{role,data}=>{data.validate()?;Some(*role)},Self::SignCommitted{role,data}=>{data.validate()?;Some(*role)},Self::SignFailed{role,data}=>{data.validate()?;Some(*role)},
        Self::WalletPrepareDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::WalletObserveDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::WalletPrepared{role,data}=>{data.validate()?;Some(*role)},
        Self::WalletObserved{role,data}=>{data.validate()?;Some(*role)},
        Self::WalletFailed{role,data}=>{data.validate()?;Some(*role)},
        Self::WalletPrepareFinal{role,presentation_digest}|Self::WalletObserveFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("wallet Final digest"));}Some(*role)},
        Self::V3AuditDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3Audited{role,data}=>{data.validate()?;Some(*role)},
        Self::V3AuditFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("Audit Final digest"));}Some(*role)},
        Self::FinancialSetupSelection{role,selection}=>{selection.validate()?;Some(*role)},
        Self::V3OwnerSelection{role,source_identity_digest,redisclosure_presentation_digest,owner_setup_json,owner_selection_challenge}=>{crate::SignerV3OwnerSetupSelectionV1::parse_json(owner_setup_json)?;if ![source_identity_digest,redisclosure_presentation_digest,owner_selection_challenge].iter().all(|v|hash(v)){return Err(rejected("owner selection binding"));}Some(*role)},
        Self::V3PrepareReadDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3ReceiveDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3Prepared{role,data}=>{data.validate()?;Some(*role)},
        Self::V3Received{role,data}=>{data.validate()?;Some(*role)},
        Self::V3PrepareReadFinal{role,presentation_digest}|Self::V3ReceiveFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("delivery Final digest"));}Some(*role)},
        Self::V3RediscloseDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3Redisclosed{role,data}=>{data.validate()?;Some(*role)},
        Self::V3RediscloseFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("redisclosure Final digest"));}Some(*role)},
        Self::V3PairEndpoint{role,data}=>{data.validate()?;Some(*role)},
        Self::V3PairDisplay{presentation}=>{presentation.validate()?;Some(presentation.actor.signer_role)},
        Self::V3Paired{role,data}=>{data.validate()?;Some(*role)},
        Self::V3PairFinal{role,presentation_digest}=>{if !hash(presentation_digest){return Err(rejected("Pair packet digest"));}Some(*role)},
        Self::V3StartEntry{start,selection}=>{start.validate()?;selection.validate()?;Some(start.role)},
        Self::V3EntryOffer{offer}=>{offer.validate()?;Some(offer.start.role)},
        Self::V3SourceOpened{start,data}=>{start.validate()?;data.validate()?;Some(start.role)},
        Self::V3SourceFailed{start,presentation_digest}=>{start.validate()?;if presentation_digest.as_ref().is_some_and(|d|!hash(d)){return Err(rejected("V3 failed digest"));}Some(start.role)},
        Self::V3EntryCipher{envelope}=>Some(match crate::v3_source_entry_envelope::Envelope::decode(envelope.as_bytes())?.binding().signer_role{crate::v3_source_entry_envelope::SourceEntryRole::Signer1=>Target::Signer1,crate::v3_source_entry_envelope::SourceEntryRole::Signer2=>Target::Signer2}),
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
    let limit=if matches!(packet,Packet::EntryCipher{..}|Packet::V3EntryCipher{..}){envelope::FRAME_LIMIT}else{MAX_PACKET};
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
    if matches!(packet,Packet::EntryCipher{..}|Packet::V3EntryCipher{..})&&count as usize>envelope::FRAME_LIMIT{return Err(rejected("workflow ciphertext frame oversized"));}
    check_direction(peer.role(),local,&packet)?;peer.check_alive()?;Ok(Some(packet))
}
fn check_direction(sender:Role,recipient:Role,packet:&Packet)->Result<()> {
    if matches!(packet,Packet::CompletedPairServing{..}){
        packet.target()?;
        return if sender==Role::Coordinator&&recipient==Role::Host{Ok(())}else{Err(rejected("Pair service observation not original C/H"))};
    }
    if matches!(packet,Packet::NormalCompletionNotice{..}|Packet::NormalReady{..}){return if sender==Role::Host&&recipient==Role::Coordinator{Ok(())}else{Err(rejected("normal observation direction"))};}
    if matches!(packet,Packet::NormalClose{..}){return if (sender==Role::Coordinator&&recipient==Role::Host)||(sender==Role::Host&&matches!(recipient,Role::Signer1|Role::Signer2)){Ok(())}else{Err(rejected("normal close direction"))};}
    if let Packet::NormalDisposed{role,..}=packet{return if (sender==role.role()&&recipient==Role::Host)||(sender==Role::Host&&recipient==Role::Coordinator){Ok(())}else{Err(rejected("normal disposal direction"))};}
    if matches!(packet,Packet::RetireRequest{..}|Packet::RetireResume{..}){
        return if sender==Role::Coordinator&&recipient==Role::Host{Ok(())}else{Err(rejected("retirement control not original C/H"))};
    }
    if matches!(packet,Packet::RetireQuiescent{..}|Packet::RetireResumed{..}){
        return if sender==Role::Host&&recipient==Role::Coordinator{Ok(())}else{Err(rejected("retirement observation not original H/C"))};
    }

    if let Packet::OriginalHostPeer{role,host_instance}=packet {
        return if sender==Role::Host && recipient==role.role() && hash(host_instance){Ok(())}else{Err(rejected("original H handshake direction rejected"))};
    }
    let down=matches!(packet,Packet::ReturnReadFinal{..}|Packet::ReturnExactFinal{..}|Packet::SignReadFinal{..}|Packet::SignExactFinal{..}|Packet::FinancialSetupSelection{..}|Packet::WalletPrepareFinal{..}|Packet::WalletObserveFinal{..}|Packet::V3AuditFinal{..}|Packet::V3AdmitArm{..}|Packet::V3AdmitFinal{..}|Packet::V3AdmitReadFinal{..}|Packet::V3OwnerSelection{..}|Packet::V3PrepareReadFinal{..}|Packet::V3ReceiveFinal{..}|Packet::V3RedisclosureReadFinal{..}|Packet::V3RediscloseFinal{..}|Packet::V3EnrollmentFinal{..}|Packet::V3ManifestFinal{..}|Packet::V3PairFinal{..}|Packet::V3StartEntry{..}|Packet::V3EntryCipher{..}|Packet::ActivateReadFinal{..}|Packet::ActivateArm{..}|Packet::ActivateFinal{..}|Packet::WriterReadFinal{..}|Packet::AcquireArm{..}|Packet::AcquireFinal{..}|Packet::StartEntry{..}|Packet::EntryCipher{..}|Packet::ReadFinal{..}|Packet::ContinuePrepare{..}|Packet::ContinueArm{..}|Packet::ContinueFinal{..}|Packet::AdmitArm{..}|Packet::AdmitFinal{..}|Packet::Cancel{..});
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
#[cfg(test)]mod v3_receipt_route_tests {use super::*;#[test]fn separate_receipt_packets_fix_role_and_reject_cross_direction(){let e=crate::signer_v3_receipt_data::tests::enrollment();let role=e.actor.signer_role;let p=Packet::V3EnrollmentDisplay{presentation:e};assert_eq!(p.target().unwrap(),Some(role));let m=crate::signer_v3_receipt_data::tests::manifest();let p=Packet::V3ManifestDisplay{presentation:m};assert_eq!(p.target().unwrap(),Some(role));assert!(Packet::V3EnrollmentFinal{role,presentation_digest:"bad".into()}.target().is_err());let p=Packet::V3EnrollmentFinal{role,presentation_digest:"ab".repeat(32)};assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());assert!(check_direction(Role::Host,Role::Signer2,&p).is_err());assert!(check_direction(Role::Signer1,Role::Host,&p).is_err());}}

#[cfg(test)]mod v3_pair_route_tests{use super::*;#[test]fn pair_final_and_display_have_opposite_exact_original_edges(){let p=Packet::V3PairDisplay{presentation:crate::signer_v3_pair_data::tests::presentation()};assert!(check_direction(Role::Signer1,Role::Host,&p).is_ok());assert!(check_direction(Role::Host,Role::Coordinator,&p).is_ok());assert!(check_direction(Role::Signer2,Role::Host,&p).is_err());assert!(check_direction(Role::Coordinator,Role::Host,&p).is_err());let p=Packet::V3PairFinal{role:Target::Signer1,presentation_digest:"ab".repeat(32)};assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());assert!(check_direction(Role::Host,Role::Signer2,&p).is_err());}}
#[cfg(test)]mod v3_redisclosure_route_tests{use super::*;#[test]fn read_and_export_are_distinct_fixed_original_edges(){let p=Packet::V3RedisclosureReadDisplay{presentation:crate::signer_v3_redisclosure_data::tests::read()};assert!(check_direction(Role::Signer1,Role::Host,&p).is_ok());assert!(check_direction(Role::Signer2,Role::Host,&p).is_err());let p=Packet::V3RediscloseFinal{role:Target::Signer1,presentation_digest:"ab".repeat(32)};assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());assert!(check_direction(Role::Host,Role::Signer2,&p).is_err());assert!(check_direction(Role::Signer1,Role::Host,&p).is_err());}}

#[cfg(test)]mod v3_delivery_route_tests{use super::*;#[test]fn original_owner_selection_and_receive_have_fixed_edges(){let p=Packet::V3OwnerSelection{role:Target::Signer1,source_identity_digest:"ab".repeat(32),redisclosure_presentation_digest:"cd".repeat(32),owner_setup_json:crate::signer_v3_delivery_data::tests::owner_json(),owner_selection_challenge:"ef".repeat(32)};assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());assert!(check_direction(Role::Signer1,Role::Host,&p).is_err());let p=Packet::V3ReceiveDisplay{presentation:crate::signer_v3_delivery_data::tests::receive()};assert!(check_direction(Role::Signer1,Role::Host,&p).is_ok());assert!(check_direction(Role::Signer2,Role::Host,&p).is_err());}}
#[cfg(test)]mod wallet_route_tests{use super::*;#[test]fn wallet_prepare_and_observe_use_only_original_fixed_edges(){let p=Packet::WalletPrepareDisplay{presentation:crate::signer_wallet_data::tests::prepare()};assert!(check_direction(Role::Signer1,Role::Host,&p).is_ok());assert!(check_direction(Role::Signer2,Role::Host,&p).is_err());let p=Packet::WalletObserveFinal{role:Target::Signer1,presentation_digest:"ab".repeat(32)};assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());assert!(check_direction(Role::Signer1,Role::Host,&p).is_err());}}
#[cfg(test)]mod financial_setup_route_tests {use super::*;#[test]fn financial_setup_is_only_original_role_downstream_data(){let p=Packet::FinancialSetupSelection{role:Target::Signer1,selection:crate::financial_setup_selection_data::tests::selection()};assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());assert!(check_direction(Role::Signer1,Role::Host,&p).is_err());assert!(check_direction(Role::Host,Role::Signer2,&p).is_err());}}
#[cfg(test)]mod sign_route_tests{use super::*;#[test]fn exact_sign_packets_have_only_fixed_edges(){let p=Packet::SignReadDisplay{presentation:crate::signer_sign_data::tests::read()};assert!(check_direction(Role::Signer1,Role::Host,&p).is_ok());assert!(check_direction(Role::Signer2,Role::Host,&p).is_err());let p=Packet::SignExactFinal{role:Target::Signer1,presentation_digest:"ab".repeat(32)};assert!(check_direction(Role::Coordinator,Role::Host,&p).is_ok());assert!(check_direction(Role::Signer1,Role::Host,&p).is_err());}}
#[cfg(test)]mod return_route_tests{use super::*;#[test]fn return_uses_fixed_original_actor_edges(){let p=Packet::ReturnReadDisplay{presentation:crate::signer_return_data::tests::read()};assert!(check_direction(Role::Signer1,Role::Host,&p).is_ok());assert!(check_direction(Role::Signer2,Role::Host,&p).is_err());let p=Packet::ReturnExactFinal{role:Target::Signer1,presentation_digest:"ab".repeat(32)};assert!(check_direction(Role::Host,Role::Signer1,&p).is_ok());assert!(check_direction(Role::Signer1,Role::Host,&p).is_err());}}

#[cfg(test)]
mod v3_delivery_packet_roundtrip_tests {
    use super::*;
    fn roundtrip_and_closed_schema(packet: Packet, kind: &str, nested: &str) {
        assert!(packet.target().unwrap() == Some(Target::Signer1));
        assert!(check_direction(Role::Signer1, Role::Host, &packet).is_ok());
        let bytes = payload(&packet).unwrap();
        assert!(bytes.len() + 8 <= MAX_PACKET);
        let decoded: Packet = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("{kind} receive grammar failed: {e}"));
        assert!(decoded.target().unwrap() == Some(Target::Signer1));
        assert!(check_direction(Role::Signer1, Role::Host, &decoded).is_ok());
        assert!(check_direction(Role::Host, Role::Coordinator, &decoded).is_ok());
        assert!(check_direction(Role::Signer2, Role::Host, &decoded).is_err());
        assert!(check_direction(Role::Host, Role::Signer1, &decoded).is_err());
        assert_eq!(serde_json::to_value(&decoded).unwrap(), serde_json::to_value(&packet).unwrap());
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["kind"], kind);
        let mut extra = value.clone();
        extra["unexpected_authority"] = true.into();
        assert!(serde_json::from_slice::<Packet>(&serde_json::to_vec(&extra).unwrap()).is_err());
        let mut nested_extra = value.clone();
        nested_extra[nested]["unexpected_authority"] = true.into();
        assert!(serde_json::from_slice::<Packet>(&serde_json::to_vec(&nested_extra).unwrap()).is_err());
        let mut unknown = value;
        unknown["kind"] = "V3ReceiveUnknown".into();
        assert!(serde_json::from_slice::<Packet>(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let duplicate = format!("{{\"kind\":\"{}\",{}", kind, std::str::from_utf8(&bytes).unwrap().strip_prefix('{').unwrap());
        assert!(serde_json::from_slice::<Packet>(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn prepared_packet_roundtrip_and_denials() {
        let data = crate::signer_v3_delivery_data::tests::prepared();
        roundtrip_and_closed_schema(Packet::V3Prepared { role: Target::Signer1, data: data.clone() }, "V3Prepared", "data");
        let mut bad = data;
        bad.read_session_digest = "ff".repeat(32);
        let bytes = payload(&Packet::V3Prepared { role: Target::Signer1, data: bad }).unwrap();
        let decoded: Packet = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.target().is_err());
        assert!(check_direction(Role::Signer1, Role::Host, &decoded).is_err());
    }
    #[test]
    fn receive_display_packet_roundtrip_and_denials() {
        let presentation = crate::signer_v3_delivery_data::tests::receive();
        roundtrip_and_closed_schema(Packet::V3ReceiveDisplay { presentation: presentation.clone() }, "V3ReceiveDisplay", "presentation");
        let mut bad = presentation;
        bad.facts.payload_bytes += 1;
        let bytes = payload(&Packet::V3ReceiveDisplay { presentation: bad }).unwrap();
        let decoded: Packet = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.target().is_err());
        assert!(check_direction(Role::Signer1, Role::Host, &decoded).is_err());
    }
    #[test]
    fn received_packet_roundtrip_and_denials() {
        let p = crate::signer_v3_delivery_data::tests::receive();
        let data = crate::SignerV3ReceivedV1 {
            receive_presentation_digest: p.presentation_digest,
            prepare_read_presentation_digest: p.facts.prepare_read_presentation_digest,
            source_identity_digest: p.facts.source_identity_digest,
            owner_service_digest: p.facts.owner_service_digest,
            recipient_intent_digest: "ab".repeat(32),
            payload_digest: p.facts.payload_digest,
            fixed_identity_digest: p.facts.fixed_identity_digest,
            payload_bytes: p.facts.payload_bytes,
        };
        roundtrip_and_closed_schema(Packet::V3Received { role: Target::Signer1, data: data.clone() }, "V3Received", "data");
        let mut bad = data;
        bad.payload_bytes = 0;
        let bytes = payload(&Packet::V3Received { role: Target::Signer1, data: bad }).unwrap();
        let decoded: Packet = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.target().is_err());
        assert!(check_direction(Role::Signer1, Role::Host, &decoded).is_err());
    }
    #[test]
    fn admit_read_display_packet_roundtrip_and_denials() {
        let presentation = crate::signer_v3_admit_read_data::tests::presentation();
        roundtrip_and_closed_schema(Packet::V3AdmitReadDisplay { presentation: presentation.clone() }, "V3AdmitReadDisplay", "presentation");
        let mut bad = presentation;
        bad.facts.received.payload_bytes = 0;
        let bytes = payload(&Packet::V3AdmitReadDisplay { presentation: bad }).unwrap();
        let decoded: Packet = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.target().is_err());
        assert!(check_direction(Role::Signer1, Role::Host, &decoded).is_err());
    }
}
