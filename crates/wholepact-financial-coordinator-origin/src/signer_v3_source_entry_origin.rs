#[path="financial_setup_selection_origin.rs"]
mod financial_setup;
// Separate initial V3 SourceEntry protocol. No legacy grant conversion.
#[path="signer_v3_delivery_origin.rs"]
mod delivery;
macro_rules! actor_boundary {($stage:ident,$class:ident,$peer:expr)=>{{
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] {use crate::financial_ci_actor_diagnostics as d;d::origin(d::OriginStage::$stage,d::Class::$class,$peer);}
}};}
pub use delivery::{SignerV3PrepareReadTicketV1,SignerV3PrepareReadOutboundV1,SignerV3PrepareReadFinalV1,SignerV3PreparedLifetimeV1,SignerV3ReceiveTicketV1,SignerV3ReceiveOutboundV1,SignerV3ReceiveFinalV1};
#[path="signer_v3_admit_read_origin.rs"]
mod admit_read;
pub use admit_read::{SignerV3AdmitReadTicketV1,SignerV3AdmitReadOutboundV1,SignerV3AdmitReadFinalV1};
#[path="signer_v3_admission_origin.rs"]
mod admission;
pub use admission::{SignerV3AdmitTicketV1,SignerV3AdmitArmOutboundV1,SignerV3AdmitArmV1,SignerV3AdmitReadyTicketV1,SignerV3AdmitFinalOutboundV1,SignerV3AdmitFinalV1};
#[path="signer_v3_audit_origin.rs"]
mod audit;
pub use audit::{SignerV3AuditTicketV1,SignerV3AuditOutboundV1,SignerV3AuditFinalV1,SignerV3CompletedLifetimeV1};
use super::*;
use crate::signer_v3_source_entry_data::*;
use crate::v3_source_entry_envelope::{self as v3crypto, Envelope, RecipientKey};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicU64;
use std::time::Duration;
#[path="signer_v3_pair_origin.rs"]
mod pair;
pub use pair::{SignerV3PairTicketV1,SignerV3PairOutboundV1,SignerV3PairFinalV1,SignerV3PairLifetimeV1};

#[path="signer_v3_receipt_origin.rs"]
mod receipts;
pub use receipts::{SignerV3EnrollmentTicketV1,SignerV3EnrollmentOutboundV1,SignerV3EnrollmentFinalV1,SignerV3ManifestTicketV1,SignerV3ManifestOutboundV1,SignerV3ManifestFinalV1};
#[path="signer_v3_redisclosure_origin.rs"]
mod redisclosure;
pub use redisclosure::{SignerV3RedisclosureReadTicketV1,SignerV3RedisclosureReadOutboundV1,SignerV3RedisclosureReadFinalV1,SignerV3RediscloseTicketV1,SignerV3RediscloseOutboundV1,SignerV3RediscloseFinalV1};
pub(super) const V3_INITIAL: u8 = 0;
pub(super) const V3_ENTRY_PREPARING: u8 = 1;
pub(super) const V3_ENTRY_REVIEW: u8 = 2;
pub(super) const V3_ENTRY_ADMITTED: u8 = 3;
pub(super) const V3_OPENED: u8 = 4;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct V3EntryOffer {
    pub start: Start,
    pub presentation: SignerV3SourceEntryPresentationV1,
    pub crypto: v3crypto::Binding,
}
impl V3EntryOffer {
    pub(crate) fn validate(&self) -> Result<()> {
        self.start.validate()?;
        self.presentation.validate()?;
        self.crypto.validate()?;
        if self.presentation.actor.coordinator_process_instance != self.start.coordinator
            || self.presentation.actor.session_challenge != self.start.session
            || self.presentation.actor.signer_role != self.start.role
            || self.presentation.request_challenge != self.start.request_challenge
            || self.presentation.native_ceiling_ms != self.start.native_ceiling_ms
            || self.crypto
                != crypto_binding(
                    &self.start,
                    &self.presentation,
                    &self.crypto.recipient_public_key,
                )?
        {
            return Err(rejected("V3 source complete offer binding"));
        }
        Ok(())
    }
}
pub(super) struct V3EntryReviewed {
    pub core: Arc<Core>,
    pub clocks: FullWorkflowClocksV1,
    pub wire: V3EntryOffer,
    pub original_source: Instant,
    pub original_entry: Instant,
    pub ceiling: Instant,
    last_wall: AtomicU64,
}
impl V3EntryReviewed {
    pub(super) fn new(
        core: Arc<Core>,
        clocks: FullWorkflowClocksV1,
        wire: V3EntryOffer,
        source: Instant,
        entry: Instant,
    ) -> Result<Arc<Self>> {
        let reviewed = Self::from_received_bounds(core, clocks, wire, source, entry)?;
        reviewed.check_action()?;
        Ok(reviewed)
    }
    // C's authenticated receive still needs exact actor/clock validation when
    // native R races it. This creates no public ticket or phase transition.
    pub(super) fn from_received_bounds(
        core: Arc<Core>,
        clocks: FullWorkflowClocksV1,
        wire: V3EntryOffer,
        source: Instant,
        entry: Instant,
    ) -> Result<Arc<Self>> {
        wire.validate()?;
        let now = Instant::now();
        let wall = state::wall_ms()?;
        let p = &wire.presentation;
        let native = clocks.restrict_received(
            &wire.start.profile,
            wire.start.native_ceiling_ms,
            clocks.supervision(),
            now,
        )?;
        let encoded_source =
            clocks.restrict_received(&wire.start.profile, p.source_ceiling_ms, source, now)?;
        let encoded_entry =
            clocks.restrict_received(&wire.start.profile, p.entry_ceiling_ms, entry, now)?;
        let ceiling = native
            .min(encoded_source)
            .min(encoded_entry)
            .min(wall_ceiling(
                now,
                wall,
                p.facts.reviewed_at_ms,
                p.facts.expires_at_ms,
            )?);
        let reviewed = Arc::new(Self {
            core,
            clocks,
            wire,
            original_source: source,
            original_entry: entry,
            ceiling,
            last_wall: AtomicU64::new(wall),
        });
        reviewed.check_action_bounds()?;
        Ok(reviewed)
    }
    pub(super) fn slot(&self) -> usize {
        self.wire.start.role.index()
    }
    pub(super) fn check_custody(&self) -> Result<()> {
        self.observe_custody().map(|_| ())
    }
    /// Private retirement only. The sole driver separately checks every
    /// original actor except its owned exiting target. This grants no action.
    pub(super) fn retirement_clock_bounds(&self) -> Result<()> {
        let wall = state::observe_shared_wall(
            &self.last_wall,
            self.original_source.min(self.clocks.supervision()),
            state::wall_ms,
        )?
        .ok_or_else(|| rejected("retirement original source clock elapsed"))?;
        let now = Instant::now();
        if now >= self.original_source
            || now >= self.clocks.supervision()
            || wall < self.wire.presentation.facts.reviewed_at_ms
            || wall >= self.wire.presentation.facts.source_expires_at_ms
        {
            actor_boundary!(SourceLifetime,PredicateDenied,None);
            return Err(rejected("retirement original source clock elapsed"));
        }
        Ok(())
    }
    fn observe_custody(&self) -> Result<u64> {
        let result = (|| {
            self.core.check()?;
            let wall = state::observe_shared_wall(
                &self.last_wall,
                self.original_source.min(self.clocks.supervision()),
                state::wall_ms,
            )?
            .ok_or_else(|| rejected("original financial custody expired"))?;
            let now = Instant::now();
            if now >= self.original_source
                || now >= self.clocks.supervision()
                || wall < self.wire.presentation.facts.reviewed_at_ms
                || wall >= self.wire.presentation.facts.source_expires_at_ms
            {
                actor_boundary!(SourceLifetime,PredicateDenied,None);
                return Err(rejected("original financial custody expired"));
            }
            Ok(wall)
        })();
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
    pub(super) fn check_action_bounds(&self) -> Result<()> {
        let result = (|| {
            let wall = self.observe_custody()?;
            if Instant::now() >= self.original_entry
                || Instant::now() >= self.ceiling
                || wall >= self.wire.presentation.facts.expires_at_ms
            {
                actor_boundary!(SourceAction,ClockExpired,None);
                return Err(rejected("SourceEntry original action bound elapsed"));
            }
            Ok(())
        })();
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
    pub(super) fn check_action(&self) -> Result<()> {
        let result = self
            .check_action_bounds()
            .and_then(|()| self.core.check_action_restrictions());
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
}
pub(super) fn wall_ceiling(now: Instant, wall: u64, start: u64, end: u64) -> Result<Instant> {
    if wall < start || wall >= end {
        return Err(rejected("original workflow wall bound elapsed"));
    }
    now.checked_add(Duration::from_millis((end - wall).min(120_000)))
        .ok_or_else(|| rejected("workflow wall cap overflow"))
}
pub struct SignerV3SourceEntryOfferV1 {
    pub(super) entry: Arc<V3EntryReviewed>,
    pub(super) consumed: bool,
}
impl SignerV3SourceEntryOfferV1 {
    pub fn presentation(&self) -> &SignerV3SourceEntryPresentationV1 {
        &self.entry.wire.presentation
    }
    pub fn request_digest(&self) -> Result<String> {
        self.entry.wire.crypto.request_digest()
    }
    pub fn native_deadline(&self) -> Instant {
        self.entry.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.entry.check_action()?;
        if self.entry.core.phase.phase(self.entry.slot()) != V3_ENTRY_REVIEW {
            return Err(rejected("SourceEntry offer is no longer pending"));
        }
        Ok(())
    }
}
impl Drop for SignerV3SourceEntryOfferV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3SourceEntryOutboundV1 {
    pub(super) entry: Arc<V3EntryReviewed>,
    pub(super) password: Option<Zeroizing<Vec<u8>>>,
    pub(super) consumed: bool,
}
impl Drop for SignerV3SourceEntryOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.entry.core.phase.revoke();
        }
    }
}

/// Only actual S authenticated receive constructs these matching values. Input
/// is not authority; Final remains restrictive through decrypt/KDF/full audit.
pub struct SignerV3SourceEntryFinalV1 {
    pub(super) entry: Arc<V3EntryReviewed>,
    pub(super) consumed: bool,
}
pub struct SignerV3SourceEntryInputV1 {
    pub(super) entry: Arc<V3EntryReviewed>,
    pub(super) recipient: Option<RecipientKey>,
    pub(super) envelope: Option<Envelope>,
    pub(super) consumed: bool,
}
impl SignerV3SourceEntryFinalV1 {
    pub fn presentation(&self) -> &SignerV3SourceEntryPresentationV1 {
        &self.entry.wire.presentation
    }
    pub fn source_selection_digest(&self) -> &str {
        &self.entry.wire.presentation.facts.source_selection_digest
    }
    pub fn presentation_digest(&self) -> &str {
        &self.entry.wire.presentation.presentation_digest
    }
    pub fn original_host_process_instance(&self) -> &str {
        &self
            .entry
            .wire
            .presentation
            .facts
            .original_host_process_instance
    }
    pub fn original_entry_deadline(&self) -> Instant {
        self.entry.original_entry
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.entry.original_source
    }
    pub fn check_current(&self) -> Result<()> {
        self.entry.check_action()?;
        if self.entry.core.phase.phase(self.entry.slot()) != V3_ENTRY_ADMITTED {
            return Err(rejected("SourceEntry Final consumed"));
        }
        Ok(())
    }
    /// The actual source opener calls only after successful complete audit and
    /// one final restriction check. This phase advance proves protocol state,
    /// not the audit itself, and gives no permission to perform another action.
    pub fn into_original_custody_lifetime(mut self) -> Result<SignerV3SourceLifetimeV1> {
        self.check_current()?;
        self.entry
            .core
            .phase
            .step(self.entry.slot(), V3_ENTRY_ADMITTED, V3_OPENED)?;
        self.consumed = true;
        Ok(SignerV3SourceLifetimeV1 {
            entry: Arc::clone(&self.entry),
        })
    }
}
impl Drop for SignerV3SourceEntryFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.entry.core.phase.revoke();
        }
    }
}
impl SignerV3SourceEntryInputV1 {
    pub fn open(mut self, final_action: &SignerV3SourceEntryFinalV1) -> Result<Zeroizing<Vec<u8>>> {
        // Consume recipient/input before all fallible work. No returned retry.
        let recipient = self.recipient.take();
        let envelope = self.envelope.take();
        self.consumed = true;
        let result = (|| {
            if !Arc::ptr_eq(&self.entry, &final_action.entry) {
                return Err(rejected("foreign SourceEntry input/Final"));
            }
            final_action.check_current()?;
            let plaintext = recipient
                .ok_or_else(|| rejected("SourceEntry key consumed"))?
                .open(
                    &self.entry.wire.crypto,
                    envelope.ok_or_else(|| rejected("SourceEntry input consumed"))?,
                )?;
            final_action.check_current()?;
            Ok(plaintext)
        })();
        if result.is_err() {
            self.entry.core.phase.revoke();
        }
        result
    }
}
impl Drop for SignerV3SourceEntryInputV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.entry.core.phase.revoke();
        }
    }
}

/// Restriction only, not PrepareRead, Receive, admission or financial authority.
pub struct SignerV3SourceLifetimeV1 {
    entry: Arc<V3EntryReviewed>,
}
impl SignerV3SourceLifetimeV1 {
    pub fn check_current(&self) -> Result<()> {
        self.entry.check_custody()?;
        self.entry.core.check_action_restrictions()
    }
}
#[derive(Default)]
pub(super) struct SV3Entry {
 admission:admission::AdmissionSlot,
 admit_read:admit_read::AdmitReadSlot,
 audit:audit::AuditSlot,
 financial_setup:Option<crate::SignerFinancialSetupSelectionV1>,
 delivery:delivery::DeliverySlots,
 redisclosure:redisclosure::RedisclosureSlots,
 receipts:receipts::ReceiptSlots,
    pub(super) pair:pair::PairSlot,
    observation: Option<SignerV3SourceOpenedV1>,
    selection: Option<SignerV3SourceEntrySelectionV1>,
    start: Option<Start>,
    entry: Option<Arc<V3EntryReviewed>>,
    pub(super) recipient: Option<RecipientKey>,
    offered: bool,
    opened: bool,
    terminal: bool,
}
#[derive(Default)]
pub(super) struct CV3Entry {
 admission:admission::AdmissionSlot,
 admit_read:admit_read::AdmitReadSlot,
 audit:audit::AuditSlot,
 financial_setup:Option<crate::SignerFinancialSetupSelectionV1>,
 delivery:delivery::DeliverySlots,
 redisclosure:redisclosure::RedisclosureSlots,
 receipts:receipts::ReceiptSlots,
    pub(super) pair:pair::PairSlot,
    observation: Option<SignerV3SourceOpenedV1>,
    selection: Option<SignerV3SourceEntrySelectionV1>,
    start: Option<Start>,
    sender: Option<v3crypto::SenderKey>,
    entry: Option<Arc<V3EntryReviewed>>,
    wire_phase: u8,
    terminal: bool,
    opened: bool,
}
#[derive(Default)]
pub(super) struct HV3Entry {
 admission:admission::AdmissionSlot,
 admit_read:admit_read::AdmitReadSlot,
 audit:audit::AuditSlot,
 financial_setup:Option<crate::SignerFinancialSetupSelectionV1>,
 delivery:delivery::DeliverySlots,
 redisclosure:redisclosure::RedisclosureSlots,
 receipts:receipts::ReceiptSlots,
    pub(super) pair:pair::PairSlot,
    observation: Option<SignerV3SourceOpenedV1>,
    last_wall: u64,
    selection: Option<SignerV3SourceEntrySelectionV1>,
    start: Option<Start>,
    offer: Option<V3EntryOffer>,
    phase: u8,
    terminal: bool,
    opened: bool,
    forwarded: bool,
}
impl SV3Entry {
    /// Cached authenticated V3 observation only; not a new source or grant.
    pub(super) fn original_source_observation(&self) -> Result<&SignerV3SourceOpenedV1> {
        self.observation.as_ref().ok_or_else(|| rejected("selector missing original V3 source observation"))
    }
    pub(super) fn disposal_allowed(&self) -> bool {
        self.start.is_none() || self.terminal || self.opened
    }
}
impl CV3Entry {
    /// Cached authenticated V3 observation only; not a new source or grant.
    pub(super) fn original_source_observation(&self) -> Result<&SignerV3SourceOpenedV1> {
        self.observation.as_ref().ok_or_else(|| rejected("selector missing original V3 source observation"))
    }
    pub(super) fn disposal_allowed(&self) -> bool {
        self.start.is_none() || self.terminal || self.opened
    }
}
impl HV3Entry {
    /// Cached authenticated V3 observation only; not a new source or grant.
    pub(super) fn original_source_observation(&self) -> Result<&SignerV3SourceOpenedV1> {
        self.observation.as_ref().ok_or_else(|| rejected("selector missing original V3 source observation"))
    }
    pub(super) fn disposal_allowed(&self) -> bool {
        self.start.is_none() || self.terminal || self.opened || !self.forwarded
    }
}
fn crypto_binding(
    start: &Start,
    p: &SignerV3SourceEntryPresentationV1,
    recipient_public_key: &str,
) -> Result<v3crypto::Binding> {
    let f = &p.facts;
    let b = v3crypto::Binding {
        version: 1,
        purpose: "original-signer-v3-source-entry-unlock".into(),
        suite: "HPKE-Auth-X25519-HKDF-SHA256-ChaCha20Poly1305".into(),
        supervision_profile: PROFILE.into(),
        coordinator_process_instance: start.coordinator.clone(),
        coordinator_focus_epoch: 1,
        signer_role: match start.role {
            Target::Signer1 => v3crypto::SourceEntryRole::Signer1,
            Target::Signer2 => v3crypto::SourceEntryRole::Signer2,
        },
        signer_process_instance: p.actor.signer_process_instance.clone(),
        original_host_process_instance: f.original_host_process_instance.clone(),
        common_image_measurement: p.actor.common_image_measurement.clone(),
        session_challenge: start.session.clone(),
        selection_digest: f.source_selection_digest.clone(),
        presentation_digest: p.presentation_digest.clone(),
        account_id: f.account_id.clone(),
        owner_certificate_digest: f.owner_certificate_digest.clone(),
        disclosure_digest: f.witness_disclosure_digest.clone(),
        session_digest: f.session_digest.clone(),
        request_challenge: start.request_challenge.clone(),
        offer_challenge: p.offer_challenge.clone(),
        sender_public_key: start.sender_public_key.clone(),
        sender_key_fingerprint: p.sender_key_fingerprint.clone(),
        recipient_public_key: recipient_public_key.into(),
        recipient_key_fingerprint: p.recipient_key_fingerprint.clone(),
        reviewed_at_ms: f.reviewed_at_ms,
        expires_at_ms: f.expires_at_ms,
        source_expires_at_ms: f.source_expires_at_ms,
        native_ceiling_ms: start.native_ceiling_ms,
        entry_ceiling_ms: p.entry_ceiling_ms,
        source_ceiling_ms: p.source_ceiling_ms,
        session_ceiling_ms: SUPERVISION_MS,
    };
    b.validate()?;
    Ok(b)
}

impl SignerFinancialWorkflowOriginV1 {
    pub(super) fn receive_v3_entry(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        if self.cancel_seen || self.failed || self.disposed || self.v3_entry.terminal {
            return Err(rejected("V3 entry after terminal"));
        }
        match p {
            Packet::V3StartEntry { start, selection } => {
                start.validate()?;
                selection.validate()?;
                if self.v3_entry.start.is_some()
                    || start.role != self.target
                    || !self.host_peer_seen
                {
                    return Err(rejected("V3 entry start replay or missing original H"));
                }
                self.clocks.restrict_received(
                    PROFILE,
                    start.native_ceiling_ms,
                    self.clocks.supervision(),
                    Instant::now(),
                )?;
                self.core
                    .phase
                    .step(self.target.index(), V3_INITIAL, V3_ENTRY_PREPARING)?;
                self.v3_entry.start = Some(start);
                self.v3_entry.selection = Some(selection.clone());
                Ok(SignerFinancialWorkflowRequestV1::V3SourceEntryRequested { selection })
            }
            Packet::V3EntryCipher { envelope } => {
                let recipient = self
                    .v3_entry
                    .recipient
                    .take()
                    .ok_or_else(|| rejected("V3 recipient consumed"))?;
                let entry = self
                    .v3_entry
                    .entry
                    .as_ref()
                    .ok_or_else(|| rejected("V3 entry offer missing"))?;
                let encrypted = Envelope::decode(envelope.as_bytes())?;
                if encrypted.binding() != &entry.wire.crypto {
                    return Err(rejected("V3 entry ciphertext substitution"));
                }
                entry.check_action()?;
                self.core
                    .phase
                    .step(self.target.index(), V3_ENTRY_REVIEW, V3_ENTRY_ADMITTED)?;
                Ok(SignerFinancialWorkflowRequestV1::V3SourceEntry {
                    input: SignerV3SourceEntryInputV1 {
                        entry: Arc::clone(entry),
                        recipient: Some(recipient),
                        envelope: Some(encrypted),
                        consumed: false,
                    },
                    final_action: SignerV3SourceEntryFinalV1 {
                        entry: Arc::clone(entry),
                        consumed: false,
                    },
                })
            }
            _ => Err(rejected("wrong V3 entry command")),
        }
    }
    pub fn offer_v3_source_entry(
        &mut self,
        facts: SignerV3SourceEntryFactsV1,
        original_source: Instant,
        original_entry: Instant,
    ) -> Result<SignerV3SourceEntryPresentationV1> {
        if std::mem::replace(&mut self.v3_entry.offered, true) {
            self.core.phase.revoke();
            return Err(rejected("V3 entry offer reused"));
        }
        let r = self.offer_v3_entry_inner(facts, original_source, original_entry);
        if r.is_err() {
            self.core.phase.revoke();
            self.v3_entry.recipient.take();
        }
        r
    }
    fn offer_v3_entry_inner(
        &mut self,
        facts: SignerV3SourceEntryFactsV1,
        source: Instant,
        entry: Instant,
    ) -> Result<SignerV3SourceEntryPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let now = Instant::now();
        if self.core.phase.phase(self.target.index()) != V3_ENTRY_PREPARING
            || source > self.clocks.supervision()
            || entry > source
            || entry > now + Duration::from_secs(120)
            || self.host_peer_instance.as_deref()
                != Some(facts.original_host_process_instance.as_str())
        {
            return Err(rejected("V3 entry original peer/clock/phase mismatch"));
        }
        crate::channel::require_time(entry)?;
        if self
            .v3_entry
            .selection
            .as_ref()
            .is_none_or(|s| !s.matches(&facts))
        {
            return Err(rejected("V3 Entry changed original selection"));
        }
        let start = self
            .v3_entry
            .start
            .clone()
            .ok_or_else(|| rejected("V3 start missing"))?;
        let recipient = RecipientKey::generate()?;
        let public = recipient.public_key();
        let sender: [u8; 32] = hex::decode(&start.sender_public_key)
            .map_err(|_| rejected("V3 sender key"))?
            .try_into()
            .map_err(|_| rejected("V3 sender key length"))?;
        let actor = FinancialActorContextV1 {
            profile: PROFILE.into(),
            coordinator_process_instance: start.coordinator.clone(),
            coordinator_focus_epoch: 1,
            signer_role: self.target,
            signer_process_instance: self.instance.clone(),
            common_image_measurement: self.image.clone(),
            session_challenge: start.session.clone(),
        };
        let mut p = SignerV3SourceEntryPresentationV1 {
            actor,
            facts,
            notice: crate::signer_v3_source_entry_data::NOTICE.into(),
            sender_key_fingerprint: v3crypto::fingerprint(&sender),
            recipient_key_fingerprint: v3crypto::fingerprint(&public),
            request_challenge: start.request_challenge.clone(),
            offer_challenge: state::nonce()?,
            native_ceiling_ms: start.native_ceiling_ms,
            entry_ceiling_ms: self.clocks.restrictive_offset(entry, source)?,
            source_ceiling_ms: self
                .clocks
                .restrictive_offset(source, self.clocks.supervision())?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        p.validate()?;
        let offer = V3EntryOffer {
            crypto: crypto_binding(&start, &p, &hex::encode(public))?,
            start,
            presentation: p.clone(),
        };
        let binding =
            V3EntryReviewed::new(Arc::clone(&self.core), self.clocks, offer, source, entry)?;
        self.core
            .phase
            .step(self.target.index(), V3_ENTRY_PREPARING, V3_ENTRY_REVIEW)?;
        self.v3_entry.recipient = Some(recipient);
        self.v3_entry.entry = Some(Arc::clone(&binding));
        self.send(&Packet::V3EntryOffer {
            offer: binding.wire.clone(),
        })?;
        Ok(p)
    }
    pub fn v3_source_opened(&mut self, data: SignerV3SourceOpenedV1) -> Result<()> {
        data.validate()?;
        if self.v3_entry.opened
            || self.v3_entry.terminal
            || self.core.phase.phase(self.target.index()) != V3_OPENED
        {
            return Err(rejected("V3 opened report missing actual consumed Final"));
        }
        let e = self
            .v3_entry
            .entry
            .as_ref()
            .ok_or_else(|| rejected("V3 opened without Entry"))?;
        if data.entry_presentation_digest != e.wire.presentation.presentation_digest {
            return Err(rejected("V3 opened report substituted Entry"));
        }
        let p = Packet::V3SourceOpened {
            start: e.wire.start.clone(),
            data: data.clone(),
        };
        self.v3_entry.observation = Some(data);
        self.v3_entry.opened = true;
        self.send(&p)
    }
    pub fn v3_source_entry_failed(&mut self) -> Result<()> {
        if self.v3_entry.terminal || self.v3_entry.opened {
            return Err(rejected("V3 failure reused or after opened"));
        }
        let start = self
            .v3_entry
            .start
            .clone()
            .ok_or_else(|| rejected("V3 failure before start"))?;
        let presentation_digest = self
            .v3_entry
            .entry
            .as_ref()
            .map(|e| e.wire.presentation.presentation_digest.clone());
        self.v3_entry.terminal = true;
        self.v3_entry.recipient.take();
        self.restrict()?;
        self.send(&Packet::V3SourceFailed {
            start,
            presentation_digest,
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_source_entry(
        &self,
        mut offer: SignerV3SourceEntryOfferV1,
        password: Zeroizing<Vec<u8>>,
        input_request_digest: &str,
    ) -> Result<SignerV3SourceEntryOutboundV1> {
        let e = &offer.entry;
        if !Arc::ptr_eq(&self.core, &e.core)
            || !(12..=1024).contains(&password.len())
            || input_request_digest != e.wire.crypto.request_digest()?
        {
            self.revoke();
            return Err(rejected("V3 native Entry/input binding"));
        }
        offer.check_current()?;
        self.core
            .phase
            .step(e.slot(), V3_ENTRY_REVIEW, V3_ENTRY_ADMITTED)?;
        offer.consumed = true;
        Ok(SignerV3SourceEntryOutboundV1 {
            entry: Arc::clone(e),
            password: Some(password),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn begin_v3_source_entry_signer1(
        &mut self,
        selection: SignerV3SourceEntrySelectionV1,
        deadline: Instant,
    ) -> Result<()> {
        self.try_begin_v3_source_entry(Target::Signer1, selection, deadline)?
            .require_sent()
    }
    pub fn begin_v3_source_entry_signer2(
        &mut self,
        selection: SignerV3SourceEntrySelectionV1,
        deadline: Instant,
    ) -> Result<()> {
        self.try_begin_v3_source_entry(Target::Signer2, selection, deadline)?
            .require_sent()
    }
    pub fn try_begin_v3_source_entry(
        &mut self,
        role: Target,
        selection: SignerV3SourceEntrySelectionV1,
        original: Instant,
    ) -> Result<FinancialSendProgressV1> {
        let result = (|| {
            self.core.check_action_restrictions()?;
            selection.validate()?;
            let i = role.index();
            if self.v3_entries[i].start.is_some() || self.slots[i].is_some() {
                return Err(rejected("V3 initial Entry repeated or out of order"));
            }
            let ceiling = original
                .min(self.clocks.supervision())
                .min(Instant::now() + Duration::from_secs(120));
            crate::channel::require_time(ceiling)?;
            if self.core.phase.source_send_restricted(i, V3_INITIAL)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            self.core.phase.step(i, V3_INITIAL, V3_ENTRY_PREPARING)?;
            let sender = v3crypto::SenderKey::generate()?;
            let start = Start {
                profile: PROFILE.into(),
                coordinator: self.coordinator.clone(),
                session: self.session.clone(),
                role,
                request_challenge: state::nonce()?,
                native_ceiling_ms: self.clocks.restrictive_offset(ceiling, original)?,
                sender_public_key: hex::encode(sender.public_key()),
            };
            self.v3_entries[i] = CV3Entry {
                admission:admission::AdmissionSlot::default(),
                admit_read:admit_read::AdmitReadSlot::default(),
                audit:audit::AuditSlot::default(),
 financial_setup:None,
                delivery:delivery::DeliverySlots::default(),
                redisclosure:redisclosure::RedisclosureSlots::default(),
                pair:pair::PairSlot::default(),
                receipts:receipts::ReceiptSlots::default(),
                observation: None,
                selection: Some(selection.clone()),
                start: Some(start.clone()),
                sender: Some(sender),
                entry: None,
                wire_phase: V3_ENTRY_PREPARING,
                terminal: false,
                opened: false,
            };
            if self
                .core
                .phase
                .source_send_restricted(i, V3_ENTRY_PREPARING)?
            {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            self.send_positive(&Packet::V3StartEntry { start, selection }, ceiling)
        })();
        if result.is_err() {
            self.core.phase.revoke();
        }
        if matches!(result, Ok(FinancialSendProgressV1::Restricted)) {
            self.v3_entries[role.index()].terminal = true;
            self.v3_entries[role.index()].sender.take();
        }
        result
    }
    pub fn send_v3_source_entry(&mut self, outbound: SignerV3SourceEntryOutboundV1) -> Result<()> {
        self.try_send_v3_source_entry(outbound)?.require_sent()
    }
    pub fn try_send_v3_source_entry(
        &mut self,
        mut outbound: SignerV3SourceEntryOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let e = Arc::clone(&outbound.entry);
        let i = e.slot();
        let key = self.v3_entries[i].sender.take();
        let password = outbound.password.take();
        let result = (|| {
            if !Arc::ptr_eq(&self.core, &e.core)
                || self.v3_entries[i].wire_phase != V3_ENTRY_REVIEW
                || self.v3_entries[i]
                    .entry
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(old, &e))
            {
                return Err(rejected("V3 outbound foreign or reused"));
            }
            e.check_action_bounds()?;
            if self
                .core
                .phase
                .source_send_restricted(i, V3_ENTRY_ADMITTED)?
            {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let encrypted = key.ok_or_else(|| rejected("V3 sender consumed"))?.seal(
                e.wire.crypto.clone(),
                password.ok_or_else(|| rejected("V3 password consumed"))?,
            )?;
            let envelope = String::from_utf8(encrypted.encode()?)
                .map_err(|_| rejected("V3 ciphertext encoding"))?;
            e.check_action_bounds()?;
            if self
                .core
                .phase
                .source_send_restricted(i, V3_ENTRY_ADMITTED)?
            {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let progress = self.send_positive(&Packet::V3EntryCipher { envelope }, e.ceiling)?;
            if progress == FinancialSendProgressV1::Sent {
                self.v3_entries[i].wire_phase = V3_ENTRY_ADMITTED;
            }
            Ok(progress)
        })();
        outbound.consumed = true;
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
    pub(super) fn receive_v3_entry_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p
            .target()?
            .ok_or_else(|| rejected("V3 event role missing"))?;
        let i = role.index();
        let slot = &mut self.v3_entries[i];
        if slot.terminal || slot.opened {
            return Err(rejected("V3 response after terminal"));
        }
        let start = slot
            .start
            .as_ref()
            .ok_or_else(|| rejected("V3 unsolicited response"))?;
        match p {
            Packet::V3EntryOffer { offer } => {
                offer.validate()?;
                if slot.wire_phase != V3_ENTRY_PREPARING
                    || &offer.start != start
                    || slot.entry.is_some()
                    || slot
                        .selection
                        .as_ref()
                        .is_none_or(|s| !s.matches(&offer.presentation.facts))
                    || offer.presentation.actor.common_image_measurement != self.image
                {
                    return Err(rejected("V3 offer original binding"));
                }
                let now = Instant::now();
                let source = self.clocks.restrict_received(
                    PROFILE,
                    offer.presentation.source_ceiling_ms,
                    self.clocks.supervision(),
                    now,
                )?;
                let entry = self.clocks.restrict_received(
                    PROFILE,
                    offer.presentation.entry_ceiling_ms,
                    source,
                    now,
                )?;
                let binding = V3EntryReviewed::from_received_bounds(
                    Arc::clone(&self.core),
                    self.clocks,
                    offer,
                    source,
                    entry,
                )?;
                slot.entry = Some(Arc::clone(&binding));
                slot.wire_phase = V3_ENTRY_REVIEW;
                if !received_workflow_progress(
                    &self.core.phase,
                    i,
                    V3_ENTRY_PREPARING,
                    V3_ENTRY_REVIEW,
                )? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3SourceEntryOffer(
                    SignerV3SourceEntryOfferV1 {
                        entry: binding,
                        consumed: false,
                    },
                ))
            }
            Packet::V3SourceOpened {
                start: received,
                data,
            } => {
                data.validate()?;
                let e = slot
                    .entry
                    .as_ref()
                    .ok_or_else(|| rejected("V3 opened before offer"))?;
                if slot.wire_phase != V3_ENTRY_ADMITTED
                    || &received != start
                    || data.entry_presentation_digest != e.wire.presentation.presentation_digest
                {
                    return Err(rejected("V3 opened retained binding"));
                }
                slot.observation = Some(data.clone());
                slot.opened = true;
                slot.wire_phase = V3_OPENED;
                if !received_workflow_progress(&self.core.phase, i, V3_ENTRY_ADMITTED, V3_OPENED)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3SourceOpened { role, data })
            }
            Packet::V3SourceFailed {
                start: received,
                presentation_digest,
            } => {
                if &received != start
                    || !v3_failure_matches(
                        slot.entry
                            .as_ref()
                            .map(|e| e.wire.presentation.presentation_digest.as_str()),
                        presentation_digest.as_deref(),
                        slot.wire_phase,
                        self.core.phase.revoked(),
                    )
                {
                    return Err(rejected("V3 failure retained binding"));
                }
                slot.terminal = true;
                self.core.phase.revoke();
                if self.cleanup.is_none() {
                    self.cleanup = Some(self.clocks.first_cleanup_ceiling(Instant::now())?);
                }
                Ok(CoordinatorFinancialEventV1::V3SourceEntryFailed {
                    role,
                    presentation_digest,
                })
            }
            _ => Err(rejected("wrong V3 entry event")),
        }
    }
}
impl HostFinancialWorkflowRelayV1 {
    pub(super) fn down_v3_entry(&mut self, p: &Packet) -> Result<()> {
        if self.restricted {
            return Err(rejected("V3 entry command after R"));
        }
        let role = p
            .target()?
            .ok_or_else(|| rejected("V3 down role missing"))?;
        let i = role.index();
        let slot = &mut self.v3_entries[i];
        if slot.terminal || slot.opened {
            return Err(rejected("V3 down after terminal"));
        }
        match p {
            Packet::V3StartEntry { start, selection } => {
                start.validate()?;
                selection.validate()?;
                if slot.start.is_some()
                    || self.slots[i].is_some()
                    || self
                        .coordinator
                        .as_ref()
                        .is_some_and(|s| s != &start.coordinator)
                    || self.session.as_ref().is_some_and(|s| s != &start.session)
                {
                    return Err(rejected("V3 relay initial binding changed"));
                }
                self.clocks.restrict_received(
                    PROFILE,
                    start.native_ceiling_ms,
                    self.clocks.supervision(),
                    Instant::now(),
                )?;
                self.coordinator = Some(start.coordinator.clone());
                self.session = Some(start.session.clone());
                slot.start = Some(start.clone());
                slot.selection = Some(selection.clone());
                slot.phase = V3_ENTRY_PREPARING;
                Ok(())
            }
            Packet::V3EntryCipher { envelope } => {
                let e = slot
                    .offer
                    .as_ref()
                    .ok_or_else(|| rejected("V3 relay cipher before offer"))?;
                let encrypted = Envelope::decode(envelope.as_bytes())?;
                if slot.phase != V3_ENTRY_REVIEW
                    || !slot.forwarded
                    || encrypted.binding() != &e.crypto
                {
                    return Err(rejected("V3 relay ciphertext binding"));
                }
                v3_relay_current(e, self.clocks, &mut slot.last_wall)?;
                slot.phase = V3_ENTRY_ADMITTED;
                Ok(())
            }
            _ => Err(rejected("wrong V3 relay command")),
        }
    }
    pub(super) fn up_v3_entry(&mut self, role: Target, p: &Packet) -> Result<bool> {
        let slot = &mut self.v3_entries[role.index()];
        if slot.terminal || slot.opened {
            return Err(rejected("V3 relay response after terminal"));
        }
        let start = slot
            .start
            .as_ref()
            .ok_or_else(|| rejected("V3 relay response before start"))?;
        match p {
            Packet::V3EntryOffer { offer } => {
                offer.validate()?;
                if slot.phase != V3_ENTRY_PREPARING
                    || slot.offer.is_some()
                    || &offer.start != start
                    || offer.presentation.actor.common_image_measurement != self.image
                    || offer.presentation.facts.original_host_process_instance
                        != self.host_peer_instance
                    || slot
                        .selection
                        .as_ref()
                        .is_none_or(|s| !s.matches(&offer.presentation.facts))
                {
                    return Err(rejected("V3 relay full selected source changed"));
                }
                if !self.restricted {
                    v3_relay_current(offer, self.clocks, &mut slot.last_wall)?;
                }
                slot.offer = Some(offer.clone());
                slot.forwarded = !self.restricted;
                slot.phase = V3_ENTRY_REVIEW;
                Ok(!self.restricted)
            }
            Packet::V3SourceOpened {
                start: received,
                data,
            } => {
                data.validate()?;
                let e = slot
                    .offer
                    .as_ref()
                    .ok_or_else(|| rejected("V3 relay opened before offer"))?;
                if slot.phase != V3_ENTRY_ADMITTED
                    || received != start
                    || data.entry_presentation_digest != e.presentation.presentation_digest
                {
                    return Err(rejected("V3 relay opened mismatch"));
                }
                slot.phase = V3_OPENED;
                slot.observation = Some(data.clone());
                slot.opened = true;
                Ok(slot.forwarded)
            }
            Packet::V3SourceFailed {
                start: received,
                presentation_digest,
            } => {
                if received != start
                    || presentation_digest.as_ref()
                        != slot
                            .offer
                            .as_ref()
                            .map(|e| &e.presentation.presentation_digest)
                {
                    return Err(rejected("V3 relay failed mismatch"));
                }
                slot.terminal = true;
                self.restrict()?;
                Ok(true)
            }
            _ => Err(rejected("wrong V3 relay response")),
        }
    }
}
fn v3_relay_current(e: &V3EntryOffer, clocks: FullWorkflowClocksV1, last: &mut u64) -> Result<()> {
    let p = &e.presentation;
    let now = Instant::now();
    for n in [p.native_ceiling_ms, p.entry_ceiling_ms, p.source_ceiling_ms] {
        clocks.restrict_received(PROFILE, n, clocks.supervision(), now)?;
    }
    let wall = state::wall_ms()?;
    if wall < *last
        || wall < p.facts.reviewed_at_ms
        || wall >= p.facts.expires_at_ms
        || wall >= p.facts.source_expires_at_ms
    {
        return Err(rejected("V3 relay original wall bounds"));
    }
    *last = wall;
    Ok(())
}

impl SV3Entry {
    pub(super) fn cancel_matches(&self, c: &str, s: &str) -> bool {
        self.start
            .as_ref()
            .is_none_or(|v| v.coordinator == c && v.session == s)
    }
}
impl CV3Entry {
    pub(super) fn observe_active(&self, phase: u8, clocks: FullWorkflowClocksV1) -> Result<()> {
        if self.terminal || self.opened {
            return Ok(());
        }
        if phase == V3_ENTRY_PREPARING {
            if let Some(s) = &self.start {
                clocks.restrict_received(
                    PROFILE,
                    s.native_ceiling_ms,
                    clocks.supervision(),
                    Instant::now(),
                )?;
            }
        } else if matches!(phase, V3_ENTRY_REVIEW | V3_ENTRY_ADMITTED) {
            self.entry
                .as_ref()
                .ok_or_else(|| rejected("V3 active offer missing"))?
                .check_action()?;
        }
        Ok(())
    }
}
impl HV3Entry {
    pub(super) fn allows_financial_entry(&self) -> bool {
        self.phase == V3_HELD && self.opened && !self.terminal && self.financial_setup.is_some()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opening_original_source_does_not_prove_completed_v3() {
        let p = Phases::new();
        for (a, b) in [
            (V3_INITIAL, V3_ENTRY_PREPARING),
            (V3_ENTRY_PREPARING, V3_ENTRY_REVIEW),
            (V3_ENTRY_REVIEW, V3_ENTRY_ADMITTED),
            (V3_ENTRY_ADMITTED, V3_OPENED),
        ] {
            p.step(0, a, b).unwrap();
            assert!(p.step(0, a, b).is_err());
        }
        assert_ne!(p.phase(0), V3_HELD);
        assert!(p.step(0, V3_HELD, ENTRY_PREPARING).is_err());
    }
    #[test]
    fn entry_new_action_and_finish_are_both_denied_after_r() {
        for phase in [
            V3_INITIAL,
            V3_ENTRY_PREPARING,
            V3_ENTRY_REVIEW,
            V3_ENTRY_ADMITTED,
        ] {
            let p = Phases::new();
            if phase != 0 {
                p.step(0, 0, phase).unwrap();
            }
            p.revoke();
            assert!(p.step(0, phase, phase + 1).is_err());
        }
    }
    #[test]
    fn public_selection_is_not_actual_source_disposition() {
        let s = SV3Entry::default();
        assert!(s.disposal_allowed());
        let h = HV3Entry::default();
        assert!(!h.allows_financial_entry());
    }
}

fn v3_failure_matches(
    observed: Option<&str>,
    reported: Option<&str>,
    phase: u8,
    revoked: bool,
) -> bool {
    observed == reported
        || (observed.is_none()
            && reported.is_some_and(state::hash)
            && phase == V3_ENTRY_PREPARING
            && revoked)
}
#[cfg(test)]
mod failure_race_tests {
    use super::*;
    #[test]
    fn queued_offer_suppressed_by_r_can_still_report_terminal_failure() {
        let h = "ab".repeat(32);
        assert!(v3_failure_matches(None, Some(&h), V3_ENTRY_PREPARING, true));
        assert!(!v3_failure_matches(
            None,
            Some(&h),
            V3_ENTRY_PREPARING,
            false
        ));
        assert!(!v3_failure_matches(None, Some(&h), V3_ENTRY_REVIEW, true));
        assert!(!v3_failure_matches(
            Some(&"cd".repeat(32)),
            Some(&h),
            V3_ENTRY_PREPARING,
            true
        ));
    }
}

impl SV3Entry { pub(super) fn has_financial_setup(&self)->bool{self.financial_setup.is_some()} }
impl CV3Entry { pub(super) fn has_financial_setup(&self)->bool{self.financial_setup.is_some()} }
/// Original transport/material ceilings observed from the actual completed V3
/// custody. Private ordinary metadata only, never a transferable permission.
#[derive(Clone,Copy)]pub(super) struct ReturnTransportBounds{pub(super) channel:Instant,pub(super) material:Instant,pub(super) channel_ceiling:u64,pub(super) material_ceiling:u64,pub(super) channel_wall:u64,pub(super) material_wall:u64}
impl SV3Entry{pub(super) fn return_transport_bounds(&self)->Result<ReturnTransportBounds>{if !self.audit.reported{return Err(rejected("Return before actual V3 Audit"));}let b=self.audit.binding.as_ref().ok_or_else(||rejected("Return missing actual V3 custody"))?;b.owner.custody_bounds()?;Ok(ReturnTransportBounds{channel:b.owner.pair.channel_deadline,material:b.owner.material_deadline,channel_ceiling:b.owner.pair.p.channel_ceiling_ms,material_ceiling:b.owner.p.material_ceiling_ms,channel_wall:b.owner.pair.p.facts.channel_expires_at_ms,material_wall:b.owner.p.facts.material_expires_at_ms})}}
impl CV3Entry{pub(super) fn return_transport_bounds(&self)->Result<ReturnTransportBounds>{if !self.audit.reported{return Err(rejected("Return before actual V3 Audit"));}let b=self.audit.binding.as_ref().ok_or_else(||rejected("Return missing actual V3 custody"))?;b.owner.custody_bounds()?;Ok(ReturnTransportBounds{channel:b.owner.pair.channel_deadline,material:b.owner.material_deadline,channel_ceiling:b.owner.pair.p.channel_ceiling_ms,material_ceiling:b.owner.p.material_ceiling_ms,channel_wall:b.owner.pair.p.facts.channel_expires_at_ms,material_wall:b.owner.p.facts.material_expires_at_ms})}}
impl HV3Entry{pub(super) fn return_transport_bounds(&self,clocks:FullWorkflowClocksV1)->Result<ReturnTransportBounds>{if !self.audit.reported{return Err(rejected("Return relay before actual V3 Audit"));}let (p,_)=self.delivery.admission_wire()?;let pair=self.pair.wire.as_ref().ok_or_else(||rejected("Return missing original Pair"))?;let now=Instant::now();let wall=state::wall_ms()?;let channel=clocks.restrict_received(PROFILE,pair.channel_ceiling_ms,clocks.supervision(),now)?.min(wall_ceiling(now,wall,pair.facts.reviewed_at_ms,pair.facts.channel_expires_at_ms)?);let material=clocks.restrict_received(PROFILE,p.material_ceiling_ms,clocks.supervision(),now)?.min(wall_ceiling(now,wall,p.facts.reviewed_at_ms,p.facts.material_expires_at_ms)?);Ok(ReturnTransportBounds{channel,material,channel_ceiling:pair.channel_ceiling_ms,material_ceiling:p.material_ceiling_ms,channel_wall:pair.facts.channel_expires_at_ms,material_wall:p.facts.material_expires_at_ms})}}

