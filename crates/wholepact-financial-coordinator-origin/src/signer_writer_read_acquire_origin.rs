//! Same-Core fresh Writer Read and exact Acquire recipe protocol. The original
//! Entry custody is restriction-only. Completed Read/Admit grants are not reused.
//! Native Writer Read and Acquire A each require the actual same-Core original
//! FinancialSigning Serving owner; its correlation never constructs that owner.
use super::signing::{FinancialSigningServingV1, SigningServiceLease};
use super::*;
use crate::financial_signing_data::{FinancialSigningOriginalV1, FinancialSigningServiceV1};
use crate::signer_admit_data::{SignerAdmitCommittedV1, SignerAdmitPresentationV1};
use crate::signer_writer_read_acquire_data::*;
use std::sync::{atomic::AtomicU64, OnceLock};

/// Original-H correlation and a once-restored restrictive service clock only.
/// S/H do not acquire a direct W peer or infer independent W liveness here.
pub(super) struct ReceivedSigning {
    data: FinancialSigningServiceV1,
    pub(super) deadline: Instant,
    pub(super) digest: String,
}
impl ReceivedSigning {
    fn restore(
        data: FinancialSigningServiceV1,
        expected: &FinancialSigningOriginalV1,
        writer: &str,
        clocks: FullWorkflowClocksV1,
        source: Instant,
    ) -> Result<Self> {
        data.validate()?;
        if !service_data_matches(&data, expected, writer) {
            return Err(rejected(
                "Signing service replaced retained originals or writer",
            ));
        }
        let deadline =
            clocks.restrict_received(PROFILE, data.service_ceiling_ms, source, Instant::now())?;
        let digest = data.commitment()?;
        Ok(Self {
            data,
            deadline,
            digest,
        })
    }
    pub(super) fn check(&self) -> Result<()> {
        crate::channel::require_time(self.deadline)
    }
    pub(super) fn correlation(&self) -> &FinancialSigningServiceV1 {
        &self.data
    }
    pub(super) fn original_deadline(&self) -> Instant {
        self.deadline
    }
    /// Copy restriction-only retained facts without restoring or renewing time.
    pub(super) fn retained_restriction(&self) -> Self {
        Self {
            data: self.data.clone(),
            deadline: self.deadline,
            digest: self.digest.clone(),
        }
    }
    pub(super) fn require_same(&self, data: &FinancialSigningServiceV1) -> Result<()> {
        if &self.data != data {
            return Err(rejected("Signing service correlation changed"));
        }
        self.check()
    }
}
fn service_data_matches(
    data: &FinancialSigningServiceV1,
    expected: &FinancialSigningOriginalV1,
    writer: &str,
) -> bool {
    &data.original == expected && data.writer_certificate_digest == writer
}
fn original_links_entry(
    o: &FinancialSigningOriginalV1,
    e: &SignerSourceEntryPresentationV1,
) -> bool {
    o.actor == e.actor
        && o.source_ceiling_ms == e.source_ceiling_ms
        && o.source_expires_at_ms == e.facts.source_expires_at_ms
        && o.original_host_process_instance == e.facts.original_host_process_instance
        && o.account_id == e.facts.account_id
        && o.owner_certificate_digest == e.facts.owner_certificate_digest
        && o.owner_disclosure_digest == e.facts.disclosure_digest
        && o.terms_digest == e.facts.terms_digest
}
// Called only with actual once-retained Admit/commit records, never a public
// source constructor. All fields are copied, not inferred from the next Read.
fn expected_signing_original(
    a: &SignerAdmitPresentationV1,
    c: &SignerAdmitCommittedV1,
) -> Result<FinancialSigningOriginalV1> {
    if c.presentation_digest != a.presentation_digest || c.request_digest != a.facts.request_digest
    {
        return Err(rejected("Signing original committed record changed"));
    }
    let f = &a.facts;
    let original = FinancialSigningOriginalV1 {
        actor: a.actor.clone(),
        continue_presentation_digest: a.continue_presentation_digest.clone(),
        prepared_digest: a.prepared_digest.clone(),
        admit_presentation_digest: a.presentation_digest.clone(),
        admission_ready_digest: c.admission_ready_digest.clone(),
        signer_source_identity_digest: f.source_identity_digest.clone(),
        admission_terms_digest: f.admission_terms_digest.clone(),
        request_json: f.request_json.clone(),
        request_digest: f.request_digest.clone(),
        original_host_process_instance: f.original_host_process_instance.clone(),
        owner_certificate_digest: f.owner_certificate_digest.clone(),
        owner_disclosure_json: f.disclosure_json.clone(),
        owner_disclosure_digest: f.disclosure_digest.clone(),
        owner_selection_digest: a.owner_selection_digest.clone(),
        terms_digest: f.terms_digest.clone(),
        account_id: f.account_id.clone(),
        network_profile_id: f.network_profile_id.clone(),
        operation_id: f.operation_id.clone(),
        admitted_head_sequence: c.head_sequence,
        admitted_head_digest: c.head_digest.clone(),
        source_ceiling_ms: a.source_ceiling_ms,
        source_expires_at_ms: f.source_expires_at_ms,
    };
    original.validate()?;
    Ok(original)
}

pub(super) const WRITER_READ_REVIEW: u8 = 40;
pub(super) const WRITER_READ_ADMITTED: u8 = 41;
pub(super) const ACQUIRE_PREPARED: u8 = 42;
pub(super) const ACQUIRE_REVIEW: u8 = 43;
pub(super) const ACQUIRE_ARMED: u8 = 44;
pub(super) const ACQUIRE_READY: u8 = 45;
pub(super) const ACQUIRE_ADMITTED: u8 = 46;
pub(super) const AWAITING_ACTIVATE_READ: u8 = 47;

struct WriterRead {
    entry: Arc<EntryReviewed>,
    wire: SignerFinancialWriterReadPresentationV1,
    original_read: Instant,
    ceiling: Instant,
    last_wall: AtomicU64,
    prepared: AtomicBool,
    original: FinancialSigningOriginalV1,
    service: OnceLock<ReceivedSigning>,
}
impl WriterRead {
    fn from_bounds(
        entry: Arc<EntryReviewed>,
        wire: SignerFinancialWriterReadPresentationV1,
        original_read: Instant,
        original: FinancialSigningOriginalV1,
    ) -> Result<Arc<Self>> {
        wire.validate()?;
        if !original_links_entry(&original, &entry.wire.presentation)
            || wire.actor != entry.wire.presentation.actor
            || wire.source_ceiling_ms != entry.wire.presentation.source_ceiling_ms
            || original.actor != wire.actor
            || original.source_ceiling_ms != wire.source_ceiling_ms
            || original.source_expires_at_ms != wire.facts.source_expires_at_ms
        {
            return Err(rejected("Writer Read original actor/source changed"));
        }
        let now = Instant::now();
        let wall = state::wall_ms()?;
        let ceiling = entry
            .clocks
            .restrict_received(PROFILE, wire.read_ceiling_ms, original_read, now)?
            .min(entry.original_source)
            .min(wall_ceiling(
                now,
                wall,
                wire.facts.reviewed_at_ms,
                wire.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            entry,
            wire,
            original_read,
            ceiling,
            last_wall: AtomicU64::new(wall),
            prepared: AtomicBool::new(false),
            original,
            service: OnceLock::new(),
        });
        b.check_bounds()?;
        Ok(b)
    }
    fn core(&self) -> &Arc<Core> {
        &self.entry.core
    }
    fn slot(&self) -> usize {
        self.entry.slot()
    }
    fn check_bounds(&self) -> Result<()> {
        self.entry.check_custody()?;
        crate::channel::require_time(self.original_read.min(self.ceiling))?;
        if let Some(service) = self.service.get() {
            service.check()?;
        }
        observe_wall(
            &self.last_wall,
            self.wire.facts.reviewed_at_ms,
            self.wire.facts.expires_at_ms,
        )
    }
    fn check(&self) -> Result<()> {
        self.check_bounds()?;
        self.core().check_action_restrictions()
    }
}
impl WriterRead {
    fn bind_service(&self, data: FinancialSigningServiceV1) -> Result<()> {
        let bound = ReceivedSigning::restore(
            data,
            &self.original,
            &self.wire.facts.writer_certificate_digest,
            self.entry.clocks,
            self.entry.original_source,
        )?;
        self.service
            .set(bound)
            .map_err(|_| rejected("Writer Read service binding reused"))
    }
    fn service(&self) -> Result<&ReceivedSigning> {
        self.service
            .get()
            .ok_or_else(|| rejected("actual Writer Read service correlation missing"))
    }
}
struct AcquireReview {
    // Retained provenance only. No completed Writer Read action clock is an
    // ancestor of Acquire; only entry custody and this own frozen clock apply.
    read: Arc<WriterRead>,
    wire: SignerAcquirePresentationV1,
    original_acquire: Instant,
    ceiling: Instant,
    last_wall: AtomicU64,
}
impl AcquireReview {
    fn from_bounds(
        read: Arc<WriterRead>,
        wire: SignerAcquirePresentationV1,
        original_acquire: Instant,
    ) -> Result<Arc<Self>> {
        wire.validate()?;
        if !acquire_links_read(&wire, &read.wire) {
            return Err(rejected("Acquire replaced retained Writer Read/source"));
        }
        let now = Instant::now();
        let wall = state::wall_ms()?;
        let ceiling = read
            .entry
            .clocks
            .restrict_received(PROFILE, wire.acquire_ceiling_ms, original_acquire, now)?
            .min(read.entry.original_source)
            .min(wall_ceiling(
                now,
                wall,
                wire.facts.reviewed_at_ms,
                wire.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            read,
            wire,
            original_acquire,
            ceiling,
            last_wall: AtomicU64::new(wall),
        });
        b.check_bounds()?;
        Ok(b)
    }
    fn core(&self) -> &Arc<Core> {
        self.read.core()
    }
    fn slot(&self) -> usize {
        self.read.slot()
    }
    fn check_bounds(&self) -> Result<()> {
        self.read.entry.check_custody()?;
        self.read.service()?.check()?;
        crate::channel::require_time(self.original_acquire.min(self.ceiling))?;
        observe_wall(
            &self.last_wall,
            self.wire.facts.reviewed_at_ms,
            self.wire.facts.expires_at_ms,
        )
    }
    fn check(&self) -> Result<()> {
        self.check_bounds()?;
        self.core().check_action_restrictions()
    }
}
fn observe_wall(last: &AtomicU64, start: u64, end: u64) -> Result<()> {
    let wall = state::wall_ms()?;
    let prior = last.fetch_max(wall, Ordering::AcqRel);
    if wall < prior || wall < start || wall >= end {
        return Err(rejected("writer action original wall bound elapsed"));
    }
    Ok(())
}
struct AcquireReady {
    review: Arc<AcquireReview>,
    challenge: String,
    digest: String,
}

pub struct SignerFinancialWriterReadTicketV1 {
    binding: Arc<WriterRead>,
    consumed: bool,
}
impl SignerFinancialWriterReadTicketV1 {
    pub fn presentation(&self) -> &SignerFinancialWriterReadPresentationV1 {
        &self.binding.wire
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        require_phase(self.binding.core(), self.binding.slot(), WRITER_READ_REVIEW)
    }
}
impl Drop for SignerFinancialWriterReadTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerFinancialWriterReadOutboundV1 {
    binding: Arc<WriterRead>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerFinancialWriterReadOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
/// Only actual matching original-H receive constructs this one-use Read.
pub struct SignerFinancialWriterReadFinalV1 {
    binding: Arc<WriterRead>,
    consumed: bool,
}
impl SignerFinancialWriterReadFinalV1 {
    pub fn presentation(&self) -> &SignerFinancialWriterReadPresentationV1 {
        &self.binding.wire
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.entry.original_source
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.binding.original_read
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding
            .service
            .get()
            .expect("private received Final service")
            .deadline
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        self.binding.service()?.check()?;
        require_phase(
            self.binding.core(),
            self.binding.slot(),
            WRITER_READ_ADMITTED,
        )
    }
    /// Only after the complete actual source/history/writer/immutable recipe
    /// preparation. Protocol progress is not proof of any of those source facts.
    pub fn finish_read(mut self) -> Result<()> {
        self.check_current()?;
        if !self.binding.prepared.load(Ordering::Acquire) {
            return Err(rejected("Writer Read lacks frozen Acquire presentation"));
        }
        self.binding.core().phase.step(
            self.binding.slot(),
            WRITER_READ_ADMITTED,
            ACQUIRE_PREPARED,
        )?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerFinancialWriterReadFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerAcquireReviewTicketV1 {
    binding: Arc<AcquireReview>,
    consumed: bool,
}
impl SignerAcquireReviewTicketV1 {
    pub fn presentation(&self) -> &SignerAcquirePresentationV1 {
        &self.binding.wire
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        require_phase(self.binding.core(), self.binding.slot(), ACQUIRE_REVIEW)
    }
}
impl Drop for SignerAcquireReviewTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerAcquireArmOutboundV1 {
    binding: Arc<AcquireReview>,
    consumed: bool,
}
impl Drop for SignerAcquireArmOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerAcquireArmV1 {
    binding: Arc<AcquireReview>,
}
impl SignerAcquireArmV1 {
    pub fn presentation(&self) -> &SignerAcquirePresentationV1 {
        &self.binding.wire
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.read.entry.original_source
    }
    pub fn original_acquire_deadline(&self) -> Instant {
        self.binding.original_acquire
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        require_phase(self.binding.core(), self.binding.slot(), ACQUIRE_ARMED)
    }
}
pub struct SignerAcquireReadyTicketV1 {
    binding: Arc<AcquireReady>,
    consumed: bool,
}
impl SignerAcquireReadyTicketV1 {
    pub fn presentation(&self) -> &SignerAcquirePresentationV1 {
        &self.binding.review.wire
    }
    pub fn acquire_ready_digest(&self) -> &str {
        &self.binding.digest
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.review.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.review.check()?;
        require_phase(
            self.binding.review.core(),
            self.binding.review.slot(),
            ACQUIRE_READY,
        )
    }
}
impl Drop for SignerAcquireReadyTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.review.core().phase.revoke();
        }
    }
}
pub struct SignerAcquireFinalOutboundV1 {
    binding: Arc<AcquireReady>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerAcquireFinalOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.review.core().phase.revoke();
        }
    }
}
/// Only exact original-H receive constructs this grant. The service correlation
/// was fixed by genuine native Serving and cannot mint a service owner here.
pub struct SignerAcquireFinalV1 {
    binding: Arc<AcquireReady>,
}
impl SignerAcquireFinalV1 {
    pub fn presentation(&self) -> &SignerAcquirePresentationV1 {
        &self.binding.review.wire
    }
    pub fn acquire_ready_digest(&self) -> &str {
        &self.binding.digest
    }
    pub fn signing_service_digest(&self) -> &str {
        &self
            .binding
            .review
            .read
            .service
            .get()
            .expect("private received Final service")
            .digest
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.review.read.entry.original_source
    }
    pub fn original_acquire_deadline(&self) -> Instant {
        self.binding.review.original_acquire
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding
            .review
            .read
            .service
            .get()
            .expect("private received Final service")
            .deadline
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.review.check()?;
        require_phase(
            self.binding.review.core(),
            self.binding.review.slot(),
            ACQUIRE_ADMITTED,
        )
    }
}
fn require_phase(core: &Core, slot: usize, phase: u8) -> Result<()> {
    if core.phase.phase(slot) != phase {
        return Err(rejected("writer action already consumed or wrong phase"));
    }
    Ok(())
}
struct AcquiredRetention {
    data: SignerAcquireCommittedV1,
    original_writer_session_deadline: Instant,
}
// One conservative restoration at authenticated receipt observation. This
// never refreshes an action and is never recomputed by a later purpose.
fn received_writer_session_deadline(
    clocks: FullWorkflowClocksV1,
    offset: u64,
    data: &SignerAcquireCommittedV1,
    source: Instant,
    service: Instant,
) -> Result<Instant> {
    let now = Instant::now();
    let wall = state::wall_ms()?
        .checked_add(1)
        .ok_or_else(|| rejected("writer receipt wall ceiling overflow"))?;
    let remaining = data
        .expires_at_ms
        .checked_sub(wall)
        .filter(|n| *n > 0)
        .ok_or_else(|| rejected("authenticated writer receipt already expired"))?;
    let wall_cap = now
        .checked_add(std::time::Duration::from_millis(remaining))
        .ok_or_else(|| rejected("writer receipt ceiling overflow"))?;
    let maximum = clocks.restrictive_offset(source.min(service), source)?;
    if offset > maximum {
        return Err(rejected(
            "writer receipt offset exceeds retained source/service",
        ));
    }
    let restored = clocks.restrict_received(PROFILE, offset, source.min(service), now)?;
    if restored > wall_cap {
        return Err(rejected("writer receipt original ceiling exceeds expiry"));
    }
    Ok(restored)
}
#[derive(Default)]
pub(super) struct SWritAcquire {
    offered: bool,
    preparing: bool,
    read: Option<Arc<WriterRead>>,
    review: Option<Arc<AcquireReview>>,
    display_sent: bool,
    ready: Option<Arc<AcquireReady>>,
    attempted: bool,
    terminal: bool,
    committed: Option<AcquiredRetention>,
}
#[derive(Default)]
pub(super) struct CWritAcquire {
    read_wire: Option<SignerFinancialWriterReadPresentationV1>,
    read: Option<Arc<WriterRead>>,
    wire: Option<SignerAcquirePresentationV1>,
    review: Option<Arc<AcquireReview>>,
    observed_ready: Option<String>,
    ready: Option<Arc<AcquireReady>>,
    terminal: bool,
    committed: Option<AcquiredRetention>,
}
#[derive(Default)]
pub(super) struct HWritAcquire {
    read: Option<SignerFinancialWriterReadPresentationV1>,
    wire: Option<SignerAcquirePresentationV1>,
    ready: Option<(String, String)>,
    service: Option<ReceivedSigning>,
    read_forwarded: bool,
    display_forwarded: bool,
    terminal: bool,
    committed: Option<AcquiredRetention>,
}
fn read_links_admit(
    p: &SignerFinancialWriterReadPresentationV1,
    a: &SignerAdmitPresentationV1,
    committed: &SignerAdmitCommittedV1,
) -> bool {
    let f = &p.facts;
    let old = &a.facts;
    p.actor == a.actor
        && p.source_ceiling_ms == a.source_ceiling_ms
        && f.source_identity_digest == old.source_identity_digest
        && f.terms_digest == old.terms_digest
        && f.continuation_request_json == old.request_json
        && f.continuation_request_digest == old.request_digest
        && f.admit_presentation_digest == a.presentation_digest
        && committed.presentation_digest == a.presentation_digest
        && f.admit_request_digest == committed.request_digest
        && f.admitted_head_sequence == committed.head_sequence
        && f.admitted_head_digest == committed.head_digest
        && f.original_host_process_instance == old.original_host_process_instance
        && f.owner_certificate_digest == old.owner_certificate_digest
        && f.owner_disclosure_digest == old.disclosure_digest
        && f.source_expires_at_ms == old.source_expires_at_ms
}
fn acquire_links_read(
    p: &SignerAcquirePresentationV1,
    r: &SignerFinancialWriterReadPresentationV1,
) -> bool {
    let f = &p.facts;
    let old = &r.facts;
    p.actor == r.actor
        && p.source_ceiling_ms == r.source_ceiling_ms
        && f.source_identity_digest == old.source_identity_digest
        && f.terms_digest == old.terms_digest
        && f.continuation_request_json == old.continuation_request_json
        && f.continuation_request_digest == old.continuation_request_digest
        && f.admit_presentation_digest == old.admit_presentation_digest
        && f.writer_read_presentation_digest == r.presentation_digest
        && f.original_host_process_instance == old.original_host_process_instance
        && f.owner_certificate_digest == old.owner_certificate_digest
        && f.owner_disclosure_digest == old.owner_disclosure_digest
        && f.writer_selection_digest == old.writer_selection_digest
        && f.writer_certificate_digest == old.writer_certificate_digest
        && f.writer_disclosure_json == old.writer_disclosure_json
        && f.writer_disclosure_digest == old.writer_disclosure_digest
        && f.source_expires_at_ms == old.source_expires_at_ms
        && f.expected_head_sequence >= old.admitted_head_sequence
        && (f.expected_head_sequence != old.admitted_head_sequence
            || f.expected_head_digest == old.admitted_head_digest)
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_writer_read(
        &mut self,
        facts: SignerFinancialWriterReadFactsV1,
        original_source: Instant,
        original_read: Instant,
    ) -> Result<SignerFinancialWriterReadPresentationV1> {
        if std::mem::replace(&mut self.writer_acquire.offered, true) {
            self.restrict()?;
            return Err(rejected("Writer Read offer reused"));
        }
        let result = self.offer_writer_read_inner(facts, original_source, original_read);
        if result.is_err() {
            self.restrict()?;
        }
        result
    }
    fn offer_writer_read_inner(
        &mut self,
        facts: SignerFinancialWriterReadFactsV1,
        original_source: Instant,
        original_read: Instant,
    ) -> Result<SignerFinancialWriterReadPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        if self.cancel_seen || self.failed || self.disposed {
            return Err(rejected("Writer Read after terminal"));
        }
        require_phase(&self.core, self.target.index(), admit::AWAITING_NEXT_READ)?;
        let entry = self
            .entry
            .as_ref()
            .ok_or_else(|| rejected("Writer Read original Entry missing"))?;
        let (admit, committed) = self.admission.retained_result()?;
        if original_source != entry.original_source {
            return Err(rejected("Writer Read changed original source Instant"));
        }
        require_new_deadline(original_read, original_source)?;
        let mut p = SignerFinancialWriterReadPresentationV1 {
            version: 1,
            purpose: WRITER_READ_PURPOSE.into(),
            actor: admit.actor.clone(),
            facts,
            notice: WRITER_READ_NOTICE.into(),
            read_challenge: state::nonce()?,
            source_ceiling_ms: admit.source_ceiling_ms,
            read_ceiling_ms: self
                .clocks
                .restrictive_offset(original_read, original_source)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        p.validate()?;
        if !read_links_admit(&p, admit, committed) {
            return Err(rejected("Writer Read changed retained Admit originals"));
        }
        let b = WriterRead::from_bounds(
            Arc::clone(entry),
            p.clone(),
            original_read,
            expected_signing_original(admit, committed)?,
        )?;
        b.check()?;
        self.core.phase.step(
            self.target.index(),
            admit::AWAITING_NEXT_READ,
            WRITER_READ_REVIEW,
        )?;
        self.writer_acquire.read = Some(b);
        self.send(&Packet::WriterReadDisplay { data: p.clone() })?;
        Ok(p)
    }
    /// All private preparation remains under the supplied actual live Read.
    /// This freezes data once; it does not authorize an Acquire effect.
    pub fn begin_acquire_review(
        &mut self,
        read: &SignerFinancialWriterReadFinalV1,
        facts: SignerAcquireFactsV1,
        original_source: Instant,
        original_acquire: Instant,
    ) -> Result<SignerAcquirePresentationV1> {
        if std::mem::replace(&mut self.writer_acquire.preparing, true) {
            self.restrict()?;
            return Err(rejected("Acquire preparation reused"));
        }
        let result = self.begin_acquire_inner(read, facts, original_source, original_acquire);
        if result.is_err() {
            self.restrict()?;
        }
        result
    }
    fn begin_acquire_inner(
        &mut self,
        read: &SignerFinancialWriterReadFinalV1,
        facts: SignerAcquireFactsV1,
        original_source: Instant,
        original_acquire: Instant,
    ) -> Result<SignerAcquirePresentationV1> {
        read.check_current()?;
        facts.validate()?;
        let retained = self
            .writer_acquire
            .read
            .as_ref()
            .ok_or_else(|| rejected("Acquire actual Writer Read missing"))?;
        if !Arc::ptr_eq(&read.binding, retained)
            || self.writer_acquire.review.is_some()
            || original_source != retained.entry.original_source
            || self.cancel_seen
            || self.failed
            || self.disposed
            || self.writer_acquire.terminal
        {
            return Err(rejected("Acquire preparation foreign or reused"));
        }
        require_new_deadline(original_acquire, original_source)?;
        let mut p = SignerAcquirePresentationV1 {
            version: 1,
            purpose: ACQUIRE_PURPOSE.into(),
            actor: retained.wire.actor.clone(),
            recipe_digest: facts.calculate_recipe_digest()?,
            facts,
            notice: ACQUIRE_NOTICE.into(),
            acquire_challenge: state::nonce()?,
            source_ceiling_ms: retained.wire.source_ceiling_ms,
            acquire_ceiling_ms: self
                .clocks
                .restrictive_offset(original_acquire, original_source)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        p.validate()?;
        let binding =
            AcquireReview::from_bounds(Arc::clone(retained), p.clone(), original_acquire)?;
        binding.check()?;
        read.check_current()?;
        self.writer_acquire.review = Some(binding);
        retained.prepared.store(true, Ordering::Release);
        Ok(p)
    }
    /// Sends only the already frozen complete presentation. No private source
    /// reads or clocks are created after finish_read.
    pub fn send_acquire_display(&mut self) -> Result<()> {
        if self.writer_acquire.display_sent
            || self.writer_acquire.terminal
            || self.cancel_seen
            || self.failed
            || self.disposed
        {
            return Err(rejected("Acquire display reused or terminal"));
        }
        let b = self
            .writer_acquire
            .review
            .as_ref()
            .ok_or_else(|| rejected("Acquire cached presentation missing"))?;
        b.check()?;
        self.core
            .phase
            .step(self.target.index(), ACQUIRE_PREPARED, ACQUIRE_REVIEW)?;
        self.writer_acquire.display_sent = true;
        self.send(&Packet::AcquireDisplay {
            data: b.wire.clone(),
        })
    }
    pub fn send_acquire_ready(
        &mut self,
        arm: SignerAcquireArmV1,
        acquire_ready_digest: String,
    ) -> Result<()> {
        let b = self
            .writer_acquire
            .review
            .as_ref()
            .ok_or_else(|| rejected("Acquire Ready before display"))?;
        if !Arc::ptr_eq(&arm.binding, b)
            || !self.writer_acquire.display_sent
            || self.writer_acquire.ready.is_some()
            || self.writer_acquire.terminal
            || !state::hash(&acquire_ready_digest)
        {
            return Err(rejected("Acquire Ready foreign or reused"));
        }
        arm.check_current()?;
        let ready = Arc::new(AcquireReady {
            review: Arc::clone(b),
            challenge: state::nonce()?,
            digest: acquire_ready_digest,
        });
        self.core
            .phase
            .step(self.target.index(), ACQUIRE_ARMED, ACQUIRE_READY)?;
        self.writer_acquire.ready = Some(Arc::clone(&ready));
        self.send(&Packet::AcquireReady {
            actor: b.wire.actor.clone(),
            presentation_digest: b.wire.presentation_digest.clone(),
            recipe_digest: b.wire.recipe_digest.clone(),
            ready_challenge: ready.challenge.clone(),
            acquire_ready_digest: ready.digest.clone(),
        })
    }
    pub fn writer_read_failed(&mut self) -> Result<()> {
        let read = self
            .writer_acquire
            .read
            .as_ref()
            .ok_or_else(|| rejected("Writer Read failure before display"))?;
        if self.writer_acquire.terminal || self.writer_acquire.display_sent {
            return Err(rejected(
                "Writer Read failure reused or after Acquire display",
            ));
        }
        let actor = read.wire.actor.clone();
        let presentation_digest = read.wire.presentation_digest.clone();
        self.writer_acquire.terminal = true;
        self.restrict()?;
        self.send(&Packet::WriterReadFailed {
            actor,
            presentation_digest,
        })
    }
    /// Actual completed-source observation only, never another action grant.
    pub fn report_acquired(
        &mut self,
        data: SignerAcquireCommittedV1,
        original_writer_session_deadline: Instant,
    ) -> Result<()> {
        data.validate()?;
        let r = self
            .writer_acquire
            .ready
            .as_ref()
            .ok_or_else(|| rejected("Acquire report before Ready"))?;
        let b = &r.review;
        let service = b.read.service()?;
        if !self.writer_acquire.attempted
            || self.writer_acquire.terminal
            || self.writer_acquire.committed.is_some()
            || !data.matches(&b.wire, &r.digest, &service.digest)
        {
            return Err(rejected("Acquire completed-source binding"));
        }
        b.read.entry.check_custody()?;
        service.check()?;
        crate::channel::require_time(original_writer_session_deadline)?;
        if original_writer_session_deadline > b.read.entry.original_source.min(service.deadline) {
            return Err(rejected(
                "writer receipt exact ceiling exceeds source/service",
            ));
        }
        let offset = self.clocks.restrictive_offset(
            original_writer_session_deadline,
            b.read.entry.original_source.min(service.deadline),
        )?;
        let restored = received_writer_session_deadline(
            self.clocks,
            offset,
            &data,
            b.read.entry.original_source,
            service.deadline,
        )?;
        // The wire's floor may only shorten, never replace S's exact Instant.
        if restored > original_writer_session_deadline {
            return Err(rejected("writer receipt offset widened"));
        }
        self.core
            .phase
            .observe_workflow_acquire_saved(self.target.index())?;
        let actor = b.wire.actor.clone();
        self.writer_acquire.committed = Some(AcquiredRetention {
            data: data.clone(),
            original_writer_session_deadline,
        });
        self.send(&Packet::Acquired {
            actor,
            data,
            writer_session_ceiling_ms: offset,
        })
    }
    pub fn send_acquire_outcome(&mut self, data: SignerAcquireOutcomeV1) -> Result<()> {
        data.validate()?;
        let b = self
            .writer_acquire
            .review
            .as_ref()
            .ok_or_else(|| rejected("Acquire outcome before preparation"))?;
        if !self.writer_acquire.display_sent
            || self.writer_acquire.terminal
            || self.writer_acquire.committed.is_some()
            || !outcome_matches(
                &b.wire,
                self.writer_acquire
                    .ready
                    .as_ref()
                    .map(|r| r.digest.as_str()),
                &data,
            )
        {
            return Err(rejected("Acquire outcome mismatch"));
        }
        let actor = b.wire.actor.clone();
        self.writer_acquire.terminal = true;
        self.restrict()?;
        self.send(&Packet::AcquireOutcome { actor, data })
    }
    pub(super) fn receive_writer_acquire(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        if self.cancel_seen || self.failed || self.disposed || self.writer_acquire.terminal {
            return Err(rejected("writer command after terminal"));
        }
        match p {
            Packet::WriterReadFinal {
                actor,
                presentation_digest,
                read_challenge,
                service,
            } => {
                let b = self
                    .writer_acquire
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("Writer Read Final before display"))?;
                if actor != b.wire.actor
                    || presentation_digest != b.wire.presentation_digest
                    || read_challenge != b.wire.read_challenge
                {
                    return Err(rejected("Writer Read Final mismatch"));
                }
                b.bind_service(service)?;
                b.check()?;
                self.core.phase.step(
                    self.target.index(),
                    WRITER_READ_REVIEW,
                    WRITER_READ_ADMITTED,
                )?;
                Ok(SignerFinancialWorkflowRequestV1::WriterRead(
                    SignerFinancialWriterReadFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                ))
            }
            Packet::AcquireArm {
                actor,
                presentation_digest,
                recipe_digest,
            } => {
                let b = self
                    .writer_acquire
                    .review
                    .as_ref()
                    .ok_or_else(|| rejected("Acquire Arm before display"))?;
                if !self.writer_acquire.display_sent
                    || actor != b.wire.actor
                    || presentation_digest != b.wire.presentation_digest
                    || recipe_digest != b.wire.recipe_digest
                {
                    return Err(rejected("Acquire Arm mismatch"));
                }
                b.check()?;
                self.core
                    .phase
                    .step(self.target.index(), ACQUIRE_REVIEW, ACQUIRE_ARMED)?;
                Ok(SignerFinancialWorkflowRequestV1::AcquireArm(
                    SignerAcquireArmV1 {
                        binding: Arc::clone(b),
                    },
                ))
            }
            Packet::AcquireFinal {
                actor,
                presentation_digest,
                recipe_digest,
                ready_challenge,
                acquire_ready_digest,
                service,
            } => {
                if std::mem::replace(&mut self.writer_acquire.attempted, true) {
                    return Err(rejected("Acquire Final reused"));
                }
                let r = self
                    .writer_acquire
                    .ready
                    .as_ref()
                    .ok_or_else(|| rejected("Acquire Final before Ready"))?;
                let b = &r.review;
                if actor != b.wire.actor
                    || presentation_digest != b.wire.presentation_digest
                    || recipe_digest != b.wire.recipe_digest
                    || ready_challenge != r.challenge
                    || acquire_ready_digest != r.digest
                {
                    return Err(rejected("Acquire Final mismatch"));
                }
                b.read.service()?.require_same(&service)?;
                b.check()?;
                self.core
                    .phase
                    .step(self.target.index(), ACQUIRE_READY, ACQUIRE_ADMITTED)?;
                Ok(SignerFinancialWorkflowRequestV1::AcquireFinal(
                    SignerAcquireFinalV1 {
                        binding: Arc::clone(r),
                    },
                ))
            }
            _ => Err(rejected("wrong writer action request")),
        }
    }
}
fn require_new_deadline(action: Instant, source: Instant) -> Result<()> {
    let now = Instant::now();
    if action <= now || action > source || action > now + std::time::Duration::from_secs(120) {
        return Err(rejected("writer action original deadline rejected"));
    }
    Ok(())
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_writer_read(
        &self,
        mut ticket: SignerFinancialWriterReadTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerFinancialWriterReadOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.core()) {
            self.revoke();
            return Err(rejected("foreign Writer Read native ticket"));
        }
        serving.matches_writer_read(&self.core, &ticket.binding.wire)?;
        let service = serving.retain()?;
        ticket.binding.bind_service(service.correlation())?;
        ticket.check_current()?;
        service.check()?;
        self.core.phase.step(
            ticket.binding.slot(),
            WRITER_READ_REVIEW,
            WRITER_READ_ADMITTED,
        )?;
        ticket.consumed = true;
        Ok(SignerFinancialWriterReadOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            service,
            consumed: false,
        })
    }
    pub fn arm_acquire(
        &self,
        mut ticket: SignerAcquireReviewTicketV1,
    ) -> Result<SignerAcquireArmOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.core()) {
            self.revoke();
            return Err(rejected("foreign Acquire native ticket"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.slot(), ACQUIRE_REVIEW, ACQUIRE_ARMED)?;
        ticket.consumed = true;
        Ok(SignerAcquireArmOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
    pub fn admit_acquire(
        &self,
        mut ticket: SignerAcquireReadyTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerAcquireFinalOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.review.core()) {
            self.revoke();
            return Err(rejected("foreign Acquire native Ready"));
        }
        serving.matches_acquire(&self.core, &ticket.binding.review.wire)?;
        let service = serving.retain()?;
        ticket
            .binding
            .review
            .read
            .service()?
            .require_same(&service.correlation())?;
        ticket.check_current()?;
        service.check()?;
        self.core.phase.step(
            ticket.binding.review.slot(),
            ACQUIRE_READY,
            ACQUIRE_ADMITTED,
        )?;
        ticket.consumed = true;
        Ok(SignerAcquireFinalOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            service,
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_writer_read_final(
        &mut self,
        outbound: SignerFinancialWriterReadOutboundV1,
    ) -> Result<()> {
        self.try_send_writer_read_final(outbound)?.require_sent()
    }
    pub fn try_send_writer_read_final(
        &mut self,
        mut outbound: SignerFinancialWriterReadOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = &outbound.binding;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core())
            || self.slots[i].as_ref().is_none_or(|s| {
                s.wire_phase != WRITER_READ_REVIEW
                    || s.writer_acquire
                        .read
                        .as_ref()
                        .is_none_or(|r| !Arc::ptr_eq(r, b))
            })
        {
            return Err(rejected("foreign or repeated Writer Read outbound"));
        }
        b.check_bounds()?;
        outbound.service.check_bounds()?;
        b.service()?.require_same(&outbound.service.correlation())?;
        if self
            .core
            .phase
            .source_send_restricted(i, WRITER_READ_ADMITTED)?
        {
            outbound.consumed = true;
            return Ok(FinancialSendProgressV1::Restricted);
        }
        let progress = self.send_positive(
            &Packet::WriterReadFinal {
                actor: b.wire.actor.clone(),
                presentation_digest: b.wire.presentation_digest.clone(),
                read_challenge: b.wire.read_challenge.clone(),
                service: outbound.service.correlation(),
            },
            b.ceiling.min(b.service()?.deadline),
        )?;
        if progress == FinancialSendProgressV1::Sent {
            self.slots[i].as_mut().unwrap().wire_phase = WRITER_READ_ADMITTED;
        }
        outbound.consumed = true;
        Ok(progress)
    }
    pub fn send_acquire_arm(&mut self, outbound: SignerAcquireArmOutboundV1) -> Result<()> {
        self.try_send_acquire_arm(outbound)?.require_sent()
    }
    pub fn try_send_acquire_arm(
        &mut self,
        mut outbound: SignerAcquireArmOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = &outbound.binding;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core())
            || self.slots[i].as_ref().is_none_or(|s| {
                s.wire_phase != ACQUIRE_REVIEW
                    || s.writer_acquire
                        .review
                        .as_ref()
                        .is_none_or(|r| !Arc::ptr_eq(r, b))
            })
        {
            return Err(rejected("foreign or repeated Acquire Arm outbound"));
        }
        b.check_bounds()?;
        if self.core.phase.source_send_restricted(i, ACQUIRE_ARMED)? {
            outbound.consumed = true;
            return Ok(FinancialSendProgressV1::Restricted);
        }
        let progress = self.send_positive(
            &Packet::AcquireArm {
                actor: b.wire.actor.clone(),
                presentation_digest: b.wire.presentation_digest.clone(),
                recipe_digest: b.wire.recipe_digest.clone(),
            },
            b.ceiling.min(b.read.service()?.deadline),
        )?;
        if progress == FinancialSendProgressV1::Sent {
            self.slots[i].as_mut().unwrap().wire_phase = ACQUIRE_ARMED;
        }
        outbound.consumed = true;
        Ok(progress)
    }
    pub fn send_acquire_final(&mut self, outbound: SignerAcquireFinalOutboundV1) -> Result<()> {
        self.try_send_acquire_final(outbound)?.require_sent()
    }
    pub fn try_send_acquire_final(
        &mut self,
        mut outbound: SignerAcquireFinalOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let r = &outbound.binding;
        let b = &r.review;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core())
            || self.slots[i].as_ref().is_none_or(|s| {
                s.wire_phase != ACQUIRE_READY
                    || s.writer_acquire
                        .ready
                        .as_ref()
                        .is_none_or(|ready| !Arc::ptr_eq(ready, r))
            })
        {
            return Err(rejected("foreign or repeated Acquire Final outbound"));
        }
        b.check_bounds()?;
        outbound.service.check_bounds()?;
        b.read
            .service()?
            .require_same(&outbound.service.correlation())?;
        if self
            .core
            .phase
            .source_send_restricted(i, ACQUIRE_ADMITTED)?
        {
            outbound.consumed = true;
            return Ok(FinancialSendProgressV1::Restricted);
        }
        let progress = self.send_positive(
            &Packet::AcquireFinal {
                actor: b.wire.actor.clone(),
                presentation_digest: b.wire.presentation_digest.clone(),
                recipe_digest: b.wire.recipe_digest.clone(),
                ready_challenge: r.challenge.clone(),
                acquire_ready_digest: r.digest.clone(),
                service: outbound.service.correlation(),
            },
            b.ceiling.min(b.read.service()?.deadline),
        )?;
        if progress == FinancialSendProgressV1::Sent {
            self.slots[i].as_mut().unwrap().wire_phase = ACQUIRE_ADMITTED;
        }
        outbound.consumed = true;
        Ok(progress)
    }
    pub(super) fn receive_writer_acquire_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p
            .target()?
            .ok_or_else(|| rejected("writer event target missing"))?;
        let i = role.index();
        let slot = self.slots[i]
            .as_mut()
            .ok_or_else(|| rejected("unsolicited writer event"))?;
        if slot.failed || slot.writer_acquire.terminal {
            return Err(rejected("writer event after terminal"));
        }
        match p {
            Packet::WriterReadDisplay { data } => {
                data.validate()?;
                let (admit, committed) = slot.admission.retained_result()?;
                if slot.wire_phase != admit::AWAITING_NEXT_READ
                    || slot.writer_acquire.read_wire.is_some()
                    || !read_links_admit(&data, admit, committed)
                {
                    return Err(rejected("Writer Read display retained binding"));
                }
                slot.wire_phase = WRITER_READ_REVIEW;
                slot.writer_acquire.read_wire = Some(data.clone());
                let entry = slot
                    .entry
                    .as_ref()
                    .ok_or_else(|| rejected("Writer Read original Entry missing"))?;
                let deadline = self.clocks.restrict_received(
                    PROFILE,
                    data.read_ceiling_ms,
                    entry.original_source,
                    Instant::now(),
                )?;
                let b = WriterRead::from_bounds(
                    Arc::clone(entry),
                    data,
                    deadline,
                    expected_signing_original(admit, committed)?,
                )?;
                slot.writer_acquire.read = Some(Arc::clone(&b));
                if !received_progress(
                    &self.core.phase,
                    i,
                    admit::AWAITING_NEXT_READ,
                    WRITER_READ_REVIEW,
                )? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::WriterReadDisplay(
                    SignerFinancialWriterReadTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::AcquireDisplay { data } => {
                data.validate()?;
                let read = slot
                    .writer_acquire
                    .read_wire
                    .as_ref()
                    .ok_or_else(|| rejected("Acquire display before Writer Read"))?;
                if slot.wire_phase != WRITER_READ_ADMITTED
                    || slot.writer_acquire.wire.is_some()
                    || !acquire_links_read(&data, read)
                {
                    return Err(rejected("Acquire display retained binding"));
                }
                slot.wire_phase = ACQUIRE_REVIEW;
                slot.writer_acquire.wire = Some(data.clone());
                let read = slot
                    .writer_acquire
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("Acquire positive Writer Read missing"))?;
                let deadline = self.clocks.restrict_received(
                    PROFILE,
                    data.acquire_ceiling_ms,
                    read.entry.original_source,
                    Instant::now(),
                )?;
                let b = AcquireReview::from_bounds(Arc::clone(read), data, deadline)?;
                slot.writer_acquire.review = Some(Arc::clone(&b));
                if !received_progress(&self.core.phase, i, WRITER_READ_ADMITTED, ACQUIRE_REVIEW)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::AcquireDisplay(
                    SignerAcquireReviewTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::AcquireReady {
                actor,
                presentation_digest,
                recipe_digest,
                ready_challenge,
                acquire_ready_digest,
            } => {
                let wire = slot
                    .writer_acquire
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("Acquire Ready before display"))?;
                if slot.wire_phase != ACQUIRE_ARMED
                    || slot.writer_acquire.observed_ready.is_some()
                    || actor != wire.actor
                    || presentation_digest != wire.presentation_digest
                    || recipe_digest != wire.recipe_digest
                    || !state::hash(&ready_challenge)
                    || !state::hash(&acquire_ready_digest)
                {
                    return Err(rejected("Acquire Ready binding"));
                }
                slot.wire_phase = ACQUIRE_READY;
                slot.writer_acquire.observed_ready = Some(acquire_ready_digest.clone());
                let b = slot
                    .writer_acquire
                    .review
                    .as_ref()
                    .ok_or_else(|| rejected("Acquire positive review missing"))?;
                b.check_bounds()?;
                let ready = Arc::new(AcquireReady {
                    review: Arc::clone(b),
                    challenge: ready_challenge,
                    digest: acquire_ready_digest,
                });
                slot.writer_acquire.ready = Some(Arc::clone(&ready));
                if !received_progress(&self.core.phase, i, ACQUIRE_ARMED, ACQUIRE_READY)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::AcquireReady(
                    SignerAcquireReadyTicketV1 {
                        binding: ready,
                        consumed: false,
                    },
                ))
            }
            Packet::WriterReadFailed {
                actor,
                presentation_digest,
            } => {
                let read = slot
                    .writer_acquire
                    .read_wire
                    .as_ref()
                    .ok_or_else(|| rejected("Writer Read failure before display"))?;
                if !matches!(slot.wire_phase, WRITER_READ_REVIEW | WRITER_READ_ADMITTED)
                    || actor != read.actor
                    || presentation_digest != read.presentation_digest
                {
                    return Err(rejected("Writer Read failure binding"));
                }
                slot.writer_acquire.terminal = true;
                self.core.phase.revoke();
                if self.cleanup.is_none() {
                    self.cleanup = Some(self.clocks.first_cleanup_ceiling(Instant::now())?);
                }
                Ok(CoordinatorFinancialEventV1::WriterReadFailed {
                    role,
                    presentation_digest,
                })
            }
            Packet::Acquired {
                actor,
                data,
                writer_session_ceiling_ms,
            } => {
                data.validate()?;
                let r = slot
                    .writer_acquire
                    .ready
                    .as_ref()
                    .ok_or_else(|| rejected("Acquire receipt before actual Ready"))?;
                let b = &r.review;
                let service = b.read.service()?;
                if slot.wire_phase != ACQUIRE_ADMITTED
                    || slot.writer_acquire.terminal
                    || slot.writer_acquire.committed.is_some()
                    || actor != b.wire.actor
                    || !data.matches(&b.wire, &r.digest, &service.digest)
                {
                    return Err(rejected("Acquire receipt retained binding"));
                }
                b.read.entry.check_custody()?;
                service.check()?;
                let original_writer_session_deadline = received_writer_session_deadline(
                    self.clocks,
                    writer_session_ceiling_ms,
                    &data,
                    b.read.entry.original_source,
                    service.deadline,
                )?;
                self.core.phase.observe_workflow_acquire_saved(i)?;
                slot.wire_phase = AWAITING_ACTIVATE_READ;
                slot.writer_acquire.committed = Some(AcquiredRetention {
                    data: data.clone(),
                    original_writer_session_deadline,
                });
                Ok(CoordinatorFinancialEventV1::AwaitingActivateRead { role, data })
            }
            Packet::AcquireOutcome { actor, data } => {
                data.validate()?;
                let p = slot
                    .writer_acquire
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("Acquire outcome before display"))?;
                if actor != p.actor
                    || !terminal_outcome_matches(
                        p,
                        slot.writer_acquire.observed_ready.as_deref(),
                        slot.wire_phase,
                        self.core.phase.revoked(),
                        &data,
                    )
                {
                    return Err(rejected("Acquire terminal binding"));
                }
                slot.writer_acquire.terminal = true;
                self.core.phase.revoke();
                if self.cleanup.is_none() {
                    self.cleanup = Some(self.clocks.first_cleanup_ceiling(Instant::now())?);
                }
                Ok(CoordinatorFinancialEventV1::AcquireOutcome { role, data })
            }
            _ => Err(rejected("wrong writer action event")),
        }
    }
}
fn received_progress(phase: &Phases, slot: usize, from: u8, to: u8) -> Result<bool> {
    if phase.source_send_restricted(slot, from)? {
        return Ok(false);
    }
    match phase.step(slot, from, to) {
        Ok(()) => Ok(!phase.source_send_restricted(slot, to)?),
        Err(error) => {
            if phase.source_send_restricted(slot, from)? {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}
fn outcome_matches(
    p: &SignerAcquirePresentationV1,
    ready: Option<&str>,
    data: &SignerAcquireOutcomeV1,
) -> bool {
    let (presentation, digest) = data.parts();
    presentation == p.presentation_digest && digest == ready
}
fn terminal_outcome_matches(
    p: &SignerAcquirePresentationV1,
    ready: Option<&str>,
    phase: u8,
    revoked: bool,
    data: &SignerAcquireOutcomeV1,
) -> bool {
    let (presentation, digest) = data.parts();
    presentation == p.presentation_digest
        && match (ready, digest) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            (None, Some(b)) => revoked && phase == ACQUIRE_ARMED && state::hash(b),
            _ => false,
        }
}
impl HostFinancialWorkflowRelayV1 {
    pub(super) fn down_writer_acquire(&mut self, p: &Packet) -> Result<()> {
        let role = p
            .target()?
            .ok_or_else(|| rejected("writer relay command target missing"))?;
        if self.restricted {
            return Err(rejected("writer command after relay restriction"));
        }
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("writer relay slot missing"))?;
        if slot.failed || slot.writer_acquire.terminal {
            return Err(rejected("writer relay command after terminal"));
        }
        writer_current(slot, self.clocks)?;
        match p {
            Packet::WriterReadFinal {
                actor,
                presentation_digest,
                read_challenge,
                service,
            } => {
                let r = slot
                    .writer_acquire
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Final before display"))?;
                if slot.phase != WRITER_READ_REVIEW
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                    || read_challenge != &r.read_challenge
                    || !slot.writer_acquire.read_forwarded
                {
                    return Err(rejected("writer relay Read Final mismatch"));
                }
                let (admit, committed) = slot.admission.retained_result()?;
                let expected = expected_signing_original(admit, committed)?;
                let entry = slot
                    .entry
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay original Entry missing"))?;
                if !original_links_entry(&expected, &entry.presentation)
                    || slot.writer_acquire.service.is_some()
                {
                    return Err(rejected("writer relay service original Entry changed"));
                }
                let source = self.clocks.restrict_received(
                    PROFILE,
                    expected.source_ceiling_ms,
                    self.clocks.supervision(),
                    Instant::now(),
                )?;
                slot.writer_acquire.service = Some(ReceivedSigning::restore(
                    service.clone(),
                    &expected,
                    &r.facts.writer_certificate_digest,
                    self.clocks,
                    source,
                )?);
                slot.phase = WRITER_READ_ADMITTED;
                Ok(())
            }
            Packet::AcquireArm {
                actor,
                presentation_digest,
                recipe_digest,
            } => {
                let r = slot
                    .writer_acquire
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Arm before display"))?;
                if slot.phase != ACQUIRE_REVIEW
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                    || recipe_digest != &r.recipe_digest
                    || !slot.writer_acquire.display_forwarded
                {
                    return Err(rejected("writer relay Acquire Arm mismatch"));
                }
                slot.phase = ACQUIRE_ARMED;
                Ok(())
            }
            Packet::AcquireFinal {
                actor,
                presentation_digest,
                recipe_digest,
                ready_challenge,
                acquire_ready_digest,
                service,
            } => {
                let r = slot
                    .writer_acquire
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Final before display"))?;
                if slot.phase != ACQUIRE_READY
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                    || recipe_digest != &r.recipe_digest
                    || slot.writer_acquire.ready.as_ref()
                        != Some(&(ready_challenge.clone(), acquire_ready_digest.clone()))
                {
                    return Err(rejected("writer relay Acquire Final mismatch"));
                }
                slot.writer_acquire
                    .service
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay service missing"))?
                    .require_same(service)?;
                slot.phase = ACQUIRE_ADMITTED;
                Ok(())
            }
            _ => Err(rejected("wrong writer relay command")),
        }
    }
    pub(super) fn up_writer_acquire(&mut self, role: Target, p: &Packet) -> Result<bool> {
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("writer relay response slot missing"))?;
        if slot.failed || slot.writer_acquire.terminal {
            return Err(rejected("writer relay response after terminal"));
        }
        match p {
            Packet::WriterReadDisplay { data } => {
                data.validate()?;
                let (admit, committed) = slot.admission.retained_result()?;
                if slot.phase != admit::AWAITING_NEXT_READ
                    || slot.writer_acquire.read.is_some()
                    || !read_links_admit(data, admit, committed)
                {
                    return Err(rejected("writer relay display retained binding"));
                }
                slot.writer_acquire.read = Some(data.clone());
                slot.writer_acquire.read_forwarded = !self.restricted;
                slot.phase = WRITER_READ_REVIEW;
                if !self.restricted {
                    writer_current(slot, self.clocks)?;
                }
                Ok(!self.restricted)
            }
            Packet::AcquireDisplay { data } => {
                data.validate()?;
                let read = slot
                    .writer_acquire
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Acquire before Read"))?;
                if slot.phase != WRITER_READ_ADMITTED
                    || slot.writer_acquire.wire.is_some()
                    || !acquire_links_read(data, read)
                {
                    return Err(rejected("writer relay Acquire retained binding"));
                }
                slot.writer_acquire.wire = Some(data.clone());
                slot.writer_acquire.display_forwarded = !self.restricted;
                slot.phase = ACQUIRE_REVIEW;
                if !self.restricted {
                    writer_current(slot, self.clocks)?;
                }
                Ok(!self.restricted)
            }
            Packet::AcquireReady {
                actor,
                presentation_digest,
                recipe_digest,
                ready_challenge,
                acquire_ready_digest,
            } => {
                let r = slot
                    .writer_acquire
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Ready before display"))?;
                if slot.phase != ACQUIRE_ARMED
                    || slot.writer_acquire.ready.is_some()
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                    || recipe_digest != &r.recipe_digest
                    || !state::hash(ready_challenge)
                    || !state::hash(acquire_ready_digest)
                {
                    return Err(rejected("writer relay Ready mismatch"));
                }
                slot.writer_acquire.ready =
                    Some((ready_challenge.clone(), acquire_ready_digest.clone()));
                slot.phase = ACQUIRE_READY;
                if !self.restricted {
                    writer_current(slot, self.clocks)?;
                }
                Ok(!self.restricted)
            }
            Packet::WriterReadFailed {
                actor,
                presentation_digest,
            } => {
                let r = slot
                    .writer_acquire
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay failure before display"))?;
                if !matches!(slot.phase, WRITER_READ_REVIEW | WRITER_READ_ADMITTED)
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                {
                    return Err(rejected("writer relay Read failure mismatch"));
                }
                let forward = slot.writer_acquire.read_forwarded;
                slot.writer_acquire.terminal = true;
                self.restrict()?;
                Ok(forward)
            }
            Packet::Acquired {
                actor,
                data,
                writer_session_ceiling_ms,
            } => {
                data.validate()?;
                let p = slot
                    .writer_acquire
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("relay Acquire receipt before display"))?;
                let ready = slot
                    .writer_acquire
                    .ready
                    .as_ref()
                    .ok_or_else(|| rejected("relay Acquire receipt before Ready"))?;
                let service = slot
                    .writer_acquire
                    .service
                    .as_ref()
                    .ok_or_else(|| rejected("relay Acquire receipt without service"))?;
                if slot.phase != ACQUIRE_ADMITTED
                    || slot.writer_acquire.terminal
                    || slot.writer_acquire.committed.is_some()
                    || actor != &p.actor
                    || !data.matches(p, &ready.1, &service.digest)
                {
                    return Err(rejected("relay Acquire receipt retained binding"));
                }
                service.check()?;
                relay_wall(
                    &mut slot.last_wall,
                    p.facts.reviewed_at_ms,
                    data.expires_at_ms,
                    p.facts.source_expires_at_ms,
                )?;
                let source = self.clocks.restrict_received(
                    PROFILE,
                    p.source_ceiling_ms,
                    self.clocks.supervision(),
                    Instant::now(),
                )?;
                let original_writer_session_deadline = received_writer_session_deadline(
                    self.clocks,
                    *writer_session_ceiling_ms,
                    data,
                    source,
                    service.deadline,
                )?;
                slot.phase = AWAITING_ACTIVATE_READ;
                slot.writer_acquire.committed = Some(AcquiredRetention {
                    data: data.clone(),
                    original_writer_session_deadline,
                });
                Ok(true)
            }
            Packet::AcquireOutcome { actor, data } => {
                data.validate()?;
                let r = slot
                    .writer_acquire
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay outcome before display"))?;
                if actor != &r.actor
                    || !outcome_matches(
                        r,
                        slot.writer_acquire.ready.as_ref().map(|r| r.1.as_str()),
                        data,
                    )
                {
                    return Err(rejected("writer relay terminal mismatch"));
                }
                let forward = slot.writer_acquire.display_forwarded;
                slot.writer_acquire.terminal = true;
                self.restrict()?;
                Ok(forward)
            }
            _ => Err(rejected("wrong writer relay response")),
        }
    }
}
fn writer_current(slot: &mut HSlot, clocks: FullWorkflowClocksV1) -> Result<()> {
    if let Some(service) = &slot.writer_acquire.service {
        service.check()?;
    }
    let (source, action, start, end, source_wall) = if let Some(p) = &slot.writer_acquire.wire {
        (
            p.source_ceiling_ms,
            p.acquire_ceiling_ms,
            p.facts.reviewed_at_ms,
            p.facts.expires_at_ms,
            p.facts.source_expires_at_ms,
        )
    } else {
        let p = slot
            .writer_acquire
            .read
            .as_ref()
            .ok_or_else(|| rejected("writer relay original display missing"))?;
        (
            p.source_ceiling_ms,
            p.read_ceiling_ms,
            p.facts.reviewed_at_ms,
            p.facts.expires_at_ms,
            p.facts.source_expires_at_ms,
        )
    };
    let now = Instant::now();
    for ms in [source, action] {
        clocks.restrict_received(PROFILE, ms, clocks.supervision(), now)?;
    }
    relay_wall(&mut slot.last_wall, start, end, source_wall)
}
impl SWritAcquire {
    pub(super) fn disposal_allowed(&self) -> bool {
        self.read.is_none() || self.terminal || self.committed.is_some()
    }
}
impl CWritAcquire {
    pub(super) fn disposal_allowed(&self) -> bool {
        self.read_wire.is_none() || self.terminal || self.committed.is_some()
    }
    pub(super) fn observe_active(&self, phase: u8) -> Result<()> {
        if matches!(phase, WRITER_READ_REVIEW | WRITER_READ_ADMITTED) {
            self.read
                .as_ref()
                .ok_or_else(|| rejected("active Writer Read binding missing"))?
                .check()?;
        } else if matches!(
            phase,
            ACQUIRE_REVIEW | ACQUIRE_ARMED | ACQUIRE_READY | ACQUIRE_ADMITTED
        ) {
            self.review
                .as_ref()
                .ok_or_else(|| rejected("active Acquire binding missing"))?
                .check()?;
        }
        Ok(())
    }
}
impl HWritAcquire {
    pub(super) fn disposal_allowed(&self) -> bool {
        self.read.is_none() || self.terminal || self.committed.is_some() || !self.read_forwarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn writer_receive_race_preserves_r_and_rejects_wrong_phase() {
        for (from, to) in [
            (admit::AWAITING_NEXT_READ, WRITER_READ_REVIEW),
            (WRITER_READ_ADMITTED, ACQUIRE_REVIEW),
            (ACQUIRE_ARMED, ACQUIRE_READY),
        ] {
            let p = Phases::new();
            p.step(0, 0, from).unwrap();
            p.revoke();
            assert!(!received_progress(&p, 0, from, to).unwrap());
            assert_eq!(p.phase(0), from);
            assert!(p.revoked());
            assert!(received_progress(&p, 0, to, ACQUIRE_ADMITTED).is_err());
            let p = Phases::new();
            p.step(1, 0, from).unwrap();
            assert!(received_progress(&p, 1, from, to).unwrap());
            assert!(received_progress(&p, 1, from, to).is_err());
        }
    }
    #[test]
    fn writer_receive_quiescence_is_fatal_even_with_ordinary_restriction() {
        for (from, to) in [
            (admit::AWAITING_NEXT_READ, WRITER_READ_REVIEW),
            (WRITER_READ_ADMITTED, ACQUIRE_REVIEW),
            (ACQUIRE_ARMED, ACQUIRE_READY),
        ] {
            let p = Phases::new();
            p.step(0, 0, from).unwrap();
            p.begin_quiescence(p.snapshot()).unwrap();
            let paused = p.snapshot();
            assert!(received_progress(&p, 0, from, to).is_err());
            assert_eq!(p.snapshot(), paused);
            p.revoke();
            let restricted = p.snapshot();
            assert!(received_progress(&p, 0, from, to).is_err());
            assert!(received_progress(&p, 0, to, ACQUIRE_ADMITTED).is_err());
            assert_eq!(p.snapshot(), restricted);
        }
    }
    #[test]
    fn writer_action_phases_do_not_refresh_prior_action_or_skip_ready() {
        let p = Phases::new();
        p.step(0, 0, admit::AWAITING_NEXT_READ).unwrap();
        for (from, to) in [
            (admit::AWAITING_NEXT_READ, WRITER_READ_REVIEW),
            (WRITER_READ_REVIEW, WRITER_READ_ADMITTED),
            (WRITER_READ_ADMITTED, ACQUIRE_PREPARED),
            (ACQUIRE_PREPARED, ACQUIRE_REVIEW),
            (ACQUIRE_REVIEW, ACQUIRE_ARMED),
            (ACQUIRE_ARMED, ACQUIRE_READY),
        ] {
            p.step(0, from, to).unwrap();
            assert!(p.step(0, from, to).is_err());
        }
        p.revoke();
        assert!(p.step(0, ACQUIRE_READY, ACQUIRE_ADMITTED).is_err());
        assert!(p
            .step(0, admit::AWAITING_NEXT_READ, WRITER_READ_REVIEW)
            .is_err());
    }
    #[test]
    fn writer_review_links_the_same_committed_admit_and_never_invents_a_session() {
        let read = crate::signer_writer_read_acquire_data::tests::read();
        let f = &read.facts;
        let a = SignerAdmitPresentationV1 {
            version: 1,
            purpose: crate::signer_admit_data::ADMIT_PURPOSE.into(),
            actor: read.actor.clone(),
            facts: crate::signer_admit_data::SignerAdmitFactsV1 {
                display: "Public test".into(),
                source_identity_digest: f.source_identity_digest.clone(),
                admission_terms_digest: "ab".repeat(32),
                request_json: f.continuation_request_json.clone(),
                request_digest: f.continuation_request_digest.clone(),
                original_host_process_instance: f.original_host_process_instance.clone(),
                owner_certificate_digest: f.owner_certificate_digest.clone(),
                disclosure_json: "{}".into(),
                disclosure_digest: f.owner_disclosure_digest.clone(),
                account_id: "ab".repeat(32),
                network_profile_id: "test-network".into(),
                operation_id: "test-admit".into(),
                expected_head_sequence: 19,
                expected_head_digest: "ab".repeat(32),
                terms_digest: f.terms_digest.clone(),
                reviewed_at_ms: 1000,
                expires_at_ms: 121000,
                source_expires_at_ms: f.source_expires_at_ms,
            },
            owner_selection_digest: "ab".repeat(32),
            continue_presentation_digest: "ab".repeat(32),
            prepared_digest: "ab".repeat(32),
            admit_challenge: "ab".repeat(32),
            source_ceiling_ms: read.source_ceiling_ms,
            admit_ceiling_ms: 121000,
            presentation_digest: f.admit_presentation_digest.clone(),
        };
        let committed = SignerAdmitCommittedV1 {
            presentation_digest: a.presentation_digest.clone(),
            admission_ready_digest: "ab".repeat(32),
            request_digest: f.admit_request_digest.clone(),
            head_sequence: f.admitted_head_sequence,
            head_digest: f.admitted_head_digest.clone(),
        };
        let original = expected_signing_original(&a, &committed).unwrap();
        let service = FinancialSigningServiceV1 {
            original: original.clone(),
            witness_instance: "ab".repeat(32),
            presentation_digest: "ab".repeat(32),
            service_challenge: "ab".repeat(32),
            service_ceiling_ms: original.source_ceiling_ms,
            writer_certificate_digest: f.writer_certificate_digest.clone(),
            admission_digest: "ab".repeat(32),
        };
        service.validate().unwrap();
        assert!(service_data_matches(
            &service,
            &original,
            &f.writer_certificate_digest
        ));
        // Pure ordinary data only. Every frozen Original field must compare,
        // including fields absent from the subsequent Writer Read display.
        let encoded = serde_json::to_value(&original).unwrap();
        for key in encoded.as_object().unwrap().keys() {
            let mut changed = encoded.clone();
            let value = &mut changed[key];
            match value {
                serde_json::Value::String(text) => text.push('x'),
                serde_json::Value::Number(number) => {
                    *number = (number.as_u64().unwrap() + 1).into()
                }
                serde_json::Value::Object(actor) => {
                    actor.insert("coordinator_focus_epoch".into(), 2u64.into());
                }
                _ => panic!("closed ordinary Original field"),
            }
            let changed: FinancialSigningOriginalV1 = serde_json::from_value(changed).unwrap();
            assert!(!service_data_matches(
                &service,
                &changed,
                &f.writer_certificate_digest
            ));
        }
        assert!(!service_data_matches(&service, &original, &"cd".repeat(32)));
        assert!(read_links_admit(&read, &a, &committed));
        for n in 0..6 {
            let mut changed = read.clone();
            match n {
                0 => changed.facts.source_identity_digest = "cd".repeat(32),
                1 => changed.facts.original_host_process_instance = "cd".repeat(32),
                2 => changed.facts.owner_certificate_digest = "cd".repeat(32),
                3 => changed.facts.admitted_head_sequence += 1,
                4 => changed.facts.continuation_request_json.push(' '),
                _ => changed.source_ceiling_ms += 1,
            }
            assert!(!read_links_admit(&changed, &a, &committed));
        }
        let acquire = crate::signer_writer_read_acquire_data::tests::acquire(&read);
        assert!(acquire_links_read(&acquire, &read));
        for n in 0..6 {
            let mut changed = acquire.clone();
            match n {
                0 => changed.facts.writer_read_presentation_digest = "cd".repeat(32),
                1 => changed.facts.writer_selection_digest = "cd".repeat(32),
                2 => changed.facts.writer_disclosure_json.push(' '),
                3 => changed.facts.expected_head_sequence -= 1,
                4 => changed.facts.expected_head_digest = "cd".repeat(32),
                _ => changed.source_ceiling_ms += 1,
            }
            assert!(!acquire_links_read(&changed, &read));
        }
    }
    #[test]
    fn writer_restricted_terminal_bookkeeping_does_not_create_ready() {
        let p = crate::signer_writer_read_acquire_data::tests::acquire(
            &crate::signer_writer_read_acquire_data::tests::read(),
        );
        let digest = "cd".repeat(32);
        let terminal = SignerAcquireOutcomeV1::Uncertain {
            presentation_digest: p.presentation_digest.clone(),
            acquire_ready_digest: Some(digest.clone()),
        };
        assert!(terminal_outcome_matches(
            &p,
            None,
            ACQUIRE_ARMED,
            true,
            &terminal
        ));
        assert!(!terminal_outcome_matches(
            &p,
            None,
            ACQUIRE_ARMED,
            false,
            &terminal
        ));
        assert!(!terminal_outcome_matches(
            &p,
            None,
            ACQUIRE_REVIEW,
            true,
            &terminal
        ));
        assert!(terminal_outcome_matches(
            &p,
            Some(&digest),
            ACQUIRE_READY,
            true,
            &terminal
        ));
        assert!(!terminal_outcome_matches(
            &p,
            Some(&"ef".repeat(32)),
            ACQUIRE_READY,
            true,
            &terminal
        ));
    }
}

impl SWritAcquire {
    pub(super) fn retained_result(
        &self,
    ) -> Result<(
        &SignerAcquirePresentationV1,
        &SignerAcquireCommittedV1,
        &ReceivedSigning,
        Instant,
    )> {
        let r = self
            .review
            .as_ref()
            .ok_or_else(|| rejected("retained Acquire review missing"))?;
        let saved = self
            .committed
            .as_ref()
            .ok_or_else(|| rejected("actual acquired receipt missing"))?;
        Ok((
            &r.wire,
            &saved.data,
            r.read.service()?,
            saved.original_writer_session_deadline,
        ))
    }
}
impl CWritAcquire {
    pub(super) fn retained_result(
        &self,
    ) -> Result<(
        &SignerAcquirePresentationV1,
        &SignerAcquireCommittedV1,
        &ReceivedSigning,
        Instant,
    )> {
        let r = self
            .review
            .as_ref()
            .ok_or_else(|| rejected("retained C Acquire review missing"))?;
        let saved = self
            .committed
            .as_ref()
            .ok_or_else(|| rejected("actual C acquired receipt missing"))?;
        Ok((
            &r.wire,
            &saved.data,
            r.read.service()?,
            saved.original_writer_session_deadline,
        ))
    }
}
impl HWritAcquire {
    pub(super) fn retained_result(
        &self,
    ) -> Result<(
        &SignerAcquirePresentationV1,
        &SignerAcquireCommittedV1,
        &ReceivedSigning,
        Instant,
    )> {
        let p = self
            .wire
            .as_ref()
            .ok_or_else(|| rejected("retained H Acquire review missing"))?;
        let saved = self
            .committed
            .as_ref()
            .ok_or_else(|| rejected("actual H acquired receipt missing"))?;
        let service = self
            .service
            .as_ref()
            .ok_or_else(|| rejected("retained H service missing"))?;
        Ok((
            p,
            &saved.data,
            service,
            saved.original_writer_session_deadline,
        ))
    }
}

impl CWritAcquire {
    // Setup may be reviewed while the fresh Writer Read is displayed, never
    // after native Read admission or once any service was already bound.
    pub(super) fn signing_setup_pending(&self, phase:u8)->bool {
        phase==WRITER_READ_REVIEW && !self.terminal && self.committed.is_none()
        && self.read_wire.is_some() && self.read.as_ref().is_some_and(|r|r.service.get().is_none())
        && self.review.is_none() && self.ready.is_none()
    }
}

impl HWritAcquire {
    pub(super) fn signing_setup_pending(&self,phase:u8)->bool {
        phase==WRITER_READ_REVIEW && self.read.is_some() && self.read_forwarded
        && self.service.is_none() && self.wire.is_none() && self.ready.is_none()
        && !self.terminal && self.committed.is_none()
    }
}
