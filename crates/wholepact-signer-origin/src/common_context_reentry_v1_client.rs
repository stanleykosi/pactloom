//! Exact original-read transition across loss of foreground native authority.
//! Old grants are destroyed, never revived. Every successful route still needs
//! a genuinely new account/native/witness decision at the same installed peer.
use super::roster_candidate_selection_v2::require_completion_at;
use super::roster_common_context_read_v1::CommonContextCompletionBinding;
use super::*;
use crate::common_context_reentry_v1::{
    MAX_COMMON_CONTEXT_REENTRY_FRAME, RosterCommonContextReentryResponseV1,
    RosterReenteredConstructionEvidenceV1, RosterReenteredConstructionResponseV1,
};
use std::sync::{Arc, atomic::AtomicU64};
use wholepact_core::common_context_reentry_v1::{
    RosterCommonContextReentryLineageV1, RosterCommonContextReentryRequestV1,
};
use wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3;

/// Key-free same-installed-peer continuation locator. This cannot request a
/// read, export keys, sign, reserve, or reconstruct a native dormant owner.
/// The old grant and token are dropped when this owner is made.
/// ```compile_fail
/// # use wholepact_signer_origin::CommonContextReentrySourceV1;
/// let _: CommonContextReentrySourceV1 = serde_json::from_str("{}").unwrap();
/// ```
pub struct CommonContextReentrySourceV1 {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    binding: CommonContextCompletionBinding,
    read_evidence_digest: String,
}
impl NativeManualClient {
    /// Erases the old request authority. A revoked/expired grant need not become
    /// current again merely to erase it. Its original digest, actual signer
    /// pidfd, installed provider, and the actual started-read identity must match.
    pub fn into_common_context_reentry_source(
        self,
        original_read: &StartedRosterCommonContextReadV1,
    ) -> Result<CommonContextReentrySourceV1> {
        self.handoff.check()?;
        if self.active_leases.load(Ordering::Acquire) != 0 {
            return Err(Error::Locked);
        }
        original_read.check_completion()?;
        let binding = original_read.reentry_completion_binding()?;
        binding.original_signer_peer.same_live_process(&self.peer)?;
        let request = original_read.request()?;
        if manual_current_caller_binding_digest(&self.grant.grant_id, &self.scope)?
            != request.current_caller_binding_digest
            || self.scope.manifest_digest != request.plan.digest().map_err(|_| Error::Binding)?
            || self.scope.history_read
            || self.scope.authorization_export
            || self.scope.preconstruction_export
        {
            return Err(Error::Binding);
        }
        let read_evidence_digest = original_read.evidence().digest()?;
        Ok(CommonContextReentrySourceV1 {
            provider: self.provider,
            socket: self.socket,
            binding,
            read_evidence_digest,
        })
    }
}
impl CommonContextReentrySourceV1 {
    /// Consumes the original shared construction attempt BEFORE endpoint wait,
    /// connect or write. Fresh native entry publishes a new endpoint through the
    /// same retained child channel; the retired read socket is never reopened.
    /// Any failure, cancelled pairing or uncertain response is terminal. The
    /// original completion ceiling is retained even though the grant is new.
    pub fn begin_pair_before(
        self,
        original_read: &StartedRosterCommonContextReadV1,
        application_label: &str,
        deadline: Instant,
    ) -> Result<PendingCommonContextReentryPairV1> {
        check_original(&self.binding, &self.read_evidence_digest, original_read)?;
        claim_reentry_once(&self.binding.identity)?;
        label(application_label)?;
        let plan = &original_read.request()?.plan;
        let terms = plan.enrollment();
        let scope = PairScope {
            account_id: terms.identity.account_id.clone(),
            agreement_id: terms.scope.agreement_id.clone(),
            participant_id: terms.scope.participant_id.clone(),
            manifest_digest: plan.digest().map_err(|_| Error::Binding)?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let deadline = deadline.min(self.binding.deadline);
        // Blur retires the original read endpoint. Only the retained installed
        // provider's authenticated, process-owned launch channel can locate the
        // freshly unlocked completion endpoint. Waiting never starts another
        // process, replaces original identity, or renews the original ceiling.
        let socket = self
            .provider
            .wait_native_endpoint(remaining_before(deadline)?)?;
        require_fresh_reentry_endpoint(&self.socket, &socket)?;
        check_original(&self.binding, &self.read_evidence_digest, original_read)?;
        let mut stream =
            connect_local_before(&socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        framing::enable_credentials(stream.as_raw_fd())?;
        let peer = self.provider.verify_server(&stream)?;
        self.binding.original_signer_peer.same_live_process(&peer)?;
        let started = Instant::now();
        write_frame_until(
            &mut stream,
            &serde_json::json!({"command":"request_pairing","schema_version":1,"application_label":application_label,"scope":scope}),
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
            None,
        )?;
        remaining_before(deadline)?;
        check_original(&self.binding, &self.read_evidence_digest, original_read)?;
        Ok(PendingCommonContextReentryPairV1 {
            pending: PendingNativeManualPair {
                provider: self.provider,
                socket,
                peer,
                scope,
                stream,
                started,
                deadline,
            },
            binding: self.binding,
            read_evidence_digest: self.read_evidence_digest,
        })
    }
}
pub struct PendingCommonContextReentryPairV1 {
    pending: PendingNativeManualPair,
    binding: CommonContextCompletionBinding,
    read_evidence_digest: String,
}
impl PendingCommonContextReentryPairV1 {
    pub fn finish(
        self,
        original_read: &StartedRosterCommonContextReadV1,
    ) -> Result<CommonContextReentryClientV1> {
        check_original(&self.binding, &self.read_evidence_digest, original_read)?;
        let client = self.pending.finish()?;
        self.binding
            .original_signer_peer
            .same_live_process(&client.peer)?;
        if client.current_caller_binding_digest()?
            == original_read.request()?.current_caller_binding_digest
        {
            return Err(Error::Binding);
        }
        check_original(&self.binding, &self.read_evidence_digest, original_read)?;
        Ok(CommonContextReentryClientV1 {
            client,
            binding: self.binding,
            read_evidence_digest: self.read_evidence_digest,
            reentry_requested: AtomicBool::new(false),
        })
    }
}
/// Purpose-restricted fresh pairing. There is no conversion to NativeManualClient
/// and no provider/read operation. A fresh native reentry grants only the next
/// separately reviewed exact construction attempt.
pub struct CommonContextReentryClientV1 {
    client: NativeManualClient,
    binding: CommonContextCompletionBinding,
    read_evidence_digest: String,
    reentry_requested: AtomicBool,
}
impl CommonContextReentryClientV1 {
    pub fn current_caller_binding_digest(&self) -> Result<String> {
        self.client.current_caller_binding_digest()
    }
    pub fn begin_reentry_before<'a>(
        &'a self,
        request: &RosterCommonContextReentryRequestV1,
        pending_grant_json: &str,
        original_read: &'a StartedRosterCommonContextReadV1,
        deadline: Instant,
    ) -> Result<PendingCommonContextReentryV1<'a>> {
        check_original(&self.binding, &self.read_evidence_digest, original_read)?;
        request.validate().map_err(|_| Error::Binding)?;
        if pending_grant_json.is_empty()
            || pending_grant_json.len()
                > crate::common_context_handoff_v1::MAX_HANDOFF_AUTHORIZATION_JSON
        {
            return Err(Error::Limit);
        }
        if request.original_read != *original_read.request()?
            || request.original_read_admission_digest != self.read_evidence_digest
            || request.original_attempt_digest != original_read.evidence().current_attempt_digest
            || request.original_attempt_sequence
                != original_read.evidence().current_attempt_sequence
            || request.current_caller_binding_digest
                != self.client.current_caller_binding_digest()?
        {
            return Err(Error::Binding);
        }
        // Separate protocol stage gate; the ORIGINAL construction gate was
        // consumed before pairing and is never reset or replaced here.
        claim_reentry_once(&self.reentry_requested)?;
        let wall = now_ms()?;
        let budget = request
            .remaining_admission_ms(wall)
            .map_err(|_| Error::Permission)?;
        let deadline = deadline
            .min(self.binding.deadline)
            .min(self.client.grant.expires)
            .min(
                Instant::now()
                    .checked_add(Duration::from_millis(budget))
                    .ok_or(Error::Permission)?,
            );
        let attempt =
            PendingRosterV2Attempt::new(&self.client.handoff, self.client.acquire_slot()?);
        let stream = self.client.open_request_before_bounded(
            serde_json::json!({"operation":"request_born_roster_common_context_reentry_v1","request":request,"pending_grant_json":pending_grant_json}),
            deadline, MAX_COMMON_CONTEXT_REENTRY_FRAME)?;
        Ok(PendingCommonContextReentryV1 {
            source: self,
            original_read,
            request: request.clone(),
            pending: PendingRosterV2Stream(Some(stream)),
            attempt,
            deadline,
            observed_at_ms: wall,
        })
    }
    pub fn begin_construction_before<'a>(
        &'a self,
        request: &ManualRosterConstructionRequestV3,
        original_read: &'a StartedRosterCommonContextReadV1,
        reentered: ReenteredCommonContextConstruction,
        deadline: Instant,
    ) -> Result<PendingReenteredRosterConstructionV1<'a>> {
        // The one-use reentered owner is consumed by value before all effects.
        check_original(&self.binding, &self.read_evidence_digest, original_read)?;
        reentered.check_original_read(original_read)?;
        request.validate().map_err(|_| Error::Binding)?;
        let lineage = &reentered.lineage;
        if !Arc::ptr_eq(&self.binding.identity, &reentered.identity)
            || request.plan != lineage.request.original_read.plan
            || request.current_caller_binding_digest
                != lineage.request.current_caller_binding_digest
            || request.current_caller_binding_digest
                != self.client.current_caller_binding_digest()?
            || request.operation_id == lineage.request.operation_id
            || request.operation_id == lineage.request.original_read.operation_id
            || request.requested_at_ms < lineage.admitted_at_ms
            || request.admission_expires_at_ms > lineage.completion_expires_at_ms
        {
            return Err(Error::Binding);
        }
        let wall = now_ms()?;
        let budget = request
            .remaining_admission_ms(wall)
            .map_err(|_| Error::Permission)?;
        let deadline = deadline
            .min(reentered.deadline)
            .min(self.client.grant.expires)
            .min(
                Instant::now()
                    .checked_add(Duration::from_millis(budget))
                    .ok_or(Error::Permission)?,
            );
        let attempt =
            PendingRosterV2Attempt::new(&self.client.handoff, self.client.acquire_slot()?);
        let stream = self.client.open_request_before_bounded(
            serde_json::json!({"operation":"request_born_roster_reentered_construction_v1","request":request,
                "reentry_lineage_digest":lineage.digest().map_err(|_| Error::Binding)?}),
            deadline, MAX_COMMON_CONTEXT_REENTRY_FRAME)?;
        Ok(PendingReenteredRosterConstructionV1 {
            source: self,
            original_read,
            request: request.clone(),
            reentered,
            pending: PendingRosterV2Stream(Some(stream)),
            attempt,
            deadline,
            observed_at_ms: wall,
        })
    }
}
pub struct PendingCommonContextReentryV1<'a> {
    source: &'a CommonContextReentryClientV1,
    original_read: &'a StartedRosterCommonContextReadV1,
    request: RosterCommonContextReentryRequestV1,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'a>,
    deadline: Instant,
    observed_at_ms: u64,
}
impl PendingCommonContextReentryV1<'_> {
    pub fn finish(mut self) -> Result<ReenteredCommonContextConstruction> {
        check_original(
            &self.source.binding,
            &self.source.read_evidence_digest,
            self.original_read,
        )?;
        let bytes = Zeroizing::new(framing::read_frame_with_deadline(
            self.pending.stream()?,
            &self.source.client.peer,
            phase_budget(
                self.deadline,
                Instant::now(),
                Some((self.observed_at_ms, self.request.admission_expires_at_ms)),
                now_ms()?,
            )?,
        )?);
        if bytes.len() > MAX_COMMON_CONTEXT_REENTRY_FRAME {
            return Err(Error::Limit);
        }
        let response: RosterCommonContextReentryResponseV1 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let RosterCommonContextReentryResponseV1::CommonContextReenteredV1 { lineage } = response
        else {
            return Err(Error::Permission);
        };
        lineage.validate().map_err(|_| Error::Binding)?;
        if lineage.request != self.request
            || lineage.retained_signer_intent_digest
                != self.original_read.evidence().retained_signer_intent_digest
        {
            return Err(Error::Binding);
        }
        let wall = now_ms()?;
        phase_budget(
            self.deadline,
            Instant::now(),
            Some((self.observed_at_ms, self.request.admission_expires_at_ms)),
            wall,
        )?;
        if wall < lineage.admitted_at_ms {
            return Err(Error::Permission);
        }
        let deadline = restrict_ceiling(
            self.source.binding.deadline,
            lineage.completion_expires_at_ms,
            wall,
        )?;
        let owner = ReenteredCommonContextConstruction {
            lineage: *lineage,
            identity: self.source.binding.identity.clone(),
            maximum_wall_seen: self.source.binding.maximum_wall_seen.clone(),
            deadline,
        };
        owner.check_original_read(self.original_read)?;
        self.source.client.check_channel()?;
        drop(self.attempt.slot.take().ok_or(Error::Permission)?);
        Ok(owner)
    }
}
/// Non-signing actual same-peer transition result. It retains only the original
/// identity/attempt and fixed clocks. The original wallet Started read remains
/// independently mandatory; neither this owner nor saved lineage can reread.
/// ```compile_fail
/// # use wholepact_signer_origin::ReenteredCommonContextConstruction;
/// let _: ReenteredCommonContextConstruction = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// # use wholepact_signer_origin::ReenteredCommonContextConstruction;
/// fn duplicate(v: &ReenteredCommonContextConstruction) -> ReenteredCommonContextConstruction { v.clone() }
/// ```
pub struct ReenteredCommonContextConstruction {
    lineage: RosterCommonContextReentryLineageV1,
    identity: Arc<AtomicBool>,
    maximum_wall_seen: Arc<AtomicU64>,
    deadline: Instant,
}
impl ReenteredCommonContextConstruction {
    pub fn lineage(&self) -> &RosterCommonContextReentryLineageV1 {
        &self.lineage
    }
    pub fn check_original_read(
        &self,
        original_read: &StartedRosterCommonContextReadV1,
    ) -> Result<()> {
        original_read.matches_reentry_identity(&self.identity)?;
        let request = &self.lineage.request;
        if request.original_read != *original_read.request()?
            || request.original_read_admission_digest != original_read.evidence().digest()?
            || request.original_attempt_digest != original_read.evidence().current_attempt_digest
            || request.original_attempt_sequence
                != original_read.evidence().current_attempt_sequence
            || self.lineage.retained_signer_intent_digest
                != original_read.evidence().retained_signer_intent_digest
            || !self.identity.load(Ordering::Acquire)
        {
            return Err(Error::Binding);
        }
        require_completion_at(
            self.deadline,
            &self.maximum_wall_seen,
            self.lineage.completion_expires_at_ms,
            now_ms()?,
            Instant::now(),
        )
    }
}
pub struct PendingReenteredRosterConstructionV1<'a> {
    source: &'a CommonContextReentryClientV1,
    original_read: &'a StartedRosterCommonContextReadV1,
    request: ManualRosterConstructionRequestV3,
    reentered: ReenteredCommonContextConstruction,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'a>,
    deadline: Instant,
    observed_at_ms: u64,
}
impl PendingReenteredRosterConstructionV1<'_> {
    pub fn finish(mut self) -> Result<AdmittedManualRosterConstructionContributionV3> {
        self.reentered.check_original_read(self.original_read)?;
        let bytes = Zeroizing::new(framing::read_frame_with_deadline(
            self.pending.stream()?,
            &self.source.client.peer,
            phase_budget(
                self.deadline,
                Instant::now(),
                Some((self.observed_at_ms, self.request.admission_expires_at_ms)),
                now_ms()?,
            )?,
        )?);
        if bytes.len() > MAX_COMMON_CONTEXT_REENTRY_FRAME {
            return Err(Error::Limit);
        }
        let response: RosterReenteredConstructionResponseV1 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let RosterReenteredConstructionResponseV1::ReenteredConstructionConsumedV1 { evidence } =
            response
        else {
            return Err(Error::Permission);
        };
        evidence.validate()?;
        if evidence.reentry_lineage != self.reentered.lineage
            || evidence.construction.request != self.request
        {
            return Err(Error::Binding);
        }
        let wall = now_ms()?;
        phase_budget(
            self.deadline,
            Instant::now(),
            Some((self.observed_at_ms, self.request.admission_expires_at_ms)),
            wall,
        )?;
        if wall < evidence.construction.consumed_at_ms {
            return Err(Error::Permission);
        }
        self.reentered.check_original_read(self.original_read)?;
        self.source.client.check_channel()?;
        let RosterReenteredConstructionEvidenceV1 {
            construction,
            reentry_lineage,
            ..
        } = *evidence;
        let owner = AdmittedManualRosterConstructionContributionV3::from_reentry(
            construction,
            reentry_lineage,
            self.reentered.identity,
            self.reentered.maximum_wall_seen,
            self.reentered.deadline,
        )?;
        owner.check_original_read(self.original_read)?;
        drop(self.attempt.slot.take().ok_or(Error::Permission)?);
        Ok(owner)
    }
}
fn check_original(
    binding: &CommonContextCompletionBinding,
    evidence_digest: &str,
    read: &StartedRosterCommonContextReadV1,
) -> Result<()> {
    read.matches_reentry_identity(&binding.identity)?;
    binding.original_signer_peer.check_alive()?;
    if read.evidence().digest()? != evidence_digest {
        return Err(Error::Binding);
    }
    require_completion_at(
        binding.deadline,
        &binding.maximum_wall_seen,
        read.request()?.completion_expires_at_ms,
        now_ms()?,
        Instant::now(),
    )
}
fn claim_reentry_once(attempted: &AtomicBool) -> Result<()> {
    if attempted.swap(true, Ordering::AcqRel) {
        Err(Error::Conflict)
    } else {
        Ok(())
    }
}
// Availability-only predicate. Passing it grants no pairing or installed-peer
// authority: production obtains `fresh` solely from the retained launch channel,
// then independently authenticates its socket and exact original live process.
fn require_fresh_reentry_endpoint(original: &Path, fresh: &Path) -> Result<()> {
    if !fresh.is_absolute() || fresh.as_os_str().len() > 4096 || fresh == original {
        Err(Error::Binding)
    } else {
        Ok(())
    }
}
fn restrict_ceiling(original: Instant, expires: u64, wall: u64) -> Result<Instant> {
    let duration = expires
        .checked_sub(wall)
        .filter(|v| *v > 0)
        .ok_or(Error::Permission)?;
    Ok(original.min(
        Instant::now()
            .checked_add(Duration::from_millis(duration))
            .ok_or(Error::Permission)?,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_completion_endpoint_must_differ_from_retired_read_locator() {
        let original = Path::new("/private/original-synthetic/request.sock");
        let fresh = Path::new("/private/fresh-synthetic/request.sock");
        // Pure path predicate only. No endpoint, socket, installed provider,
        // native decision or opaque admitted owner is created by this test.
        assert!(require_fresh_reentry_endpoint(original, fresh).is_ok());
        assert!(require_fresh_reentry_endpoint(original, original).is_err());
        assert!(require_fresh_reentry_endpoint(original, Path::new("request.sock")).is_err());
        let oversized = format!("/{}", "x".repeat(4096));
        assert!(require_fresh_reentry_endpoint(original, Path::new(&oversized)).is_err());
    }
    #[test]
    fn claim_is_shared_irreversible_and_not_recreated_by_moving_identity() {
        let original = Arc::new(AtomicBool::new(false));
        let retained = original.clone();
        claim_reentry_once(&original).unwrap();
        drop(original);
        assert!(claim_reentry_once(&retained).is_err());
        let unrelated = Arc::new(AtomicBool::new(true));
        assert!(!Arc::ptr_eq(&retained, &unrelated));
    }
    #[test]
    fn fresh_absolute_ceiling_cannot_extend_original_instant() {
        let original = Instant::now() + Duration::from_millis(20);
        assert!(restrict_ceiling(original, 100_000, 1).unwrap() <= original);
        assert!(restrict_ceiling(original, 100, 100).is_err());
        assert!(restrict_ceiling(original, 99, 100).is_err());
    }
}
