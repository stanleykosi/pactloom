//! Pure replay of separately authenticated handoff events. Transport possession
//! is checked by the encrypted journal; immutable events retain its distinct kind.
use crate::{
    construction_transport_handoff_v1::*,
    policy::{Event, Ledger},
    *,
};
use std::collections::{BTreeMap, BTreeSet};
impl Ledger {
    pub(crate) fn construction_transport_history_v1(&self) -> ConstructionTransportHistoryV1 {
        let mut history = ConstructionTransportHistoryV1 {
            version: 1,
            ..Default::default()
        };
        for (m, _, r) in self.operations.values() {
            match (m, r) {
                (
                    AuthorityMutation::OwnerControl(OwnerControlRequest {
                        control: OwnerControl::GrantConstructionTransportV1 { grant },
                        ..
                    }),
                    MutationResult::Controlled(s),
                ) => history.grants.push(PendingConstructionTransportGrantV1 {
                    grant: (**grant).clone(),
                    committed_head: s.head.clone(),
                }),
                (_, MutationResult::ConstructionTransportClaimedV1(c)) => {
                    history.credentials.push((**c).clone())
                }
                (_, MutationResult::ConstructionTransportReservedV1(r)) => {
                    history.reservations.push((**r).clone())
                }
                (_, MutationResult::ConstructionTransportConsumedV1(r)) => {
                    history.consumptions.push((**r).clone())
                }
                _ => {}
            }
        }
        history.grants.sort_by_key(|g| g.committed_head.sequence);
        history.credentials.sort_by_key(|c| c.claimed_head.sequence);
        history
            .reservations
            .sort_by_key(|r| r.original.snapshot.head.sequence);
        history
            .consumptions
            .sort_by_key(|r| r.original.snapshot.head.sequence);
        history
    }
    pub(crate) fn construction_transport_grant(
        &self,
        d: &str,
    ) -> Result<PendingConstructionTransportGrantV1> {
        hash(d)?;
        let mut found = None;
        for g in self.construction_transport_history_v1().grants {
            if g.digest()? == d {
                if found.is_some() {
                    return Err(AuthorityError::CorruptHistory);
                }
                found = Some(g);
            }
        }
        found.ok_or(AuthorityError::InvalidBinding)
    }
    pub(crate) fn construction_transport_credential(
        &self,
        id: &str,
    ) -> Result<&ConstructionTransportCredentialV1> {
        hash(id)?;
        self.operations
            .values()
            .find_map(|(_, _, r)| match r {
                MutationResult::ConstructionTransportClaimedV1(c) if c.credential_id() == id => {
                    Some(c.as_ref())
                }
                _ => None,
            })
            .ok_or(AuthorityError::SessionRequired)
    }
    pub(crate) fn require_unfenced_transport(&self, id: &str) -> Result<()> {
        self.snapshot.require_unfenced_transport(id)
    }
    pub(crate) fn validate_construction_transport_authorization(
        &self,
        a: &ConstructionTransportPreauthorizationV1,
        now: u64,
    ) -> Result<()> {
        a.validate()?;
        self.require_supported_manual_history()?;
        self.account_use_history
            .require_not_permanently_excluded()?;
        let active = self
            .snapshot
            .active_writer_session
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        let attempt = self.latest_manual_roster_attempt_v2()?;
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        let admission = attempt
            .admission
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        if self.snapshot.writer_status != WriterStatus::Active
            || active != &a.original_session
            || self.snapshot.writer_epoch != active.writer_epoch
            || self.snapshot.writer_certificate_digest != active.writer_certificate_digest
            || !self.activated_sessions.contains(&active.session_id)
            || self.sessions.get(&active.session_id) != Some(active)
            || a.account_id != self.policy.account_id
            || a.network_profile_id != self.policy.network_profile_id
            || a.policy_digest != self.policy.policy_digest()?
            || self
                .policy
                .account_use_genesis
                .as_ref()
                .map(|g| g.digest())
                .transpose()?
                .as_deref()
                != Some(a.genesis_digest.as_str())
            || a.attempt_digest != attempt.attempt_digest
            || a.attempt_sequence != attempt.sequence
            || admission.session != *active
        {
            return Err(AuthorityError::Permission);
        }
        if now < a.authorized_at_ms
            || now >= a.expires_at_ms
            || a.expires_at_ms > e.account_extension.terms.scope.expires_at_ms
            || a.expires_at_ms > admission.publication_expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        let mut approval = None;
        for (m, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ApproveManualRosterConstructionV3 { record },
                ..
            }) = m
            {
                if record
                    .approval
                    .plan
                    .invocation_digest()
                    .map_err(|_| AuthorityError::CorruptHistory)?
                    == a.invocation_digest
                {
                    if approval.is_some() {
                        return Err(AuthorityError::CorruptHistory);
                    }
                    approval = Some(record);
                }
            }
        }
        let approval = approval.ok_or(AuthorityError::Permission)?;
        if approval.approval.digest_for(e)? != a.plan_approval_digest
            || a.expires_at_ms > approval.approval.plan.completion_deadline_ms()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        self.require_retained_roster_construction_origin_v3(&approval.approval.plan)?;
        Ok(())
    }
    pub(crate) fn validate_construction_transport_grant(
        &self,
        g: &ConstructionTransportGrantV1,
        now: u64,
    ) -> Result<()> {
        g.validate()?;
        g.authorization
            .verify(&self.policy.owner_certificate_digest)?;
        let a = &g.authorization.authorization;
        self.fence(&g.expected_head, a.original_session.writer_epoch)?;
        self.validate_construction_transport_authorization(a, now)?;
        self.require_unfenced_transport(&a.original_session.session_id)?;
        if now < g.granted_at_ms {
            return Err(AuthorityError::Expired);
        }
        for old in self.construction_transport_history_v1().grants {
            let b = &old.grant.authorization.authorization;
            if b.original_session.session_id == a.original_session.session_id
                || b.invocation_digest == a.invocation_digest
                || b.read_request_digest == a.read_request_digest
                || b.nonce == a.nonce
            {
                return Err(AuthorityError::Conflict);
            }
        }
        // A handoff cannot be introduced after construction already reserved.
        for (_, _, r) in self.operations.values() {
            if let MutationResult::ManualRosterConstructionReservedV3(r) = r {
                if r.request.invocation_digest()? == a.invocation_digest {
                    return Err(AuthorityError::Conflict);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn apply_construction_transport_claim(
        &mut self,
        s: &SignedConstructionTransportClaimV1,
        event: &Event,
        next: &AuthorityHead,
    ) -> Result<ConstructionTransportCredentialV1> {
        s.verify(&self.policy.owner_certificate_digest)?;
        let pending = self.construction_transport_grant(&s.claim.pending_grant_digest)?;
        let a = &pending.grant.authorization.authorization;
        self.validate_construction_transport_authorization(a, event.witness_time_ms)?;
        self.require_unfenced_transport(&a.original_session.session_id)?;
        self.fence(&s.claim.expected_head, a.original_session.writer_epoch)?;
        if s.claim.expected_head != pending.committed_head
            || s.claim.original_host_process_commitment != a.original_host_process_commitment
            || event.writer_session_id.is_some()
            || event.authenticated_certificate_digest
                != a.original_session.writer_certificate_digest
            || s.claim.claimed_at_ms < pending.grant.granted_at_ms
            || event.witness_time_ms < s.claim.claimed_at_ms
            || self
                .construction_transport_history_v1()
                .credentials
                .iter()
                .any(|c| c.pending_grant == pending || c.credential_id() == s.claim.credential_id)
        {
            return Err(AuthorityError::Conflict);
        }
        let c = ConstructionTransportCredentialV1 {
            old_key_fence_digest: old_key_fence_digest(a, s, next)?,
            pending_grant: pending,
            signed_claim: s.clone(),
            claimed_head: next.clone(),
        };
        c.validate()?;
        self.snapshot
            .transport_fences
            .get_or_insert(ConstructionTransportFenceSnapshotV1 {
                version: 1,
                fenced_session_ids: BTreeSet::new(),
            })
            .fenced_session_ids
            .insert(c.authorization().original_session.session_id.clone());
        Ok(c)
    }
    pub(crate) fn require_construction_transport_current(
        &self,
        id: &str,
        peer: &str,
        now: u64,
    ) -> Result<&ConstructionTransportCredentialV1> {
        let c = self.construction_transport_credential(id)?;
        c.validate()?;
        self.validate_construction_transport_authorization(c.authorization(), now)?;
        if peer != c.authorization().original_session.writer_certificate_digest
            || self.snapshot.transport_fences.as_ref().is_none_or(|f| {
                f.version != 1
                    || !f
                        .fenced_session_ids
                        .contains(&c.authorization().original_session.session_id)
            })
        {
            return Err(AuthorityError::SessionRequired);
        }
        Ok(c)
    }
    pub(crate) fn require_construction_transport_request(
        &self,
        r: &ConstructionTransportRequestV1,
        event: &Event,
    ) -> Result<()> {
        if r.version != 1 || event.writer_session_id.is_some() {
            return Err(AuthorityError::InvalidBinding);
        }
        let c = self.require_construction_transport_current(
            &r.credential_id,
            &event.authenticated_certificate_digest,
            event.witness_time_ms,
        )?;
        let a = c.authorization();
        match &r.mutation {
            ConstructionTransportMutationV1::Reserve(v) => {
                if v.invocation_digest()? != a.invocation_digest
                    || v.session_id != a.original_session.session_id
                    || v.attempt_digest != a.attempt_digest
                    || v.attempt_sequence != a.attempt_sequence
                    || v.construction.current_caller_binding_digest
                        != c.signed_claim.claim.new_caller_binding_digest
                    || v.construction.admission_expires_at_ms > a.expires_at_ms
                    || v.expected_head != c.claimed_head
                {
                    return Err(AuthorityError::InvalidBinding);
                }
                for (_, _, result) in self.operations.values() {
                    if matches!(result,MutationResult::ConstructionTransportReservedV1(old) if old.credential_id==r.credential_id)
                    {
                        return Err(AuthorityError::Uncertain);
                    }
                }
            }
            ConstructionTransportMutationV1::Consume(v) => {
                let (_, _, result) = self
                    .operations
                    .get(&v.reservation_operation_id)
                    .ok_or(AuthorityError::InvalidBinding)?;
                let MutationResult::ConstructionTransportReservedV1(old) = result else {
                    return Err(AuthorityError::InvalidBinding);
                };
                if old.credential_id != r.credential_id
                    || v.session_id != a.original_session.session_id
                {
                    return Err(AuthorityError::InvalidBinding);
                }
                if self.operations.contains_key(&v.operation_id) {
                    return Err(AuthorityError::Uncertain);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn apply_construction_transport_use(
        &mut self,
        r: &ConstructionTransportRequestV1,
        event: &Event,
        next: &AuthorityHead,
    ) -> Result<MutationResult> {
        self.require_construction_transport_request(r, event)?;
        let (extension, continuation) = self.current_roster_construction_terms_v3()?;
        let extension = extension.clone();
        match &r.mutation {
            ConstructionTransportMutationV1::Reserve(v) => {
                Ok(MutationResult::ConstructionTransportReservedV1(Box::new(
                    ConstructionTransportReservationRecordV1 {
                        credential_id: r.credential_id.clone(),
                        original: self.apply_roster_construction_reservation_v3(v, event, next)?,
                        extension,
                        continuation,
                    },
                )))
            }
            ConstructionTransportMutationV1::Consume(v) => {
                Ok(MutationResult::ConstructionTransportConsumedV1(Box::new(
                    ConstructionTransportConsumedRecordV1 {
                        credential_id: r.credential_id.clone(),
                        original: self.apply_roster_construction_consume_v3(v, event, next)?,
                    },
                )))
            }
        }
    }
}
impl ReconciledAuthorityHistory {
    pub fn construction_transport_history_v1(&self) -> Result<ConstructionTransportHistoryV1> {
        self.construction_transport_history
            .validate_for(&self.account_policy, &self.snapshot)?;
        Ok(self.construction_transport_history.clone())
    }
}
impl ConstructionTransportHistoryV1 {
    pub fn validate_for(&self, policy: &AccountPolicy, snapshot: &AccountSnapshot) -> Result<()> {
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_HISTORY_BYTES)?;
        let genesis_digest = policy
            .account_use_genesis
            .as_ref()
            .map(|genesis| genesis.digest())
            .transpose()?;
        if self.version != 1
            || self.grants.len() > MAX_EVENTS as usize
            || snapshot.policy_digest != policy.policy_digest()?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut grants = BTreeMap::new();
        let mut sessions = BTreeSet::new();
        let mut invocations = BTreeSet::new();
        let mut reads = BTreeSet::new();
        let mut nonces = BTreeSet::new();
        let mut previous = 0;
        for g in &self.grants {
            g.validate()?;
            g.grant
                .authorization
                .verify(&policy.owner_certificate_digest)?;
            let a = &g.grant.authorization.authorization;
            if a.account_id != policy.account_id
                || a.network_profile_id != policy.network_profile_id
                || a.policy_digest != policy.policy_digest()?
                || genesis_digest.as_deref() != Some(a.genesis_digest.as_str())
                || g.committed_head.sequence <= previous
                || g.committed_head.sequence > snapshot.head.sequence
                || !sessions.insert(&a.original_session.session_id)
                || !invocations.insert(&a.invocation_digest)
                || !reads.insert(&a.read_request_digest)
                || !nonces.insert(&a.nonce)
                || grants.insert(g.digest()?, g).is_some()
            {
                return Err(AuthorityError::InvalidBinding);
            }
            previous = g.committed_head.sequence;
        }
        let mut credentials = BTreeMap::new();
        let mut used_grants = BTreeSet::new();
        let mut fences = BTreeSet::new();
        previous = 0;
        for c in &self.credentials {
            c.validate()?;
            c.signed_claim.verify(&policy.owner_certificate_digest)?;
            if grants.get(&c.pending_grant.digest()?).copied() != Some(&c.pending_grant)
                || !used_grants.insert(c.pending_grant.digest()?)
                || credentials.insert(c.credential_id(), c).is_some()
                || c.claimed_head.sequence <= previous
                || c.claimed_head.sequence > snapshot.head.sequence
            {
                return Err(AuthorityError::InvalidBinding);
            }
            fences.insert(c.authorization().original_session.session_id.clone());
            previous = c.claimed_head.sequence;
        }
        match (&snapshot.transport_fences, self.is_empty()) {
            (None, true) => {}
            (Some(f), false) if f.version == 1 && f.fenced_session_ids == fences => {}
            _ => return Err(AuthorityError::InvalidBinding),
        }
        let mut reserves = BTreeMap::new();
        let mut reserved_credentials = BTreeSet::new();
        previous = 0;
        for r in &self.reservations {
            r.extension.validate_original_policy(policy)?;
            r.original.validate_for(&r.extension, &r.continuation)?;
            let c = credentials
                .get(r.credential_id.as_str())
                .ok_or(AuthorityError::InvalidBinding)?;
            let a = c.authorization();
            if r.original.request.session_id != a.original_session.session_id
                || r.original.session != a.original_session
                || r.original.request.invocation_digest()? != a.invocation_digest
                || r.original.request.attempt_digest != a.attempt_digest
                || r.original.request.attempt_sequence != a.attempt_sequence
                || r.original
                    .request
                    .construction
                    .current_caller_binding_digest
                    != c.signed_claim.claim.new_caller_binding_digest
                || r.original.request.construction.admission_expires_at_ms > a.expires_at_ms
                || r.original.request.expected_head != c.claimed_head
                || r.original.snapshot.head.sequence <= previous
                || r.original.snapshot.head.sequence > snapshot.head.sequence
                || !reserved_credentials.insert(&r.credential_id)
                || reserves
                    .insert(&r.original.request.construction.operation_id, r)
                    .is_some()
            {
                return Err(AuthorityError::InvalidBinding);
            }
            previous = r.original.snapshot.head.sequence;
        }
        let mut consumed = BTreeSet::new();
        previous = 0;
        for r in &self.consumptions {
            let old = reserves
                .get(&r.original.request.reservation_operation_id)
                .ok_or(AuthorityError::InvalidBinding)?;
            r.original
                .validate_for(&old.original, &old.extension, &old.continuation)?;
            if old.credential_id != r.credential_id
                || !consumed.insert(&r.credential_id)
                || r.original.snapshot.head.sequence <= previous
                || r.original.snapshot.head.sequence > snapshot.head.sequence
            {
                return Err(AuthorityError::InvalidBinding);
            }
            previous = r.original.snapshot.head.sequence;
        }
        Ok(())
    }
}
