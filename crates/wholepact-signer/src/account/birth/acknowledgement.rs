//! Native-approved historical origin acknowledgement. The preserved account
//! envelope remains financially denied until a separate qualified enrollment.
use super::*;
use wholepact_authority::{ReconciledAuthorityHistory, pending_birth::PendingBirthRequest};

/// Keeps the complete original anchor and exact original witness record. It must
/// be encoded inside a future active envelope, not substituted with a new anchor.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedBornAccountOrigin {
    anchor: BirthAnchor,
    witness_commit: wholepact_authority::pending_birth::PendingBirthCommitRecord,
    observed_snapshot: wholepact_authority::AccountSnapshot,
    observed_checkpoint: wholepact_authority::account_use::AccountUseCheckpoint,
    permanent_exclusion: Option<wholepact_authority::account_use::PermanentAccountExclusion>,
}
impl BirthAnchor {
    pub(super) fn require_exact_pending_request(
        &self,
        request: &PendingBirthRequest,
    ) -> Result<()> {
        request.validate().map_err(|_| Error::InvalidData)?;
        self.audit_policy_match(&request.policy)?;
        if request.operation_id != self.operation_id()
            || request.generation_instance_id != self.generation_instance_id()
            || request.native_birth_digest != self.birth_digest()
            || request.original_terms_digest != self.original_policy_terms_digest()
            || request.original_target_digest
                != canonical(
                    "wholepact:pending-birth-target:v1",
                    &self.intent.original_target,
                )?
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}
impl PendingBirthVault {
    /// Only the real complete authenticated history can supply witness metadata.
    /// The exact encrypted locally retained request, including original times,
    /// must match. Anchor-only equality cannot substitute for this operation.
    pub(crate) fn retain_acknowledged_origin(
        &self,
        history: &ReconciledAuthorityHistory,
    ) -> Result<(
        RetainedBornAccountOrigin,
        super::history::HistoricalBirthLinkAudit,
    )> {
        super::active::authenticate_staged_envelope(self)?;
        let retained = self.read_owner_request()?.ok_or(Error::RecoveryRequired)?;
        let audit = self.anchor.audit_historical_witness_link(history)?;
        let commit = history
            .pending_birth_commit()
            .ok_or(Error::RecoveryRequired)?;
        self.anchor.require_exact_pending_request(&commit.request)?;
        commit.validate().map_err(|_| Error::ReviewMismatch)?;
        commit
            .require_exact_retry(&retained)
            .map_err(|_| Error::ReviewMismatch)?;
        // Recheck supported lock-owned durable input after complete comparison.
        if self.read_owner_request()?.as_ref() != Some(&retained) {
            return Err(Error::ReviewMismatch);
        }
        Ok((
            RetainedBornAccountOrigin {
                anchor: self.anchor.clone(),
                witness_commit: commit.clone(),
                observed_snapshot: history.snapshot().clone(),
                observed_checkpoint: audit.checkpoint().clone(),
                permanent_exclusion: audit.permanent_exclusion().cloned(),
            },
            audit,
        ))
    }
}
impl RetainedBornAccountOrigin {
    /// At-rest decoding is audit only; real current use requires fresh native
    /// authority, surviving witness history and all exclusion/action checks.
    pub(crate) fn validate_at_rest(&self, account: &DedicatedAccount) -> Result<()> {
        self.anchor.validate_historical_account(account)?;
        self.anchor
            .require_exact_pending_request(&self.witness_commit.request)?;
        self.witness_commit
            .validate()
            .map_err(|_| Error::InvalidData)?;
        let genesis = self.anchor.expected_account_use_genesis()?;
        let (_, disclosure) = self
            .anchor
            .audit_policy_match(&self.witness_commit.request.policy)?;
        if self.observed_checkpoint.genesis_digest
            != genesis.digest().map_err(|_| Error::InvalidData)?
            || self.observed_snapshot.account_use_checkpoint.as_ref()
                != Some(&self.observed_checkpoint)
            || self.observed_snapshot.account_id != genesis.identity.account_id
            || self.observed_snapshot.network_profile_id != genesis.identity.network_profile_id
            || self.observed_snapshot.witness_id != genesis.witness_id
            || self.observed_snapshot.policy_digest != disclosure.policy_digest
        {
            return Err(Error::InvalidData);
        }
        let excluded = self
            .permanent_exclusion
            .as_ref()
            .map(|e| {
                e.validate().map_err(|_| Error::InvalidData)?;
                if e.identity != genesis.identity
                    || e.genesis_digest != self.observed_checkpoint.genesis_digest
                {
                    return Err(Error::InvalidData);
                }
                e.digest().map_err(|_| Error::InvalidData)
            })
            .transpose()?;
        if excluded != self.observed_checkpoint.permanent_exclusion_digest {
            return Err(Error::InvalidData);
        }
        Ok(())
    }
    pub(crate) fn anchor(&self) -> &BirthAnchor {
        &self.anchor
    }
}

impl RetainedBornAccountOrigin {
    pub(super) fn witness_commit(
        &self,
    ) -> &wholepact_authority::pending_birth::PendingBirthCommitRecord {
        &self.witness_commit
    }
    pub(super) fn permanent_exclusion(
        &self,
    ) -> Option<&wholepact_authority::account_use::PermanentAccountExclusion> {
        self.permanent_exclusion.as_ref()
    }
    pub(super) fn original_request(&self) -> &PendingBirthRequest {
        &self.witness_commit.request
    }
}

/// Genuine native acknowledgement publication. Historical witness linkage is
/// necessary evidence, but this type still grants no financial enrollment.
pub(crate) struct PreparedPendingBirthAcknowledgement {
    pending: Arc<PendingBirthVault>,
    origin: RetainedBornAccountOrigin,
    source: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
    created: Instant,
}
impl PreparedPendingBirthAcknowledgement {
    pub(crate) fn prepare(
        pending: Arc<PendingBirthVault>,
        history: ReconciledAuthorityHistory,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        pending.require_original_request_target()?;
        // Authenticated active stages are evidence only; no request/signature is reminted.
        super::active::authenticate_staged_envelope(&pending)?;
        let (origin, audit) = pending.retain_acknowledged_origin(&history)?;
        origin.validate_at_rest(&pending.account)?;
        let source = owner.native().binding();
        let digest = canonical(
            "wholepact:native-pending-birth-acknowledgement:v1",
            &(
                &origin,
                pending._directory.root(),
                &pending.pending_envelope_digest,
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        let display = Zeroizing::new(format!(
            "Preserve this exact acknowledged account origin in the selected private vault.\n\nTarget: {}\nOriginal operation: {}\nOriginal birth: {}\nWitness observed head: {}\nPermanent exclusion: {}\n\n{}\n\nThis preserves historical evidence only. It does not authorize a writer, spending, restored scope or financial enrollment. Current witness and signer authority must be checked separately for every later action.",
            pending._directory.root().display(),
            origin.anchor.operation_id(),
            origin.anchor.birth_digest(),
            serde_json::to_string(audit.observed_head()).map_err(|_| Error::InvalidData)?,
            if audit.permanent_exclusion().is_some() {
                "PRESENT: remains excluded"
            } else {
                "not present in this observed history; no current eligibility asserted"
            },
            serde_json::to_string_pretty(&origin).map_err(|_| Error::InvalidData)?
        ));
        Ok(Self {
            pending,
            origin,
            source,
            digest,
            display,
            created: Instant::now(),
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME {
            return Err(Error::ReviewMismatch);
        }
        Ok(self.display.to_string())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        self.source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME || self.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        self.pending.require_original_request_target()?;
        let retained = self
            .pending
            .read_owner_request()?
            .ok_or(Error::RecoveryRequired)?;
        if &retained != self.origin.original_request() {
            return Err(Error::ReviewMismatch);
        }
        self.origin.validate_at_rest(&self.pending.account)
    }
    pub(crate) fn approve_and_publish(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let _serialization = self
            .pending
            .request_publication
            .lock()
            .map_err(|_| Error::Locked)?;
        self.check(owner)?;
        let _lease = self.source.publication_lease()?;
        self.check(owner)?;
        super::active::publish(&self.pending, &self.origin)
    }
}
