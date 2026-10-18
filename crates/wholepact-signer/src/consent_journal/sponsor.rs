//! Native-owned durable sponsor constraints. Coordinator policy objects are
//! never authority. Policy history and manifest bindings are append-only.
use super::*;
use rusqlite::{Connection, OptionalExtension, params};
use wholepact_core::sponsor::SponsorPolicyTerms;

#[derive(Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorPolicyBinding {
    pub policy_key: String,
    pub version: u64,
    pub terms_digest: String,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSponsorPolicyStatus {
    Active,
    Paused,
    Revoked,
}
#[derive(Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSponsorPolicyRecord {
    pub witness: SponsorWitnessBinding,
    pub binding: SponsorPolicyBinding,
    pub terms: SponsorPolicyTerms,
    pub status: NativeSponsorPolicyStatus,
    pub principal_id: String,
    pub approval_digest: String,
}
impl NativeSponsorPolicyRecord {
    pub(super) fn validate(&self) -> Result<()> {
        hash(&self.binding.policy_key)?;
        hash(&self.approval_digest)?;
        hash(&self.witness.policy_digest)?;
        id(&self.witness.witness_id)?;
        if self.witness.aggregate_budget_zatoshis == 0
            || self.witness.aggregate_budget_zatoshis > self.terms.aggregate_budget.as_zatoshis()
        {
            return Err(JournalError::BudgetExceeded);
        }
        id(&self.principal_id)?;
        self.terms
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        if self.binding.version == 0 || self.binding.terms_digest != terms_digest(&self.terms)? {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(super) fn require_active(&self) -> Result<()> {
        self.validate()?;
        if self.status != NativeSponsorPolicyStatus::Active {
            return Err(JournalError::Permission);
        }
        if let Some(expiry) = &self.terms.expires_at {
            let now = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|_| JournalError::Expired)?;
            // Terms admit only canonical fixed-width UTC seconds. Truncate the
            // current time's fractional seconds before lexicographic comparison.
            if now.len() < 19 || now[..19] >= expiry[..19] {
                return Err(JournalError::Expired);
            }
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorWitnessBinding {
    pub witness_id: String,
    pub policy_digest: String,
    pub aggregate_budget_zatoshis: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorOwnerBinding {
    pub account_id: String,
    pub participant_id: String,
    pub fvk_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorOwnerAttestation {
    pub manifest_digest: String,
    pub policy_terms_digest: String,
    pub owners: Vec<SponsorOwnerBinding>,
}
#[derive(Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredSponsorAttestation {
    pub(super) assertion: SponsorOwnerAttestation,
    pub(super) source: TransportIdentityBinding,
    pub(super) verifier_label: String,
}
pub(super) fn read_attestation(c: &Connection, manifest: &str) -> Result<Option<StoredSponsorAttestation>> {
    let raw: Option<String> = c
        .query_row(
            "SELECT payload FROM signer_sponsor_owner_attestations WHERE manifest_ref=?1",
            [manifest],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(decode).transpose()
}
pub(super) fn attestation_digest(record: &StoredSponsorAttestation) -> Result<String> {
    digest("wholepact:native-sponsor-owner-attestation:v1", record)
}
pub(super) fn validate_attestation(
    record: &StoredSponsorAttestation,
    manifest: &AcceptedManifestRecord,
    binding: &SponsorPolicyBinding,
) -> Result<()> {
    let proposal = manifest.proposal()?;
    record.source.validate()?;
    id(&record.verifier_label)?;
    let a = &record.assertion;
    if a.manifest_digest != manifest.manifest_digest()
        || a.policy_terms_digest != binding.terms_digest
        || a.owners.len() != proposal.manifest().participants.len()
    {
        return Err(JournalError::InvalidBinding);
    }
    let mut accounts = std::collections::BTreeSet::new();
    let mut fvks = std::collections::BTreeSet::new();
    for owner in &a.owners {
        hash(&owner.fvk_digest)?;
        if !accounts.insert(&owner.account_id)
            || !fvks.insert(&owner.fvk_digest)
            || !proposal.manifest().participants.iter().any(|p| {
                p.account_id == owner.account_id && p.participant_id == owner.participant_id
            })
        {
            return Err(JournalError::InvalidBinding);
        }
    }
    if a.owners
        .windows(2)
        .any(|pair| pair[0].account_id >= pair[1].account_id)
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}
fn terms_digest(terms: &SponsorPolicyTerms) -> Result<String> {
    digest("wholepact:sponsor-policy-terms:v1", terms)
}
pub(super) fn read_current(c: &Connection, key: &str) -> Result<Option<NativeSponsorPolicyRecord>> {
    let row: Option<(u64, String)> = c.query_row(
        "SELECT version,payload FROM signer_sponsor_policy_events WHERE policy_key=?1 ORDER BY version DESC LIMIT 1",
        [key], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    row.map(|(version, raw)| {
        let record: NativeSponsorPolicyRecord = decode(raw)?;
        record.validate()?;
        if record.binding.policy_key != key || record.binding.version != version {
            return Err(JournalError::InvalidBinding);
        }
        Ok(record)
    })
    .transpose()
}
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
fn current_for_terms(
    c: &Connection,
    terms: &SponsorPolicyTerms,
) -> Result<Option<NativeSponsorPolicyRecord>> {
    let mut q =
        c.prepare("SELECT policy_key FROM signer_sponsor_policy_events GROUP BY policy_key")?;
    let keys = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut found = None;
    for key in keys {
        let record = read_current(c, &key)?.ok_or(JournalError::InvalidBinding)?;
        if &record.terms == terms {
            if found.is_some() {
                return Err(JournalError::Conflict);
            }
            found = Some(record);
        }
    }
    Ok(found)
}
pub(super) fn manifest_binding(
    c: &Connection,
    manifest: &str,
) -> Result<Option<SponsorPolicyBinding>> {
    let row: Option<(String,u64,String)> = c.query_row(
        "SELECT policy_key,version,payload FROM signer_sponsor_manifest_bindings WHERE manifest_ref=?1",
        [manifest], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    row.map(|(key, version, raw)| {
        let binding: SponsorPolicyBinding = decode(raw)?;
        hash(&binding.policy_key)?;
        hash(&binding.terms_digest)?;
        if binding.policy_key != key || binding.version != version || version == 0 {
            return Err(JournalError::InvalidBinding);
        }
        Ok(binding)
    })
    .transpose()
}
#[cfg(any(
    test,
    all(
        feature = "native-ui",
        feature = "authority-signing",
        target_os = "linux"
    )
))]
fn validate_scope_owner(c: &Connection, candidate: &NativeSponsorPolicyRecord) -> Result<()> {
    let mut q = c.prepare("SELECT payload FROM signer_sponsor_policy_events")?;
    for raw in q.query_map([], |r| r.get::<_, String>(0))? {
        let old: NativeSponsorPolicyRecord = decode(raw?)?;
        old.validate()?;
        if old.binding.policy_key != candidate.binding.policy_key
            && old.terms.sponsor.account_id == candidate.terms.sponsor.account_id
            && old
                .terms
                .agreement_scope
                .iter()
                .any(|scope| candidate.terms.agreement_scope.contains(scope))
        {
            return Err(JournalError::Conflict);
        }
    }
    Ok(())
}
/// Enrollment remains scoped even after pause, revoke or a later scope update.
/// Only an explicit future native unenrollment transition could remove this gate.
pub(super) fn policy_required(c: &Connection, manifest: &AcceptedManifestRecord) -> Result<bool> {
    let proposal = manifest.proposal()?;
    let mut q = c.prepare("SELECT payload FROM signer_sponsor_policy_events")?;
    for raw in q.query_map([], |r| r.get::<_, String>(0))? {
        let policy: NativeSponsorPolicyRecord = decode(raw?)?;
        policy.validate()?;
        if policy.terms.sponsor.account_id == manifest.terms.account_id
            && policy
                .terms
                .agreement_scope
                .contains(&proposal.manifest().agreement.agreement_id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(super) fn current_for_consent(
    c: &Connection,
    terms: &SpendConsentTerms,
) -> Result<Option<NativeSponsorPolicyRecord>> {
    let frozen = manifest_binding(c, &terms.accepted_manifest_ref)?;
    let manifest =
        storage::read_manifest(c, &terms.accepted_manifest_ref)?.ok_or(JournalError::NotFound)?;
    if frozen.is_none() && policy_required(c, &manifest)? {
        return Err(JournalError::Permission);
    }
    if frozen != terms.sponsor_policy {
        return Err(JournalError::InvalidBinding);
    }
    if frozen.is_none() && terms.sponsor_owner_attestation_digest.is_some() {
        return Err(JournalError::InvalidBinding);
    }
    frozen
        .map(|binding| {
            let current = read_current(c, &binding.policy_key)?.ok_or(JournalError::NotFound)?;
            if current.binding != binding
                || current.terms.sponsor.account_id != terms.account_id
                || current.principal_id != terms.principal_id
            {
                return Err(JournalError::Permission);
            }
            current.require_active()?;
            let attestation = read_attestation(c, &terms.accepted_manifest_ref)?
                .ok_or(JournalError::Permission)?;
            let manifest = storage::read_manifest(c, &terms.accepted_manifest_ref)?
                .ok_or(JournalError::NotFound)?;
            validate_attestation(&attestation, &manifest, &binding)?;
            wholepact_core::sponsor::evaluate_sponsor_policy(
                &current.terms,
                manifest.proposal()?.manifest(),
            )
            .map_err(|_| JournalError::InvalidBinding)?;
            if terms.sponsor_owner_attestation_digest.as_deref()
                != Some(attestation_digest(&attestation)?.as_str())
                || attestation.source != terms.transport
            {
                return Err(JournalError::Permission);
            }
            match &current.terms.assurance {
                wholepact_core::MatchAssurance::Attested { verifier_identity }
                    if verifier_identity == &attestation.verifier_label => {}
                _ => return Err(JournalError::Permission),
            }
            Ok(current)
        })
        .transpose()
}
#[cfg(any(
    test,
    all(
        feature = "native-ui",
        feature = "authority-signing",
        target_os = "linux"
    )
))]
pub(super) fn current_for_manifest(
    c: &Connection,
    manifest: &str,
) -> Result<Option<NativeSponsorPolicyRecord>> {
    manifest_binding(c, manifest)?
        .map(|binding| {
            let current = read_current(c, &binding.policy_key)?.ok_or(JournalError::Permission)?;
            if current.binding != binding {
                return Err(JournalError::Permission);
            }
            current.require_active()?;
            Ok(current)
        })
        .transpose()
}
impl SignerConsentJournal {
    /// Must precede display of the exact spending review. The final append and
    /// held key-use lease independently reload this binding under the same fence.
    pub fn bind_spend_sponsor(
        &self,
        prepared: PreparedSpendConsent,
        session: &SignerConsentSession,
    ) -> Result<PreparedSpendConsent> {
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        storage::check_account(&c, &account)?;
        if prepared.record().terms().principal_id != permission.principal {
            return Err(JournalError::Permission);
        }
        let binding = manifest_binding(&c, &prepared.record().terms().accepted_manifest_ref)?;
        let attestation_digest = if let Some(binding) = &binding {
            let attestation =
                read_attestation(&c, &prepared.record().terms().accepted_manifest_ref)?
                    .ok_or(JournalError::Permission)?;
            let manifest =
                storage::read_manifest(&c, &prepared.record().terms().accepted_manifest_ref)?
                    .ok_or(JournalError::NotFound)?;
            validate_attestation(&attestation, &manifest, binding)?;
            let reviewed = prepared.reviewed_owner_fvks()?;
            if reviewed.len() != attestation.assertion.owners.len()
                || !reviewed.iter().all(|(account, fvk)| {
                    attestation
                        .assertion
                        .owners
                        .iter()
                        .any(|o| &o.account_id == account && &o.fvk_digest == fvk)
                })
            {
                return Err(JournalError::Permission);
            }
            Some(attestation_digest(&attestation)?)
        } else {
            None
        };
        let prepared = prepared.with_sponsor_binding(binding, attestation_digest)?;
        current_for_consent(&c, prepared.record().terms())?;
        Ok(prepared)
    }
}

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
mod native {
    use super::*;
    use crate::native_ui::{NativeAuthorityBinding, NativeDecision};
    use rusqlite::TransactionBehavior;
    use std::time::{Duration, Instant};

    pub(crate) struct ApprovedSponsorManifestBinding {
        terms: SponsorPolicyTerms,
        witness: SponsorWitnessBinding,
        manifest_ref: String,
        source: NativeAuthorityBinding,
        approval_digest: String,
        created: Instant,
    }
    impl ApprovedSponsorManifestBinding {
        pub(crate) fn from_native(
            terms: SponsorPolicyTerms,
            manifest_ref: String,
            source: &NativeAuthorityBinding,
            expected_digest: &str,
            snapshot: &wholepact_authority::AccountSnapshot,
            peer: &crate::ipc::AuthenticatedPeer,
            decision: &NativeDecision,
        ) -> Result<Self> {
            source
                .check_current()
                .map_err(|_| JournalError::Permission)?;
            if decision.binding() != source || decision.reviewed_digest() != expected_digest {
                return Err(JournalError::Permission);
            }
            peer.check_current().map_err(|_| JournalError::Permission)?;
            if &peer.native_origin != source
                || snapshot.account_id != terms.sponsor.account_id
                || snapshot.network_profile_id != terms.network_profile_id
                || snapshot.aggregate_budget_zatoshis > terms.aggregate_budget.as_zatoshis()
            {
                return Err(JournalError::Permission);
            }
            match &terms.assurance {
                wholepact_core::MatchAssurance::Attested { verifier_identity }
                    if verifier_identity == &peer.label => {}
                _ => return Err(JournalError::Permission),
            }
            hash(&manifest_ref)?;
            hash(expected_digest)?;
            terms.validate().map_err(|_| JournalError::InvalidBinding)?;
            Ok(Self {
                terms,
                witness: SponsorWitnessBinding {
                    witness_id: snapshot.witness_id.clone(),
                    policy_digest: snapshot.policy_digest.clone(),
                    aggregate_budget_zatoshis: snapshot.aggregate_budget_zatoshis,
                },
                manifest_ref,
                source: source.clone(),
                approval_digest: expected_digest.into(),
                created: Instant::now(),
            })
        }
    }
    pub(crate) struct PreparedSponsorPolicyChange {
        record: NativeSponsorPolicyRecord,
        previous: SponsorPolicyBinding,
        source: NativeAuthorityBinding,
        digest: String,
        created: Instant,
    }
    impl PreparedSponsorPolicyChange {
        pub(crate) fn digest(&self) -> &str {
            &self.digest
        }
        pub(crate) fn display(&self) -> Result<String> {
            Ok(format!(
                "CHANGE NATIVE SPONSOR POLICY\n{}\n\nThis changes future authorization eligibility. Every earlier accepted manifest remains bound to its frozen policy version and becomes ineligible after this change. Existing signatures and reservations cannot be canceled or erased by pausing, revoking or updating. A fresh native review and accepted manifest are needed for the new version. Revocation is permanent for this policy key. This does not authorize a payment.",
                serde_json::to_string_pretty(&self.record)
                    .map_err(|_| JournalError::InvalidBinding)?
            ))
        }
    }
    impl SignerConsentJournal {
        pub(crate) fn record_sponsor_manifest_binding(
            &self,
            approved: ApprovedSponsorManifestBinding,
            session: &SignerConsentSession,
        ) -> Result<SponsorPolicyBinding> {
            approved
                .source
                .check_current()
                .map_err(|_| JournalError::Permission)?;
            if approved.created.elapsed() >= Duration::from_secs(120) {
                return Err(JournalError::Expired);
            }
            let account = self.account_state()?;
            if account.recovery_required {
                return Err(JournalError::RecoveryRequired);
            }
            let permission = session.read_lease(&self.binding(), &account)?;
            permission.require_native_origin(&approved.source)?;
            let _fence = self
                .authority_fence
                .write()
                .map_err(|_| JournalError::Permission)?;
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            storage::check_account(&tx, &account)?;
            permission.check_current()?;
            approved
                .source
                .check_current()
                .map_err(|_| JournalError::Permission)?;
            if approved.created.elapsed() >= Duration::from_secs(120) {
                return Err(JournalError::Expired);
            }
            let manifest = storage::read_manifest(&tx, &approved.manifest_ref)?
                .ok_or(JournalError::NotFound)?;
            let proposal = manifest.proposal()?;
            if manifest.terms.account_id != account.account_id
                || manifest.terms.principal_id != permission.principal
                || approved.terms.sponsor.account_id != account.account_id
            {
                return Err(JournalError::Permission);
            }
            wholepact_core::sponsor::evaluate_sponsor_policy(&approved.terms, proposal.manifest())
                .map_err(|_| JournalError::InvalidBinding)?;
            let key = terms_digest(&approved.terms)?;
            let matching = current_for_terms(&tx, &approved.terms)?.or(read_current(&tx, &key)?);
            let record = match matching {
                Some(old) => {
                    if old.terms != approved.terms
                        || old.witness != approved.witness
                        || old.principal_id != permission.principal
                    {
                        return Err(JournalError::Conflict);
                    }
                    old.require_active()?;
                    old
                }
                None => NativeSponsorPolicyRecord {
                    witness: approved.witness,
                    binding: SponsorPolicyBinding {
                        policy_key: key.clone(),
                        version: 1,
                        terms_digest: key,
                    },
                    terms: approved.terms,
                    status: NativeSponsorPolicyStatus::Active,
                    principal_id: permission.principal.into(),
                    approval_digest: approved.approval_digest,
                },
            };
            record.require_active()?;
            validate_scope_owner(&tx, &record)?;
            if let Some(old) = manifest_binding(&tx, &approved.manifest_ref)? {
                if old != record.binding {
                    return Err(JournalError::Conflict);
                }
                return Ok(old);
            }
            if read_current(&tx, &record.binding.policy_key)?.is_none() {
                insert_event(&tx, &record)?;
            }
            let raw = encode(&record.binding)?;
            tx.execute(
                "INSERT INTO signer_sponsor_manifest_bindings VALUES(?1,?2,?3,?4)",
                params![
                    approved.manifest_ref,
                    record.binding.policy_key,
                    record.binding.version,
                    raw.as_str()
                ],
            )?;
            storage::bounded(&tx, self.capacity_limits())?;
            permission.check_current()?;
            if approved.created.elapsed() >= Duration::from_secs(120) {
                return Err(JournalError::Expired);
            }
            tx.commit()?;
            Ok(record.binding)
        }
        #[cfg(feature = "authority-signing")]
        pub(crate) fn record_sponsor_owner_attestation(
            &self,
            lease: &super::super::preconstruction_lease::PreconstructionRecordLease<'_>,
            peer: &crate::ipc::AuthenticatedPeer,
            attestation: SponsorOwnerAttestation,
        ) -> Result<()> {
            lease.require_journal(&self.binding())?;
            lease.check_current()?;
            lease.require_native_origin(&peer.native_origin)?;
            peer.check_current().map_err(|_| JournalError::Permission)?;
            let transport = lease.enrollment().transport();
            match transport {
                TransportIdentityBinding::LocalProcess {
                    transport_identity_id,
                    channel_binding_digest,
                    uid,
                    pid,
                    ..
                } if transport_identity_id == &peer.grant_id
                    && channel_binding_digest == &peer.channel_digest
                    && *uid == peer.peer.uid()
                    && *pid == peer.peer.pid() => {}
                _ => return Err(JournalError::Permission),
            }
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            lease.check_current()?;
            peer.check_current().map_err(|_| JournalError::Permission)?;
            let binding = manifest_binding(&tx, lease.manifest().reference())?
                .ok_or(JournalError::Permission)?;
            let policy = read_current(&tx, &binding.policy_key)?.ok_or(JournalError::Permission)?;
            policy.require_active()?;
            if policy.binding != binding {
                return Err(JournalError::Permission);
            }
            match &policy.terms.assurance {
                wholepact_core::MatchAssurance::Attested { verifier_identity }
                    if verifier_identity == &peer.label => {}
                _ => return Err(JournalError::Permission),
            }
            let record = StoredSponsorAttestation {
                assertion: attestation,
                source: transport.clone(),
                verifier_label: peer.label.clone(),
            };
            validate_attestation(&record, lease.manifest(), &binding)?;
            if let Some(old) = read_attestation(&tx, lease.manifest().reference())? {
                if old != record {
                    return Err(JournalError::Conflict);
                }
                return Ok(());
            }
            let raw = encode(&record)?;
            tx.execute(
                "INSERT INTO signer_sponsor_owner_attestations VALUES(?1,?2)",
                params![lease.manifest().reference(), raw.as_str()],
            )?;
            storage::bounded(&tx, self.capacity_limits())?;
            lease.check_current()?;
            peer.check_current().map_err(|_| JournalError::Permission)?;
            tx.commit()?;
            Ok(())
        }
        pub(crate) fn prepare_sponsor_policy_change(
            &self,
            key: &str,
            status: NativeSponsorPolicyStatus,
            replacement: Option<SponsorPolicyTerms>,
            session: &SignerConsentSession,
            source: &NativeAuthorityBinding,
        ) -> Result<PreparedSponsorPolicyChange> {
            hash(key)?;
            let account = self.account_state()?;
            if account.recovery_required {
                return Err(JournalError::RecoveryRequired);
            }
            let permission = session.read_lease(&self.binding(), &account)?;
            permission.require_native_origin(source)?;
            let _fence = self
                .authority_fence
                .read()
                .map_err(|_| JournalError::Permission)?;
            let c = self.connection.lock().map_err(|_| JournalError::Database)?;
            storage::check_account(&c, &account)?;
            let old = read_current(&c, key)?.ok_or(JournalError::NotFound)?;
            if old.principal_id != permission.principal
                || old.status == NativeSponsorPolicyStatus::Revoked
            {
                return Err(JournalError::Permission);
            }
            let terms = replacement.unwrap_or_else(|| old.terms.clone());
            terms.validate().map_err(|_| JournalError::InvalidBinding)?;
            if !matches!(
                terms.assurance,
                wholepact_core::MatchAssurance::Attested { .. }
            ) || !terms.identity_requirements.is_empty()
            {
                return Err(JournalError::Permission);
            }
            if terms.sponsor.account_id != account.account_id {
                return Err(JournalError::InvalidBinding);
            }
            if current_for_terms(&c, &terms)?
                .is_some_and(|p| p.binding.policy_key != old.binding.policy_key)
            {
                return Err(JournalError::Conflict);
            }
            let mut record = NativeSponsorPolicyRecord {
                witness: old.witness.clone(),
                binding: SponsorPolicyBinding {
                    policy_key: key.into(),
                    version: old
                        .binding
                        .version
                        .checked_add(1)
                        .ok_or(JournalError::Limit)?,
                    terms_digest: terms_digest(&terms)?,
                },
                terms,
                status,
                principal_id: permission.principal.into(),
                approval_digest: "0".repeat(64),
            };
            record.validate()?;
            validate_scope_owner(&c, &record)?;
            let digest = digest(
                "wholepact:native-sponsor-change:v1",
                &(&record, random_id()?),
            )?;
            record.approval_digest = digest.clone();
            Ok(PreparedSponsorPolicyChange {
                record,
                previous: old.binding,
                source: source.clone(),
                digest,
                created: Instant::now(),
            })
        }
        pub(crate) fn commit_sponsor_policy_change(
            &self,
            prepared: PreparedSponsorPolicyChange,
            decision: NativeDecision,
            session: &SignerConsentSession,
        ) -> Result<()> {
            prepared
                .source
                .check_current()
                .map_err(|_| JournalError::Permission)?;
            if decision.binding() != &prepared.source
                || decision.reviewed_digest() != prepared.digest
                || prepared.created.elapsed() >= Duration::from_secs(120)
            {
                return Err(JournalError::Permission);
            }
            let account = self.account_state()?;
            if account.recovery_required {
                return Err(JournalError::RecoveryRequired);
            }
            let permission = session.read_lease(&self.binding(), &account)?;
            permission.require_native_origin(&prepared.source)?;
            let _fence = self
                .authority_fence
                .write()
                .map_err(|_| JournalError::Permission)?;
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            storage::check_account(&tx, &account)?;
            permission.check_current()?;
            prepared
                .source
                .check_current()
                .map_err(|_| JournalError::Permission)?;
            if prepared.created.elapsed() >= Duration::from_secs(120) {
                return Err(JournalError::Expired);
            }
            if current_for_terms(&tx, &prepared.record.terms)?
                .is_some_and(|p| p.binding.policy_key != prepared.previous.policy_key)
            {
                return Err(JournalError::Conflict);
            }
            let old =
                read_current(&tx, &prepared.previous.policy_key)?.ok_or(JournalError::NotFound)?;
            if old.binding != prepared.previous
                || old.status == NativeSponsorPolicyStatus::Revoked
                || old.principal_id != permission.principal
                || prepared.record.principal_id != permission.principal
            {
                return Err(JournalError::Permission);
            }
            validate_scope_owner(&tx, &prepared.record)?;
            insert_event(&tx, &prepared.record)?;
            storage::bounded(&tx, self.capacity_limits())?;
            permission.check_current()?;
            if prepared.created.elapsed() >= Duration::from_secs(120) {
                return Err(JournalError::Expired);
            }
            tx.commit()?;
            Ok(())
        }
    }
}
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
pub(crate) use native::{ApprovedSponsorManifestBinding, PreparedSponsorPolicyChange};
#[cfg(any(
    test,
    all(
        feature = "native-ui",
        feature = "authority-signing",
        target_os = "linux"
    )
))]
fn insert_event(c: &Connection, record: &NativeSponsorPolicyRecord) -> Result<()> {
    record.validate()?;
    let raw = encode(record)?;
    c.execute(
        "INSERT INTO signer_sponsor_policy_events VALUES(?1,?2,?3)",
        params![
            record.binding.policy_key,
            record.binding.version,
            raw.as_str()
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> NativeSponsorPolicyRecord {
        let mut terms: SponsorPolicyTerms = serde_json::from_str(include_str!(
            "../../../wholepact-core/tests/fixtures/sponsor_policy.json"
        ))
        .unwrap();
        terms.assurance = wholepact_core::MatchAssurance::Attested {
            verifier_identity: "synthetic-local-verifier".into(),
        };
        terms.identity_requirements.clear();
        let key = terms_digest(&terms).unwrap();
        NativeSponsorPolicyRecord {
            witness: SponsorWitnessBinding {
                witness_id: "synthetic-witness".into(),
                policy_digest: "ab".repeat(32),
                aggregate_budget_zatoshis: 50,
            },
            binding: SponsorPolicyBinding {
                policy_key: key.clone(),
                version: 1,
                terms_digest: key,
            },
            terms,
            status: NativeSponsorPolicyStatus::Active,
            principal_id: "synthetic-owner".into(),
            approval_digest: "cd".repeat(32),
        }
    }
    fn database() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        // Structural-only synthetic parents preserve the real foreign-key graph.
        c.execute("INSERT INTO signer_enrollments VALUES('synthetic-enrollment','account-s','synthetic-agreement','sponsor','{}')",[]).unwrap();
        c.execute("INSERT INTO signer_accepted_manifests VALUES(?1,'synthetic-enrollment','synthetic-proposal','synthetic-digest','{}')",["ef".repeat(32)]).unwrap();
        c
    }
    #[test]
    fn sponsor_native_history_is_append_only_and_capacity_accounted() {
        let c = database();
        let initial = storage::capacity_estimate(&c).unwrap();
        let record = policy();
        insert_event(&c, &record).unwrap();
        let after = storage::capacity_estimate(&c).unwrap();
        assert_eq!(after.0, initial.0 + 1);
        assert!(after.1 > initial.1);
        assert!(
            c.execute("UPDATE signer_sponsor_policy_events SET version=2", [])
                .is_err()
        );
        assert!(
            c.execute("DELETE FROM signer_sponsor_policy_events", [])
                .is_err()
        );
        assert!(insert_event(&c, &record).is_err());
        assert!(
            read_current(&c, &record.binding.policy_key)
                .unwrap()
                .unwrap()
                == record
        );
    }
    #[test]
    fn sponsor_pause_revoke_and_version_changes_invalidate_frozen_manifest() {
        for status in [
            NativeSponsorPolicyStatus::Paused,
            NativeSponsorPolicyStatus::Revoked,
            NativeSponsorPolicyStatus::Active,
        ] {
            let c = database();
            let mut record = policy();
            insert_event(&c, &record).unwrap();
            let raw = encode(&record.binding).unwrap();
            c.execute(
                "INSERT INTO signer_sponsor_manifest_bindings VALUES(?1,?2,?3,?4)",
                params!["ef".repeat(32), record.binding.policy_key, 1, raw.as_str()],
            )
            .unwrap();
            assert!(
                current_for_manifest(&c, &"ef".repeat(32))
                    .unwrap()
                    .is_some()
            );
            record.binding.version = 2;
            record.status = status;
            insert_event(&c, &record).unwrap();
            assert!(matches!(
                current_for_manifest(&c, &"ef".repeat(32)),
                Err(JournalError::Permission)
            ));
        }
    }
    #[test]
    fn sponsor_expiry_and_weaker_shared_budget_fail_closed() {
        let mut record = policy();
        record.terms.expires_at = Some("2000-01-01T00:00:00Z".into());
        record.binding.terms_digest = terms_digest(&record.terms).unwrap();
        assert!(matches!(
            record.require_active(),
            Err(JournalError::Expired)
        ));
        record.terms.expires_at = None;
        record.binding.terms_digest = terms_digest(&record.terms).unwrap();
        record.witness.aggregate_budget_zatoshis = 51;
        assert!(matches!(
            record.validate(),
            Err(JournalError::BudgetExceeded)
        ));
    }
    #[test]
    fn sponsor_payload_version_and_key_substitution_are_rejected() {
        let c = database();
        let record = policy();
        let raw = encode(&record).unwrap();
        c.execute(
            "INSERT INTO signer_sponsor_policy_events VALUES(?1,?2,?3)",
            params![record.binding.policy_key, 2, raw.as_str()],
        )
        .unwrap();
        assert!(matches!(
            read_current(&c, &record.binding.policy_key),
            Err(JournalError::InvalidBinding)
        ));
    }
    #[test]
    fn sponsor_binding_and_attribution_storage_never_overwrite() {
        let c = database();
        let record = policy();
        insert_event(&c, &record).unwrap();
        let raw = encode(&record.binding).unwrap();
        let manifest = "ef".repeat(32);
        c.execute(
            "INSERT INTO signer_sponsor_manifest_bindings VALUES(?1,?2,?3,?4)",
            params![manifest, record.binding.policy_key, 1, raw.as_str()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO signer_sponsor_owner_attestations VALUES(?1,'{}')",
            [manifest],
        )
        .unwrap();
        for sql in [
            "UPDATE signer_sponsor_manifest_bindings SET version=2",
            "DELETE FROM signer_sponsor_manifest_bindings",
            "UPDATE signer_sponsor_owner_attestations SET payload='[]'",
            "DELETE FROM signer_sponsor_owner_attestations",
        ] {
            assert!(c.execute(sql, []).is_err());
        }
        assert_eq!(storage::capacity_estimate(&c).unwrap().0, 5);
    }
    struct SyntheticSponsorFixture {
        private_directory: crate::files::PrivateDirectory,
        _dir: tempfile::TempDir,
        journal: SignerConsentJournal,
        session: SignerConsentSession,
        manifest: AcceptedManifestRecord,
        terms: SpendConsentTerms,
        record: NativeSponsorPolicyRecord,
        attestation: StoredSponsorAttestation,
    }
    impl SyntheticSponsorFixture {
        fn new(include_attestation: bool) -> Self {
            use wholepact_core::sponsor::{
                SponsorAccountRestriction, SponsorBeneficiaryRestriction,
            };
            let dir = tempfile::tempdir().unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            let key = wholepact_storage_security::DatabaseKey::from_bytes([89; 32]);
            let private_directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
            let journal = SignerConsentJournal::create_encrypted(
                &dir.path().join("synthetic-sponsor"),
                &key,
                "account-alice",
                1,
                false,
                &private_directory
                    .signer_journal_source_owner_for_test(&dir.path().join("synthetic-sponsor"))
                    .unwrap(),
            )
            .unwrap();
            let session = authority::fixture::session(&journal, "synthetic-owner");
            let proposal =
                super::super::tests::proposal("agreement-a", "obligation-a", "proposal-a");
            let (enrollment, manifest) =
                super::super::tests::enroll(&journal, &session, &proposal, 1_000_000_000);
            let mut record = policy();
            let t = &mut record.terms;
            t.network_profile_id = proposal.manifest().agreement.network_profile_id.clone();
            t.agreement_scope = vec!["agreement-a".into()];
            t.sponsor = SponsorAccountRestriction {
                participant_id: "alice".into(),
                account_id: "account-alice".into(),
            };
            t.eligible_contributors = vec![SponsorAccountRestriction {
                participant_id: "bob".into(),
                account_id: "account-bob".into(),
            }];
            t.beneficiaries = proposal
                .manifest()
                .agreement
                .recipients
                .iter()
                .map(|r| SponsorBeneficiaryRestriction {
                    recipient_id: r.recipient_id.clone(),
                    address: r.address.clone(),
                    maximum_amount: r.amount,
                })
                .collect();
            t.maximum_match = wholepact_core::Amount::from_zatoshis(400_000_000).unwrap();
            t.fee_cap = wholepact_core::Amount::from_zatoshis(12_000).unwrap();
            t.maximum_net_debit = wholepact_core::Amount::from_zatoshis(400_012_000).unwrap();
            t.aggregate_budget = wholepact_core::Amount::from_zatoshis(1_000_000_000).unwrap();
            t.privacy_profile = proposal.manifest().agreement.privacy_profile.clone();
            record.witness.aggregate_budget_zatoshis = 1_000_000_000;
            record.binding.terms_digest = terms_digest(&record.terms).unwrap();
            record.binding.policy_key = record.binding.terms_digest.clone();
            wholepact_core::sponsor::evaluate_sponsor_policy(&record.terms, proposal.manifest())
                .unwrap();
            let attestation = StoredSponsorAttestation {
                assertion: SponsorOwnerAttestation {
                    manifest_digest: manifest.manifest_digest().into(),
                    policy_terms_digest: record.binding.terms_digest.clone(),
                    owners: vec![
                        SponsorOwnerBinding {
                            account_id: "account-alice".into(),
                            participant_id: "alice".into(),
                            fvk_digest: "11".repeat(32),
                        },
                        SponsorOwnerBinding {
                            account_id: "account-bob".into(),
                            participant_id: "bob".into(),
                            fvk_digest: "22".repeat(32),
                        },
                    ],
                },
                source: enrollment.transport().clone(),
                verifier_label: "synthetic-local-verifier".into(),
            };
            let mut terms =
                super::super::tests::terms(&session, &enrollment, &manifest, "authorization-a");
            terms.sponsor_policy = Some(record.binding.clone());
            terms.sponsor_owner_attestation_digest =
                Some(attestation_digest(&attestation).unwrap());
            // Fabricated isolated provenance is deliberately inserted only in tests.
            let c = journal.connection.lock().unwrap();
            insert_event(&c, &record).unwrap();
            c.execute(
                "INSERT INTO signer_sponsor_manifest_bindings VALUES(?1,?2,?3,?4)",
                params![
                    manifest.reference(),
                    record.binding.policy_key,
                    1,
                    encode(&record.binding).unwrap().as_str()
                ],
            )
            .unwrap();
            if include_attestation {
                c.execute(
                    "INSERT INTO signer_sponsor_owner_attestations VALUES(?1,?2)",
                    params![manifest.reference(), encode(&attestation).unwrap().as_str()],
                )
                .unwrap();
            }
            drop(c);
            Self {
                private_directory,
                _dir: dir,
                journal,
                session,
                manifest,
                terms,
                record,
                attestation,
            }
        }
    }
    #[test]
    fn sponsor_original_omission_foreign_source_and_attribution_digest_fail_closed() {
        let f = SyntheticSponsorFixture::new(true);
        let c = f.journal.connection.lock().unwrap();
        assert!(current_for_consent(&c, &f.terms).unwrap().is_some());
        let mut omitted = f.terms.clone();
        omitted.sponsor_policy = None;
        omitted.sponsor_owner_attestation_digest = None;
        assert!(matches!(
            current_for_consent(&c, &omitted),
            Err(JournalError::InvalidBinding)
        ));
        let mut substituted = f.terms.clone();
        substituted.sponsor_owner_attestation_digest = Some("99".repeat(32));
        assert!(matches!(
            current_for_consent(&c, &substituted),
            Err(JournalError::Permission)
        ));
        let mut foreign = f.terms.clone();
        if let TransportIdentityBinding::RemoteAuthenticatedKeys {
            transport_identity_id,
            ..
        } = &mut foreign.transport
        {
            *transport_identity_id = "another-synthetic-source".into();
        }
        assert!(matches!(
            current_for_consent(&c, &foreign),
            Err(JournalError::Permission)
        ));
        drop(c);
        let missing = SyntheticSponsorFixture::new(false);
        assert!(matches!(
            current_for_consent(&missing.journal.connection.lock().unwrap(), &missing.terms),
            Err(JournalError::Permission)
        ));
    }
    #[test]
    fn sponsor_full_roster_manifest_terms_and_duplicate_fvk_substitution_are_rejected() {
        let f = SyntheticSponsorFixture::new(true);
        validate_attestation(&f.attestation, &f.manifest, &f.record.binding).unwrap();
        for index in 0..6 {
            let mut changed = f.attestation.clone();
            match index {
                0 => changed.assertion.manifest_digest = "99".repeat(32),
                1 => changed.assertion.policy_terms_digest = "99".repeat(32),
                2 => {
                    changed.assertion.owners.pop();
                }
                3 => {
                    changed.assertion.owners[1].fvk_digest =
                        changed.assertion.owners[0].fvk_digest.clone()
                }
                4 => changed.assertion.owners[1].account_id = "account-intruder".into(),
                _ => changed.assertion.owners.reverse(),
            }
            assert!(validate_attestation(&changed, &f.manifest, &f.record.binding).is_err());
        }
    }
    #[test]
    fn sponsor_revocation_keeps_original_history_readable_but_denies_fresh_key_use() {
        let mut f = SyntheticSponsorFixture::new(true);
        f.journal
            .record_original_consent_release(authority::fixture::approve_spend(
                &f.session,
                f.terms.clone(),
            ))
            .unwrap();
        let lease = f
            .journal
            .acquire_original_authorization("authorization-a", &f.session)
            .unwrap();
        lease.require_current_spending_decision().unwrap();
        assert!(f.journal.authority_fence.try_write().is_err());
        drop(lease);
        f.record.binding.version += 1;
        f.record.status = NativeSponsorPolicyStatus::Revoked;
        {
            let _fence = f.journal.authority_fence.write().unwrap();
            insert_event(&f.journal.connection.lock().unwrap(), &f.record).unwrap();
        }
        let history = f
            .journal
            .acquire_original_authorization("authorization-a", &f.session)
            .unwrap();
        history.check_current().unwrap();
        assert!(matches!(
            history.require_current_spending_decision(),
            Err(JournalError::Permission)
        ));
        assert!(
            history.evidence().original_consent().terms().sponsor_policy == f.terms.sponsor_policy
        );
    }
    #[test]
    fn sponsor_populated_exact_backup_inventory_roundtrip_stays_quarantined() {
        use std::collections::{BTreeMap, BTreeSet};
        use wholepact_storage_security::{DatabaseKey, StorageSecurityError, bundle::*};
        let f = SyntheticSponsorFixture::new(true);
        let adapter = f.journal.backup_adapter();
        let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
        let coverage = Coverage {
            present: BTreeMap::from([(
                JournalKind::SignerConsentAuthority,
                vec!["signer-authority".into()],
            )]),
            absent: BTreeSet::from([
                JournalKind::CoordinationAuthority,
                JournalKind::WalletScan,
                JournalKind::ProofWitness,
                JournalKind::SignedResults,
                JournalKind::ExactTransactions,
                JournalKind::Submission,
                JournalKind::TransportInbox,
                JournalKind::TransportOutbox,
            ]),
        };
        let archive = f._dir.path().join("sponsor-backup");
        let restored = f._dir.path().join("sponsor-restored");
        let backup_key = DatabaseKey::from_bytes([90; 32]);
        let restored_key = DatabaseKey::from_bytes([91; 32]);
        let manifest = snapshot(SnapshotRequest {
            principal_id: "synthetic-owner",
            profile_id: "synthetic-signer-profile",
            coverage,
            sources: &sources,
            destination: &archive,
            key: &backup_key,
            authority: &super::super::tests::BackupGate,
        })
        .unwrap();
        let expected = storage::capacity_estimate(&f.journal.connection.lock().unwrap()).unwrap();
        assert_eq!(manifest.components[0].rows as u64, expected.0);
        assert_eq!(expected.0, 6); // Account, enrollment, manifest and three sponsor tables.
        let report = test_restore(RestoreRequest {
            principal_id: "synthetic-owner",
            profile_id: "synthetic-signer-profile",
            archive: &archive,
            key: &backup_key,
            targets: &[RestoreTarget {
                component_id: "signer-authority",
                template: SignerConsentBundleAdapter::template(),
                destination: &restored,
                key: &restored_key,
            }],
            authority: &super::super::tests::BackupGate,
        })
        .unwrap();
        assert!(!report.authorization_allowed);
        assert!(matches!(
            SignerConsentJournal::open_encrypted(
                &restored,
                &restored_key,
                "account-alice",
                &f.private_directory
                    .signer_journal_source_owner_for_test(&restored)
                    .unwrap()
            ),
            Err(JournalError::Storage(
                StorageSecurityError::QuarantinedDatabase
            ))
        ));
    }
    #[test]
    fn sponsor_new_manifest_omission_cannot_escape_enrolled_paused_or_revoked_scope() {
        for status in [
            NativeSponsorPolicyStatus::Active,
            NativeSponsorPolicyStatus::Paused,
            NativeSponsorPolicyStatus::Revoked,
        ] {
            let mut f = SyntheticSponsorFixture::new(true);
            if status != NativeSponsorPolicyStatus::Active {
                f.record.binding.version += 1;
                f.record.status = status;
                insert_event(&f.journal.connection.lock().unwrap(), &f.record).unwrap();
            }
            let enrollment = storage::read_enrollment(
                &f.journal.connection.lock().unwrap(),
                f.manifest.enrollment_ref(),
            )
            .unwrap()
            .unwrap();
            let proposal =
                super::super::tests::proposal("agreement-a", "obligation-new", "proposal-new");
            let prepared = f.session.prepare_manifest(&enrollment, &proposal).unwrap();
            let decision = authority::fixture::decision(&f.session, prepared.review_digest());
            let manifest = f
                .journal
                .record_accepted_manifest(f.session.approve_manifest(prepared, decision).unwrap())
                .unwrap();
            let terms =
                super::super::tests::terms(&f.session, &enrollment, &manifest, "authorization-new");
            assert!(terms.sponsor_policy.is_none());
            assert!(policy_required(&f.journal.connection.lock().unwrap(), &manifest).unwrap());
            assert!(matches!(
                current_for_consent(&f.journal.connection.lock().unwrap(), &terms),
                Err(JournalError::Permission)
            ));
            assert!(matches!(
                f.journal
                    .record_original_consent_release(authority::fixture::approve_spend(
                        &f.session, terms
                    )),
                Err(JournalError::Permission)
            ));
        }
    }
    #[test]
    fn sponsor_changed_terms_cannot_reenroll_a_new_key_to_escape_paused_or_revoked_scope() {
        for status in [
            NativeSponsorPolicyStatus::Active,
            NativeSponsorPolicyStatus::Paused,
            NativeSponsorPolicyStatus::Revoked,
        ] {
            let mut f = SyntheticSponsorFixture::new(true);
            f.record.binding.version += 1;
            f.record.status = status;
            insert_event(&f.journal.connection.lock().unwrap(), &f.record).unwrap();
            let mut replacement = f.record.clone();
            replacement.status = NativeSponsorPolicyStatus::Active;
            replacement.terms.minimum_qualifying_total =
                wholepact_core::Amount::from_zatoshis(2).unwrap();
            replacement.binding.terms_digest = terms_digest(&replacement.terms).unwrap();
            replacement.binding.policy_key = replacement.binding.terms_digest.clone();
            replacement.binding.version = 1;
            assert!(matches!(
                validate_scope_owner(&f.journal.connection.lock().unwrap(), &replacement),
                Err(JournalError::Conflict)
            ));
            replacement.binding.policy_key = f.record.binding.policy_key.clone();
            validate_scope_owner(&f.journal.connection.lock().unwrap(), &replacement).unwrap();
        }
    }
    #[cfg(all(
        feature = "native-ui",
        feature = "authority-signing",
        target_os = "linux"
    ))]
    #[test]
    fn sponsor_attestation_lease_is_bound_to_exact_journal_instance() {
        let first = SyntheticSponsorFixture::new(true);
        let second = SyntheticSponsorFixture::new(true);
        let lease = first
            .journal
            .acquire_preconstruction_records(
                first.manifest.enrollment_ref(),
                first.manifest.reference(),
                &first.session,
            )
            .unwrap();
        lease.require_journal(&first.journal.binding()).unwrap();
        assert!(matches!(
            lease.require_journal(&second.journal.binding()),
            Err(JournalError::Permission)
        ));
    }
}
