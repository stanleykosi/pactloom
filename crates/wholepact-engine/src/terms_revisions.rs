//! Bounded, local, pre-participation terms revision. This is not a replacement
//! protocol and never establishes or clears authorization exposure.
use super::*;

pub const MAX_TERMS_REVISIONS: usize = 64;
pub(super) fn is_false(value: &bool) -> bool {
    !*value
}
const CLOSED: &str = "Editing requires complete local draft-only history. Participation, sharing, candidates, native work, cancellation, or recovery closes this editing window; no safe replacement protocol is available.";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermsEditability {
    pub allowed: bool,
    pub reason: String,
}
impl TermsEditability {
    pub fn is_unavailable(&self) -> bool {
        !self.allowed && self.reason.is_empty()
    }
    fn denied(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
        }
    }
}

fn same_identity(old: &AgreementDraft, new: &AgreementDraft) -> bool {
    old.schema_version == new.schema_version
        && old.agreement_id == new.agreement_id
        && old.obligation_id == new.obligation_id
        && old.organizer_identity == new.organizer_identity
        && old.network_profile_id == new.network_profile_id
        && old.privacy_profile == new.privacy_profile
}

pub(super) fn validate_history(view: &AgreementView) -> Result<()> {
    if view.terms_history.len() >= MAX_TERMS_REVISIONS
        || view.agreement.revision as usize != view.terms_history.len() + 1
        || view.terms_history.iter().enumerate().any(|(i, terms)| {
            terms.revision as usize != i + 1
                || !same_identity(terms, &view.agreement)
                || terms.validate().is_err()
        })
    {
        return Err(ApiError::new(
            "RECOVERY_REQUIRED",
            "Stored terms revision history is incomplete or incompatible; preserve the journal",
        ));
    }
    Ok(())
}

fn local_draft_envelope(e: &Envelope) -> bool {
    let v = &e.view;
    e.terms_editing_origin
        && !v.cancellation_requested
        && v.intents.is_empty()
        && !v.roster_selected
        && v.candidates.is_empty()
        && e.intent_owners.is_empty()
        && e.sponsor_policies.is_empty()
        && e.participant_records.is_empty()
        && e.transport_peer_grants.is_empty()
        && e.checkpoint_receipts.is_empty()
        && e.native_requests.is_empty()
        && e.native_proof_requests.is_empty()
        && e.native_proof_execution_requests.is_empty()
        && e.native_artifact_handoff_requests.is_empty()
        && e.native_settlement_requests.is_empty()
        && e.native_dispatch_requests.is_empty()
        && e.native_reconciliation_requests.is_empty()
        && matches!(
            v.progress.as_str(),
            "gathering_intent" | "preparing_proposal"
        )
        && v.proposals.iter().all(|p| {
            p.status == "terms_only_not_signable"
                && p.artifact_digest.is_none()
                && p.effects_commitment.is_none()
                && p.manifest["scope"] == "unverified_nonbinding_terms"
                && p.manifest["intents"].as_array().is_some_and(Vec::is_empty)
                && p.manifest["roster_selected"] == false
        })
        && v.verification_reports.iter().all(|r| {
            r.status == "unsupported"
                && r.artifact_digest.is_none()
                && r.effects_commitment.is_none()
                && r.review_summary["signable"] == false
        })
}

impl Engine {
    fn editability(&self, principal: &str, e: &Envelope) -> Result<TermsEditability> {
        if principal != e.owner_client_id {
            return Ok(TermsEditability::denied(
                "Only the creating application can revise these local terms.",
            ));
        }
        if self
            .require_current_agreement(&e.view.agreement.agreement_id)
            .is_err()
        {
            return Ok(TermsEditability::denied(
                "Recovered or historical agreements remain read-only; fresh terms editing requires an unfenced local draft.",
            ));
        }
        if e.view.terms_history.len() + 1 >= MAX_TERMS_REVISIONS {
            return Ok(TermsEditability::denied(
                "The bounded terms revision history is full.",
            ));
        }
        if !local_draft_envelope(e)
            || !self
                .store
                .agreement_has_local_draft_history(
                    &e.view.agreement.agreement_id,
                    e.view.revision,
                    &e.owner_client_id,
                    &e.view.agreement.obligation_id,
                )
                .map_err(store_error)?
        {
            return Ok(TermsEditability::denied(CLOSED));
        }
        Ok(TermsEditability { allowed: true, reason: "Local pre-participation terms only. Every revision requires fresh review; exposure remains unknown.".into() })
    }

    pub(super) fn present_terms_editability(
        &self,
        principal: &str,
        mut e: Envelope,
    ) -> Result<AgreementView> {
        crate::private_workspace_origin_v1::refuse_public_payload(&encode(&e)?)?;
        // Returning terms to a second principal is a disclosure boundary too.
        // Close the local editing window before any such snapshot escapes.
        if principal != e.owner_client_id
            && local_draft_envelope(&e)
            && !self
                .store
                .runtime_recovery_required()
                .map_err(store_error)?
            && !self
                .store
                .recovery_record_is_historical("agreement", &e.view.agreement.agreement_id)
                .map_err(store_error)?
        {
            let access = Access {
                principal_id: principal.into(),
                ..Default::default()
            };
            let id = e.view.agreement.agreement_id.clone();
            let revision = e.view.revision;
            let key = hash_domain(
                b"wholepact:terms-read-closure:v1\0",
                &json!({"id":id,"revision":revision,"principal":principal}),
            )?;
            let command = context(
                &access,
                &key,
                "close_terms_before_shared_read",
                &id,
                Some(revision),
                &json!({}),
            )?;
            e.terms_editing_origin = false;
            e.view.revision = revision.checked_add(1).ok_or_else(internal)?;
            e.view.updated_at = now();
            let closed = self
                .store
                .update_agreement(
                    &command,
                    &id,
                    revision,
                    encode(&e)?,
                    "terms_editing_closed_before_shared_read",
                )
                .map_err(store_error)?;
            e = decode(&closed.record)?;
        }
        e.view.terms_editability = self.editability(principal, &e)?;
        Ok(e.view)
    }
    pub(super) fn present_mutation(
        &self,
        principal: &str,
        result: MutationResult,
    ) -> Result<Mutation> {
        let e = decode(&result.record)?;
        Ok(Mutation {
            agreement: self.present_terms_editability(principal, e)?,
            operation_id: result.operation_id,
            event_sequence: result.event_sequence,
            replayed: result.replayed,
        })
    }

    /// The supplied terms revision must be current+1; `revision` is the exact
    /// journal CAS revision, which also advances on previews and reviews.
    pub fn revise_agreement(
        &self,
        access: &Access,
        key: &str,
        id: &str,
        revision: u64,
        draft: AgreementDraft,
    ) -> Result<Mutation> {
        let command = context(
            access,
            key,
            "revise_agreement_terms",
            id,
            Some(revision),
            &draft,
        )?;
        // A restored journal may expose old receipts for historical reading,
        // but this mutating endpoint must never reopen a recovered edit flow.
        self.load(access, id)?;
        self.require_current_agreement(id)?;
        // Same-key retries recover the original durable result before current
        // lifecycle/CAS checks. They never replay a new write or transfer review.
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        let result = (|| {
            let mut e = self.load(access, id)?;
            planning::check_proposer(&e, access)?;
            candidates::check_revision(&e, revision)?;
            self.require_current_agreement(id)?;
            let editability = self.editability(&access.principal_id, &e)?;
            if !editability.allowed {
                candidates::check_revision(&self.load(access, id)?, revision)?;
                return Err(ApiError::new("INVALID_TRANSITION", &editability.reason));
            }
            draft.validate()?;
            check_profile(&draft)?;
            if !same_identity(&e.view.agreement, &draft) || draft.agreement_id != id {
                return Err(ApiError::new(
                    "INVALID_TERMS",
                    "Agreement, obligation, organizer, schema, network and privacy identity must remain unchanged",
                ));
            }
            if e.view.agreement.revision.checked_add(1) != Some(draft.revision) {
                return Err(ApiError::new(
                    "REVISION_CONFLICT",
                    "Terms revision must be exactly one after the reviewed current terms; refresh and review again",
                ));
            }
            let mut unchanged = draft.clone();
            unchanged.revision = e.view.agreement.revision;
            if unchanged == e.view.agreement {
                return Err(ApiError::new(
                    "INVALID_TERMS",
                    "No terms changed; a new terms revision was not created",
                ));
            }
            e.view.terms_history.push(e.view.agreement.clone());
            e.view.agreement = draft;
            // Prior proposal/review snapshots remain immutable and refer only to
            // their old terms. Never copy approval or reset exposure fields.
            e.view.progress = "gathering_intent".into();
            self.commit(&command, id, revision, e, "agreement_terms_revised")
        })();
        if result.is_err() {
            // Another copy of this same command may commit between the initial
            // replay lookup and an advisory lifecycle/CAS read. Recover its
            // original receipt rather than treating that successful duplicate
            // as a new stale command. The store repeats replay under its lock.
            if let Some(replay) = self.replay(access, &command)? {
                return Ok(replay);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_shared_read_snapshot_never_escapes_without_durable_closure() {
        let e = Engine::in_memory().unwrap();
        let owner = Access {
            principal_id: "owner".into(),
            include_owned_agreements: true,
            ..Default::default()
        };
        let original: AgreementDraft = serde_json::from_str(include_str!(
            "../../wholepact-core/tests/fixtures/agreement.json"
        ))
        .unwrap();
        let id = original.agreement_id.clone();
        e.create(&owner, "synthetic-origin-create", original.clone())
            .unwrap();
        let stale = e.load(&owner, &id).unwrap();
        let mut next = original;
        next.revision = 2;
        next.purpose = "Current synthetic terms".into();
        e.revise_agreement(&owner, "synthetic-owner-revision", &id, 1, next.clone())
            .unwrap();
        assert_eq!(
            e.present_terms_editability("other", stale)
                .unwrap_err()
                .code,
            "REVISION_CONFLICT"
        );
        let current = e.get(&owner, &id).unwrap();
        assert!(current.terms_editability.allowed);
        assert_eq!(current.agreement, next);
        let reader = Access {
            principal_id: "other".into(),
            agreement_ids: [id.clone()].into(),
            ..Default::default()
        };
        let shared = e.get(&reader, &id).unwrap();
        assert_eq!(shared.revision, 3);
        assert!(!shared.terms_editability.allowed);
        assert!(!e.get(&owner, &id).unwrap().terms_editability.allowed);
    }
}
