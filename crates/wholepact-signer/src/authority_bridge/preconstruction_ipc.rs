//! Native-consented dedicated viewing-key disclosure to the pinned local host.
//! Wire descriptors are claims. Only a live authenticated signer response makes
//! the opaque lease; it is not spending authority or a wallet observation.
use super::{BridgeError, Result, dispatch_ipc::write_frame, ipc::OriginalHistoryClient};
use orchard::keys::FullViewingKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    os::unix::net::UnixStream,
    sync::Mutex,
    time::{Duration, Instant},
};
use wholepact_core::Proposal;
use zeroize::Zeroize;

pub use wholepact_core::manual_construction::{
    PreconstructionBirthday, PreconstructionProvider, PreconstructionScope,
};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreconstructionRequest {
    pub scope: PreconstructionScope,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    /// Explicit native-reviewed disclosure of the sponsor's account-wide budget
    /// to this paired constructor, bound to these exact reusable constraints.
    #[serde(default)]
    pub sponsor_policy: Option<wholepact_core::sponsor::SponsorPolicyTerms>,
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl PreconstructionRequest {
    pub fn validate(&self) -> Result<Proposal> {
        if serde_json::to_vec(self)
            .map_err(|_| BridgeError::Binding)?
            .len()
            > 128 * 1024
        {
            return Err(BridgeError::Limit);
        }
        hash(&self.enrollment_ref)?;
        hash(&self.accepted_manifest_ref)?;
        let s = &self.scope;
        let proposal = s.validate().map_err(|_| BridgeError::Binding)?;
        if let Some(terms) = &self.sponsor_policy {
            if terms.sponsor.account_id != s.account_id
                || terms.sponsor.participant_id != s.participant_id
                || !terms.identity_requirements.is_empty()
                || !matches!(
                    terms.assurance,
                    wholepact_core::MatchAssurance::Attested { .. }
                )
            {
                return Err(BridgeError::Binding);
            }
            wholepact_core::sponsor::evaluate_sponsor_policy(terms, proposal.manifest())
                .map_err(|_| BridgeError::Verification)?;
        }
        Ok(proposal)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest("wholepact:preconstruction-disclosure:v1", self)
            .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PreconstructionResponse {
    Disclosed {
        lease_id: String,
        request_digest: String,
        account_fvk_hex: String,
        sponsor_budget: Option<Box<wholepact_authority::AccountSnapshot>>,
    },
    Current {
        lease_id: String,
    },
    SponsorAttestationRetained {
        lease_id: String,
        attestation_digest: String,
    },
    Finished,
    Denied,
}
impl Drop for PreconstructionResponse {
    fn drop(&mut self) {
        if let Self::Disclosed {
            account_fvk_hex, ..
        } = self
        {
            account_fvk_hex.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PreconstructionCommand {
    CheckCurrent,
    AttestSponsorOwners {
        attestation: crate::consent_journal::SponsorOwnerAttestation,
    },
    Finish,
}

/// Genuine FVK from the actual unlocked native account. No Deserialize, Clone,
/// from-wire or user-asserted constructor. Hold through construction/proof commit.
/// Expiry stops new use; it cannot revoke already disclosed viewing capability.
pub struct SignerPreconstructionLease<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    request: PreconstructionRequest,
    manifest_digest: String,
    fvk: FullViewingKey,
    started: Instant,
    sponsor_budget: Option<wholepact_authority::AccountSnapshot>,
    finished: bool,
}
impl OriginalHistoryClient {
    pub fn request_preconstruction(
        &self,
        request: &PreconstructionRequest,
    ) -> Result<SignerPreconstructionLease<'_>> {
        let proposal = request.validate()?;
        let stream = self.open_preconstruction_request(
            serde_json::json!({"operation":"request_preconstruction", "request":request}),
        )?;
        let frame =
            crate::ipc::read_frame_with_deadline(&stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let response: PreconstructionResponse =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        let PreconstructionResponse::Disclosed {
            lease_id,
            request_digest,
            account_fvk_hex,
            sponsor_budget,
        } = &response
        else {
            return Err(BridgeError::Permission);
        };
        hash(lease_id)?;
        if request_digest != &request.digest()? || account_fvk_hex.len() != 192 {
            return Err(BridgeError::Binding);
        }
        let bytes = zeroize::Zeroizing::new(
            hex::decode(account_fvk_hex).map_err(|_| BridgeError::Binding)?,
        );
        let raw = zeroize::Zeroizing::new(
            <[u8; 96]>::try_from(bytes.as_slice()).map_err(|_| BridgeError::Binding)?,
        );
        let fvk = FullViewingKey::from_bytes(&raw).ok_or(BridgeError::Verification)?;
        if sponsor_budget.is_some() != request.sponsor_policy.is_some()
            || sponsor_budget.as_ref().is_some_and(|b| {
                b.account_id != request.scope.account_id
                    || b.network_profile_id != proposal.manifest().agreement.network_profile_id
                    || b.remaining_budget_zatoshis().is_err()
            })
        {
            return Err(BridgeError::Binding);
        }
        let lease = SignerPreconstructionLease {
            client: self,
            stream: Mutex::new(stream),
            lease_id: lease_id.clone(),
            request: request.clone(),
            manifest_digest: proposal.manifest_digest().into(),
            fvk,
            started: Instant::now(),
            sponsor_budget: sponsor_budget.as_deref().cloned(),
            finished: false,
        };
        lease.check_current()?;
        Ok(lease)
    }
}
impl SignerPreconstructionLease<'_> {
    /// This named local verifier derives attribution only from actual live owner
    /// leases. The recipient signer treats it as explicitly trusted attestation,
    /// not independent protocol proof of legal identity or economic independence.
    pub fn attest_sponsor_accounts(
        &self,
        owners: &[SignerPreconstructionLease<'_>],
    ) -> Result<String> {
        use crate::consent_journal::{SponsorOwnerAttestation, SponsorOwnerBinding};
        use sha2::{Digest, Sha256};
        self.check_current()?;
        let terms = self.sponsor_policy().ok_or(BridgeError::Permission)?;
        if !matches!(
            terms.assurance,
            wholepact_core::MatchAssurance::Attested { .. }
        ) || owners.len() != self.scope().proposal.manifest.participants.len()
        {
            return Err(BridgeError::Binding);
        }
        let mut accounts = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut bindings = Vec::new();
        for owner in owners {
            owner.check_current()?;
            let scope = owner.scope();
            if scope.proposal != self.scope().proposal
                || scope.principal_id != self.scope().principal_id
                || !accounts.insert(scope.account_id.clone())
                || !keys.insert(owner.fvk().to_bytes())
                || !self.scope().proposal.manifest.participants.iter().any(|p| {
                    p.account_id == scope.account_id && p.participant_id == scope.participant_id
                })
            {
                return Err(BridgeError::Binding);
            }
            bindings.push(SponsorOwnerBinding {
                account_id: scope.account_id.clone(),
                participant_id: scope.participant_id.clone(),
                fvk_digest: hex::encode(Sha256::digest(owner.fvk().to_bytes())),
            });
        }
        bindings.sort_by(|a, b| a.account_id.cmp(&b.account_id));
        let attestation = SponsorOwnerAttestation {
            manifest_digest: self.manifest_digest().into(),
            policy_terms_digest: wholepact_core::proposal::canonical_digest(
                "wholepact:sponsor-policy-terms:v1",
                terms,
            )
            .map_err(|_| BridgeError::Binding)?,
            owners: bindings,
        };
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:sponsor-owner-attestation:v1",
            &attestation,
        )
        .map_err(|_| BridgeError::Binding)?;
        for owner in owners {
            owner.check_current()?;
        }
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        write_frame(
            &mut stream,
            &PreconstructionCommand::AttestSponsorOwners { attestation },
        )?;
        let frame = crate::ipc::read_frame_with_deadline(
            &stream,
            self.client.peer(),
            Duration::from_secs(5),
        )
        .map_err(|_| BridgeError::Ipc)?;
        match serde_json::from_slice::<PreconstructionResponse>(&frame)
            .map_err(|_| BridgeError::Ipc)?
        {
            PreconstructionResponse::SponsorAttestationRetained {
                ref lease_id,
                ref attestation_digest,
            } if lease_id == &self.lease_id && attestation_digest == &digest => Ok(digest),
            _ => Err(BridgeError::Permission),
        }
    }
    /// Read-only budget at the live lease's exact witness head. Never a permit.
    pub fn sponsor_budget(&self) -> Result<Option<&wholepact_authority::AccountSnapshot>> {
        self.check_current()?;
        Ok(self.sponsor_budget.as_ref())
    }
    pub fn sponsor_policy(&self) -> Option<&wholepact_core::sponsor::SponsorPolicyTerms> {
        self.request.sponsor_policy.as_ref()
    }
    /// Explicitly end this original disclosure and wait for the actual signer
    /// to acknowledge release of its retained journal read fence. This creates
    /// no replacement grant and retracts no data already disclosed. A failed or
    /// ambiguous finish is not permission to start a dependent native review.
    pub fn finish(mut self) -> Result<()> {
        self.client.peer().check_alive().map_err(|_| BridgeError::Permission)?;
        {
            let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
            write_frame(&mut stream, &PreconstructionCommand::Finish)?;
            let frame = crate::ipc::read_frame_with_deadline(
                &stream, self.client.peer(), Duration::from_secs(2),
            ).map_err(|_| BridgeError::Ipc)?;
            if !matches!(serde_json::from_slice::<PreconstructionResponse>(&frame)
                .map_err(|_| BridgeError::Binding)?, PreconstructionResponse::Finished)
            { return Err(BridgeError::Permission); }
        }
        self.finished = true;
        Ok(())
    }
    pub fn scope(&self) -> &PreconstructionScope {
        &self.request.scope
    }
    pub fn account_id(&self) -> &str {
        &self.request.scope.account_id
    }
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }
    pub fn check_current(&self) -> Result<()> {
        if self.started.elapsed() >= Duration::from_secs(900) {
            return Err(BridgeError::Permission);
        }
        self.client
            .peer()
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        write_frame(&mut stream, &PreconstructionCommand::CheckCurrent)?;
        let frame = crate::ipc::read_frame_with_deadline(
            &stream,
            self.client.peer(),
            Duration::from_secs(2),
        )
        .map_err(|_| BridgeError::Ipc)?;
        let response: PreconstructionResponse =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        match &response {
            PreconstructionResponse::Current { lease_id } if lease_id == &self.lease_id => Ok(()),
            _ => Err(BridgeError::Permission),
        }
    }
}
impl Drop for SignerPreconstructionLease<'_> {
    fn drop(&mut self) {
        if self.finished { return; }
        if let Ok(mut stream) = self.stream.lock() {
            let _ = write_frame(&mut stream, &PreconstructionCommand::Finish);
        }
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    fn request() -> PreconstructionRequest {
        let (accepted, _, _) = crate::manifest::tests::consent_fixture();
        let p = &accepted.proposal.manifest().participants[0];
        PreconstructionRequest {
            sponsor_policy: None,
            enrollment_ref: "11".repeat(32),
            accepted_manifest_ref: "22".repeat(32),
            scope: PreconstructionScope {
                schema_version: 1,
                proposal: accepted.proposal.input().clone(),
                account_id: p.account_id.clone(),
                participant_id: p.participant_id.clone(),
                profile_id: "synthetic-profile".into(),
                principal_id: "synthetic-owner".into(),
                operator_name: "synthetic-prover".into(),
                operator_destination: "/synthetic/proof.sqlite".into(),
                wallet_destination: "/synthetic/wallet.sqlite".into(),
                reviewer_account_ids: accepted
                    .proposal
                    .manifest()
                    .participants
                    .iter()
                    .map(|p| p.account_id.clone())
                    .collect(),
                privacy_domain: "synthetic-dedicated".into(),
                purpose: "construct_exact_accepted_candidate".into(),
                retention_policy: "Encrypted local retention; no erasure guarantee".into(),
                provider: PreconstructionProvider {
                    source_id: "synthetic-source".into(),
                    endpoint: "https://example.invalid:443".into(),
                    trust_profile: "single_tls_provider_report_not_consensus".into(),
                },
                minimum_confirmations: 10,
                maximum_blocks: 100,
                anchor_height: 1000,
                maximum_net_debit_zatoshis: p.maximum_net_debit.as_zatoshis(),
                birthday: PreconstructionBirthday {
                    prior_height: 900,
                    prior_block_hash: "33".repeat(32),
                    sapling_tree: String::new(),
                    orchard_tree: String::new(),
                    ironwood_tree: String::new(),
                },
            },
        }
    }
    fn sponsor_request() -> PreconstructionRequest {
        use wholepact_core::sponsor::*;
        let mut r = request();
        let m = &r.scope.proposal.manifest;
        let sponsor = &m.participants[0];
        let eligible_total =
            wholepact_core::Amount::checked_sum(m.participants[1..].iter().map(|p| p.contribution))
                .unwrap();
        r.sponsor_policy = Some(SponsorPolicyTerms {
            schema_version: 1,
            network_profile_id: m.agreement.network_profile_id.clone(),
            agreement_scope: vec![m.agreement.agreement_id.clone()],
            sponsor: SponsorAccountRestriction {
                participant_id: sponsor.participant_id.clone(),
                account_id: sponsor.account_id.clone(),
            },
            eligible_contributors: m.participants[1..]
                .iter()
                .map(|p| SponsorAccountRestriction {
                    participant_id: p.participant_id.clone(),
                    account_id: p.account_id.clone(),
                })
                .collect(),
            beneficiaries: m
                .agreement
                .recipients
                .iter()
                .map(|r| SponsorBeneficiaryRestriction {
                    recipient_id: r.recipient_id.clone(),
                    address: r.address.clone(),
                    maximum_amount: r.amount,
                })
                .collect(),
            rate_numerator: sponsor.contribution.as_zatoshis(),
            rate_denominator: eligible_total.as_zatoshis(),
            maximum_match: sponsor.contribution,
            minimum_qualifying_total: eligible_total,
            fee_cap: sponsor.fee_share,
            maximum_net_debit: sponsor.maximum_net_debit,
            aggregate_budget: sponsor.maximum_net_debit,
            assurance: wholepact_core::MatchAssurance::Attested {
                verifier_identity: "explicit-native-local-verifier".into(),
            },
            identity_requirements: vec![],
            privacy_profile: m.agreement.privacy_profile.clone(),
            expires_at: None,
        });
        r
    }
    #[test]
    fn sponsor_descriptor_only_supports_explicit_attested_exact_account_constraints() {
        let original = sponsor_request();
        assert!(original.validate().is_ok());
        for case in 0..4 {
            let mut r = original.clone();
            let terms = r.sponsor_policy.as_mut().unwrap();
            match case {
                0 => terms.assurance = wholepact_core::MatchAssurance::IndependentlyVerified,
                1 => terms
                    .identity_requirements
                    .push("Distinct legal organization".into()),
                2 => terms.sponsor.account_id = "substituted-account".into(),
                _ => terms.rate_denominator *= 2,
            }
            assert!(r.validate().is_err(), "case {case}");
        }
        let digest = original.digest().unwrap();
        let mut changed = original.clone();
        changed.sponsor_policy.as_mut().unwrap().assurance =
            wholepact_core::MatchAssurance::Attested {
                verifier_identity: "different-native-verifier".into(),
            };
        assert_ne!(changed.digest().unwrap(), digest);
    }
    #[test]
    fn bounded_descriptor_rejects_scope_substitution_and_unknown_approval() {
        let original = request();
        assert!(original.validate().is_ok());
        for case in 0..9 {
            let mut changed = original.clone();
            match case {
                0 => changed.scope.maximum_net_debit_zatoshis += 1,
                1 => changed
                    .scope
                    .reviewer_account_ids
                    .push(changed.scope.reviewer_account_ids[0].clone()),
                2 => changed.scope.reviewer_account_ids.clear(),
                3 => changed.scope.provider.endpoint = "http://example.invalid".into(),
                4 => changed.scope.operator_name = "substituted-prover".into(),
                5 => changed.scope.maximum_blocks = 1001,
                6 => changed.scope.wallet_destination = "relative-wallet".into(),
                7 => changed.scope.birthday.prior_height = changed.scope.anchor_height,
                _ => changed.scope.purpose = "any_future_construction".into(),
            }
            assert!(changed.validate().is_err(), "case {case}");
        }
        let mut json = serde_json::to_value(&original).unwrap();
        json["approved"] = true.into();
        assert!(serde_json::from_value::<PreconstructionRequest>(json).is_err());
    }
    #[test]
    fn all_retention_destinations_and_privacy_terms_are_digest_bound() {
        let original = request();
        let digest = original.digest().unwrap();
        for case in 0..6 {
            let mut changed = original.clone();
            match case {
                0 => changed.scope.wallet_destination = "/different/wallet.sqlite".into(),
                1 => changed.scope.operator_destination = "/different/proof.sqlite".into(),
                2 => changed.scope.retention_policy = "Different retention".into(),
                3 => changed.scope.privacy_domain = "different-domain".into(),
                4 => changed.scope.provider.source_id = "different-source".into(),
                _ => changed.scope.birthday.prior_block_hash = "44".repeat(32),
            }
            assert_ne!(changed.digest().unwrap(), digest);
        }
    }
}
