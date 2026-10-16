//! Disabled native composition. No runtime command, issuer or key-use adapter.
//! This consumes opaque bridge evidence, never a caller's verified/approved flag.
//! The candidate importer remains unavailable pending minimal-profile qualification.
#![allow(dead_code)]
use super::{NativeAuthority, NativeAuthorityBinding, authority::ExactNativeReview};
use crate::{Error, Result, account::AccountVault};
use std::time::{Duration, Instant};
use wholepact_authority::offline::{
    OfflineAuthorizationTerms, OfflineReservationIntent, OfflineSnapshotCommitment,
    OfflineUnknownFact,
};
use wholepact_offline_bridge::{OfflineReviewInspection, OfflineWitnessAdmissionEvidence};

const REVIEW_LIFETIME: Duration = Duration::from_secs(120);

/// Holds the actual unlocked account throughout local review. Account IDs in a
/// file never select or establish ownership of this vault.
struct AccountBinding<'a> {
    vault: &'a AccountVault,
    source: NativeAuthorityBinding,
    account_id: String,
}
impl<'a> AccountBinding<'a> {
    fn new(
        vault: &'a AccountVault,
        authority: &NativeAuthority,
        terms: &OfflineAuthorizationTerms,
    ) -> Result<Self> {
        authority.check_current()?;
        terms.validate().map_err(|_| Error::ReviewMismatch)?;
        if vault.account().recovery_required() || vault.account_id()? != terms.account_id {
            return Err(Error::ReviewMismatch);
        }
        Ok(Self {
            vault,
            source: authority.binding(),
            account_id: terms.account_id.clone(),
        })
    }
    fn check(&self) -> Result<()> {
        self.source.check_current()?;
        if self.vault.account().recovery_required() || self.vault.account_id()? != self.account_id {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}

fn unknown_facts(terms: &OfflineAuthorizationTerms) -> Result<String> {
    terms.validate().map_err(|_| Error::ReviewMismatch)?;
    Ok(unknown_facts_text())
}

fn unknown_facts_text() -> String {
    // Fixed text is derived from the complete required enum set. A sender cannot
    // omit unknowns or replace them with remotely supplied reassuring labels.
    let mut text = String::from("Facts unavailable while disconnected:\n");
    for fact in OfflineUnknownFact::ALL {
        text.push_str(match fact {
            OfflineUnknownFact::CurrentChainTip => "- Current chain tip is unknown.\n",
            OfflineUnknownFact::CurrentInputSpendability => {
                "- Current input spendability is unknown.\n"
            }
            OfflineUnknownFact::MempoolConflicts => "- Mempool conflicts are unknown.\n",
            OfflineUnknownFact::SubsequentReorganization => {
                "- Reorganizations after the snapshot are unknown.\n"
            }
            OfflineUnknownFact::CurrentRemotePolicyAndRevocation => {
                "- Current remote policy and revocation are unknown.\n"
            }
            OfflineUnknownFact::GlobalSingleKeyInvocation => {
                "- Global single key invocation cannot be guaranteed across cloned software.\n"
            }
        });
    }
    text.push_str("Previously admitted exact exposure remains reserved after pause/revoke. A disconnected copy may still sign the same exact effects. Local refusal does not cancel witness exposure or prove that no signature exists. Online current validation is required before submission; this review cannot establish settlement.\n");
    text
}

fn snapshot_display(snapshot: &OfflineSnapshotCommitment, local_wall_clock_ms: u64) -> String {
    let age = match local_wall_clock_ms.checked_sub(snapshot.observed_at_ms) {
        Some(ms) => format!("{ms} ms using this device's untrusted wall clock"),
        None => "unknown: snapshot timestamp is ahead of this device's wall clock".into(),
    };
    format!(
        "Authenticated snapshot source: {}\nSource identity: {}\nSource policy: {}\nSnapshot digest: {}\nObserved timestamp (source claim): {} ms\nDisplayed age: {}\nSnapshot tip: {} / {}\nAnchor: {} / {} / {}\nTimestamps and authenticated provenance do not prove current chain truth.\n",
        snapshot.source_id,
        snapshot.source_identity_digest,
        snapshot.source_policy_digest,
        snapshot.snapshot_digest,
        snapshot.observed_at_ms,
        age,
        snapshot.tip_height,
        snapshot.tip_hash,
        snapshot.anchor_height,
        snapshot.anchor_hash,
        snapshot.anchor_root
    )
}

fn wall_clock_ms() -> Result<u64> {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidData)?
        .as_millis();
    u64::try_from(ms).map_err(|_| Error::InvalidData)
}

/// First decision only requests exact durable reservation. It is never final
/// signature consent, a released authorization, or proof that a witness admitted.
pub(super) struct PreparedOfflineReservation<'a> {
    account: AccountBinding<'a>,
    inspection: OfflineReviewInspection,
    intent_id: String,
    review: ExactNativeReview,
}
pub(super) struct ApprovedOfflineReservationIntent {
    intent: OfflineReservationIntent,
}
impl ApprovedOfflineReservationIntent {
    pub(super) fn intent(&self) -> &OfflineReservationIntent {
        &self.intent
    }
}
impl<'a> PreparedOfflineReservation<'a> {
    pub(super) fn prepare(
        vault: &'a AccountVault,
        authority: &NativeAuthority,
        inspection: OfflineReviewInspection,
        intent_id: String,
        focus_epoch: u64,
    ) -> Result<Self> {
        crate::review::validate_label(&intent_id)?;
        inspection.recheck().map_err(|_| Error::Verification)?;
        let terms = inspection.terms();
        let account = AccountBinding::new(vault, authority, terms)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-offline-reservation-review:v1",
            &(
                &intent_id,
                terms,
                inspection.package_digest(),
                authority.principal_id(),
                authority.measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "REQUEST EXACT OFFLINE RESERVATION\nThis is a request to reserve account-wide exposure. It is not final permission to sign. A witness rejection creates no authority.\n{}\n{}\n{}\nExact review: {}",
            inspection.display(),
            snapshot_display(&terms.snapshot, wall_clock_ms()?),
            unknown_facts(terms)?,
            digest
        );
        let review = ExactNativeReview::stage(authority, &digest, display, focus_epoch)?;
        Ok(Self {
            account,
            inspection,
            intent_id,
            review,
        })
    }
    pub(super) fn display(&self) -> &str {
        self.review.display()
    }
    pub(super) fn digest(&self) -> &str {
        self.review.digest()
    }
    pub(super) fn continue_from_native_click(&mut self, focused: bool, epoch: u64) -> Result<()> {
        self.account.check()?;
        self.inspection.recheck().map_err(|_| Error::Verification)?;
        self.review.continue_from_native_click(focused, epoch)
    }
    pub(super) fn confirm_from_native_click(
        self,
        focused: bool,
        epoch: u64,
        phrase: &str,
    ) -> Result<ApprovedOfflineReservationIntent> {
        self.account.check()?;
        self.inspection.recheck().map_err(|_| Error::Verification)?;
        let decision = self.review.consume_native_click(focused, epoch, phrase)?;
        if decision.binding() != &self.account.source {
            return Err(Error::ReviewMismatch);
        }
        let intent = OfflineReservationIntent {
            schema_version: 1,
            intent_id: self.intent_id,
            terms: self.inspection.terms().clone(),
            native_reservation_review_digest: decision.reviewed_digest().into(),
        };
        intent.validate().map_err(|_| Error::ReviewMismatch)?;
        Ok(ApprovedOfflineReservationIntent { intent })
    }
}

/// Second independent decision consumes authenticated witness evidence plus a
/// newly independently checked candidate. Returning this object does not use keys.
pub(super) struct PreparedOfflineFinalConsent<'a> {
    account: AccountBinding<'a>,
    inspection: OfflineReviewInspection,
    admission: OfflineWitnessAdmissionEvidence,
    review: ExactNativeReview,
    created: Instant,
}
pub(super) struct ApprovedOfflineFinalConsent<'a> {
    account: AccountBinding<'a>,
    inspection: OfflineReviewInspection,
    admission: OfflineWitnessAdmissionEvidence,
    native_review_digest: String,
    created: Instant,
}
impl<'a> PreparedOfflineFinalConsent<'a> {
    pub(super) fn prepare(
        vault: &'a AccountVault,
        authority: &NativeAuthority,
        inspection: OfflineReviewInspection,
        admission: OfflineWitnessAdmissionEvidence,
        focus_epoch: u64,
    ) -> Result<Self> {
        let created = Instant::now();
        inspection.recheck().map_err(|_| Error::Verification)?;
        admission.recheck().map_err(|_| Error::ReviewMismatch)?;
        let terms = inspection.terms();
        let account = AccountBinding::new(vault, authority, terms)?;
        if admission.intent().terms != *terms
            || admission.package_digest() != inspection.package_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-offline-final-consent:v1",
            &(
                terms,
                admission.intent_digest(),
                admission.admission_digest(),
                admission.witness_id(),
                admission.committed_head(),
                authority.principal_id(),
                authority.measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "FINAL EXACT OFFLINE SIGNING CONSENT\nWitness: {}\nAdmission evidence: {}\nIntent: {}\n{}\n{}\n{}\nApproval covers only these exact effects. No current freshness, successful submission or settlement is implied.\nExact review: {}",
            admission.witness_id(),
            admission.admission_digest(),
            admission.intent_digest(),
            inspection.display(),
            snapshot_display(&terms.snapshot, wall_clock_ms()?),
            unknown_facts(terms)?,
            digest
        );
        let review = ExactNativeReview::stage(authority, &digest, display, focus_epoch)?;
        Ok(Self {
            account,
            inspection,
            admission,
            review,
            created,
        })
    }
    pub(super) fn display(&self) -> &str {
        self.review.display()
    }
    pub(super) fn digest(&self) -> &str {
        self.review.digest()
    }
    pub(super) fn continue_from_native_click(&mut self, focused: bool, epoch: u64) -> Result<()> {
        self.account.check()?;
        self.inspection.recheck().map_err(|_| Error::Verification)?;
        self.admission
            .recheck()
            .map_err(|_| Error::ReviewMismatch)?;
        self.review.continue_from_native_click(focused, epoch)
    }
    pub(super) fn confirm_from_native_click(
        self,
        focused: bool,
        epoch: u64,
        phrase: &str,
    ) -> Result<ApprovedOfflineFinalConsent<'a>> {
        if self.created.elapsed() >= REVIEW_LIFETIME {
            return Err(Error::ReviewMismatch);
        }
        self.admission
            .recheck()
            .map_err(|_| Error::ReviewMismatch)?;
        self.account.check()?;
        self.inspection.recheck().map_err(|_| Error::Verification)?;
        self.admission
            .recheck()
            .map_err(|_| Error::ReviewMismatch)?;
        let decision = self.review.consume_native_click(focused, epoch, phrase)?;
        if decision.binding() != &self.account.source {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedOfflineFinalConsent {
            account: self.account,
            inspection: self.inspection,
            admission: self.admission,
            native_review_digest: decision.reviewed_digest().into(),
            created: self.created,
        })
    }
}
impl ApprovedOfflineFinalConsent<'_> {
    /// Future journal transaction must retain this original lifetime and acquire
    /// source.publication_lease through commit. It must not deserialize this type.
    fn check_current(&self) -> Result<()> {
        self.account.check()?;
        self.admission
            .recheck()
            .map_err(|_| Error::ReviewMismatch)?;
        if self.created.elapsed() >= REVIEW_LIFETIME {
            return Err(Error::ReviewMismatch);
        }
        self.inspection.recheck().map_err(|_| Error::Verification)?;
        self.admission
            .recheck()
            .map_err(|_| Error::ReviewMismatch)?;
        self.account.check()?;
        if self.created.elapsed() >= REVIEW_LIFETIME {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> OfflineSnapshotCommitment {
        OfflineSnapshotCommitment {
            source_id: "synthetic-source".into(),
            source_identity_digest: "11".repeat(32),
            source_policy_digest: "12".repeat(32),
            snapshot_digest: "13".repeat(32),
            observed_at_ms: 2_000,
            tip_height: 20,
            tip_hash: "14".repeat(32),
            anchor_height: 19,
            anchor_hash: "15".repeat(32),
            anchor_root: "16".repeat(32),
        }
    }
    #[test]
    fn all_six_unknowns_and_retained_exposure_are_always_visible() {
        let display = unknown_facts_text();
        assert_eq!(
            display
                .lines()
                .filter(|line| line.starts_with("- "))
                .count(),
            6
        );
        for required in [
            "Current chain tip",
            "Current input spendability",
            "Mempool conflicts",
            "Reorganizations",
            "Current remote policy",
            "Global single key invocation",
            "remains reserved after pause/revoke",
            "does not cancel witness exposure",
            "Online current validation is required",
        ] {
            assert!(
                display.contains(required),
                "missing fixed warning: {required}"
            );
        }
    }
    #[test]
    fn snapshot_future_clock_never_becomes_zero_age_or_freshness() {
        let display = snapshot_display(&snapshot(), 1_000);
        assert!(display.contains("unknown: snapshot timestamp is ahead"));
        assert!(display.contains("do not prove current chain truth"));
    }
    #[test]
    fn snapshot_age_keeps_untrusted_clock_and_original_provenance() {
        let s = snapshot();
        let display = snapshot_display(&s, 4_500);
        assert!(display.contains("2500 ms using this device's untrusted wall clock"));
        assert!(display.contains(&s.source_identity_digest));
        assert!(display.contains(&s.snapshot_digest));
        assert!(display.contains("Observed timestamp (source claim): 2000 ms"));
    }
}

mod named_verifier;
