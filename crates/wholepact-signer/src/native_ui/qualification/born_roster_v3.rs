//! Synthetic-only controller delivery for two independent, never-funded births.
//!
//! This file is a child of `birth_workspace`, not an alternate authority factory.
//! Its callers must first enter each ceremony through the actual runtime entry
//! controller. The fixture supplies backup text and synthetic scroll/click events
//! to the existing private controller. It never constructs a native owner,
//! decision, birth anchor, witness commit, or authenticated history.
//!
//! The result is deliberately named PENDING. It is not acknowledged genesis,
//! roster enrollment, a witness read/handoff, or attended native qualification.

use super::*;
use std::time::{Duration, Instant};

pub(in crate::native_ui) const SYNTHETIC_PENDING_PASSWORD: &str =
    "PUBLIC-NEVER-FUNDED-BORN-ROSTER-QUALIFICATION";

/// Ordinary public inputs only. Both policy variants still pass the production
/// parser, backup verification, exact-review machine, and birth publication.
pub(in crate::native_ui) struct PublicFixtureBirthSetup {
    pub(in crate::native_ui) disclosure: WitnessDisclosureDescriptor,
    pub(in crate::native_ui) original_policy: AccountPolicy,
    pub(in crate::native_ui) stable_recipient_policy_json: Option<String>,
}

/// A private retained path plus public identity. No authority is returned.
pub(in crate::native_ui) struct ProducedPendingBirth {
    pub(in crate::native_ui) temporary: Arc<tempfile::TempDir>,
    pub(in crate::native_ui) root: PathBuf,
    pub(in crate::native_ui) identity: BirthIdentity,
    pub(in crate::native_ui) birth_digest: String,
}

struct DrainingBirthCeremony(NativeBirthCeremony);
impl std::ops::Deref for DrainingBirthCeremony {
    type Target = NativeBirthCeremony;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for DrainingBirthCeremony {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for DrainingBirthCeremony {
    fn drop(&mut self) {
        let phase = self.0.phase.take();
        self.0.clear();
        if let Some(Phase::Publishing(receive)) = phase {
            // Production exposes the terminal receiver, not a thread handle.
            // Drain through sender disconnection before fixture storage drops.
            while let Ok(outcome) = receive.recv() {
                drop(outcome);
            }
        }
    }
}

/// Finish exactly two separately entered native birth controllers. The setup
/// callback receives their actually generated identity, never a guessed FVK or
/// legacy account. It should bind the separately created ephemeral witness TLS
/// credentials and public policy. No witness contact occurs in this stage.
pub(in crate::native_ui) fn finish_two_pending_births(
    temporary: Arc<tempfile::TempDir>,
    ceremonies: [NativeBirthCeremony; 2],
    setup: impl FnMut(usize, &BirthIdentity) -> Result<PublicFixtureBirthSetup>,
) -> Result<[ProducedPendingBirth; 2]> {
    finish_pending_births(temporary, ceremonies, setup)
}

/// One unfunded first-account anchor plus the two independent roster accounts.
/// Every member passes the exact same production birth-controller sequence.
pub(in crate::native_ui) fn finish_three_pending_births(
    temporary: Arc<tempfile::TempDir>,
    ceremonies: [NativeBirthCeremony; 3],
    setup: impl FnMut(usize, &BirthIdentity) -> Result<PublicFixtureBirthSetup>,
) -> Result<[ProducedPendingBirth; 3]> {
    finish_pending_births(temporary, ceremonies, setup)
}
fn finish_pending_births<const N: usize>(
    temporary: Arc<tempfile::TempDir>,
    ceremonies: [NativeBirthCeremony; N],
    mut setup_for_identity: impl FnMut(usize, &BirthIdentity) -> Result<PublicFixtureBirthSetup>,
) -> Result<[ProducedPendingBirth; N]> {
    if N != 2 && N != 3 {
        return Err(Error::InvalidData);
    }
    let mut results = Vec::with_capacity(N);
    for (index, ceremony) in ceremonies.into_iter().enumerate() {
        let mut ceremony = DrainingBirthCeremony(ceremony);
        let owner = ceremony.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        let epoch = owner.focus_epoch();
        let (identity, words) = match ceremony.phase.as_ref() {
            Some(Phase::Backup {
                identity, words, ..
            }) => ((**identity).clone(), Zeroizing::new(words.to_string())),
            _ => return Err(Error::ReviewMismatch),
        };
        if ceremony.password.as_str() != SYNTHETIC_PENDING_PASSWORD {
            return Err(Error::ReviewMismatch);
        }
        let root = ceremony.root.clone();
        if !root.starts_with(temporary.path()) || root == temporary.path() {
            return Err(Error::ReviewMismatch);
        }
        let setup = setup_for_identity(index, &identity)?;
        ceremony.setup = Zeroizing::new(
            serde_json::to_string(&PublicBirthSetup {
                disclosure: setup.disclosure,
                original_policy: setup.original_policy,
            })
            .map_err(|_| Error::InvalidData)?,
        );
        ceremony.backup = words;
        if let Some(policy) = setup.stable_recipient_policy_json {
            ceremony.stable_recipient_policy = Zeroizing::new(policy);
            ceremony.derive_stable_recipient_scope(epoch)?;
        }
        ceremony.stage_backup_and_review(epoch)?;

        // The actual controller refuses an unread review. Synthetic scroll
        // completion below is explicitly not evidence of a human reading it.
        if ceremony.continue_review(true, epoch).is_ok() {
            return Err(Error::ReviewMismatch);
        }
        let digest = match ceremony.phase.as_mut() {
            Some(Phase::Review(review)) => {
                if review.review.display().is_empty() || review.review.confirming() {
                    return Err(Error::ReviewMismatch);
                }
                review.displayed_to_end = true;
                review.review.digest().to_owned()
            }
            _ => return Err(Error::ReviewMismatch),
        };
        if ceremony.continue_review(false, epoch).is_ok()
            || ceremony
                .continue_review(true, epoch.wrapping_add(1))
                .is_ok()
        {
            return Err(Error::ReviewMismatch);
        }
        ceremony.continue_review(true, epoch)?;
        ceremony.confirmation = Zeroizing::new(format!("AUTHORIZE {}", &digest[..12]));
        ceremony.publish_from_native_click(true, epoch)?;

        // Poll the genuine KDF/publication worker, without synthesizing output.
        let timeout = Instant::now() + Duration::from_secs(120);
        while !matches!(ceremony.phase, Some(Phase::Pending(_))) {
            if Instant::now() >= timeout {
                return Err(Error::Uncertain);
            }
            ceremony.poll(epoch)?;
            std::thread::sleep(Duration::from_millis(2));
        }
        let Some(Phase::Pending(pending)) = ceremony.phase.take() else {
            return Err(Error::ReviewMismatch);
        };
        if ceremony.owner.is_some() || pending.anchor().identity() != &identity {
            return Err(Error::ReviewMismatch);
        }
        let birth_digest = pending.anchor().birth_digest().to_owned();
        drop(pending);

        // The published pending envelope must stay denied to ordinary unlock.
        if AccountVault::unlock(&root, SYNTHETIC_PENDING_PASSWORD.as_bytes()).is_ok() {
            return Err(Error::ReviewMismatch);
        }
        let reopened = PendingBirthVault::reopen(&root, SYNTHETIC_PENDING_PASSWORD.as_bytes())?;
        if reopened.anchor().identity() != &identity
            || reopened.anchor().birth_digest() != birth_digest
        {
            return Err(Error::ReviewMismatch);
        }
        drop(reopened);
        results.push(ProducedPendingBirth {
            temporary: temporary.clone(),
            root,
            identity,
            birth_digest,
        });
    }
    let results: [ProducedPendingBirth; N] = results.try_into().map_err(|_| Error::InvalidData)?;
    for left in 0..N {
        for right in (left + 1)..N {
            if results[left].root == results[right].root
                || results[left].identity.account_id() == results[right].identity.account_id()
                || results[left].identity.full_viewing_key_digest()
                    == results[right].identity.full_viewing_key_digest()
                || results[left].birth_digest == results[right].birth_digest
            {
                return Err(Error::ReviewMismatch);
            }
        }
    }
    Ok(results)
}

#[test]
fn two_native_controller_pending_births_remain_unacknowledged_and_blocked() {
    use crate::native_ui::runtime::NativeRuntime;
    use std::time::{SystemTime, UNIX_EPOCH};
    let temporary = Arc::new(
        tempfile::Builder::new()
            .prefix("wholepact-synthetic-two-pending-births-")
            .tempdir()
            .unwrap(),
    );
    let left = NativeRuntime::entered_pending_birth_for_qualification(
        &temporary.path().join("owner-one"),
        "synthetic-never-funded-owner-one",
    )
    .unwrap();
    let right = NativeRuntime::entered_pending_birth_for_qualification(
        &temporary.path().join("owner-two"),
        "synthetic-never-funded-owner-two",
    )
    .unwrap();
    let expires = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
    .checked_add(600_000)
    .unwrap();
    let pair = finish_two_pending_births(temporary.clone(), [left, right], |index, identity| {
        // Public data-only origin pins. This test deliberately performs no TLS,
        // witness setup or acknowledgment; the longer composed fixture supplies
        // actual ephemeral P-256 certificate pins through this same callback.
        let policy = AccountPolicy {
            account_use_genesis: None,
            witness_id: format!("synthetic-uncontacted-witness-{index}"),
            account_id: identity.account_id().into(),
            network_profile_id: identity.network_profile_id().into(),
            owner_certificate_digest: "22".repeat(32),
            initial_writer_certificate_digest: "33".repeat(32),
            initial_writer_epoch: 1,
            enrollment_refs: vec!["44".repeat(32)],
            agreement_ids: vec!["synthetic-unfunded-agreement".into()],
            recipient_scope_digests: vec!["55".repeat(32)],
            aggregate_budget_zatoshis: 100,
            per_operation_limit_zatoshis: 90,
            maximum_fee_share_zatoshis: 5,
            maximum_transaction_fee_zatoshis: 10,
            maximum_permit_lifetime_ms: 60_000,
            policy_expires_at_ms: expires,
        };
        Ok(PublicFixtureBirthSetup {
            disclosure: WitnessDisclosureDescriptor {
                endpoint: "127.0.0.1:443".into(),
                server_name: "synthetic.invalid".into(),
                witness_id: policy.witness_id.clone(),
                account_id: policy.account_id.clone(),
                network_profile_id: policy.network_profile_id.clone(),
                policy_digest: policy.policy_digest().map_err(|_| Error::InvalidData)?,
                pinned_server_certificate_digest: "66".repeat(32),
            },
            original_policy: policy,
            stable_recipient_policy_json: None,
        })
    })
    .unwrap();
    for produced in pair {
        let pending = Arc::new(
            PendingBirthVault::reopen(&produced.root, SYNTHETIC_PENDING_PASSWORD.as_bytes())
                .unwrap(),
        );
        assert!(pending.retained_owner_request().unwrap().is_none());
        assert!(!produced.root.join("authority.sqlite").exists());
        assert!(!produced.root.join("birth-owner-request.wp").exists());
    }
}
