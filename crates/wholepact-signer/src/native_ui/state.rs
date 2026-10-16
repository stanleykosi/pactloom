//! Private state machine. No Deserialize, public constructor, callback trait,
//! IPC command, or exported application action can mint local consent.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use wholepact_core::{Proposal, ProposalInput};
use zeroize::{Zeroize, Zeroizing};

const REVIEW_LIFETIME: Duration = Duration::from_secs(120);
const MAX_MANIFEST: usize = 131_072;

/// This records the surface that handled a request, not OS/human attestation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SurfaceMode {
    NativePreview,
    SyntheticDemo,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Idle,
    Reading,
    Confirming,
    Accepted,
    Rejected,
}
/// Internal one-shot input. There is deliberately no public API or serde derive.
struct LocalClick {
    surface: [u8; 32],
    generation: u64,
    focus_epoch: u64,
    binding: [u8; 32],
}
struct Pending {
    proposal: Proposal,
    exact_text: Zeroizing<String>,
    binding: [u8; 32],
    account_id: String,
    client_id: String,
    created: Instant,
}
/// No signer/key/vault in this preview/demo state. It can acknowledge application
/// terms, never return an AcceptedManifest to a spending path.
pub(super) struct ReviewState {
    mode: SurfaceMode,
    surface: [u8; 32],
    generation: u64,
    focus_epoch: u64,
    focused: bool,
    phase: Phase,
    pending: Option<Pending>,
    receipt: Option<Receipt>,
}
#[derive(Clone)]
pub(super) struct Receipt {
    pub proposal_id: String,
    pub manifest_digest: String,
    pub exact_binding: String,
    pub account_id: String,
    pub client_id: String,
    pub demo: bool,
}
impl ReviewState {
    pub(super) fn new(mode: SurfaceMode) -> Result<Self> {
        Ok(Self {
            mode,
            surface: crate::vault::random()?,
            generation: 0,
            focus_epoch: 0,
            focused: false,
            phase: Phase::Idle,
            pending: None,
            receipt: None,
        })
    }
    pub(super) fn phase(&self) -> Phase {
        self.phase
    }
    pub(super) fn receipt(&self) -> Option<&Receipt> {
        self.receipt.as_ref()
    }
    pub(super) fn proposal(&self) -> Option<&Proposal> {
        self.pending.as_ref().map(|p| &p.proposal)
    }
    pub(super) fn exact_text(&self) -> Option<&str> {
        self.pending.as_ref().map(|p| p.exact_text.as_str())
    }
    pub(super) fn binding(&self) -> Option<String> {
        self.pending.as_ref().map(|p| hex::encode(p.binding))
    }
    pub(super) fn focused(&self) -> bool {
        self.focused
    }
    pub(super) fn observe_focus(&mut self, focused: bool) {
        if self.focused && !focused {
            self.invalidate();
            self.focus_epoch = self.focus_epoch.saturating_add(1);
        }
        self.focused = focused;
    }
    pub(super) fn expire(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.created.elapsed() > REVIEW_LIFETIME)
        {
            self.invalidate();
        }
    }
    pub(super) fn invalidate(&mut self) {
        self.pending = None;
        self.receipt = None;
        self.generation = self.generation.saturating_add(1);
        self.phase = Phase::Idle;
    }
    /// Only staging, no approval. Replacing a review invalidates all old events.
    pub(super) fn stage(&mut self, input: &[u8], account: &str, client: &str) -> Result<()> {
        self.invalidate();
        if input.len() > MAX_MANIFEST {
            return Err(Error::InvalidData);
        }
        crate::review::validate_label(account)?;
        crate::review::validate_label(client)?;
        let input: ProposalInput =
            wholepact_core::parse_typed_json(input).map_err(|_| Error::InvalidData)?;
        let proposal = Proposal::validate(input).map_err(|_| Error::Verification)?;
        if !proposal
            .manifest()
            .participants
            .iter()
            .any(|p| p.account_id == account)
        {
            return Err(Error::Verification);
        }
        let bytes = serde_json::to_vec(proposal.input()).map_err(|_| Error::InvalidData)?;
        let mut hash = Sha256::new();
        hash.update(b"wholepact:native-review-preview:v1\0");
        hash.update(self.surface);
        hash.update(self.generation.to_le_bytes());
        hash.update([matches!(self.mode, SurfaceMode::SyntheticDemo) as u8]);
        for field in [account.as_bytes(), client.as_bytes(), &bytes] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field);
        }
        let text =
            serde_json::to_string_pretty(proposal.input()).map_err(|_| Error::InvalidData)?;
        self.pending = Some(Pending {
            proposal,
            exact_text: Zeroizing::new(inert_text(&text)),
            binding: hash.finalize().into(),
            account_id: account.into(),
            client_id: client.into(),
            created: Instant::now(),
        });
        self.phase = Phase::Reading;
        Ok(())
    }
    /// Called only from a button event in the private native app implementation.
    /// The button that enters this phase is never the final confirmation button.
    pub(super) fn continue_from_local_click(&mut self) -> Result<()> {
        self.expire();
        if !self.focused || self.phase != Phase::Reading || self.pending.is_none() {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::Confirming;
        Ok(())
    }
    fn local_click(&self) -> Result<LocalClick> {
        if !self.focused || self.phase != Phase::Confirming {
            return Err(Error::ReviewMismatch);
        }
        Ok(LocalClick {
            surface: self.surface,
            generation: self.generation,
            focus_epoch: self.focus_epoch,
            binding: self.pending.as_ref().ok_or(Error::ReviewMismatch)?.binding,
        })
    }
    pub(super) fn confirm_from_local_click(
        &mut self,
        entered: &str,
        understood: bool,
    ) -> Result<()> {
        let click = self.local_click()?;
        self.consume(click, entered, understood)
    }
    fn consume(&mut self, click: LocalClick, entered: &str, understood: bool) -> Result<()> {
        self.expire();
        let pending = self.pending.as_ref().ok_or(Error::ReviewMismatch)?;
        if !self.focused
            || self.phase != Phase::Confirming
            || !understood
            || click.surface != self.surface
            || click.generation != self.generation
            || click.focus_epoch != self.focus_epoch
            || click.binding != pending.binding
            || entered != confirmation_phrase(pending.proposal.manifest_digest())
        {
            return Err(Error::ReviewMismatch);
        }
        // Revalidate the full immutable input immediately before acknowledgment.
        let validated = Proposal::validate(pending.proposal.input().clone())
            .map_err(|_| Error::Verification)?;
        if validated.manifest_digest() != pending.proposal.manifest_digest() {
            return Err(Error::ReviewMismatch);
        }
        self.receipt = Some(Receipt {
            proposal_id: pending.proposal.input().proposal_id.clone(),
            manifest_digest: pending.proposal.manifest_digest().into(),
            exact_binding: hex::encode(pending.binding),
            account_id: pending.account_id.clone(),
            client_id: pending.client_id.clone(),
            demo: self.mode == SurfaceMode::SyntheticDemo,
        });
        self.pending = None;
        self.generation = self.generation.saturating_add(1);
        self.phase = Phase::Accepted;
        Ok(())
    }
    pub(super) fn reject(&mut self) {
        self.invalidate();
        self.phase = Phase::Rejected;
    }
}
impl Drop for ReviewState {
    fn drop(&mut self) {
        self.surface.zeroize();
    }
}
pub(super) fn confirmation_phrase(digest: &str) -> String {
    format!("ACCEPT {}", &digest[..8])
}
/// Make bidi, control characters and untrusted unicode visibly inert. No markup,
/// URI handlers, embedded images or remote resource loading are used.
pub(super) fn inert_text(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\n' || c == ' ' || c.is_ascii_graphic() {
            safe.push(c);
        } else {
            safe.extend(c.escape_default());
        }
    }
    safe
}

pub(super) fn demo_manifest() -> Vec<u8> {
    // Explicitly fabricated application accounting, not PCZT/chain verification.
    include_bytes!("synthetic-proposal.json").to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready() -> ReviewState {
        let mut state = ReviewState::new(SurfaceMode::SyntheticDemo).unwrap();
        state.observe_focus(true);
        state
            .stage(&demo_manifest(), "account-alice", "synthetic-workspace")
            .unwrap();
        state.continue_from_local_click().unwrap();
        state
    }
    fn phrase(s: &ReviewState) -> String {
        confirmation_phrase(s.proposal().unwrap().manifest_digest())
    }
    #[test]
    fn two_distinct_clicks_exact_phrase_and_acknowledgment_required() {
        let mut s = ready();
        let correct = phrase(&s);
        assert!(s.confirm_from_local_click("wrong", true).is_err());
        assert!(s.confirm_from_local_click(&correct, false).is_err());
        s.confirm_from_local_click(&correct, true).unwrap();
        assert!(s.receipt().unwrap().demo);
        assert_eq!(s.phase(), Phase::Accepted);
        assert!(s.confirm_from_local_click(&correct, true).is_err());
    }
    #[test]
    fn stale_focus_lock_cancel_expiry_and_cross_surface_events_fail() {
        for reason in 0..5 {
            let mut s = ready();
            let event = s.local_click().unwrap();
            let correct = phrase(&s);
            match reason {
                0 => {
                    s.observe_focus(false);
                    s.observe_focus(true);
                }
                1 => s.invalidate(),
                2 => s.reject(),
                3 => {
                    s.pending.as_mut().unwrap().created = Instant::now() - Duration::from_secs(121);
                }
                _ => {
                    s = ready();
                }
            }
            assert!(s.consume(event, &correct, true).is_err());
        }
    }
    #[test]
    fn replaced_proposal_fields_or_client_cannot_reuse_consent() {
        // Every serialized field, including non-economic application text, is bound.
        for mutation in 0..7 {
            let mut s = ready();
            let event = s.local_click().unwrap();
            let old_binding = s.binding().unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&demo_manifest()).unwrap();
            match mutation {
                0 => value["manifest"]["agreement"]["revision"] = 2.into(),
                1 => {
                    value["manifest"]["agreement"]["recipients"][0]["address"] =
                        "usyntheticchangedreceiver".into();
                    value["manifest"]["outputs"][0]["address"] = "usyntheticchangedreceiver".into();
                }
                2 => {
                    value["manifest"]["agreement"]["recipients"][0]["memo"] = "changed memo".into()
                }
                3 => value["manifest"]["participants"][0]["fee_cap"] = "12001".into(),
                4 => value["effects_commitment"] = "77".repeat(32).into(),
                5 => {
                    value["manifest"]["agreement"]["purpose"] =
                        "changed disclosure statement".into()
                }
                _ => (),
            }
            let client = if mutation == 6 {
                "different-client"
            } else {
                "synthetic-workspace"
            };
            s.stage(
                &serde_json::to_vec(&value).unwrap(),
                "account-alice",
                client,
            )
            .unwrap();
            s.continue_from_local_click().unwrap();
            assert_ne!(old_binding, s.binding().unwrap());
            let current_phrase = phrase(&s);
            assert!(s.consume(event, &current_phrase, true).is_err());
        }
    }
    #[test]
    fn malformed_duplicate_oversized_and_wrong_account_inputs_fail_closed() {
        let mut s = ready();
        assert!(s
            .stage(&vec![b' '; MAX_MANIFEST + 1], "account-alice", "app")
            .is_err());
        assert!(s
            .stage(
                b"{\"proposal_id\":1,\"proposal_id\":2}",
                "account-alice",
                "app"
            )
            .is_err());
        assert!(s
            .stage(&demo_manifest(), "account-stranger", "app")
            .is_err());
        assert!(s.receipt().is_none());
        assert!(inert_text("evil\u{202e}\u{1b}<script>").contains("\\u{202e}"));
    }
}
