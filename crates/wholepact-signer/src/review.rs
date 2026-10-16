//! Generic signer-side review source. Human approval is deliberately separate
//! from app IPC. Incomplete chain/input/journal qualification still blocks release.
use crate::{
    account::DedicatedAccount,
    manifest::{reconcile, AcceptedManifest, ReviewInputs},
    Error, Result,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use wholepact_protocol::review::{verify_review, OutputPurpose, ReviewPolicy};
use zeroize::Zeroizing;

pub struct ReviewContext {
    pub agreement_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub client_id: String,
    pub writer_epoch: u64,
    pub disclosure_recipients: Vec<String>,
    pub disclosure_purpose: String,
    pub retention_policy: String,
}
/// Holds independently verified bytes and a local human-readable review. It has
/// no Deserialize/Clone and cannot be constructed from a JSON success flag.
pub struct PreparedReview {
    pczt: Zeroizing<Vec<u8>>,
    policy: ReviewPolicy,
    context: ReviewContext,
    account_id: String,
    protocol_binding: String,
    challenge: String,
    consent_digest: String,
    display: String,
    created: Instant,
}
/// Only internal review surfaces can produce one. A controlling terminal may be app-owned,
/// so this is not independently authenticated evidence of a human. It also does not establish
/// chain freshness, input spendability, grant authority or a qualified journal.
pub struct HumanApprovedReview {
    review: PreparedReview,
}
impl PreparedReview {
    pub fn verify(
        bytes: &[u8],
        inputs: ReviewInputs,
        accepted: AcceptedManifest,
        account: &DedicatedAccount,
        context: ReviewContext,
    ) -> Result<Self> {
        for id in [
            &context.agreement_id,
            &context.obligation_id,
            &context.proposal_id,
            &context.client_id,
        ] {
            validate_label(id)?;
        }
        if context.writer_epoch == 0 || context.disclosure_recipients.len() > 33 {
            return Err(Error::InvalidData);
        }
        validate_disclosure_labels(&context.disclosure_recipients)?;
        for text in [&context.disclosure_purpose, &context.retention_policy] {
            if text.is_empty()
                || text.len() > 512
                || !text.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            {
                return Err(Error::InvalidData);
            }
        }
        if account.recovery_required() {
            return Err(Error::RecoveryRequired);
        }
        let own_fvk = account.fvk()?;
        let account_id = account.account_id()?;
        reconcile(&accepted, &inputs, &account_id, &own_fvk)?;
        let manifest = accepted.proposal.manifest();
        if context.agreement_id != manifest.agreement.agreement_id
            || context.obligation_id != manifest.agreement.obligation_id
            || context.proposal_id != accepted.proposal.input().proposal_id
            || !manifest
                .agreement
                .privacy_profile
                .dedicated_accounts_required
        {
            return Err(Error::Verification);
        }
        let mut expected_disclosures: Vec<String> = manifest
            .agreement
            .privacy_profile
            .proving_operator
            .iter()
            .map(|p| format!("operator:{p}"))
            .chain(
                manifest
                    .participants
                    .iter()
                    .map(|p| format!("reviewer:{}", p.account_id)),
            )
            .collect();
        expected_disclosures.sort();
        let mut actual_disclosures = context.disclosure_recipients.clone();
        actual_disclosures.sort();
        if actual_disclosures != expected_disclosures {
            return Err(Error::Verification);
        }
        let selection = &inputs.own_selection.context;
        let selection_binding = (
            selection.tip_height,
            selection.tip_hash,
            selection.anchor_height,
            selection.anchor_hash,
            selection.anchor_root,
        );
        let policy = inputs.policy;
        let owner = policy
            .participants
            .iter()
            .position(|p| p.account_id == account_id && p.fvk.to_bytes() == own_fvk.to_bytes())
            .ok_or(Error::Verification)?;
        let verified = verify_review(bytes, &policy).map_err(|_| Error::Verification)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;
        let challenge = hex::encode(nonce);
        let mut hash = Sha256::new();
        hash.update(b"wholepact:trusted-local-consent:v1\0");
        for field in [
            &context.agreement_id,
            &context.obligation_id,
            &context.proposal_id,
            &context.client_id,
            &account_id,
            verified.review_binding(),
            &challenge,
        ] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(context.writer_epoch.to_le_bytes());
        hash.update(selection_binding.0.to_le_bytes());
        hash.update(selection_binding.1);
        hash.update(selection_binding.2.to_le_bytes());
        hash.update(selection_binding.3);
        hash.update(selection_binding.4);
        for field in [&context.disclosure_purpose, &context.retention_policy] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(Sha256::digest(bytes));
        hash.update(policy.manifest_digest);
        hash.update((context.disclosure_recipients.len() as u64).to_le_bytes());
        for recipient in &context.disclosure_recipients {
            hash.update((recipient.len() as u64).to_le_bytes());
            hash.update(recipient.as_bytes());
        }
        let consent_digest = hex::encode(hash.finalize());
        let mut display=format!("Wholepact trusted local review\nNetwork: testnet NU7 / Ironwood\nAccount: {account_id}\nApplication: {}\nAgreement: {}\nObligation: {}\nProposal: {}\nManifest digest: {}\nEffects digest: {}\nFrozen review binding: {}\nRaw artifact digest: {}\nMaximum net debit: {} zatoshis\nOwn fee share: {} zatoshis\nTotal transaction fee: {} zatoshis\nExpiry height: {}\n",context.client_id,context.agreement_id,context.obligation_id,context.proposal_id,hex::encode(policy.manifest_digest),verified.shielded_sighash(),verified.review_binding(),hex::encode(Sha256::digest(bytes)),verified.net_debits_zatoshis()[owner],policy.participants[owner].fee_share_zatoshis,verified.fee_zatoshis(),policy.expiry_height);
        display.push_str(&format!("Local wallet snapshot tip: {} / {}\nSelected anchor: {} / {} / {}\nDisclosure purpose: {}\nDeclared retention: {}\nBroad disclosure fields: dedicated-account FVK, selected notes, values, witnesses, outputs and memos; each listed reviewer and operator can see them. Viewing authority can reveal future activity and cannot be revoked.\n",selection_binding.0,hex::encode(selection_binding.1),selection_binding.2,hex::encode(selection_binding.3),hex::encode(selection_binding.4),context.disclosure_purpose,context.retention_policy));
        let manifest_text = serde_json::to_string_pretty(accepted.proposal.input())
            .map_err(|_| Error::InvalidData)?;
        display
            .push_str("Previously accepted complete application manifest (escaped inert text):\n");
        for ch in manifest_text.chars() {
            if ch == '\n' || ch.is_ascii_graphic() || ch == ' ' {
                display.push(ch)
            } else {
                display.extend(ch.escape_default())
            }
        }
        display.push('\n');
        for output in &policy.outputs {
            let purpose = match output.purpose {
                OutputPurpose::Recipient => "Recipient".to_string(),
                OutputPurpose::Return { participant_index } if participant_index == owner => {
                    "Verified own return".to_string()
                }
                OutputPurpose::Return { participant_index } => {
                    format!("Other account return index {participant_index}")
                }
            };
            display.push_str(&format!(
                "{purpose}: {} zatoshis to receiver {}\nMemo bytes: {}\n",
                output.value_zatoshis,
                hex::encode(output.receiver.to_raw_address_bytes()),
                hex::encode(output.memo)
            ));
        }
        display.push_str(&format!("Disclosure recipients: {}\nMatch assurance: fixed contributions only; no authenticated sponsor or real-world identities\nChain/input readiness: NOT QUALIFIED; current approval cannot release a signature\nTrusted user launch: NOT QUALIFIED; an application can own a PTY\nAuthority journal: encrypted production metadata/fencing NOT QUALIFIED\nConsensus signatures do not authenticate application manifest text. Released signatures cannot be recalled.\nConsent digest: {consent_digest}\n",context.disclosure_recipients.join(", ")));
        Ok(Self {
            pczt: Zeroizing::new(bytes.to_vec()),
            policy,
            context,
            account_id,
            protocol_binding: verified.review_binding().into(),
            challenge,
            consent_digest,
            display,
            created: Instant::now(),
        })
    }
    /// Erase any future approval eligibility when routing to the unqualified
    /// native inspection surface. Inspection cannot become a signing token.
    pub fn into_inspection(self) -> crate::inspection::TransactionInspection {
        crate::inspection::TransactionInspection::from_prepared(
            self.pczt,
            self.policy,
            self.consent_digest,
            self.display,
            self.created,
            self.protocol_binding,
        )
    }
    pub fn display(&self) -> &str {
        &self.display
    }
    pub fn consent_digest(&self) -> &str {
        &self.consent_digest
    }
    pub(crate) fn expired(&self) -> bool {
        self.created.elapsed() > Duration::from_secs(120)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        if self.expired() {
            return Err(Error::ReviewMismatch);
        }
        let verified = verify_review(&self.pczt, &self.policy).map_err(|_| Error::Verification)?;
        if verified.review_binding() != self.protocol_binding {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn challenge(&self) -> String {
        format!("APPROVE {}", self.challenge)
    }
    pub(crate) fn approve(self, entered: &str) -> Result<HumanApprovedReview> {
        if entered != self.challenge() {
            return Err(Error::ReviewMismatch);
        }
        self.check_current()?;
        Ok(HumanApprovedReview { review: self })
    }
}
#[cfg(all(feature = "synthetic-qualification", feature = "native-ui"))]
impl PreparedReview {
    /// Fixed public, never-funded fixture only. No arbitrary account, key, artifact
    /// or success flag is accepted. This is not an AcceptedManifest provider.
    pub(crate) fn synthetic_preview() -> Result<Self> {
        let fixture =
            wholepact_protocol::synthetic::review_fixture().map_err(|_| Error::Verification)?;
        let verified =
            verify_review(&fixture.pczt_bytes, &fixture.policy).map_err(|_| Error::Verification)?;
        let challenge = hex::encode(crate::vault::random::<32>()?);
        let artifact_digest = hex::encode(Sha256::digest(&fixture.pczt_bytes));
        let mut hash = Sha256::new();
        hash.update(b"wholepact:synthetic-native-transaction-review:v1\0");
        hash.update(challenge.as_bytes());
        hash.update(artifact_digest.as_bytes());
        hash.update(verified.review_binding().as_bytes());
        let consent_digest = hex::encode(hash.finalize());
        let mut display = format!(
            "SYNTHETIC CRYPTOGRAPHIC REVIEW ONLY\nNever-funded public fixture; no real wallet or chain.\nAccount: synthetic-owner-0\nApplication label: synthetic-native-preview (not authenticated)\nNetwork: synthetic testnet NU7 / Ironwood\nArtifact digest: {artifact_digest}\nManifest digest: {}\nExact review binding: {}\nEffects digest: {}\nOwn net debit: {} zatoshis\nOwn fee share: {} zatoshis\nTransaction fee: {} zatoshis\nExpiry height: {}\n",
            hex::encode(fixture.policy.manifest_digest), verified.review_binding(),
            verified.shielded_sighash(), verified.net_debits_zatoshis()[0],
            fixture.policy.participants[0].fee_share_zatoshis,
            verified.fee_zatoshis(), fixture.policy.expiry_height);
        for output in &fixture.policy.outputs {
            let purpose = match output.purpose {
                OutputPurpose::Recipient => "Recipient",
                OutputPurpose::Return {
                    participant_index: 0,
                } => "Verified own return",
                OutputPurpose::Return { .. } => "Other participant return",
            };
            display.push_str(&format!(
                "{purpose}: {} zatoshis to receiver {}\nMemo bytes: {}\n",
                output.value_zatoshis,
                hex::encode(output.receiver.to_raw_address_bytes()),
                hex::encode(output.memo)
            ));
        }
        display.push_str("Disclosure: public synthetic FVK/note/witness fixture held locally; no transmission.\nApplication manifest/account identity/disclosure consent: NOT AUTHENTICATED.\nTrusted launch, wallet freshness, unspentness and release authority: NOT QUALIFIED.\nAcknowledgment never releases a signature or authorizes disclosure.\n");
        Ok(Self {
            pczt: Zeroizing::new(fixture.pczt_bytes),
            policy: fixture.policy,
            context: ReviewContext {
                agreement_id: "synthetic-native-agreement".into(),
                obligation_id: "synthetic-native-obligation".into(),
                proposal_id: "synthetic-native-proposal".into(),
                client_id: "synthetic-native-preview".into(),
                writer_epoch: 1,
                disclosure_recipients: vec![],
                disclosure_purpose: "local public fixture".into(),
                retention_policy: "memory only".into(),
            },
            account_id: "synthetic-owner-0".into(),
            protocol_binding: verified.review_binding().into(),
            challenge,
            consent_digest,
            display,
            created: Instant::now(),
        })
    }
}

impl HumanApprovedReview {
    pub fn human_origin_authenticated(&self) -> bool {
        false
    }
    pub fn consent_digest(&self) -> &str {
        &self.review.consent_digest
    }
    pub fn account_id(&self) -> &str {
        &self.review.account_id
    }
    pub fn client_id(&self) -> &str {
        &self.review.context.client_id
    }
    /// Deliberately no signature operation until all independent release gates
    /// are available. A human approval never manufactures missing evidence.
    pub fn release(self) -> Result<Vec<u8>> {
        Err(Error::Unavailable)
    }
}
fn validate_disclosure_labels(recipients: &[String]) -> Result<()> {
    if recipients.len() > 33 {
        return Err(Error::InvalidData);
    }
    let mut seen = std::collections::BTreeSet::new();
    for recipient in recipients {
        let (kind, id) = recipient.split_once(':').ok_or(Error::InvalidData)?;
        if !matches!(kind, "operator" | "reviewer") || !seen.insert(recipient) {
            return Err(Error::InvalidData);
        }
        validate_label(id)?;
    }
    Ok(())
}
pub(crate) fn validate_label(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:./@".contains(&b))
    {
        Err(Error::InvalidData)
    } else {
        Ok(())
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    fn prepared() -> PreparedReview {
        let fixture = wholepact_protocol::synthetic::review_fixture().unwrap();
        let verified = verify_review(&fixture.pczt_bytes, &fixture.policy).unwrap();
        PreparedReview {
            pczt: Zeroizing::new(fixture.pczt_bytes),
            policy: fixture.policy,
            context: ReviewContext {
                agreement_id: "synthetic-agreement".into(),
                obligation_id: "synthetic-obligation".into(),
                proposal_id: "synthetic-proposal".into(),
                client_id: "synthetic-client".into(),
                writer_epoch: 1,
                disclosure_recipients: vec!["synthetic-prover".into()],
                disclosure_purpose: "synthetic review".into(),
                retention_policy: "temporary synthetic test only".into(),
            },
            account_id: "synthetic-owner-0".into(),
            protocol_binding: verified.review_binding().into(),
            challenge: "synthetic-test-nonce".into(),
            consent_digest: "synthetic-test-digest".into(),
            display: "synthetic review".into(),
            created: Instant::now(),
        }
    }
    #[test]
    fn human_response_never_manufactures_missing_chain_or_launch_evidence() {
        assert!(prepared().approve("wrong challenge").is_err());
        let mut expired = prepared();
        expired.created = Instant::now() - Duration::from_secs(121);
        assert!(expired.approve("APPROVE synthetic-test-nonce").is_err());
        let mut substituted = prepared();
        substituted.policy.manifest_digest[0] ^= 1;
        assert!(substituted.approve("APPROVE synthetic-test-nonce").is_err());
        let approved = prepared().approve("APPROVE synthetic-test-nonce").unwrap();
        assert!(!approved.human_origin_authenticated());
        assert!(matches!(approved.release(), Err(Error::Unavailable)));
    }

    #[test]
    fn complete_32_owner_roster_allows_full_underlying_identifier_bound() {
        let mut recipients = vec![format!("operator:{}", "o".repeat(128))];
        for i in 0..32 {
            recipients.push(format!("reviewer:{i:03}{}", "r".repeat(125)));
        }
        assert_eq!(recipients.len(), 33);
        validate_disclosure_labels(&recipients).unwrap();
        recipients.push("reviewer:extra".into());
        assert!(validate_disclosure_labels(&recipients).is_err());
        assert!(validate_disclosure_labels(&["reviewer:bad\u{1b}label".into()]).is_err());
    }
}
