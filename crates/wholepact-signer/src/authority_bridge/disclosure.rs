//! Separate native permission to disclose exact accounting/linkage metadata to
//! the optional witness. Spending approval never substitutes for this decision.
use super::{BridgeError, Result};
use crate::consent_journal::{OriginalSpendConsent, PreparedSpendConsent};
use serde::{Deserialize, Serialize};
use wholepact_authority::{AuthorityClient, AuthorityHead, WitnessDisclosureDescriptor};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedWitnessDisclosure {
    pub descriptor: WitnessDisclosureDescriptor,
    pub original_consent_ref: String,
    pub native_review_digest: String,
    pub expected_head: AuthorityHead,
    pub nonce: String,
    pub native_origin_measurement: String,
    pub native_principal_id: String,
}
/// Read-only native review. No serialization or app request can approve it.
pub struct WitnessDisclosureReview {
    record: RetainedWitnessDisclosure,
    display: zeroize::Zeroizing<String>,
}
impl WitnessDisclosureReview {
    pub fn new(
        client: &AuthorityClient,
        prepared: &PreparedSpendConsent,
        expected_head: AuthorityHead,
    ) -> Result<Self> {
        Self::new_original(client, prepared.record(), expected_head)
    }
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn new_automatic(
        client: &AuthorityClient,
        approved: &crate::consent_journal::ApprovedAutomaticSpendConsent,
        expected_head: AuthorityHead,
    ) -> Result<Self> {
        Self::new_original(client, approved.record(), expected_head)
    }
    fn new_original(
        client: &AuthorityClient,
        original: &OriginalSpendConsent,
        expected_head: AuthorityHead,
    ) -> Result<Self> {
        let descriptor = client.disclosure_descriptor();
        let t = original.terms();
        if descriptor.account_id != t.account_id {
            return Err(BridgeError::Binding);
        }
        let nonce = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Permission)?);
        let digest = disclosure_digest(&descriptor, &expected_head, &nonce, original)?;
        let mut display = zeroize::Zeroizing::new(format!(
            "OPTIONAL INDEPENDENT WITNESS DISCLOSURE\nWitness: {}\nEndpoint: {}\nTLS name: {}\nPinned certificate: {}\nPolicy: {}\nAccount: {}\nNetwork: {}\nAuthorization: {}\nAgreement: {}\nObligation: {}\nOwn maximum debit: {} zatoshis\nOwn fee share: {} zatoshis\nTransaction fee: {} zatoshis\nSelected input identities, values and nullifiers: {}\nConsent/enrollment/manifest references and exact artifact/effects/review commitments will be disclosed. No spending key, FVK, private note, memo, witness or raw PCZT is sent.\nThe witness retains this history, can correlate account/input/amount metadata, and its availability is required for new reservations. Already disclosed history and issued exposure cannot be recalled. Wall-clock expiry or a lost response does not clear exposure.\nThis is a separate disclosure decision; it is not spending approval.\nWitness head: {} / {}\nExact disclosure review: {}",
            descriptor.witness_id,
            descriptor.endpoint,
            descriptor.server_name,
            descriptor.pinned_server_certificate_digest,
            descriptor.policy_digest,
            t.account_id,
            descriptor.network_profile_id,
            t.authorization_id,
            t.agreement_id,
            t.obligation_id,
            t.maximum_debit_zatoshis,
            t.fee_share_zatoshis,
            t.transaction_fee_zatoshis,
            serde_json::to_string(&t.input_bindings).map_err(|_| BridgeError::Binding)?,
            expected_head.sequence,
            expected_head.digest,
            digest
        ));
        if let Some(automatic) = &t.automation {
            display.push_str(&format!(
                "\nBounded automation grant linkage also disclosed: grant {}, revision {}, application {}, exact terms digest {}. The witness records a separate one-shot key-use admission for this exact reservation. This permission applies only to this displayed request.",
                automatic.grant.grant_id, automatic.grant.revision,
                automatic.grant.application_id, automatic.grant.terms_digest,
            ));
        }
        Ok(Self {
            record: RetainedWitnessDisclosure {
                descriptor,
                original_consent_ref: original.reference().into(),
                native_review_digest: digest,
                expected_head,
                nonce,
                native_origin_measurement: t.receipt.trusted_launch_measurement().into(),
                native_principal_id: t.principal_id.clone(),
            },
            display,
        })
    }
    pub fn review_digest(&self) -> &str {
        &self.record.native_review_digest
    }
    pub fn display(&self) -> &str {
        &self.display
    }
    #[cfg(feature = "native-ui")]
    pub(crate) fn approve(
        self,
        decision: crate::native_ui::NativeDecision,
        authority: &crate::native_ui::NativeAuthority,
    ) -> Result<ApprovedWitnessDisclosure> {
        if decision.binding() != &authority.binding()
            || decision.reviewed_digest() != self.review_digest()
            || authority.measurement() != self.record.native_origin_measurement
            || authority.principal_id() != self.record.native_principal_id
        {
            return Err(BridgeError::Permission);
        }
        authority
            .binding()
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        Ok(ApprovedWitnessDisclosure {
            record: self.record,
            source: authority.binding(),
            created: std::time::Instant::now(),
        })
    }
}
/// Non-cloneable one-shot native authority, retained separately from its evidence.
/// The only production issuer is the actual native decision callback above.
pub struct ApprovedWitnessDisclosure {
    record: RetainedWitnessDisclosure,
    #[cfg(feature = "native-ui")]
    source: crate::native_ui::NativeAuthorityBinding,
    #[cfg(feature = "native-ui")]
    created: std::time::Instant,
}
impl ApprovedWitnessDisclosure {
    pub(crate) fn record(&self) -> &RetainedWitnessDisclosure {
        &self.record
    }
    pub(crate) fn check(
        &self,
        original: &OriginalSpendConsent,
        client: Option<&AuthorityClient>,
    ) -> Result<()> {
        #[cfg(not(feature = "native-ui"))]
        let _ = (original, client);
        #[cfg(feature = "native-ui")]
        self.source
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        #[cfg(not(feature = "native-ui"))]
        return Err(BridgeError::Permission);
        #[cfg(feature = "native-ui")]
        {
            if self.created.elapsed() >= std::time::Duration::from_secs(120) {
                return Err(BridgeError::Permission);
            }
            self.record.validate_original(original)?;
            if client.is_some_and(|c| c.disclosure_descriptor() != self.record.descriptor) {
                return Err(BridgeError::Binding);
            }
            Ok(())
        }
    }
    pub(crate) fn require_origin(
        &self,
        lease: &crate::consent_journal::OriginalAuthorizationLease<'_>,
    ) -> Result<()> {
        #[cfg(feature = "native-ui")]
        {
            lease.require_native_origin(&self.source)?;
            Ok(())
        }
        #[cfg(not(feature = "native-ui"))]
        {
            let _ = lease;
            Err(BridgeError::Permission)
        }
    }
}
impl RetainedWitnessDisclosure {
    pub(crate) fn validate_original(&self, original: &OriginalSpendConsent) -> Result<()> {
        if self.original_consent_ref != original.reference()
            || self.descriptor.account_id != original.terms().account_id
            || self.native_principal_id != original.terms().principal_id
            || self.native_origin_measurement
                != original.terms().receipt.trusted_launch_measurement()
            || self.native_review_digest
                != disclosure_digest(&self.descriptor, &self.expected_head, &self.nonce, original)?
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
fn disclosure_digest(
    descriptor: &WitnessDisclosureDescriptor,
    head: &AuthorityHead,
    nonce: &str,
    original: &OriginalSpendConsent,
) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:exact-native-witness-disclosure:v1",
        &(descriptor, head, nonce, original),
    )
    .map_err(|_| BridgeError::Binding)
}
