//! Evidence view of an atomically recorded, non-authorizing terminal control.
//! Never signing authority, cancellation, exposure release or settlement.
use super::*;
use wholepact_authority::{AccountPolicy, OfflineAdmissionControl, OfflineAdmissionExportPlan};

#[cfg(test)]
const CONTROL_FIELD: &str = "offline-admission-control-v1";

/// Caller must obtain every reference from retained authenticated original state,
/// not labels/digests supplied by the incoming control. This is comparison data,
/// not a portable authority capability or an enrollment factory.
pub struct OfflineControlExpected<'a> {
    pub request: &'a ReserveOfflineAuthorization,
    pub account_policy: &'a AccountPolicy,
    pub offline_policy: &'a OfflineEnrollmentPolicy,
    pub original_export_plan: &'a OfflineAdmissionExportPlan,
    pub prepared_record_digest: &'a str,
    pub authenticated_receipt_digest: &'a str,
}

/// No conversion into admission, permit, final consent or dispatch authority.
/// No public constructor, Clone, Deserialize or Debug.
pub struct OfflineControlEnvelopeEvidence {
    control: OfflineAdmissionControl,
    envelope_digest: String,
    currently_within_transport_window: bool,
}
impl OfflineControlEnvelopeEvidence {
    pub fn control(&self) -> &OfflineAdmissionControl { &self.control }
    pub fn envelope_digest(&self) -> &str { &self.envelope_digest }
    pub fn authorization_allowed(&self) -> bool { false }
    pub fn currently_within_transport_window(&self) -> bool { self.currently_within_transport_window }
}

/// Evidence view of the concrete atomic control importer. Feature-disabled
/// builds refuse without mutation; no inbox-only intake can consume this slot.
/// The returned evidence itself still grants no financial or signing authority.
pub fn authenticate_control_evidence(
    envelope: &EncryptedEnvelope, offline_secret: &TransportSecret,
    witness_key: &TransportPublicKey, expected: &OfflineControlExpected<'_>,
    now: &Timestamp, inbox: &mut SqliteReplayLedger,
) -> Result<OfflineControlEnvelopeEvidence> {
    #[cfg(feature = "offline-control-import")]
    {
        let receipt = import_control_atomically(envelope, offline_secret, witness_key, expected, now, inbox)?;
        Ok(OfflineControlEnvelopeEvidence {
            control: receipt.control().clone(), envelope_digest: receipt.envelope_digest().into(),
            currently_within_transport_window: receipt.currently_within_transport_window(),
        })
    }
    #[cfg(not(feature = "offline-control-import"))]
    {
        let _ = (envelope, offline_secret, witness_key, expected, now, inbox);
        Err(TransportError::AuthorityUnavailable)
    }
}

/// Reauthenticate exact existing inbox evidence after interruption, without
/// changing replay state, renewing the control or performing a domain transition.
pub fn recover_control_evidence(
    offline_secret: &TransportSecret, witness_key: &TransportPublicKey,
    expected: &OfflineControlExpected<'_>, now: &Timestamp, inbox: &SqliteReplayLedger,
) -> Result<Option<OfflineControlEnvelopeEvidence>> {
    #[cfg(feature = "offline-control-import")]
    {
        Ok(recover_atomic_control_receipt(offline_secret, witness_key, expected, now, inbox)?.map(|receipt|
            OfflineControlEnvelopeEvidence {
                control: receipt.control().clone(), envelope_digest: receipt.envelope_digest().into(),
                currently_within_transport_window: receipt.currently_within_transport_window(),
            }))
    }
    #[cfg(not(feature = "offline-control-import"))]
    {
        let _ = (offline_secret, witness_key, expected, now, inbox);
        Err(TransportError::AuthorityUnavailable)
    }
}

/// Enabled composed path: concrete SQLCipher receipt plus typed control outcome
/// share one commit. No application callback or portable capability is accepted.
#[cfg(feature = "offline-control-import")]
pub fn import_control_atomically(
    envelope: &EncryptedEnvelope, offline_secret: &TransportSecret,
    witness_key: &TransportPublicKey, expected: &OfflineControlExpected<'_>,
    now: &Timestamp, inbox: &mut SqliteReplayLedger,
) -> Result<wholepact_transport::OfflineControlInboxReceipt> {
    let expected = wholepact_transport::OfflineControlImportExpected {
        request: expected.request, account_policy: expected.account_policy,
        offline_policy: expected.offline_policy, original_export_plan: expected.original_export_plan,
        prepared_record_digest: expected.prepared_record_digest,
        authenticated_receipt_digest: expected.authenticated_receipt_digest,
    };
    wholepact_transport::accept_offline_control(envelope, offline_secret, witness_key, &expected, now, inbox)
}

/// Historical coherent receipt recovery, never an outcome insertion or authority.
#[cfg(feature = "offline-control-import")]
pub fn recover_atomic_control_receipt(
    offline_secret: &TransportSecret, witness_key: &TransportPublicKey,
    expected: &OfflineControlExpected<'_>, now: &Timestamp, inbox: &SqliteReplayLedger,
) -> Result<Option<wholepact_transport::OfflineControlInboxReceipt>> {
    let expected = wholepact_transport::OfflineControlImportExpected {
        request: expected.request, account_policy: expected.account_policy,
        offline_policy: expected.offline_policy, original_export_plan: expected.original_export_plan,
        prepared_record_digest: expected.prepared_record_digest,
        authenticated_receipt_digest: expected.authenticated_receipt_digest,
    };
    wholepact_transport::recover_offline_control_receipt(offline_secret, witness_key, &expected, now, inbox)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_cannot_be_parsed_from_admission_field_or_extra_fields() {
        let fields = vec![DisclosureField::new(ADMISSION_FIELD, b"{}".to_vec()).unwrap()];
        assert!(matches!(exact_field::<OfflineAdmissionControl>(&fields, CONTROL_FIELD), Err(TransportError::WrongContext)));
        let fields = vec![DisclosureField::new(CONTROL_FIELD, b"{}".to_vec()).unwrap(),
            DisclosureField::new("extra", b"{}".to_vec()).unwrap()];
        assert!(matches!(exact_field::<OfflineAdmissionControl>(&fields, CONTROL_FIELD), Err(TransportError::WrongContext)));
    }
    #[test]
    fn no_admission_and_retained_exposure_are_distinct_wire_outcomes() {
        use wholepact_authority::OfflineAdmissionControlOutcome;
        let a = serde_json::to_vec(&OfflineAdmissionControlOutcome::NoAdmission).unwrap();
        let b = serde_json::to_vec(&OfflineAdmissionControlOutcome::ExposureRetained { admission_digest: "a".repeat(64) }).unwrap();
        assert_ne!(a, b);
    }
}

