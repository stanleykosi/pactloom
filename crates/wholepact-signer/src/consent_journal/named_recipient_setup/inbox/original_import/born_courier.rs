//! Exact purpose-distinct courier. Native approval authorizes one original
//! network request, never a new enrollment/session or spending-key invocation.
use super::super::NamedRecipientOperation;
use super::*;
use wholepact_authority::{
    AuthorityClient, BornOfflineDeliveryLookupV1, BornOfflineDeliveryV1,
    WitnessDisclosureDescriptor,
};
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BornCourierActionV1 {
    SubmitOriginal,
    RecoverOriginal,
}
pub(crate) struct PreparedBornIntentCourierV1 {
    profile: LiveNamedRecipientProfile,
    handoff: BornIntentHandoffV1,
    action: BornCourierActionV1,
    witness: WitnessDisclosureDescriptor,
    operation: NamedRecipientOperation,
    created: Instant,
    original_window: Option<OriginalSubmissionWindow>,
    digest: String,
    display: String,
}
pub(crate) struct RetainedBornCourierDeliveryV1 {
    profile: LiveNamedRecipientProfile,
    delivery: BornOfflineDeliveryV1,
    digest: String,
    display: String,
}
pub(crate) struct PreparedBornDeliveryFileV1 {
    retained: RetainedBornCourierDeliveryV1,
    destination: ExactFileDestination,
    operation: NamedRecipientOperation,
    created: Instant,
    digest: String,
    display: String,
}
pub(super) fn profile_current(
    profile: &LiveNamedRecipientProfile,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> ImportResult<()> {
    require_profile_owner(profile, journal)?;
    profile.check_current(journal, session).map_err(unavailable)
}
impl LiveNamedRecipientProfile {
    pub(crate) fn prepare_born_intent_courier(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        client: &AuthorityClient,
        bytes: &[u8],
        action: BornCourierActionV1,
        operation: NamedRecipientOperation,
    ) -> ImportResult<PreparedBornIntentCourierV1> {
        operation.check()?;
        profile_current(self, journal, session)?;
        // Capture before parsing/network preparation. Local wall time is only an
        // expiry guard, never witness-clock authority; preparation cannot renew it.
        let created = Instant::now();
        let captured_wall_ms = local_wall_milliseconds()?;
        let handoff = BornIntentHandoffV1::parse(bytes)?;
        let original_window = match action {
            BornCourierActionV1::SubmitOriginal => Some(OriginalSubmissionWindow::new(
                created,
                captured_wall_ms,
                &handoff,
            )?),
            BornCourierActionV1::RecoverOriginal => None,
        };
        let witness = client.disclosure_descriptor();
        let terms = &handoff.request().reservation.intent.terms;
        if witness.account_id != self.record.account_id
            || witness.network_profile_id != terms.network_profile_id
            || witness.pinned_server_certificate_digest != self.record.witness_certificate_digest
            || terms.account_id != self.record.account_id
            || terms.enrollment_ref != self.record.witness_enrollment_ref()
            || terms.offline_signer_key_digest
                != super::super::super::super::named_recipient_records::transport_fingerprint(
                    &self.record.transport_public_key,
                )
            || handoff.admission_export_template().sender_key_fingerprint
                != super::super::super::super::named_recipient_records::transport_fingerprint(
                    &self.record.witness_transport_public_key,
                )
        {
            return Err(TransportError::WrongContext);
        }
        require_courier_provenance(self, journal, action, &handoff)?;
        let digest = digest(
            "wholepact:native-born-intent-courier:v1",
            &(
                &self.record.reference,
                self.source.entry_digest(),
                handoff.commitment()?,
                &witness,
                action,
            ),
        )
        .map_err(unavailable)?;
        let display = format!(
            "EXACT BORN INTENT COURIER\nAction: {}\nPinned witness: {}\nCanonical original handoff: {}\nExact request: {}\nOriginal response template: {}\nThis sends the full own request/input identifiers and original HPKE ciphertext to the selected witness. Parsing this file establishes no authority. Submit may reserve original exposure; it never signs or makes a payment. Recovery returns only original retained ciphertext, even after original expiry. Cancel during a network request is uncertain: preserve this exact file/lookup and recover, never automatically resubmit or change its head, clock, operation or template.",
            match action {
                BornCourierActionV1::SubmitOriginal => "submit original",
                BornCourierActionV1::RecoverOriginal => "recover original ciphertext",
            },
            serde_json::to_string_pretty(&witness).map_err(unavailable)?,
            handoff.commitment()?,
            serde_json::to_string_pretty(handoff.request()).map_err(unavailable)?,
            serde_json::to_string_pretty(handoff.admission_export_template())
                .map_err(unavailable)?
        );
        operation.check()?;
        profile_current(self, journal, session)?;
        Ok(PreparedBornIntentCourierV1 {
            profile: self.clone(),
            handoff,
            action,
            witness,
            operation,
            created,
            original_window,
            digest,
            display,
        })
    }
}
impl PreparedBornIntentCourierV1 {
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        client: &AuthorityClient,
    ) -> ImportResult<RetainedBornCourierDeliveryV1> {
        if decision.binding() != &self.profile.source
            || decision.reviewed_digest() != self.digest
            || client.disclosure_descriptor() != self.witness
        {
            return Err(TransportError::WrongContext);
        }
        let mut deadline = review_deadline(self.created, &decision)?.min(self.operation.deadline());
        if let Some(window) = &self.original_window {
            window.check(local_wall_milliseconds()?, Instant::now())?;
            deadline = deadline.min(window.deadline);
        }
        profile_current(&self.profile, journal, session)?;
        check_setup_current(&self.profile.source, deadline).map_err(unavailable)?;
        self.operation.check()?;
        let enrollment =
            require_courier_provenance(&self.profile, journal, self.action, &self.handoff)?;
        let lookup = BornOfflineDeliveryLookupV1::from_request(self.handoff.request())
            .map_err(unavailable)?;
        // Network I/O never holds a publication lease, so blur/cancel can revoke the
        // local continuation. A request already admitted to the socket is uncertain.
        if let Some(window) = &self.original_window {
            window.check(local_wall_milliseconds()?, Instant::now())?;
        }
        let mut still_current = || {
            let checked = (|| -> ImportResult<()> {
                self.operation.check()?;
                profile_current(&self.profile, journal, session)?;
                check_setup_current(&self.profile.source, deadline).map_err(unavailable)?;
                if let Some(window) = &self.original_window {
                    window.check(local_wall_milliseconds()?, Instant::now())?;
                }
                if require_courier_provenance(&self.profile, journal, self.action, &self.handoff)?
                    != enrollment
                {
                    return Err(TransportError::WrongContext);
                }
                // A local journal mutex/read can block. The native source and
                // signer session have independent lifetimes; recheck both.
                profile_current(&self.profile, journal, session)?;
                self.profile.source.check_current().map_err(unavailable)?;
                if let Some(window) = &self.original_window {
                    window.check(local_wall_milliseconds()?, Instant::now())?;
                }
                if Instant::now() >= deadline {
                    return Err(TransportError::InvalidTime);
                }
                self.operation.check()
            })();
            checked.map_err(|_| wholepact_authority::AuthorityError::Permission)
        };
        let delivery = match self.action {
            BornCourierActionV1::SubmitOriginal if enrollment.owner_continuation.is_some() => {
                client.submit_born_owner_intent_checked_until_v1(
                    &enrollment,
                    self.handoff.request().clone(),
                    &self.handoff.encrypted_intent()?,
                    self.handoff.admission_export_template().clone(),
                    deadline,
                    &mut still_current,
                )
            }
            BornCourierActionV1::SubmitOriginal => client
                .submit_born_offline_intent_checked_until_v1(
                    self.handoff.request().clone(),
                    &self.handoff.encrypted_intent()?,
                    self.handoff.admission_export_template().clone(),
                    deadline,
                    &mut still_current,
                ),
            BornCourierActionV1::RecoverOriginal => client
                .recover_born_offline_delivery_checked_until_v1(
                    lookup.clone(),
                    deadline,
                    &mut still_current,
                ),
        }
        .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        let after = (|| -> ImportResult<()> {
            self.operation.check()?;
            if let Some(window) = &self.original_window {
                window.check(local_wall_milliseconds()?, Instant::now())?;
            }
            profile_current(&self.profile, journal, session)?;
            check_setup_current(&self.profile.source, deadline).map_err(unavailable)?;
            if delivery.original() != &lookup {
                return Err(TransportError::WrongContext);
            }
            Ok(())
        })();
        after.map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        let digest = envelope_commitment(delivery.ciphertext())?;
        let display = format!(
            "ORIGINAL BORN HPKE DELIVERY\nAuthorization: {}\nOriginal born request: {}\nExact encrypted envelope: {}\nCommitted admission: {}\nRecovered original: {}\nThis is not recipient approval, signature or payment. Recipient import must independently verify the born wrapper, pinned HPKE peers, full actual history and original unchanged deadlines.",
            self.handoff
                .request()
                .reservation
                .intent
                .terms
                .authorization_id,
            lookup.original_born_request_digest,
            digest,
            delivery.original_admission_digest(),
            delivery.recovered_original()
        );
        Ok(RetainedBornCourierDeliveryV1 {
            profile: self.profile,
            delivery,
            digest,
            display,
        })
    }
}
impl RetainedBornCourierDeliveryV1 {
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn prepare_file_export(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        destination: &Path,
        operation: NamedRecipientOperation,
    ) -> ImportResult<PreparedBornDeliveryFileV1> {
        profile_current(&self.profile, journal, session)?;
        operation.check()?;
        let destination = ExactFileDestination::prepare(destination)?;
        let digest = digest(
            "wholepact:native-born-delivery-file:v1",
            &(
                &self.profile.record.reference,
                self.profile.source.entry_digest(),
                self.delivery.original(),
                &self.digest,
                destination.review_binding(),
            ),
        )
        .map_err(unavailable)?;
        let display = format!(
            "{}\nWrite unchanged HPKE ciphertext to new private file: {}\nNo overwrite or plaintext disclosure is permitted. Original expiry is unchanged; backup/history is not fresh authority.",
            self.display,
            destination.display_path().display()
        );
        Ok(PreparedBornDeliveryFileV1 {
            retained: self,
            destination,
            operation,
            created: Instant::now(),
            digest,
            display,
        })
    }
}
impl PreparedBornDeliveryFileV1 {
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn write_new_file(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> ImportResult<()> {
        if decision.binding() != &self.retained.profile.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(TransportError::WrongContext);
        }
        let deadline = review_deadline(self.created, &decision)?;
        let current = || -> ImportResult<()> {
            self.operation.check()?;
            profile_current(&self.retained.profile, journal, session)?;
            check_setup_current(&self.retained.profile.source, deadline).map_err(unavailable)
        };
        current()?;
        self.destination.check_directory()?;
        let mut file = self.destination.allocate()?;
        let result = (|| -> ImportResult<()> {
            current()?;
            self.destination.check_created(&file, 0)?;
            let _publication = self
                .retained
                .profile
                .source
                .publication_lease()
                .map_err(unavailable)?;
            current()?;
            file.write_all(self.retained.delivery.ciphertext())
                .map_err(|_| TransportError::Storage)?;
            file.sync_all().map_err(|_| TransportError::Storage)?;
            self.destination.sync_parent()?;
            self.destination
                .check_created(&file, self.retained.delivery.ciphertext().len() as u64)?;
            current()
        })();
        result.map_err(|_| TransportError::ImportCommittedButUnavailable)
    }
}

fn require_courier_provenance(
    profile: &LiveNamedRecipientProfile,
    journal: &SignerConsentJournal,
    action: BornCourierActionV1,
    handoff: &BornIntentHandoffV1,
) -> ImportResult<wholepact_authority::born_offline_enrollment_v1::BornOfflineEnrollmentV1> {
    let c = journal
        .connection
        .lock()
        .map_err(|_| TransportError::Storage)?;
    exact_profile(&c, profile, journal)?;
    let provenance =
        super::super::super::super::account_use_storage::inspect(&c, &profile.record.account_id)
            .map_err(unavailable)?;
    let genesis = provenance
        .genesis()
        .ok_or(TransportError::AuthorityUnavailable)?;
    if genesis.identity.account_id != profile.record.account_id
        || genesis.identity.full_viewing_key_digest != profile.record.full_viewing_key_digest
        || matches!(action, BornCourierActionV1::SubmitOriginal) && provenance.exclusion().is_some()
    {
        return Err(TransportError::AuthorityUnavailable);
    }
    // The courier is a transport for an already native-retained original, not
    // a second draft authoring surface. Canonical syntax or a genuine HPKE intent
    // does not bind outer operation/head/time/template fields on its own.
    let original = read_original_by_authorization(
        &c,
        &profile.record,
        &handoff.request().reservation.intent.terms.authorization_id,
    )?
    .ok_or(TransportError::AuthorityUnavailable)?;
    let origin = original
        .born_origin
        .as_ref()
        .ok_or(TransportError::WrongContext)?;
    let enrollment = storage::read_enrollment(&c, &profile.record.enrollment_ref)
        .map_err(unavailable)?
        .ok_or(TransportError::AuthorityUnavailable)?;
    if courier_requires_actual_signer(action, origin.checkpoint_origin.version)? {
        origin.require_actual_signer(&c, &profile.record, &enrollment)
    } else {
        origin.require_retained_signer(&c, &profile.record, &enrollment)
    }
    .map_err(unavailable)?;
    let outbox = read_outbox(&c, &original, &profile.record)?;
    let encrypted = hex::decode(&outbox.envelope_hex).map_err(|_| TransportError::Malformed)?;
    let retained = BornIntentHandoffV1::from_original(&original, &encrypted)?;
    handoff.require_exact_retained(&retained)?;
    Ok(origin.enrollment.enrollment.clone())
}

// Only selects which EXISTING full original/source validator is mandatory.
// No version or enum value can supply its actual rows, origin or native owner.
fn courier_requires_actual_signer(
    action: BornCourierActionV1,
    carrier_version: u16,
) -> ImportResult<bool> {
    match (action, carrier_version) {
        (BornCourierActionV1::SubmitOriginal, 2) => Ok(true),
        (BornCourierActionV1::RecoverOriginal, 1 | 2) => Ok(false),
        _ => Err(TransportError::AuthorityUnavailable),
    }
}

// Submit is bounded by both original wall labels and a fixed monotonic ceiling.
// Historical ciphertext recovery deliberately has no OriginalSubmissionWindow.
struct OriginalSubmissionWindow {
    captured_wall_ms: u64,
    start_ms: u64,
    end_ms: u64,
    deadline: Instant,
}
impl OriginalSubmissionWindow {
    fn new(
        created: Instant,
        captured_wall_ms: u64,
        handoff: &BornIntentHandoffV1,
    ) -> ImportResult<Self> {
        let request = &handoff.request().reservation;
        let plan = handoff.admission_export_template();
        let to_ms = |seconds: i64| {
            u64::try_from(seconds)
                .ok()
                .and_then(|v| v.checked_mul(1000))
                .ok_or(TransportError::InvalidTime)
        };
        Self::from_bounds(
            created,
            captured_wall_ms,
            request
                .requested_at_ms
                .max(to_ms(plan.issued_at_unix_seconds)?),
            request
                .admission_expires_at_ms
                .min(to_ms(plan.expires_at_unix_seconds)?),
        )
    }
    fn from_bounds(
        created: Instant,
        captured_wall_ms: u64,
        start_ms: u64,
        end_ms: u64,
    ) -> ImportResult<Self> {
        let remaining = end_ms
            .checked_sub(captured_wall_ms)
            .filter(|v| *v > 0)
            .ok_or(TransportError::InvalidTime)?;
        let result = Self {
            captured_wall_ms,
            start_ms,
            end_ms,
            deadline: created
                .checked_add(Duration::from_millis(remaining))
                .ok_or(TransportError::InvalidTime)?,
        };
        result.check(captured_wall_ms, created)?;
        Ok(result)
    }
    fn check(&self, wall_ms: u64, now: Instant) -> ImportResult<()> {
        if wall_ms < self.captured_wall_ms
            || wall_ms < self.start_ms
            || wall_ms >= self.end_ms
            || now >= self.deadline
        {
            return Err(TransportError::InvalidTime);
        }
        Ok(())
    }
}
#[cfg(test)]
mod clock_tests {
    use super::*;
    #[test]
    fn courier_carrier1_is_historical_recovery_only_not_new_admission() {
        // Inert generation-routing test only. Exact retained original/outbox,
        // native approval and full actual source validation remain mandatory.
        assert!(courier_requires_actual_signer(BornCourierActionV1::SubmitOriginal, 1).is_err());
        assert!(!courier_requires_actual_signer(BornCourierActionV1::RecoverOriginal, 1).unwrap());
        assert!(courier_requires_actual_signer(BornCourierActionV1::SubmitOriginal, 2).unwrap());
        assert!(!courier_requires_actual_signer(BornCourierActionV1::RecoverOriginal, 2).unwrap());
        for version in [0, 3, u16::MAX] {
            assert!(
                courier_requires_actual_signer(BornCourierActionV1::SubmitOriginal, version)
                    .is_err()
            );
            assert!(
                courier_requires_actual_signer(BornCourierActionV1::RecoverOriginal, version)
                    .is_err()
            );
        }
    }
    #[test]
    fn original_submit_window_rejects_expiry_backwards_clock_and_monotonic_renewal() {
        let created = Instant::now();
        let window = OriginalSubmissionWindow::from_bounds(created, 2_500, 2_000, 3_000).unwrap();
        assert!(window.check(2_500, created).is_ok());
        assert!(window.check(2_499, created).is_err());
        assert!(window.check(3_000, created).is_err());
        assert!(
            window
                .check(2_500, created + Duration::from_millis(500))
                .is_err()
        );
        assert!(OriginalSubmissionWindow::from_bounds(created, 1_999, 2_000, 3_000).is_err());
        assert!(OriginalSubmissionWindow::from_bounds(created, 3_000, 2_000, 3_000).is_err());
    }
}
