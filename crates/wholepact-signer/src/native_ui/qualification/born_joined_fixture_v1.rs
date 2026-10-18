//! Opt-in, ephemeral, never-funded joined-controller fixture.
//!
//! Opaque values retain the actual native controllers and temporary owners.
//! The API accepts ordinary policy/Host request data, never native decisions,
//! history/session claims, transport peers, leases, or caller-selected roots.
//! Synthetic delivery is not attended native or financial qualification.

use super::birth_workspace::born_roster_v3::{
    ProducedPendingBirth, PublicFixtureBirthSetup, finish_three_pending_births,
    finish_two_pending_births,
};
use super::born_manual::born_single_anchor_v1::{
    ExportedSingleAnchor, InitialSingleFixture, SinglePublicationFixture,
};
use super::born_manual_roster_v2::born_manual_roster::continuation_fixture::{
    ContinuationExportFixture, ContinuedDisclosuresFixture, ContinuedPublicationFixture,
    ExpectedDisclosures, ExportedContinuationFixture, close_publication,
};
use super::born_manual_roster_v2::born_manual_roster::{
    ExportedOriginalRoster, InitialRosterFixture, PublicationRosterFixture,
};
use super::pending_enrollment::born_pending_continuation::{
    AcknowledgedBornFixture, EphemeralOwnerCredentials, ExportedPendingBirth,
    retain_sign_and_export,
};
use super::runtime::NativeRuntime;
use crate::{Error, Result};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use wholepact_authority::{
    AccountPolicy, WitnessDisclosureDescriptor, native_witness_owner::EphemeralWitnessOriginV1,
};
use wholepact_signer_origin::manual::{HostManualEnrollmentIntent, HostManualEnrollmentRequest};
use wholepact_signer_origin::{
    InstalledSignerProvider,
    manual_roster_v2::{
        HostManualRosterEnrollmentIntentV2, HostManualRosterEnrollmentRequestV2,
        HostManualRosterPublicationRequestV2,
    },
};

/// Public identity copied from the genuinely generated pending account.
/// This DTO has no authority and cannot be passed back as an account owner.
pub struct PublicBornIdentityV1 {
    pub account_id: String,
    pub full_viewing_key_digest: String,
    pub network_profile_id: String,
}
/// Public original policy inputs. A stable V2 policy must be set before birth;
/// the fixture cannot add one to an acknowledged original afterward.
pub struct OriginalBirthSetupV1 {
    pub policy: AccountPolicy,
    pub stable_recipient_policy_json: String,
}

pub struct EphemeralPendingBornV1 {
    pending: ProducedPendingBirth,
    credentials: EphemeralOwnerCredentials,
    exports: PathBuf,
}
impl EphemeralPendingBornV1 {
    /// First create the nominal temporary witness; this function uses its exact
    /// current public pins and retains its private installation lifetime.
    pub fn create_two(
        origin: EphemeralWitnessOriginV1,
        mut setup: impl FnMut(usize, &PublicBornIdentityV1) -> Result<OriginalBirthSetupV1>,
    ) -> Result<[Self; 2]> {
        let credentials = EphemeralOwnerCredentials::from_origin(origin)?;
        let temporary = Arc::new(
            tempfile::Builder::new()
                .prefix("wholepact-synthetic-joined-born-")
                .tempdir()?,
        );
        let left = NativeRuntime::entered_pending_birth_for_qualification(
            &temporary.path().join("owner-one"),
            "synthetic-never-funded-owner-one",
        )?;
        let right = NativeRuntime::entered_pending_birth_for_qualification(
            &temporary.path().join("owner-two"),
            "synthetic-never-funded-owner-two",
        )?;
        let origin = credentials.origin();
        let pair =
            finish_two_pending_births(temporary.clone(), [left, right], |index, identity| {
                let public = PublicBornIdentityV1 {
                    account_id: identity.account_id().into(),
                    full_viewing_key_digest: identity.full_viewing_key_digest().into(),
                    network_profile_id: identity.network_profile_id().into(),
                };
                let setup = setup(index, &public)?;
                if setup.policy.account_id != public.account_id
                    || setup.policy.network_profile_id != public.network_profile_id
                    || setup.policy.witness_id != origin.witness_id
                    || setup.policy.owner_certificate_digest != origin.owner_certificate_digest
                    || setup.policy.initial_writer_certificate_digest
                        != origin.writer_certificate_digest
                    || setup.stable_recipient_policy_json.is_empty()
                {
                    return Err(Error::ReviewMismatch);
                }
                let disclosure = WitnessDisclosureDescriptor {
                    endpoint: origin.endpoint.clone(),
                    server_name: origin.server_name.clone(),
                    witness_id: origin.witness_id.clone(),
                    account_id: public.account_id,
                    network_profile_id: public.network_profile_id,
                    policy_digest: setup
                        .policy
                        .policy_digest()
                        .map_err(|_| Error::InvalidData)?,
                    pinned_server_certificate_digest: origin.server_certificate_digest.clone(),
                };
                Ok(PublicFixtureBirthSetup {
                    disclosure,
                    original_policy: setup.policy,
                    stable_recipient_policy_json: Some(setup.stable_recipient_policy_json),
                })
            })?;
        let mut outputs = Vec::with_capacity(2);
        for (index, pending) in pair.into_iter().enumerate() {
            let exports = temporary
                .path()
                .join(format!("owner-{}-exports", index + 1));
            private_export_directory(&exports)?;
            outputs.push(Self {
                pending,
                credentials: credentials.clone(),
                exports,
            });
        }
        outputs.try_into().map_err(|_| Error::InvalidData)
    }
    /// Returns [unfunded Single audit anchor, roster participant one, roster
    /// participant two]. Fund only participant public receivers with synthetic
    /// compact-block fixtures; this never creates a network-funded account.
    pub fn create_three(
        origin: EphemeralWitnessOriginV1,
        mut setup: impl FnMut(usize, &PublicBornIdentityV1) -> Result<OriginalBirthSetupV1>,
    ) -> Result<[Self; 3]> {
        let credentials = EphemeralOwnerCredentials::from_origin(origin)?;
        let temporary = Arc::new(
            tempfile::Builder::new()
                .prefix("wholepact-synthetic-joined-born-")
                .tempdir()?,
        );
        let anchor = NativeRuntime::entered_pending_birth_for_qualification(
            &temporary.path().join("unfunded-anchor"),
            "synthetic-never-funded-anchor",
        )?;
        let left = NativeRuntime::entered_pending_birth_for_qualification(
            &temporary.path().join("owner-one"),
            "synthetic-never-funded-owner-one",
        )?;
        let right = NativeRuntime::entered_pending_birth_for_qualification(
            &temporary.path().join("owner-two"),
            "synthetic-never-funded-owner-two",
        )?;
        let origin = credentials.origin();
        let pair = finish_three_pending_births(
            temporary.clone(),
            [anchor, left, right],
            |index, identity| {
                let public = PublicBornIdentityV1 {
                    account_id: identity.account_id().into(),
                    full_viewing_key_digest: identity.full_viewing_key_digest().into(),
                    network_profile_id: identity.network_profile_id().into(),
                };
                let setup = setup(index, &public)?;
                if setup.policy.account_id != public.account_id
                    || setup.policy.network_profile_id != public.network_profile_id
                    || setup.policy.witness_id != origin.witness_id
                    || setup.policy.owner_certificate_digest != origin.owner_certificate_digest
                    || setup.policy.initial_writer_certificate_digest
                        != origin.writer_certificate_digest
                    || setup.stable_recipient_policy_json.is_empty()
                {
                    return Err(Error::ReviewMismatch);
                }
                let disclosure = WitnessDisclosureDescriptor {
                    endpoint: origin.endpoint.clone(),
                    server_name: origin.server_name.clone(),
                    witness_id: origin.witness_id.clone(),
                    account_id: public.account_id,
                    network_profile_id: public.network_profile_id,
                    policy_digest: setup
                        .policy
                        .policy_digest()
                        .map_err(|_| Error::InvalidData)?,
                    pinned_server_certificate_digest: origin.server_certificate_digest.clone(),
                };
                Ok(PublicFixtureBirthSetup {
                    disclosure,
                    original_policy: setup.policy,
                    stable_recipient_policy_json: Some(setup.stable_recipient_policy_json),
                })
            },
        )?;
        let mut outputs = Vec::with_capacity(3);
        for (index, pending) in pair.into_iter().enumerate() {
            let exports = temporary
                .path()
                .join(format!("owner-{}-exports", index + 1));
            private_export_directory(&exports)?;
            outputs.push(Self {
                pending,
                credentials: credentials.clone(),
                exports,
            });
        }
        outputs.try_into().map_err(|_| Error::InvalidData)
    }
    /// Separate full-path fixture only: three genuine original witness owners,
    /// each pinned before its corresponding birth, through the same actual
    /// native birth controllers. No caller-root, native decision or key input.
    pub fn create_three_with_original_witnesses(
        origins: [EphemeralWitnessOriginV1; 3],
        mut setup: impl FnMut(usize, &PublicBornIdentityV1) -> Result<OriginalBirthSetupV1>,
    ) -> Result<[Self; 3]> {
        // Each nominal origin was produced by its own concrete native witness
        // before any birth. No endpoint or certificate may be switched later.
        let mut endpoints = std::collections::BTreeSet::new();
        let mut identities = std::collections::BTreeSet::new();
        let mut certificates = std::collections::BTreeSet::new();
        for origin in &origins {
            if origin.endpoint.is_empty()
                || origin.witness_id.is_empty()
                || !endpoints.insert(&origin.endpoint)
                || !identities.insert(&origin.witness_id)
                || [
                    &origin.server_certificate_digest,
                    &origin.owner_certificate_digest,
                    &origin.writer_certificate_digest,
                ]
                .into_iter()
                .any(|certificate| certificate.is_empty() || !certificates.insert(certificate))
            {
                return Err(Error::ReviewMismatch);
            }
        }
        let [anchor_origin, one_origin, two_origin] = origins;
        let credentials = [
            EphemeralOwnerCredentials::from_origin(anchor_origin)?,
            EphemeralOwnerCredentials::from_origin(one_origin)?,
            EphemeralOwnerCredentials::from_origin(two_origin)?,
        ];
        let temporary = Arc::new(
            tempfile::Builder::new()
                .prefix("wholepact-synthetic-joined-born-")
                .tempdir()?,
        );
        let anchor = NativeRuntime::entered_pending_birth_for_qualification(
            &temporary.path().join("unfunded-anchor"),
            "synthetic-never-funded-anchor",
        )?;
        let left = NativeRuntime::entered_pending_birth_for_qualification(
            &temporary.path().join("owner-one"),
            "synthetic-never-funded-owner-one",
        )?;
        let right = NativeRuntime::entered_pending_birth_for_qualification(
            &temporary.path().join("owner-two"),
            "synthetic-never-funded-owner-two",
        )?;
        let pair = finish_three_pending_births(
            temporary.clone(),
            [anchor, left, right],
            |index, identity| {
                let origin = credentials.get(index).ok_or(Error::InvalidData)?.origin();
                let public = PublicBornIdentityV1 {
                    account_id: identity.account_id().into(),
                    full_viewing_key_digest: identity.full_viewing_key_digest().into(),
                    network_profile_id: identity.network_profile_id().into(),
                };
                let setup = setup(index, &public)?;
                if setup.policy.account_id != public.account_id
                    || setup.policy.network_profile_id != public.network_profile_id
                    || setup.policy.witness_id != origin.witness_id
                    || setup.policy.owner_certificate_digest != origin.owner_certificate_digest
                    || setup.policy.initial_writer_certificate_digest
                        != origin.writer_certificate_digest
                    || setup.stable_recipient_policy_json.is_empty()
                {
                    return Err(Error::ReviewMismatch);
                }
                let disclosure = WitnessDisclosureDescriptor {
                    endpoint: origin.endpoint.clone(),
                    server_name: origin.server_name.clone(),
                    witness_id: origin.witness_id.clone(),
                    account_id: public.account_id,
                    network_profile_id: public.network_profile_id,
                    policy_digest: setup
                        .policy
                        .policy_digest()
                        .map_err(|_| Error::InvalidData)?,
                    pinned_server_certificate_digest: origin.server_certificate_digest.clone(),
                };
                Ok(PublicFixtureBirthSetup {
                    disclosure,
                    original_policy: setup.policy,
                    stable_recipient_policy_json: Some(setup.stable_recipient_policy_json),
                })
            },
        )?;
        let mut outputs = Vec::with_capacity(3);
        for (index, (pending, credentials)) in pair.into_iter().zip(credentials).enumerate() {
            let exports = temporary
                .path()
                .join(format!("owner-{}-exports", index + 1));
            private_export_directory(&exports)?;
            outputs.push(Self {
                pending,
                credentials,
                exports,
            });
        }
        outputs.try_into().map_err(|_| Error::InvalidData)
    }
    pub fn account_id(&self) -> &str {
        self.pending.identity.account_id()
    }
    pub fn birth_digest(&self) -> &str {
        &self.pending.birth_digest
    }
    pub fn export_owner_request(self) -> Result<EphemeralExportedBirthV1> {
        let account_id = self.account_id().to_owned();
        let birth_digest = self.birth_digest().to_owned();
        let ui = NativeRuntime::entered_pending_continuation_for_qualification(&self.pending.root)?;
        let inner = retain_sign_and_export(ui, self.pending, &self.credentials, &self.exports)?;
        Ok(EphemeralExportedBirthV1 {
            inner,
            account_id,
            birth_digest,
        })
    }
}

pub struct EphemeralExportedBirthV1 {
    inner: ExportedPendingBirth,
    account_id: String,
    birth_digest: String,
}
impl EphemeralExportedBirthV1 {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn birth_digest(&self) -> &str {
        &self.birth_digest
    }
    /// Exact reviewed, private O_EXCL output made by the production exporter.
    pub fn exported_file(&self) -> &Path {
        &self.inner.exported_file
    }
    /// Requires the independently reviewed original witness to be serving its
    /// genuine committed history. No caller-supplied history is accepted.
    pub fn acknowledge_original(self) -> Result<EphemeralAcknowledgedBornV1> {
        Ok(EphemeralAcknowledgedBornV1 {
            original: self.inner.acknowledge_original_witness()?,
        })
    }
}

pub struct EphemeralAcknowledgedBornV1 {
    original: AcknowledgedBornFixture,
}
impl EphemeralAcknowledgedBornV1 {
    pub fn privacy_domain(&self) -> &str {
        &self.original.privacy_domain
    }
    /// Ordinary public receive address from this genuinely acknowledged
    /// generated account, not viewing material or a substitute wallet fixture.
    pub fn public_receive_address(&self) -> &str {
        &self.original.public_receive_address
    }
    pub fn account_id(&self) -> &str {
        &self.original.account_id
    }
    pub fn birth_digest(&self) -> &str {
        &self.original.birth_digest
    }
    /// Fresh native reentry only after the independent original witness has
    /// committed the exported extension and serves that exact initial attempt.
    pub fn open_initial_publication(
        self,
        request: HostManualRosterPublicationRequestV2,
    ) -> Result<EphemeralRosterPublicationV1> {
        let ui = NativeRuntime::entered_born_roster_for_qualification(&self.original.root)?;
        Ok(EphemeralRosterPublicationV1 {
            inner: PublicationRosterFixture::open(ui, self.original, request)?,
        })
    }
    /// A new actual bounded entry over the original retained account and Host
    /// intent. The prior publication deadline must genuinely have elapsed.
    pub fn open_continuation_intent(
        self,
        intent: HostManualRosterEnrollmentIntentV2,
    ) -> Result<EphemeralContinuationIntentV1> {
        let exports = self.original.temporary.path().join(format!(
            "continuation-{}",
            hex::encode(crate::vault::random::<16>()?)
        ));
        private_export_directory(&exports)?;
        let ui = NativeRuntime::entered_born_roster_for_qualification(&self.original.root)?;
        Ok(EphemeralContinuationIntentV1 {
            inner: ContinuationExportFixture::open(ui, self.original, intent)?,
            exports,
        })
    }
    /// Fresh reentry after independent witness review of the exact signed
    /// successor. Optional disclosure inputs must come from the prepared Host.
    pub fn open_continued_publication(
        self,
        request: HostManualRosterPublicationRequestV2,
        disclosures: Option<ExpectedRosterDisclosuresV1>,
    ) -> Result<EphemeralContinuedPublicationV1> {
        let ui = NativeRuntime::entered_born_roster_for_qualification(&self.original.root)?;
        let publication = ContinuedPublicationFixture::open(ui, self.original, request)?;
        let inner = match disclosures {
            Some(expected) => ContinuedDriver::Disclosures(ContinuedDisclosuresFixture::new(
                publication,
                ExpectedDisclosures {
                    inventory: expected.inventory,
                    inventory_operation: expected.inventory_operation,
                    selection: expected.selection,
                    selection_operation: expected.selection_operation,
                    retention_operation: expected.retention_operation,
                },
            )?),
            None => ContinuedDriver::Publication(publication),
        };
        Ok(EphemeralContinuedPublicationV1 { inner })
    }
    pub fn open_first_anchor_intent(
        self,
        intent: HostManualEnrollmentIntent,
    ) -> Result<EphemeralFirstAnchorIntentV1> {
        let exports = self
            .original
            .temporary
            .path()
            .join("unfunded-first-anchor-export");
        private_export_directory(&exports)?;
        let ui = NativeRuntime::entered_born_single_for_qualification(&self.original.root)?;
        Ok(EphemeralFirstAnchorIntentV1 {
            inner: InitialSingleFixture::open(ui, self.original, intent)?,
            exports,
        })
    }
    pub fn open_first_anchor_publication(
        self,
        request: HostManualEnrollmentRequest,
    ) -> Result<EphemeralFirstAnchorPublicationV1> {
        let ui = NativeRuntime::entered_born_single_for_qualification(&self.original.root)?;
        Ok(EphemeralFirstAnchorPublicationV1 {
            inner: SinglePublicationFixture::open(ui, self.original, request)?,
        })
    }
    pub fn open_initial_intent(
        self,
        intent: HostManualRosterEnrollmentIntentV2,
    ) -> Result<EphemeralOriginalRosterIntentV1> {
        let exports = self
            .original
            .temporary
            .path()
            .join(format!("roster-{}", self.original.account_id));
        private_export_directory(&exports)?;
        let ui = NativeRuntime::entered_born_roster_for_qualification(&self.original.root)?;
        Ok(EphemeralOriginalRosterIntentV1 {
            inner: InitialRosterFixture::open(ui, self.original, intent)?,
            exports,
        })
    }
}

pub struct EphemeralOriginalRosterIntentV1 {
    inner: InitialRosterFixture,
    exports: PathBuf,
}
impl EphemeralOriginalRosterIntentV1 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        current_provider()
    }
    /// Call concurrently with the actual Host's finite intent sender. True means
    /// the actual exact request has been retained, not roster enrollment.
    pub fn poll_initial_intent(&mut self) -> Result<bool> {
        self.inner.poll_intent()
    }
    pub fn export_original_roster(self) -> Result<EphemeralExportedRosterV1> {
        Ok(EphemeralExportedRosterV1 {
            inner: self.inner.export(&self.exports)?,
        })
    }
}

pub struct EphemeralExportedRosterV1 {
    inner: ExportedOriginalRoster,
}
impl EphemeralExportedRosterV1 {
    pub fn signed_extension_file(&self) -> &Path {
        &self.inner.signed_extension_file
    }
    pub fn original_policy_file(&self) -> &Path {
        &self.inner.original_policy_file
    }
    pub fn enrollment_request(&self) -> &HostManualRosterEnrollmentRequestV2 {
        &self.inner.enrollment_request
    }
    /// Ends and joins the initial export-only entry before independent witness
    /// review. It cannot be upgraded in place into a writer-acquisition entry.
    pub fn close_for_witness_review(self) -> EphemeralAcknowledgedBornV1 {
        EphemeralAcknowledgedBornV1 {
            original: self.inner.close_for_independent_witness_review(),
        }
    }
}

/// Retains the actual born controller and original temporary owners. The Host
/// obtains any finite publication lease only from ordinary authenticated IPC.
pub struct EphemeralRosterPublicationV1 {
    inner: PublicationRosterFixture,
}
impl EphemeralRosterPublicationV1 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        current_provider()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn poll_manual_publication(&mut self) -> Result<bool> {
        self.inner.poll_publication()
    }
    pub fn close_for_continuation(self) -> EphemeralAcknowledgedBornV1 {
        EphemeralAcknowledgedBornV1 {
            original: close_publication(self.inner),
        }
    }
}

pub struct EphemeralContinuationIntentV1 {
    inner: ContinuationExportFixture,
    exports: PathBuf,
}
impl EphemeralContinuationIntentV1 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        current_provider()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn poll_continuation_proposal(&mut self) -> Result<bool> {
        self.inner.poll_proposal()
    }
    pub fn export_continuation(self) -> Result<EphemeralExportedContinuationV1> {
        Ok(EphemeralExportedContinuationV1 {
            inner: self.inner.export(&self.exports)?,
        })
    }
}
pub struct EphemeralExportedContinuationV1 {
    inner: ExportedContinuationFixture,
}
impl EphemeralExportedContinuationV1 {
    pub fn exported_file(&self) -> &Path {
        &self.inner.exported_file
    }
    pub fn close_for_witness_review(self) -> EphemeralAcknowledgedBornV1 {
        EphemeralAcknowledgedBornV1 {
            original: self.inner.close(),
        }
    }
}
/// Read-only correlation copied from actual prepared Host scopes. Dynamic
/// request timestamps/caller bindings and leases cannot be supplied here.
pub struct ExpectedRosterDisclosuresV1 {
    pub inventory: wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryScopeV2,
    pub inventory_operation: String,
    pub selection:
        wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionScopeV2,
    pub selection_operation: String,
    pub retention_operation: String,
}
enum ContinuedDriver {
    Publication(ContinuedPublicationFixture),
    Disclosures(ContinuedDisclosuresFixture),
}
pub struct EphemeralContinuedPublicationV1 {
    inner: ContinuedDriver,
}
impl EphemeralContinuedPublicationV1 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        match &self.inner {
            ContinuedDriver::Publication(p) => p.endpoint(),
            ContinuedDriver::Disclosures(p) => p.endpoint(),
        }
    }
    pub fn deadline(&self) -> Result<Instant> {
        match &self.inner {
            ContinuedDriver::Publication(p) => p.deadline(),
            ContinuedDriver::Disclosures(p) => p.deadline(),
        }
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        current_provider()
    }
    pub fn poll_manual_publication_and_disclosures(&mut self) -> Result<bool> {
        match &mut self.inner {
            ContinuedDriver::Publication(p) => p.poll_publication(),
            ContinuedDriver::Disclosures(p) => p.poll(),
        }
    }
    pub fn close_for_next_continuation(self) -> EphemeralAcknowledgedBornV1 {
        EphemeralAcknowledgedBornV1 {
            original: match self.inner {
                ContinuedDriver::Publication(p) => p.close(),
                ContinuedDriver::Disclosures(p) => p.close(),
            },
        }
    }
}

pub struct EphemeralFirstAnchorIntentV1 {
    inner: InitialSingleFixture,
    exports: PathBuf,
}
impl EphemeralFirstAnchorIntentV1 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        current_provider()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn poll_initial_intent(&mut self) -> Result<bool> {
        self.inner.poll_intent()
    }
    pub fn export_original_single(self) -> Result<EphemeralExportedSingleV1> {
        Ok(EphemeralExportedSingleV1 {
            inner: self.inner.export(&self.exports)?,
        })
    }
}
pub struct EphemeralExportedSingleV1 {
    inner: ExportedSingleAnchor,
}
impl EphemeralExportedSingleV1 {
    pub fn signed_extension_file(&self) -> &Path {
        &self.inner.signed_extension_file
    }
    pub fn enrollment_request(&self) -> &HostManualEnrollmentRequest {
        &self.inner.enrollment_request
    }
    pub fn close_for_witness_review(self) -> EphemeralAcknowledgedBornV1 {
        EphemeralAcknowledgedBornV1 {
            original: self.inner.close_for_independent_witness_review(),
        }
    }
}
pub struct EphemeralFirstAnchorPublicationV1 {
    inner: SinglePublicationFixture,
}
impl EphemeralFirstAnchorPublicationV1 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        current_provider()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn poll_manual_publication(&mut self) -> Result<bool> {
        self.inner.poll_publication()
    }
    /// The original V1 audit stays V1; this does not migrate it to roster V2.
    pub fn close_for_continuation(self) -> EphemeralAcknowledgedBornV1 {
        EphemeralAcknowledgedBornV1 {
            original: self.inner.close(),
        }
    }
}

fn current_provider() -> Result<InstalledSignerProvider> {
    InstalledSignerProvider::qualification_current_process().map_err(|_| Error::Authentication)
}
fn private_export_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

#[path = "born_joined_construction_v3.rs"]
mod construction_fixture;
pub use construction_fixture::{
    EphemeralCommonContextCompletionV3, EphemeralCommonContextReadV3, EphemeralConsumedNamedV3,
    EphemeralDormantCommonContextV3, EphemeralExportedFullPlanV3, ExpectedCommonContextReadV3Input,
    ExpectedCompletionOperationsV3Input,
};

#[path = "born_joined_named_v1.rs"]
mod named_fixture;
pub use named_fixture::EphemeralNamedPaymentV1;

pub use crate::native_ui::named_verifier_owner::EphemeralNamedVerifierV1;

pub use crate::consent_journal::OriginalNamedSetupMetadataV1;

pub use crate::consent_journal::{
    OriginalNamedPaymentArtifactsV1, OriginalNamedReturnReferencesV1,
};

/// Emit fixed, synthetic-only inclusive timing counters after scenario teardown.
/// This accepts no owner, clock, identifier, or caller-selected payload and has
/// no effect on authorization or the returned scenario result.
pub fn emit_synthetic_timing_summary() {
    super::born_manual_roster_v2::emit_synthetic_timing_summary();
}

#[cfg(feature = "durable-proposal")]
#[path = "durable_proposal_v1/facade.rs"]
mod durable_proposal_fixture;
#[cfg(feature = "durable-proposal")]
pub use durable_proposal_fixture::*;
