//! Genuine consumed-source continuation. Local consent is separately reviewed;
//! neither the V3 decision nor this retained owner authorizes a transaction.
use super::super::{AuthenticatedPairing, NativeDecision, PendingAccountNativeAuthority};
use super::common_context_handoff::PinnedOwnerSigner;
use crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::ConsumedBornNamedSourceV1;
use crate::consent_journal::{
    AccountEnrollmentRecord, AcceptedManifestRecord, AuthenticatedTransportIdentity,
    EnrollmentRequest, PreparedEnrollment, PreparedManifestAcceptance, SignerConsentSession,
};
use crate::{Error, Result};
use std::sync::Arc;
use wholepact_authority::AuthorityClient;

pub(in crate::native_ui) struct ConsumedBornNamedOwnerV1 {
    source: ConsumedBornNamedSourceV1,
    witness: Arc<super::super::witness_workspace::NativeWitnessWorkspace>,
    signer: PinnedOwnerSigner,
    session: Option<Arc<SignerConsentSession>>,
    enrollment: Option<AccountEnrollmentRecord>,
    manifest: Option<AcceptedManifestRecord>,
}
impl ConsumedBornNamedOwnerV1 {
    pub(super) fn from_consumed(
        source: ConsumedBornNamedSourceV1,
        client: AuthorityClient,
        signer: PinnedOwnerSigner,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check(owner)?;
        let disclosure = client.disclosure_descriptor();
        let t = &source.construction().extension.account_extension.terms;
        if disclosure.account_id != t.identity.account_id
            || disclosure.network_profile_id != t.identity.network_profile_id
            || disclosure.policy_digest != t.original_policy_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let witness = Arc::new(
            super::super::witness_workspace::NativeWitnessWorkspace::from_consumed_born_named(
                &source, owner, client,
            )?,
        );
        let (enrollment, manifest) = source.local_records(owner)?;
        if enrollment.is_some() != manifest.is_some() {
            return Err(Error::RecoveryRequired);
        }
        Ok(Self {
            source,
            witness,
            signer,
            session: None,
            enrollment,
            manifest,
        })
    }
    pub(super) fn into_dormant(self) -> Result<crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::DormantConsumedBornNamedSourceV1>{
        let Self {
            source,
            witness,
            signer,
            session,
            enrollment,
            manifest,
        } = self;
        // Called only on the retired worker, after actual foreground revocation
        // and every admitted worker drain. No private clone enters the token.
        drop((session, enrollment, manifest, witness, signer));
        source.into_dormant()
    }
    pub(in crate::native_ui) fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.source.check(owner)
    }
    pub(super) fn prepare_enrollment(
        &mut self,
        pairing: &AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Option<PreparedEnrollment>> {
        self.check(owner)?;
        if self.session.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let session = self.source.local_consent_session(pairing, owner)?;
        match (&self.enrollment, &self.manifest) {
            (Some(enrollment), Some(manifest)) => {
                // Historical rows remain unchanged. The new actual source,
                // native entry and paired Host issue only this new read lease.
                let records = self.source.journal().acquire_preconstruction_records(
                    enrollment.reference(),
                    manifest.reference(),
                    &session,
                )?;
                records.require_native_origin(&owner.native().binding())?;
                records.check_current()?;
                drop(records);
                self.session = Some(session);
                return Ok(None);
            }
            (None, None) => {}
            _ => return Err(Error::RecoveryRequired),
        }
        let plan = &self
            .source
            .construction()
            .reservation
            .request
            .construction
            .plan;
        let proposal = plan.validate().map_err(|_| Error::InvalidData)?;
        let prepared = session.prepare_enrollment(
            self.source.vault().account(),
            &proposal,
            AuthenticatedTransportIdentity::from_native(pairing)?,
            EnrollmentRequest {
                participant_id: plan.enrollment().scope.participant_id.clone(),
                aggregate_budget_limit_zatoshis: plan.enrollment().scope.aggregate_budget_zatoshis,
            },
        )?;
        self.session = Some(session);
        Ok(Some(prepared))
    }
    pub(super) fn approve_enrollment(
        &mut self,
        prepared: PreparedEnrollment,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedManifestAcceptance> {
        self.check(owner)?;
        if self.enrollment.is_some() || self.manifest.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let session = self.session.as_ref().ok_or(Error::Locked)?;
        let approved = session.approve_enrollment(prepared, session.native_decision(decision)?)?;
        let binding = owner.native().binding();
        let _lease = binding.publication_lease()?;
        self.check(owner)?;
        let enrollment = self.source.journal().record_enrollment(approved)?;
        self.enrollment = Some(enrollment.clone());
        self.check(owner)?;
        let proposal = self
            .source
            .construction()
            .reservation
            .request
            .construction
            .plan
            .validate()
            .map_err(|_| Error::InvalidData)?;
        Ok(session.prepare_manifest(&enrollment, &proposal)?)
    }
    pub(super) fn approve_manifest(
        &mut self,
        prepared: PreparedManifestAcceptance,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        if self.enrollment.is_none() || self.manifest.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let session = self.session.as_ref().ok_or(Error::Locked)?;
        let approved = session.approve_manifest(prepared, session.native_decision(decision)?)?;
        let binding = owner.native().binding();
        let _lease = binding.publication_lease()?;
        self.check(owner)?;
        self.manifest = Some(self.source.journal().record_accepted_manifest(approved)?);
        self.check(owner)
    }
    pub(in crate::native_ui) fn source(&self) -> &ConsumedBornNamedSourceV1 {
        &self.source
    }
    pub(in crate::native_ui) fn client(&self) -> &AuthorityClient {
        self.witness.client()
    }
    pub(super) fn signer(&self) -> &PinnedOwnerSigner {
        &self.signer
    }
    pub(in crate::native_ui) fn session(&self) -> Result<&Arc<SignerConsentSession>> {
        self.session.as_ref().ok_or(Error::Locked)
    }
    pub(in crate::native_ui) fn local_records(
        &self,
    ) -> Result<(&AccountEnrollmentRecord, &AcceptedManifestRecord)> {
        Ok((
            self.enrollment.as_ref().ok_or(Error::Locked)?,
            self.manifest.as_ref().ok_or(Error::Locked)?,
        ))
    }
}

impl ConsumedBornNamedOwnerV1 {
    pub(in crate::native_ui) fn witness(
        &self,
    ) -> &Arc<super::super::witness_workspace::NativeWitnessWorkspace> {
        &self.witness
    }
    #[cfg(feature = "offline-review-foundation")]
    pub(in crate::native_ui) fn context<'a>(
        &'a self,
        owner: &'a PendingAccountNativeAuthority,
    ) -> Result<super::super::wallet_workspace::NamedRecipientOwnerContext<'a>> {
        owner.check_current()?;
        self.source.native_binding().check_current()?;
        let (enrollment, manifest) = self.local_records()?;
        Ok(super::super::wallet_workspace::NamedRecipientOwnerContext {
            journal: self.source.journal(),
            session: self.session()?,
            enrollment_ref: enrollment.reference(),
            manifest_ref: manifest.reference(),
            vault: self.source.vault(),
            authority: owner.native(),
            born: Some((&self.source, owner)),
        })
    }
}
