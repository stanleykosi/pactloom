//! Authenticated native disclosure intake for durable, NON-SPENDING material.
//! The response closes after one bounded export. Later construction never needs
//! this signer connection to remain alive. Public records are historical data;
//! only the actual authenticated client can produce an intake owner. Same-grant
//! redelivery cannot authorize a new pairing after restart; that needs a new native disclosure.
use super::{BridgeError, Result, ipc::OriginalHistoryClient};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wholepact_core::Proposal;
pub use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
    DurableConstructionScopeV1, HistoricalConstructionMaterialV1,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionRequestV1 {
    pub operation_id: String,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub scope: DurableConstructionScopeV1,
    pub material: HistoricalConstructionMaterialV1,
}
pub(super) fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl DurableConstructionRequestV1 {
    pub fn validate(&self) -> Result<Proposal> {
        crate::review::validate_label(&self.operation_id).map_err(|_| BridgeError::Binding)?;
        hash(&self.enrollment_ref)?;
        hash(&self.accepted_manifest_ref)?;
        self.material
            .validate_for(&self.scope)
            .map_err(|_| BridgeError::Binding)?;
        let raw =
            zeroize::Zeroizing::new(serde_json::to_vec(self).map_err(|_| BridgeError::Binding)?);
        if raw.len() > 120 * 1024 {
            return Err(BridgeError::Limit);
        }
        self.scope.validate().map_err(|_| BridgeError::Binding)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:durable-construction-disclosure-request:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionHistoryRequestV1 {
    pub operation_id: String,
    pub expected_request_digest: String,
}
impl DurableConstructionHistoryRequestV1 {
    pub fn validate(&self) -> Result<()> {
        crate::review::validate_label(&self.operation_id).map_err(|_| BridgeError::Binding)?;
        hash(&self.expected_request_digest)
    }
}
/// A NEW native disclosure to the current authenticated local application.
/// It can recover bytes lost before intake, but cannot renew their validity.
/// An absent digest permits only staging this exact original operation for a
/// new native decision. It does not permit history, metadata or material export.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionRedisclosureSourceV1 {
    pub operation_id: String,
    pub expected_request_digest: Option<String>,
}
impl DurableConstructionRedisclosureSourceV1 {
    pub fn validate(&self) -> Result<()> {
        crate::review::validate_label(&self.operation_id).map_err(|_| BridgeError::Binding)?;
        if let Some(digest) = &self.expected_request_digest {
            hash(digest)?;
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionRedisclosureRequestV1 {
    pub operation_id: String,
    pub original: DurableConstructionRedisclosureSourceV1,
    /// Freshly accepted records from the current native owner. Historical
    /// record references never regain their previous native origin on reload.
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
}
impl DurableConstructionRedisclosureRequestV1 {
    pub fn validate(&self) -> Result<()> {
        crate::review::validate_label(&self.operation_id).map_err(|_| BridgeError::Binding)?;
        self.original.validate()?;
        hash(&self.enrollment_ref)?;
        hash(&self.accepted_manifest_ref)?;
        if self.operation_id == self.original.operation_id {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionRedisclosureLinkV1 {
    pub original_operation_id: String,
    pub original_request_digest: String,
    pub original_outbox_reference: String,
}
/// Historical signer-owned consent/outbox, not a portable authentication proof
/// or an executable permit. Native decision objects never appear on this wire.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionOutboxV1 {
    pub(crate) request: DurableConstructionRequestV1,
    pub(crate) request_digest: String,
    pub(crate) material_digest: String,
    pub(crate) native_review_digest: String,
    pub(crate) native_entry_digest: String,
    pub(crate) recipient_grant_digest: String,
    pub(crate) original_channel_digest: String,
    pub(crate) original_grant_id: String,
    pub(crate) recipient_transport: crate::consent_journal::TransportIdentityBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) redisclosure: Option<DurableConstructionRedisclosureLinkV1>,
    pub(crate) reference: String,
}
impl DurableConstructionOutboxV1 {
    pub fn request(&self) -> &DurableConstructionRequestV1 {
        &self.request
    }
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
    pub fn material_digest(&self) -> &str {
        &self.material_digest
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn recipient_grant_digest(&self) -> &str {
        &self.recipient_grant_digest
    }
    pub fn redisclosure(&self) -> Option<&DurableConstructionRedisclosureLinkV1> {
        self.redisclosure.as_ref()
    }
    /// Data consistency only. The journal separately joins this exact link to
    /// its immutable original row before a new native-approved write.
    pub(crate) fn validate_redisclosure_of(&self, original: &Self) -> Result<()> {
        let link = self.redisclosure.as_ref().ok_or(BridgeError::Binding)?;
        if original.redisclosure.is_some()
            || link.original_operation_id != original.request.operation_id
            || link.original_request_digest != original.request_digest
            || link.original_outbox_reference != original.reference
        {
            return Err(BridgeError::Binding);
        }
        let mut expected = original.request.clone();
        expected.operation_id = self.request.operation_id.clone();
        // These current references are independently joined to the same exact
        // account/FVK/participant/proposal by native preparation and the journal.
        // Only references change; the original row and its origin remain inert.
        expected.enrollment_ref = self.request.enrollment_ref.clone();
        expected.accepted_manifest_ref = self.request.accepted_manifest_ref.clone();
        expected.scope.constructor.authenticated_local_grant_digest =
            self.recipient_grant_digest.clone();
        expected.scope.prover.authenticated_local_grant_digest =
            self.recipient_grant_digest.clone();
        if self.request != expected || self.material_digest != original.material_digest {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub fn recipient_transport(&self) -> &crate::consent_journal::TransportIdentityBinding {
        &self.recipient_transport
    }
    pub fn validate(&self) -> Result<()> {
        if let Some(link) = &self.redisclosure {
            crate::review::validate_label(&link.original_operation_id)
                .map_err(|_| BridgeError::Binding)?;
            hash(&link.original_request_digest)?;
            hash(&link.original_outbox_reference)?;
            if link.original_operation_id == self.request.operation_id {
                return Err(BridgeError::Binding);
            }
        }
        let crate::consent_journal::TransportIdentityBinding::LocalProcess {
            transport_identity_id,
            channel_key_digest,
            channel_binding_digest,
            uid: _,
            pid,
            process_instance,
            signer_generation,
            account_id,
            agreement_id,
            participant_id,
            manifest_digest,
        } = &self.recipient_transport
        else {
            return Err(BridgeError::Binding);
        };
        hash(process_instance)?;
        let proposal = self.request.validate()?;
        if *pid == 0
            || *signer_generation == 0
            || transport_identity_id != &self.original_grant_id
            || channel_key_digest != &self.recipient_grant_digest
            || channel_binding_digest != &self.original_channel_digest
            || account_id != &self.request.scope.account_id
            || agreement_id != &proposal.manifest().agreement.agreement_id
            || participant_id != &self.request.scope.participant_id
            || manifest_digest != proposal.manifest_digest()
        {
            return Err(BridgeError::Binding);
        }
        for h in [
            &self.request_digest,
            &self.material_digest,
            &self.native_review_digest,
            &self.native_entry_digest,
            &self.recipient_grant_digest,
            &self.original_channel_digest,
            &self.reference,
        ] {
            hash(h)?;
        }
        hash(&self.original_grant_id)?;
        let encoded =
            zeroize::Zeroizing::new(serde_json::to_vec(self).map_err(|_| BridgeError::Binding)?);
        if encoded.len() > 128 * 1024 - 64 {
            return Err(BridgeError::Limit);
        }
        if self.request.digest()? != self.request_digest
            || self
                .request
                .material
                .digest()
                .map_err(|_| BridgeError::Binding)?
                != self.material_digest
            || self
                .request
                .scope
                .constructor
                .authenticated_local_grant_digest
                != self.recipient_grant_digest
            || self.request.scope.prover.authenticated_local_grant_digest
                != self.recipient_grant_digest
            || self.compute_reference()? != self.reference
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub(crate) fn compute_reference(&self) -> Result<String> {
        wholepact_core::proposal::canonical_digest(
            "wholepact:durable-construction-consent-outbox:v1",
            &(
                &self.request_digest,
                &self.material_digest,
                &self.native_review_digest,
                &self.native_entry_digest,
                &self.recipient_grant_digest,
                &self.original_channel_digest,
                &self.original_grant_id,
                &self.recipient_transport,
                &self.redisclosure,
            ),
        )
        .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableConstructionResponseV1 {
    Retained {
        outbox: Box<DurableConstructionOutboxV1>,
    },
    Denied,
}
/// Sealed proof that THIS process received this exact immutable outbox from the
/// installed signer on its authenticated channel. No Clone/Deserialize/from-DTO.
/// It is consumed by encrypted engine intake, not by a spending API.
pub struct AuthenticatedDurableConstructionDisclosureV1 {
    outbox: DurableConstructionOutboxV1,
    signer_enrollment_reference: String,
    signer_process_instance: String,
}
impl AuthenticatedDurableConstructionDisclosureV1 {
    pub fn outbox(&self) -> &DurableConstructionOutboxV1 {
        &self.outbox
    }
    pub fn signer_enrollment_reference(&self) -> &str {
        &self.signer_enrollment_reference
    }
    pub fn signer_process_instance(&self) -> &str {
        &self.signer_process_instance
    }
}
impl OriginalHistoryClient {
    pub fn request_durable_construction_v1(
        &self,
        request: &DurableConstructionRequestV1,
    ) -> Result<AuthenticatedDurableConstructionDisclosureV1> {
        request.validate()?;
        let stream = self.open_preconstruction_request(
            serde_json::json!({"operation":"request_durable_construction_v1", "request":request}),
        )?;
        self.receive_durable_construction_v1(
            stream,
            &request.operation_id,
            Some(&request.digest()?),
        )
    }
    pub fn read_durable_construction_v1(
        &self,
        request: &DurableConstructionHistoryRequestV1,
    ) -> Result<AuthenticatedDurableConstructionDisclosureV1> {
        request.validate()?;
        let stream = self.open_preconstruction_request(serde_json::json!({"operation":"request_durable_construction_history_v1", "request":request}))?;
        self.receive_durable_construction_v1(
            stream,
            &request.operation_id,
            Some(&request.expected_request_digest),
        )
    }
    pub fn redisclose_durable_construction_v1(
        &self,
        request: &DurableConstructionRedisclosureRequestV1,
    ) -> Result<AuthenticatedDurableConstructionDisclosureV1> {
        request.validate()?;
        let stream = self.open_preconstruction_request(serde_json::json!({
            "operation":"request_durable_construction_redisclosure_v1", "request":request
        }))?;
        let received = self.receive_durable_construction_v1(stream, &request.operation_id, None)?;
        let link = received.outbox.redisclosure().ok_or(BridgeError::Binding)?;
        if link.original_operation_id != request.original.operation_id
            || request
                .original
                .expected_request_digest
                .as_ref()
                .is_some_and(|digest| &link.original_request_digest != digest)
            || received.outbox.request().enrollment_ref != request.enrollment_ref
            || received.outbox.request().accepted_manifest_ref != request.accepted_manifest_ref
        {
            return Err(BridgeError::Binding);
        }
        Ok(received)
    }
    fn receive_durable_construction_v1(
        &self,
        stream: std::os::unix::net::UnixStream,
        operation: &str,
        expected: Option<&str>,
    ) -> Result<AuthenticatedDurableConstructionDisclosureV1> {
        let observed = self.proved_disclosure_recipient()?;
        let frame =
            crate::ipc::read_frame_with_deadline(&stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let response: DurableConstructionResponseV1 =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Binding)?;
        let DurableConstructionResponseV1::Retained { outbox } = response else {
            return Err(BridgeError::Permission);
        };
        outbox.validate()?;
        self.verify_durable_construction_recipient_v1(outbox.recipient_transport())?;
        if outbox.request.operation_id != operation
            || expected.is_some_and(|expected| outbox.request_digest != expected)
            || outbox.request.scope.account_id != observed.account_id
        {
            return Err(BridgeError::Binding);
        }
        let current = self.proved_disclosure_recipient()?;
        if current != observed {
            return Err(BridgeError::Permission);
        }
        Ok(AuthenticatedDurableConstructionDisclosureV1 {
            outbox: *outbox,
            signer_enrollment_reference: observed.provider_enrollment_reference,
            signer_process_instance: observed.process_instance,
        })
    }
}

#[cfg(test)]
mod redisclosure_request_tests {
    use super::*;

    #[test]
    fn fresh_reference_request_is_data_only_and_refuses_legacy_shape() {
        let request = DurableConstructionRedisclosureRequestV1 {
            operation_id: "new-disclosure".into(),
            original: DurableConstructionRedisclosureSourceV1 {
                operation_id: "original-disclosure".into(),
                expected_request_digest: Some("11".repeat(32)),
            },
            enrollment_ref: "22".repeat(32),
            accepted_manifest_ref: "33".repeat(32),
        };
        request.validate().unwrap();
        let mut native_stage_only = request.clone();
        native_stage_only.original.expected_request_digest = None;
        native_stage_only.validate().unwrap();
        // The ordinary history request still refuses an absent expected digest.
        let locator = serde_json::to_value(&native_stage_only.original).unwrap();
        assert!(serde_json::from_value::<DurableConstructionHistoryRequestV1>(locator).is_err());
        let mut raw = serde_json::to_value(&request).unwrap();
        raw.as_object_mut().unwrap().remove("enrollment_ref");
        assert!(serde_json::from_value::<DurableConstructionRedisclosureRequestV1>(raw).is_err());
        let mut replay = request.clone();
        replay.operation_id = replay.original.operation_id.clone();
        assert!(replay.validate().is_err());
        let mut malformed = request;
        malformed.accepted_manifest_ref = "not-an-accepted-record".into();
        assert!(malformed.validate().is_err());
    }
}

/// Material-free request for the genuine, sequential per-owner initial capture.
/// The old live disclosure permits only initial import/selection. A separate new
/// native decision is mandatory before this helper returns durable admission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionCaptureRequestV1 {
    pub operation_id: String,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub scope: DurableConstructionScopeV1,
}

impl OriginalHistoryClient {
    /// Consume a genuinely new empty protected wallet at the native-approved
    /// exact destination, import this actual owner's disclosed FVK/full birthday,
    /// scan and capture under that owner's live bounded permission, then request
    /// NEW durable consent. No second owner's native lifetime is needed.
    ///
    /// Failure drops the material and returns no durable authority. The initially
    /// approved encrypted wallet import may remain on disk: privacy disclosure is
    /// irreversible, and this method neither deletes it nor claims it was erased.
    #[allow(clippy::too_many_arguments)]
    pub async fn capture_and_request_durable_construction_v1(
        &self,
        original: super::preconstruction_ipc::SignerPreconstructionLease<'_>,
        destination: wholepact_storage_security::EncryptedConnection,
        source: wholepact_chain::ChainAdapter,
        request: DurableConstructionCaptureRequestV1,
    ) -> Result<(
        wholepact_wallet::wallet::protected_sync::ProtectedWalletSync,
        AuthenticatedDurableConstructionDisclosureV1,
    )> {
        use wholepact_wallet::wallet::{
            AccountUuid, DedicatedTestnetWallet,
            protected_sync::{
                BackendIdentity, LocalWalletAccess, ProtectedWalletSync, SyncLimits, TreeState,
                WalletAccessPurpose, account_birthday_from_tree,
            },
        };
        crate::review::validate_label(&request.operation_id).map_err(|_| BridgeError::Binding)?;
        hash(&request.enrollment_ref)?;
        hash(&request.accepted_manifest_ref)?;
        let proposal = request.scope.validate().map_err(|_| BridgeError::Binding)?;
        original.check_current()?;
        let old = original.scope();
        old.validate().map_err(|_| BridgeError::Binding)?;
        if original.sponsor_policy().is_some()
            || original.sponsor_budget()?.is_some()
            || request.scope.version != 2
            || request.scope.proposal != old.proposal
            || request.scope.account_id != old.account_id
            || request.scope.participant_id != old.participant_id
            || request.scope.privacy_domain != old.privacy_domain
            || request.scope.constructor.principal_id != old.principal_id
            || request.scope.prover.principal_id != old.principal_id
            || request.scope.protected_destination != old.operator_destination
            || request.scope.minimum_confirmations != old.minimum_confirmations
            || request.scope.maximum_scan_blocks != old.maximum_blocks
            || source.identity().source_id != old.provider.source_id
            || source.identity().endpoint != old.provider.endpoint
            || source.identity().trust_profile != old.provider.trust_profile
            || !matches!(
                proposal.manifest().agreement.fee_policy,
                wholepact_core::FeePolicy::ProRata
            )
            || proposal
                .manifest()
                .participants
                .iter()
                .any(|p| !p.charges.is_empty())
            || !proposal.manifest().agreement.extensions.is_empty()
            || proposal
                .manifest()
                .inputs
                .iter()
                .any(|i| i.ownership_evidence_ref.is_some())
            || proposal
                .manifest()
                .outputs
                .iter()
                .any(|o| match &o.allocation {
                    wholepact_core::OutputAllocation::Charge { .. } => true,
                    wholepact_core::OutputAllocation::Return {
                        ownership_evidence_ref,
                        ..
                    } => ownership_evidence_ref.is_some(),
                    wholepact_core::OutputAllocation::Recipient { .. } => false,
                })
        {
            return Err(BridgeError::Binding);
        }
        let actual_recipient = self.durable_construction_recipient_v1(&old.principal_id)?;
        if request.scope.constructor != actual_recipient || request.scope.prover != actual_recipient
        {
            return Err(BridgeError::Binding);
        }
        // Join the approved path to the actual authenticated SQLite main handle,
        // not to a caller string or a reconstructed account lookup.
        let identity = destination
            .database_identity()
            .map_err(|_| BridgeError::Binding)?;
        identity
            .check_current(destination.connection())
            .map_err(|_| BridgeError::Binding)?;
        if destination.connection().path() != Some(old.wallet_destination.as_str())
            || std::fs::canonicalize(&old.wallet_destination).map_err(|_| BridgeError::Binding)?
                != std::path::Path::new(&old.wallet_destination)
            || destination
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(|_| BridgeError::Binding)?
                != 0
        {
            return Err(BridgeError::Binding);
        }
        identity
            .check_current(destination.connection())
            .map_err(|_| BridgeError::Binding)?;
        let birthday = &old.birthday;
        let birthday = account_birthday_from_tree(TreeState {
            network: "test".into(),
            height: u64::from(birthday.prior_height),
            hash: birthday.prior_block_hash.clone(),
            sapling_tree: birthday.sapling_tree.clone(),
            orchard_tree: birthday.orchard_tree.clone(),
            ironwood_tree: birthday.ironwood_tree.clone(),
            ..Default::default()
        })
        .map_err(|_| BridgeError::Binding)?;
        original.check_current()?;
        let mut wallet = DedicatedTestnetWallet::from_encrypted_connection(destination)
            .map_err(|_| BridgeError::Binding)?;
        // Schema initialization/migrations can take time. Recheck the real
        // disclosure immediately before the first viewing-key write, not merely
        // before opening the maintained wallet. Failure after import is uncertain
        // persistence, never erasure or permission to reuse the old grant.
        original.check_current()?;
        identity
            .check_retained_owner_path()
            .map_err(|_| BridgeError::Binding)?;
        let account = wallet
            .import_dedicated_fvk(original.fvk(), birthday)
            .map_err(|_| BridgeError::Binding)?;
        identity
            .check_retained_owner_path()
            .map_err(|_| BridgeError::Binding)?;
        original.check_current()?;
        let mut sync = ProtectedWalletSync::from_initialized_wallet(
            wallet,
            source,
            std::num::NonZeroU32::new(old.minimum_confirmations).ok_or(BridgeError::Binding)?,
        )
        .map_err(|_| BridgeError::Binding)?;
        struct InitialCaptureAccess<'a, 'b> {
            original: &'a super::preconstruction_ipc::SignerPreconstructionLease<'b>,
            account: AccountUuid,
            identity: &'a wholepact_storage_security::DatabaseFileIdentity,
        }
        impl LocalWalletAccess for InitialCaptureAccess<'_, '_> {
            fn permits(
                &self,
                account: AccountUuid,
                provider: &BackendIdentity,
                _: WalletAccessPurpose,
            ) -> bool {
                let expected = &self.original.scope().provider;
                self.account == account
                    && provider.source_id == expected.source_id
                    && provider.endpoint == expected.endpoint
                    && provider.trust_profile == expected.trust_profile
                    && self.identity.check_retained_owner_path().is_ok()
                    && self.original.check_current().is_ok()
            }
        }
        let access = InitialCaptureAccess {
            original: &original,
            account,
            identity: &identity,
        };
        sync.verify_account_fvk(original.fvk())
            .map_err(|_| BridgeError::Binding)?;
        sync.synchronize(
            &access,
            SyncLimits {
                maximum_blocks: old.maximum_blocks,
                anchor_height: Some(old.anchor_height),
                deadline: Duration::from_secs(120),
            },
        )
        .await
        .map_err(|_| BridgeError::Permission)?;
        original.check_current()?;
        let debit = proposal
            .accounting()
            .participant_net_debits
            .get(&old.participant_id)
            .ok_or(BridgeError::Binding)?
            .as_zatoshis();
        if debit > old.maximum_net_debit_zatoshis {
            return Err(BridgeError::Binding);
        }
        let selected = sync
            .select_contribution(&access, original.fvk(), &old.account_id, debit, &[])
            .map_err(|_| BridgeError::Permission)?;
        let material = HistoricalConstructionMaterialV1::capture(&selected, &sync)
            .map_err(|_| BridgeError::Binding)?;
        material
            .validate_for(&request.scope)
            .map_err(|_| BridgeError::Binding)?;
        original.check_current()?;
        identity
            .check_retained_owner_path()
            .map_err(|_| BridgeError::Binding)?;
        // Finish the original owner's lease before another human review. Its
        // retained journal read fence must not overlap the new native decision.
        // Captured bytes remain data; only that separate exact decision can
        // approve their durable retention. No original grant is reconstructed.
        drop(selected);
        drop(access);
        original.finish()?;
        let disclosure = self.request_durable_construction_v1(&DurableConstructionRequestV1 {
            operation_id: request.operation_id,
            enrollment_ref: request.enrollment_ref,
            accepted_manifest_ref: request.accepted_manifest_ref,
            scope: request.scope,
            material,
        })?;
        Ok((sync, disclosure))
    }
}
