//! Unconnected owner-private issuer. A future native caller must obtain the
//! immutable anchor from its born-vault owner, not from host/journal JSON. No IPC
//! handler or native button invokes this module, and no witness activation occurs.
use super::*;
use crate::{
    account::{
        AccountVault,
        birth::{BirthAnchor, BirthAnchorRead},
    },
    consent_journal::{RetiredLocalSnapshot, SignerConsentJournal},
    ipc::AuthenticatedPeer,
    native_ui::{NativeAuthority, NativeAuthorityBinding, NativeDecision},
};
use wholepact_authority::{AuthorityClient, account_use_link::reconcile_account_exclusion};

const REVIEW_LIFETIME: Duration = Duration::from_secs(120);

pub(crate) struct PreparedRetiredHistoryDisclosure {
    request: RetiredHistoryRequest,
    local: RetiredLocalSnapshot,
    anchor: BirthAnchor,
    peer: AuthenticatedPeer,
    source: NativeAuthorityBinding,
    digest: String,
    native_principal: String,
    native_measurement: String,
    started: Instant,
}
pub(crate) struct ApprovedRetiredHistoryDisclosure(PreparedRetiredHistoryDisclosure);

fn permission(_: impl std::fmt::Display) -> BridgeError {
    BridgeError::Permission
}
fn binding(_: impl std::fmt::Display) -> BridgeError {
    BridgeError::Binding
}
fn recipient(peer: &AuthenticatedPeer) -> RetiredHistoryRecipient {
    RetiredHistoryRecipient {
        grant_id: peer.grant_id.clone(),
        channel_digest: peer.channel_digest.clone(),
        process_instance: peer.peer.instance().into(),
        uid: peer.peer.uid(),
        pid: peer.peer.pid(),
        application_label: peer.label.clone(),
    }
}
fn require_anchor(
    request: &RetiredHistoryRequest,
    anchor: &BirthAnchor,
    vault: &AccountVault,
) -> Result<()> {
    anchor
        .validate_historical_account(vault.account())
        .map_err(binding)?;
    let origin = anchor.witness_origin();
    if anchor.expected_account_use_genesis().map_err(binding)? != request.expected_genesis
        || origin.endpoint() != request.original_witness.endpoint
        || origin.server_name() != request.original_witness.server_name
        || origin.witness_id() != request.original_witness.witness_id
        || origin.pinned_server_certificate_digest()
            != request.original_witness.pinned_server_certificate_digest
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl PreparedRetiredHistoryDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        request: RetiredHistoryRequest,
        journal: &SignerConsentJournal,
        vault: &AccountVault,
        born: &BirthAnchorRead<'_>,
        peer: AuthenticatedPeer,
        authority: &NativeAuthority,
    ) -> Result<Self> {
        let anchor = born.anchor();
        request.validate()?;
        authority.check_current().map_err(permission)?;
        peer.check_current().map_err(permission)?;
        let source = authority.binding();
        if peer.native_origin != source
            || !peer.scope.history_read
            || peer.scope.account_id != request.expected_genesis.identity.account_id
        {
            return Err(BridgeError::Permission);
        }
        validate_recipient(&recipient(&peer))?;
        require_anchor(&request, anchor, vault)?;
        let local = journal.retired_history_snapshot(&request.expected_genesis)?;
        let digest = canonical(
            "wholepact:native-retired-history-disclosure:v1",
            &(
                &request,
                local.audit(),
                recipient(&peer),
                authority.principal_id(),
                authority.measurement(),
                crate::vault::random::<32>().map_err(binding)?,
            ),
        )?;
        Ok(Self {
            request,
            local,
            anchor: anchor.clone(),
            peer,
            source,
            digest,
            native_principal: authority.principal_id().into(),
            native_measurement: authority.measurement().into(),
            started: Instant::now(),
        })
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    fn check_current(&self) -> Result<()> {
        self.source.check_current().map_err(permission)?;
        self.peer.check_current().map_err(permission)?;
        if self.started.elapsed() >= REVIEW_LIFETIME {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        let details = serde_json::to_string_pretty(&(
            &self.request,
            self.local.audit(),
            recipient(&self.peer),
        ))
        .map_err(binding)?;
        if details.len() > MAX_AUDIT_BYTES {
            return Err(BridgeError::Limit);
        }
        Ok(format!(
            "DISCLOSE RETIRED ACCOUNT HISTORY FOR THIS EXACT HOST INVENTORY\n\nThis authorizes a complete authenticated historical read from the original displayed witness and disclosure to the exact paired process below. It discloses account identity and FVK digest, immutable birth/genesis/origin, local retirement and pending acknowledgment state, all witnessed authorization, agreement, obligation, input/nullifier, amount, fee and automatic-key-use metadata.\n\nThe witness must already contain this account's permanent exclusion. Every permit remains conservative exposure, including consumed, expired or resolved records. Lifetime consumed capacity stays visible. A pending local exclusion stays pending; this read does not record an acknowledgment, clear recovery flags, retire an account, erase obligations or establish absence of signatures outside this witness. Unknown legacy and offline-origin history are unsupported.\n\nOnly an informational audit for the exact inventory, semantic inventory, generation, plan, target and paired process is returned. This is no active writer admission, signing consent, dispatch permission, enrollment or durable host publication approval. Local read transactions reserve nothing; no financial freshness is asserted.\n\nThe complete remote replay occurs only after this native decision. Its observed immutable head is historical, not a promise that no later event exists.\n\nExact request, preserved local state and recipient:\n{details}\n\nNative principal: {}\nNative measurement: {}\nNative review binding: {}",
            self.native_principal, self.native_measurement, self.digest
        ))
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedRetiredHistoryDisclosure> {
        self.check_current()?;
        authority.check_current().map_err(permission)?;
        if self.source != authority.binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(BridgeError::Permission);
        }
        Ok(ApprovedRetiredHistoryDisclosure(self))
    }
}
impl ApprovedRetiredHistoryDisclosure {
    /// Only this genuine-decision path constructs the opaque disclosure. A full
    /// authenticated replay supplies exclusion/head evidence; no writer-session
    /// acquisition or admission is requested. The output stays process-local.
    pub(crate) fn observe<'a>(
        self,
        journal: &'a SignerConsentJournal,
        vault: &AccountVault,
        client: &AuthorityClient,
    ) -> Result<RetiredHistoryDisclosureAdmission<'a>> {
        let p = self.0;
        p.check_current()?;
        require_anchor(&p.request, &p.anchor, vault)?;
        if !p
            .local
            .same_original(&journal.retired_history_snapshot(&p.request.expected_genesis)?)
            || client.disclosure_descriptor() != p.request.original_witness
        {
            return Err(BridgeError::Binding);
        }
        let started = Instant::now();
        let history = client.reconcile_history()?;
        history.require_legacy_online_only()?;
        let linked = p
            .anchor
            .audit_historical_witness_link(&history)
            .map_err(binding)?;
        let exclusion = linked
            .permanent_exclusion()
            .ok_or(BridgeError::RecoveryRequired)?
            .clone();
        if linked.genesis() != &p.request.expected_genesis
            || linked.original_disclosure() != &p.request.original_witness
        {
            return Err(BridgeError::Binding);
        }
        let receipt = reconcile_account_exclusion(
            &history,
            &p.request.expected_genesis,
            &p.request.original_witness,
            &exclusion,
        )?;
        p.local.audit().validate_against(
            &p.request.expected_genesis,
            &exclusion,
            receipt.evidence(),
        )?;
        if !p
            .local
            .same_original(&journal.retired_history_snapshot(&p.request.expected_genesis)?)
            || started.elapsed() >= DISCLOSURE_LIFETIME
        {
            return Err(BridgeError::Binding);
        }
        p.check_current()?;
        let record = RetiredHistoryAuditRecord {
            purpose: RetiredHistoryPurpose::InformationalRetiredHistoryOnly,
            request: p.request.clone(),
            local: p.local.audit().clone(),
            recipient: recipient(&p.peer),
            native_review_digest: p.digest.clone(),
            witness_policy: history.account_policy().clone(),
            witnessed_exclusion: exclusion,
            witnessed_ack: receipt.evidence().clone(),
            snapshot: history.snapshot().clone(),
            history_digest: history.history_digest()?,
            conservative_permits: history.permits()?.to_vec(),
            automatic_key_use_history: history.automatic_key_use_admissions().to_vec(),
        };
        record.validate_audit()?;
        // The retained check follows the actual native/peer lifetime and exact
        // local snapshot. It holds no SQLite transaction, writer or reservation.
        let current = Box::new(move || {
            p.check_current()?;
            if !p
                .local
                .same_original(&journal.retired_history_snapshot(&p.request.expected_genesis)?)
            {
                return Err(BridgeError::Binding);
            }
            Ok(())
        });
        Ok(RetiredHistoryDisclosureAdmission {
            record,
            issued: started,
            current,
        })
    }
}
