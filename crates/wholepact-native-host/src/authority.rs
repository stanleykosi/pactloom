//! Native consent is session-only and exactly bound. A counted fence serializes
//! revocation with held effects, including async observation leases. No production
//! allow-all controller or caller-supplied approval bit exists.
#[cfg(all(feature = "financial-runtime", feature = "manual-admission", target_os = "linux"))]
pub(crate) mod born_post_return_inputs_v1;
#[cfg(feature = "financial-runtime")]
pub(crate) mod construction;
#[cfg(feature = "financial-runtime")]
pub(crate) mod financial;
#[cfg(all(
    feature = "financial-runtime",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) mod manual_candidate_selection;
#[cfg(all(
    feature = "financial-runtime",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) mod manual_inventory;
#[cfg(all(
    feature = "financial-runtime",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) mod manual_roster_candidate_selection_v2;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) mod manual_roster_common_context_read_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) mod manual_roster_exact_input_observation_v1;
#[cfg(all(
    feature = "financial-runtime",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) mod manual_roster_inventory_v2;
#[cfg(feature = "financial-runtime")]
pub(crate) mod portable;
#[cfg(feature = "financial-runtime")]
pub(crate) mod positive_settlement;
#[cfg(feature = "financial-runtime")]
mod proposal_review;
#[cfg(feature = "financial-runtime")]
pub(crate) mod record_retention;
#[cfg(feature = "financial-runtime")]
pub(crate) mod retention;
mod settlement;
#[cfg(feature = "financial-runtime")]
pub(crate) mod submission;
#[cfg(all(feature = "financial-runtime", feature = "durable-proposal"))]
pub(crate) mod durable_submission_v1;
use crate::{Error, Result, id, now, terminal::Terminal};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Condvar, Mutex},
};
use wholepact_core::records::ObservationWindow;
use wholepact_engine::{
    ApiError,
    participant_records::{
        ParticipantRecordAction, ParticipantRecordAuthority, ParticipantRecordLease,
        ParticipantRecordScope, RecordStoreBinding,
    },
};
use wholepact_service::{
    operator::TaskFailure,
    operator_chain::{ObservationAuthority, ObservationLease, ObservationScope},
    protected_transport::*,
};
use wholepact_transport::{
    DisclosureField, DisclosurePreview, MessageContext, Timestamp, TransportPublicKey,
    TransportSecret,
};
use zeroize::Zeroizing;

#[derive(Default)]
struct FenceState {
    blocked: bool,
    active: usize,
}
#[derive(Default)]
pub(crate) struct Fence {
    state: Mutex<FenceState>,
    done: Condvar,
}
pub(crate) struct Held {
    fence: Arc<Fence>,
    expires: u64,
}
impl Fence {
    pub(crate) fn acquire(self: &Arc<Self>, expires: u64) -> Result<Held> {
        let mut s = self.state.lock().map_err(|_| Error::Permission)?;
        if s.blocked || expires <= now()? {
            return Err(Error::Permission);
        }
        s.active = s.active.checked_add(1).ok_or(Error::Invalid)?;
        Ok(Held {
            fence: self.clone(),
            expires,
        })
    }
    /// Blocks future effects immediately, then waits for all existing leases.
    /// A return guarantees no effect still holds old permission.
    pub(crate) fn revoke(&self) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Error::Permission)?;
        s.blocked = true;
        while s.active != 0 {
            s = self.done.wait(s).map_err(|_| Error::Permission)?;
        }
        Ok(())
    }
}
impl Held {
    pub(crate) fn check(&self) -> Result<()> {
        let s = self.fence.state.lock().map_err(|_| Error::Permission)?;
        if s.blocked || self.expires <= now()? {
            Err(Error::Permission)
        } else {
            Ok(())
        }
    }
}
impl Drop for Held {
    fn drop(&mut self) {
        if let Ok(mut s) = self.fence.state.lock() {
            s.active = s.active.saturating_sub(1);
            if s.active == 0 {
                self.fence.done.notify_all();
            }
        }
    }
}
struct Pin {
    principal: String,
    context: MessageContext,
    direction: TransportDirection,
    peer: TransportPublicKey,
}
pub(crate) struct Authority {
    terminal: Terminal,
    profile: String,
    runtime: String,
    principal: Mutex<Option<String>>,
    store: RecordStoreBinding,
    secret: Zeroizing<[u8; 32]>,
    pins: Mutex<BTreeMap<String, Pin>>,
    observation: Mutex<Option<(ObservationScope, u64)>>,
    pub(crate) fence: Arc<Fence>,
}
impl Authority {
    pub(crate) fn new(
        terminal: Terminal,
        profile: String,
        store: RecordStoreBinding,
        secret: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        Ok(Self {
            terminal,
            profile,
            runtime: hex::encode(crate::random::<16>()?),
            principal: Mutex::new(None),
            store,
            secret,
            pins: Mutex::new(BTreeMap::new()),
            observation: Mutex::new(None),
            fence: Arc::new(Fence::default()),
        })
    }
    pub(crate) fn enroll(&self, principal: &str) -> Result<()> {
        id(principal)?;
        let mut p = self.principal.lock().map_err(|_| Error::Permission)?;
        if p.is_some() {
            return Err(Error::Permission);
        }
        *p = Some(principal.into());
        Ok(())
    }
    fn principal(&self, p: &str) -> Result<()> {
        if self
            .principal
            .lock()
            .map_err(|_| Error::Permission)?
            .as_deref()
            != Some(p)
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
    pub(crate) fn pin(
        &self,
        principal: &str,
        context: MessageContext,
        direction: TransportDirection,
        peer: TransportPublicKey,
    ) -> Result<()> {
        self.principal(principal)?;
        let detail = format!(
            "Pin a non-signing transport peer for this exact session scope. This is not human, receiving-address or wallet ownership verification.\nProfile: {}\nRuntime: {}\nPrincipal: {principal}\nContext: {}\nDirection: {}\nPeer public key: {}\nPeer fingerprint: {}\nExpires: lock, restart or revoke\n",
            self.profile,
            self.runtime,
            serde_json::to_string_pretty(&context)?,
            match direction {
                TransportDirection::Incoming => "incoming",
                TransportDirection::Outgoing => "outgoing",
            },
            hex::encode(peer.as_bytes()),
            peer.fingerprint()
        );
        self.terminal.confirm(&detail)?;
        let _held = self.fence.acquire(now()?.saturating_add(60))?;
        let key = pin_key(principal, &context, direction)?;
        let mut pins = self.pins.lock().map_err(|_| Error::Permission)?;
        if pins.len() >= 64 || pins.contains_key(&key) {
            return Err(Error::Permission);
        }
        pins.insert(
            key,
            Pin {
                principal: principal.into(),
                context,
                direction,
                peer,
            },
        );
        Ok(())
    }
    pub(crate) fn approve_observation(&self, scope: ObservationScope, expires: u64) -> Result<()> {
        if scope.profile_id != self.profile
            || expires <= now()?
            || expires > now()?.saturating_add(3600)
        {
            return Err(Error::Permission);
        }
        self.terminal.confirm(&format!("Allow READ-ONLY transaction linkage disclosure to precisely these providers until Unix time {expires}. The descriptor was loaded from the retained submission journal. This does not submit, sign, clear exposure, or prove consensus.\nProfile: {}\nRuntime: {}\nExact scope: {scope:#?}",self.profile,self.runtime))?;
        let _held = self.fence.acquire(expires)?;
        *self.observation.lock().map_err(|_| Error::Permission)? = Some((scope, expires));
        Ok(())
    }
}
fn pin_key(
    principal: &str,
    context: &MessageContext,
    direction: TransportDirection,
) -> Result<String> {
    Ok(format!(
        "{principal}:{}:{}",
        match direction {
            TransportDirection::Incoming => "i",
            TransportDirection::Outgoing => "o",
        },
        hex::encode(Sha256::digest(serde_json::to_vec(context)?))
    ))
}
fn denied() -> ApiError {
    ApiError::new(
        "PERMISSION_DENIED",
        "A current exact native foreground consent and session enrollment are required",
    )
}
fn api<T>(r: Result<T>) -> std::result::Result<T, ApiError> {
    r.map_err(|_| denied())
}
impl LocalTransportKeyController for Authority {
    fn keys(
        &self,
        scope: &TransportKeyScope,
    ) -> std::result::Result<ProtectedTransportKeys, ApiError> {
        api((|| {
            self.principal(&scope.principal_id)?;
            let _held = self.fence.acquire(now()?.saturating_add(60))?;
            let pins = self.pins.lock().map_err(|_| Error::Permission)?;
            let p = pins
                .get(&pin_key(
                    &scope.principal_id,
                    &scope.context,
                    scope.direction,
                )?)
                .ok_or(Error::Permission)?;
            if p.principal != scope.principal_id
                || p.context != scope.context
                || p.direction != scope.direction
            {
                return Err(Error::Permission);
            }
            Ok(ProtectedTransportKeys {
                local_secret: TransportSecret::from_bytes(*self.secret)?,
                pinned_peer: p.peer.clone(),
            })
        })())
    }
}
struct TransportLease {
    scope: LocalTransportScope,
    action: LocalTransportAction,
    expires: Timestamp,
    held: Held,
}
impl LocalTransportLease for TransportLease {
    fn scope(&self) -> &LocalTransportScope {
        &self.scope
    }
    fn action(&self) -> LocalTransportAction {
        self.action
    }
    fn expires_at(&self) -> &Timestamp {
        &self.expires
    }
    fn check_current(&self) -> std::result::Result<(), ApiError> {
        api(self.held.check())
    }
}
impl LocalTransportConsent for Authority {
    fn acquire<'a>(
        &'a self,
        scope: &LocalTransportScope,
        action: LocalTransportAction,
        preview: &DisclosurePreview,
        fields: &[DisclosureField],
    ) -> std::result::Result<Box<dyn LocalTransportLease + 'a>, ApiError> {
        api((|| {
            self.principal(&scope.principal_id)?;
            if scope.context != preview.context
                || scope.agreement_id != preview.context.agreement_id
                || scope.artifact_fingerprint != preview.digest()?
            {
                return Err(Error::Permission);
            }
            let expiry = if action == LocalTransportAction::ReadAuthorization {
                if scope.context.artifact_kind != wholepact_transport::ArtifactKind::Authorization {
                    return Err(Error::Permission);
                }
                now()?.saturating_add(900)
            } else if matches!(
                action,
                LocalTransportAction::ReadRetained
                    | LocalTransportAction::ReadSummary
                    | LocalTransportAction::ReadInvitation
                    | LocalTransportAction::RetrieveEncryptedExport
            ) {
                now()?.saturating_add(60)
            } else {
                (preview.order.expires_at.unix_seconds().max(0) as u64)
                    .min(now()?.saturating_add(60))
            };
            let held = self.fence.acquire(expiry)?;
            // Verify actual pinned peer for whichever direction matches this exact preview.
            let pins = self.pins.lock().map_err(|_| Error::Permission)?;
            let own = TransportSecret::from_bytes(*self.secret)?
                .public_key()?
                .fingerprint();
            let matched = pins.values().any(|p| {
                p.principal == scope.principal_id
                    && p.context == scope.context
                    && match p.direction {
                        TransportDirection::Incoming => {
                            preview.sender_key_fingerprint == p.peer.fingerprint()
                                && preview.recipient_key_fingerprint == own
                        }
                        TransportDirection::Outgoing => {
                            preview.recipient_key_fingerprint == p.peer.fingerprint()
                                && preview.sender_key_fingerprint == own
                        }
                    }
            });
            if !matched {
                return Err(Error::Permission);
            }
            drop(pins);
            let mut text = Zeroizing::new(format!(
                "Approve exactly one non-signing transport operation.\nProfile: {}\nRuntime: {}\nPrincipal: {}\nAction: {}\nConsent expires Unix: {expiry}\nExact preview:\n{}\n",
                self.profile,
                self.runtime,
                scope.principal_id,
                action_name(action),
                serde_json::to_string_pretty(preview)?
            ));
            for field in fields {
                let expected = preview
                    .fields
                    .iter()
                    .find(|p| p.name == field.name())
                    .ok_or(Error::Permission)?;
                if expected.byte_length != field.bytes().len() as u64
                    || expected.sha256 != hex::encode(Sha256::digest(field.bytes()))
                {
                    return Err(Error::Permission);
                }
                if matches!(
                    field.name(),
                    "external_spend_signatures_v1" | "finalized_transaction_v1"
                ) {
                    text.push_str(&format!("\nUsable authorization/transaction bytes are not rendered; exact SHA256 {} ({} bytes). Finalized transaction disclosure permits later broadcast by anyone holding the bytes.\n", expected.sha256, expected.byte_length));
                    continue;
                }
                text.push_str(&format!(
                    "\nSelected field {} (exact bytes rendered safely): {}\n",
                    field.name(),
                    match std::str::from_utf8(field.bytes()) {
                        Ok(s) => serde_json::to_string(s)?,
                        Err(_) => format!("hex:{}", hex::encode(field.bytes())),
                    }
                ));
            }
            self.terminal.confirm(&text)?;
            held.check()?;
            Ok(Box::new(TransportLease {
                scope: scope.clone(),
                action,
                expires: Timestamp::from_unix_seconds(expiry as i64)?,
                held,
            }) as Box<dyn LocalTransportLease>)
        })())
    }
}
fn action_name(a: LocalTransportAction) -> &'static str {
    match a {
        LocalTransportAction::RetainIncoming => "retain incoming",
        LocalTransportAction::ReadAuthorization => {
            "read exact authorization signatures under held native permission (no signing approval)"
        }
        LocalTransportAction::ReadRetained => {
            "read/restage retained history without renewing message validity"
        }
        LocalTransportAction::PrepareInvitation => "prepare invitation",
        LocalTransportAction::ReadSummary => "read summary",
        LocalTransportAction::ReadInvitation => "read invitation",
        LocalTransportAction::ImportNonbinding => "import nonbinding participation",
        LocalTransportAction::SealExport => "seal encrypted export",
        LocalTransportAction::RetrieveEncryptedExport => "retrieve committed encrypted export",
    }
}
struct RecordLease {
    scope: ParticipantRecordScope,
    expires: String,
    held: Held,
}
impl ParticipantRecordLease for RecordLease {
    fn scope(&self) -> &ParticipantRecordScope {
        &self.scope
    }
    fn expires_at(&self) -> &str {
        &self.expires
    }
    fn check_current(&self) -> std::result::Result<(), ApiError> {
        api(self.held.check())
    }
}
impl ParticipantRecordAuthority for Authority {
    fn acquire<'a>(
        &'a self,
        scope: &ParticipantRecordScope,
        _window: &ObservationWindow,
    ) -> std::result::Result<Box<dyn ParticipantRecordLease + 'a>, ApiError> {
        api((|| {
            self.principal(&scope.principal_id)?;
            if scope.profile_id != self.profile
                || scope.store != self.store
                || !matches!(
                    scope.action,
                    ParticipantRecordAction::ReadPrivate
                        | ParticipantRecordAction::ReadSummary
                        | ParticipantRecordAction::PreviewDisclosure
                        | ParticipantRecordAction::ExportReceipt
                )
            {
                return Err(Error::Unsupported);
            }
            let expires = now()?.saturating_add(60);
            let held = self.fence.acquire(expires)?;
            self.terminal.confirm(&format!("Access an EXISTING owner-bound protected participant record for the exact action shown. PreviewDisclosure prepares/reads selected fields but grants no file export. ExportReceipt still requires separate exact selected-payload and target approval. This does not establish wallet ownership, spending control, fresh record provenance or complete exposure.\nRuntime: {}\nExact record scope: {scope:#?}\nExpires Unix: {expires}",self.runtime))?;
            held.check()?;
            Ok(Box::new(RecordLease {
                scope: scope.clone(),
                expires: Timestamp::from_unix_seconds(expires as i64)?
                    .as_str()
                    .into(),
                held,
            }) as Box<dyn ParticipantRecordLease>)
        })())
    }
}
struct ObserverLease {
    scope: ObservationScope,
    held: Held,
}
impl ObservationLease for ObserverLease {
    fn scope(&self) -> &ObservationScope {
        &self.scope
    }
    fn check_current(&self, _now: u64) -> std::result::Result<(), TaskFailure> {
        self.held.check().map_err(|_| TaskFailure::PermissionLost)
    }
}
impl ObservationAuthority for Authority {
    fn acquire(
        &self,
        scope: &ObservationScope,
        _now: u64,
    ) -> std::result::Result<Box<dyn ObservationLease + '_>, TaskFailure> {
        let grant = self
            .observation
            .lock()
            .map_err(|_| TaskFailure::PermissionLost)?;
        let (approved, expires) = grant.as_ref().ok_or(TaskFailure::PermissionLost)?;
        if approved != scope {
            return Err(TaskFailure::PermissionLost);
        }
        let held = self
            .fence
            .acquire(*expires)
            .map_err(|_| TaskFailure::PermissionLost)?;
        Ok(Box::new(ObserverLease {
            scope: scope.clone(),
            held,
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revoke_waits_for_effects_and_rejects_future_acquisition() {
        let f = Arc::new(Fence::default());
        let held = f.acquire(now().unwrap() + 60).unwrap();
        let copy = f.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            copy.revoke().unwrap();
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(20))
                .is_err()
        );
        assert!(held.check().is_err());
        drop(held);
        rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        t.join().unwrap();
        assert!(f.acquire(now().unwrap() + 60).is_err());
    }
}
