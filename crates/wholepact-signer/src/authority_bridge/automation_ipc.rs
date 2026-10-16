//! Authenticated two-phase automatic authorization. Descriptors are public claims;
//! only the private live channel owns a continuation. No signature export occurs.
use super::{BridgeError, Result, dispatch_ipc::write_frame, ipc::OriginalHistoryClient};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    os::unix::net::UnixStream,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_core::automation::{
    AutomationAccountPolicy, AutomationGrantTerms, AutomationRequest, evaluate_automation_request,
};
use wholepact_store::{Store, automation::*};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticRequest {
    pub grant_id: String,
    pub candidate_id: String,
    pub artifact_digest: String,
    pub accepted_manifest_digest: String,
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl AutomaticRequest {
    pub fn validate(&self) -> Result<()> {
        for id in [&self.grant_id, &self.candidate_id] {
            crate::review::validate_label(id).map_err(|_| BridgeError::Binding)?;
        }
        hash(&self.artifact_digest)?;
        hash(&self.accepted_manifest_digest)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticDescriptor {
    pub request: AutomationRequest,
    pub policy: AutomationAccountPolicy,
    pub grant: AutomationGrantTerms,
    pub grant_reference: String,
    pub original_consent_ref: String,
    pub grant_revision: u64,
    pub participant_id: String,
    pub expires_at_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticRetained {
    pub result_digest: String,
    pub outbox_digest: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutomaticHistory {
    pub request: AutomaticRequest,
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub retained: Option<AutomaticRetained>,
}
/// Authenticated historical response, never a signing lease or export permit.
/// Public fields are display-only claims after receipt and may be changed by the
/// caller. No trust adapter accepts this object as authority or reconciliation.
/// No public constructor, Deserialize or Clone implementation.
#[non_exhaustive]
pub struct AuthenticatedAutomaticHistory {
    pub request: AutomaticRequest,
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub retained: Option<AutomaticRetained>,
}
/// Historical metadata never carries an executable continuation.
#[allow(clippy::large_enum_variant)] // A linear channel is deliberately returned by value.
pub enum AutomaticAuthorizationAttempt<'a> {
    Prepared(SignerAutomaticAuthorization<'a>),
    Historical(AuthenticatedAutomaticHistory),
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AutomaticResponse {
    Historical {
        history: Box<AutomaticHistory>,
    },
    Prepared {
        lease_id: String,
        descriptor: Box<AutomaticDescriptor>,
    },
    Current {
        lease_id: String,
    },
    Retained {
        lease_id: String,
        authorization_id: String,
        original_consent_ref: String,
        result_digest: String,
        outbox_digest: String,
    },
    Denied,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AutomaticCommand {
    CheckCurrent,
    Execute {
        lease_id: String,
        authorization_id: String,
    },
    Finish,
}
#[cfg(feature = "authority-signing")]
pub(crate) fn write_response(stream: &mut UnixStream, response: &AutomaticResponse) -> Result<()> {
    write_frame(stream, response)
}
#[cfg(feature = "authority-signing")]
pub(crate) fn read_command(
    stream: &UnixStream,
    peer: &crate::ipc::AuthenticatedPeer,
    timeout: Duration,
) -> Result<AutomaticCommand> {
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    let bytes = crate::ipc::read_frame_with_deadline(stream, &peer.peer, timeout)
        .map_err(|_| BridgeError::Ipc)?;
    serde_json::from_slice(&bytes).map_err(|_| BridgeError::Binding)
}
fn now() -> wholepact_store::automation::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(AutomationError::ClockInvalid)
}
/// Non-cloneable, non-deserializable and constructed only after installed signer
/// identity, kernel credentials and the exact paired capability are checked.
pub struct SignerAutomaticAuthorization<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    descriptor: AutomaticDescriptor,
    started: Instant,
    issued_at_ms: u64,
    executed: Cell<bool>,
}
impl OriginalHistoryClient {
    pub fn request_automatic_authorization(
        &self,
        request: &AutomaticRequest,
    ) -> Result<SignerAutomaticAuthorization<'_>> {
        match self.request_automatic_attempt(request)? {
            AutomaticAuthorizationAttempt::Prepared(lease) => Ok(lease),
            AutomaticAuthorizationAttempt::Historical(_) => Err(BridgeError::Uncertain),
        }
    }
    pub fn request_automatic_attempt(
        &self,
        request: &AutomaticRequest,
    ) -> Result<AutomaticAuthorizationAttempt<'_>> {
        request.validate()?;
        let stream = self.open_automatic_request(
            serde_json::json!({"operation":"request_automatic_authorization", "request":request}),
        )?;
        let bytes =
            crate::ipc::read_frame_with_deadline(&stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let (lease_id, descriptor) =
            match serde_json::from_slice(&bytes).map_err(|_| BridgeError::Binding)? {
                AutomaticResponse::Prepared {
                    lease_id,
                    descriptor,
                } => (lease_id, descriptor),
                AutomaticResponse::Historical { history } => {
                    if history.request != *request {
                        return Err(BridgeError::Binding);
                    }
                    crate::review::validate_label(&history.authorization_id)
                        .map_err(|_| BridgeError::Binding)?;
                    hash(&history.original_consent_ref)?;
                    if let Some(retained) = &history.retained {
                        hash(&retained.result_digest)?;
                        hash(&retained.outbox_digest)?;
                    }
                    return Ok(AutomaticAuthorizationAttempt::Historical(
                        AuthenticatedAutomaticHistory {
                            request: history.request,
                            authorization_id: history.authorization_id,
                            original_consent_ref: history.original_consent_ref,
                            retained: history.retained,
                        },
                    ));
                }
                _ => return Err(BridgeError::Permission),
            };
        hash(&lease_id)?;
        hash(&descriptor.grant_reference)?;
        hash(&descriptor.original_consent_ref)?;
        let current = now().map_err(|_| BridgeError::Permission)?;
        if descriptor.grant.grant_id != request.grant_id
            || descriptor.request.proposal_id != request.candidate_id
            || descriptor.request.artifact_digest != request.artifact_digest
            || descriptor.request.manifest_digest != request.accepted_manifest_digest
            || descriptor.grant_revision == 0
            || descriptor.expires_at_ms > descriptor.request.authorization_expires_at_ms
            || descriptor.grant.signer_id != "native-retained-automation-v1"
            || descriptor.grant.verifier_id != "native-exact-automation-v1"
        {
            return Err(BridgeError::Binding);
        }
        self.check_automatic_scope(&descriptor)?;
        evaluate_automation_request(
            &descriptor.policy,
            &descriptor.grant,
            &descriptor.request,
            current,
        )
        .map_err(|_| BridgeError::Permission)?;
        let lease = SignerAutomaticAuthorization {
            client: self,
            stream: Mutex::new(stream),
            lease_id,
            descriptor: *descriptor,
            started: Instant::now(),
            issued_at_ms: current,
            executed: Cell::new(false),
        };
        lease
            .remote_current()
            .map_err(|_| BridgeError::Permission)?;
        Ok(AutomaticAuthorizationAttempt::Prepared(lease))
    }
}
impl SignerAutomaticAuthorization<'_> {
    pub fn descriptor(&self) -> &AutomaticDescriptor {
        &self.descriptor
    }
    fn local_current(&self, now: u64) -> wholepact_store::automation::Result<()> {
        if now < self.issued_at_ms
            || now >= self.descriptor.expires_at_ms
            || self.started.elapsed() >= Duration::from_secs(120)
            || self.started.elapsed().as_millis()
                >= u128::from(
                    self.descriptor
                        .expires_at_ms
                        .saturating_sub(self.issued_at_ms),
                )
        {
            return Err(AutomationError::Denied);
        }
        self.client
            .peer()
            .check_alive()
            .map_err(|_| AutomationError::Unavailable)
    }
    fn remote_current(&self) -> wholepact_store::automation::Result<()> {
        self.local_current(now()?)?;
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| AutomationError::Unavailable)?;
        write_frame(&mut stream, &AutomaticCommand::CheckCurrent)
            .map_err(|_| AutomationError::Unavailable)?;
        let bytes = crate::ipc::read_frame_with_deadline(
            &stream,
            self.client.peer(),
            Duration::from_secs(5),
        )
        .map_err(|_| AutomationError::Unavailable)?;
        match serde_json::from_slice::<AutomaticResponse>(&bytes)
            .map_err(|_| AutomationError::Unavailable)?
        {
            AutomaticResponse::Current { lease_id } if lease_id == self.lease_id => Ok(()),
            _ => Err(AutomationError::Denied),
        }
    }
    /// Uses the caller's original encrypted Store. It never creates another ledger.
    /// No remote operation occurs while a Store transaction is held.
    pub fn authorize_in_store(
        self,
        store: &Store,
    ) -> wholepact_store::automation::Result<AutomaticAuthorizationReceipt> {
        let d = &self.descriptor;
        let trust = ChannelTrust(&self);
        let mut authorizer = ChannelAuthorizer(&self);
        // Store replay is metadata-only, including after grant/recovery changes.
        if store
            .automatic_authorization(&d.request.authorization_id)?
            .is_some()
        {
            return store.authorize_automatically(
                &d.grant.grant_id,
                d.request.clone(),
                &trust,
                &mut authorizer,
            );
        }
        self.remote_current()?;
        match store.authority_account(&d.policy.account_id)? {
            None => {
                store.initialize_authority_account(&d.policy.account_id, d.policy.writer_epoch)?
            }
            Some(a) if a.writer_epoch == d.policy.writer_epoch && !a.recovery_required => {}
            _ => return Err(AutomationError::Denied),
        }
        match store.automation_account(&d.policy.account_id)? {
            None => {
                store.configure_automation_account(d.policy.clone(), None, &trust)?;
            }
            Some(a) if a.policy == d.policy => {}
            _ => return Err(AutomationError::Denied),
        }
        let grant = match store.automation_grant(&d.grant.grant_id)? {
            None => store.create_automation_grant(d.grant.clone(), &trust)?,
            Some(g) if g.terms == d.grant => g,
            _ => return Err(AutomationError::Denied),
        };
        match grant.status {
            AutomationGrantStatus::Draft
                if grant.current_activation_consent_reference.is_none() =>
            {
                store.change_automation_grant(
                    &d.grant.grant_id,
                    grant.revision,
                    AutomationGrantAction::Activate,
                    &trust,
                )?;
            }
            AutomationGrantStatus::Active
                if grant.current_activation_consent_reference.as_deref()
                    == Some(&d.grant_reference) => {}
            _ => return Err(AutomationError::Denied),
        }
        store.authorize_automatically(
            &d.grant.grant_id,
            d.request.clone(),
            &trust,
            &mut authorizer,
        )
    }
}
struct ChannelTrust<'a, 'b>(&'a SignerAutomaticAuthorization<'b>);
struct ChannelReview<'a, 'b> {
    channel: &'a SignerAutomaticAuthorization<'b>,
    review: AutomationReview,
}
impl AutomationLease for ChannelReview<'_, '_> {
    fn consent_reference(&self) -> &str {
        match self.review {
            AutomationReview::Authorize { .. } => &self.channel.descriptor.original_consent_ref,
            _ => &self.channel.descriptor.grant_reference,
        }
    }
    fn check_current(
        &self,
        review: &AutomationReview,
        time: u64,
    ) -> wholepact_store::automation::Result<()> {
        self.channel.local_current(time)?;
        if review != &self.review {
            return Err(AutomationError::Denied);
        }
        let d = &self.channel.descriptor;
        match review {
            AutomationReview::ConfigureAccount { policy, previous }
                if policy == &d.policy && previous.is_none() => {}
            AutomationReview::CreateGrant { terms, account }
                if terms == &d.grant && account.policy == d.policy => {}
            AutomationReview::ChangeGrant {
                grant,
                action: AutomationGrantAction::Activate,
            } if grant.terms == d.grant
                && grant.status == AutomationGrantStatus::Draft
                && grant.current_activation_consent_reference.is_none() => {}
            AutomationReview::Authorize {
                account,
                grant,
                request,
            } if account.policy == d.policy
                && grant.terms == d.grant
                && grant.status == AutomationGrantStatus::Active
                && grant.current_activation_consent_reference.as_deref()
                    == Some(&d.grant_reference)
                && request.as_ref() == &d.request => {}
            _ => return Err(AutomationError::Denied),
        }
        evaluate_automation_request(&d.policy, &d.grant, &d.request, time)?;
        Ok(())
    }
}
impl<'a, 'b> AutomationTrustSource for ChannelTrust<'a, 'b> {
    type Lease = ChannelReview<'a, 'b>;
    fn verifier_id(&self) -> &str {
        "native-exact-automation-v1"
    }
    fn now_ms(&self) -> wholepact_store::automation::Result<u64> {
        now()
    }
    fn acquire(
        &self,
        review: &AutomationReview,
    ) -> wholepact_store::automation::Result<Self::Lease> {
        self.0.remote_current()?;
        let lease = ChannelReview {
            channel: self.0,
            review: review.clone(),
        };
        lease.check_current(review, now()?)?;
        Ok(lease)
    }
}
struct ChannelAuthorizer<'a, 'b>(&'a SignerAutomaticAuthorization<'b>);
impl AutomaticAuthorizer for ChannelAuthorizer<'_, '_> {
    fn signer_id(&self) -> &str {
        "native-retained-automation-v1"
    }
    fn authorize_exact(
        &mut self,
        prepared: PreparedAutomaticAuthorization<'_>,
    ) -> wholepact_store::automation::Result<AutomaticAuthorizationOutcome> {
        prepared.check_current()?;
        let d = &self.0.descriptor;
        if prepared.record().request != d.request
            || prepared.record().grant_id != d.grant.grant_id
            || prepared.record().account_policy_id != d.policy.policy_id
            || prepared.record().active_consent_reference != d.grant_reference
            || prepared.record().authorization_verification_reference != d.original_consent_ref
        {
            return Err(AutomationError::Denied);
        }
        if self.0.executed.replace(true) {
            return Err(AutomationError::AuthorizationUncertain);
        }
        let execute = || -> Result<()> {
            let mut stream = self.0.stream.lock().map_err(|_| BridgeError::Ipc)?;
            write_frame(
                &mut stream,
                &AutomaticCommand::Execute {
                    lease_id: self.0.lease_id.clone(),
                    authorization_id: d.request.authorization_id.clone(),
                },
            )?;
            let bytes = crate::ipc::read_frame_with_deadline(
                &stream,
                self.0.client.peer(),
                Duration::from_secs(120),
            )
            .map_err(|_| BridgeError::Ipc)?;
            match serde_json::from_slice::<AutomaticResponse>(&bytes)
                .map_err(|_| BridgeError::Binding)?
            {
                AutomaticResponse::Retained {
                    lease_id,
                    authorization_id,
                    original_consent_ref,
                    result_digest,
                    outbox_digest,
                } if lease_id == self.0.lease_id
                    && authorization_id == d.request.authorization_id
                    && original_consent_ref == d.original_consent_ref =>
                {
                    hash(&original_consent_ref)?;
                    hash(&result_digest)?;
                    hash(&outbox_digest)
                }
                _ => Err(BridgeError::Permission),
            }
        };
        execute().map_err(|_| AutomationError::AuthorizationUncertain)?;
        Ok(AutomaticAuthorizationOutcome::RetainedLocally)
    }
}
impl Drop for SignerAutomaticAuthorization<'_> {
    fn drop(&mut self) {
        if let Ok(mut stream) = self.stream.lock() {
            let _ = write_frame(&mut stream, &AutomaticCommand::Finish);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> AutomaticRequest {
        AutomaticRequest {
            grant_id: "grant".into(),
            candidate_id: "candidate".into(),
            artifact_digest: "11".repeat(32),
            accepted_manifest_digest: "22".repeat(32),
        }
    }
    #[test]
    fn automatic_ipc_request_is_reference_only_and_strict() {
        let value = request();
        assert!(value.validate().is_ok());
        for field in [
            "pczt_hex",
            "approved",
            "unlocked",
            "execute",
            "authorization_id",
        ] {
            let mut json = serde_json::to_value(&value).unwrap();
            json[field] = serde_json::json!(true);
            assert!(serde_json::from_value::<AutomaticRequest>(json).is_err());
        }
        for case in 0..4 {
            let mut value = request();
            match case {
                0 => value.grant_id.clear(),
                1 => value.candidate_id = "bad\ncandidate".into(),
                2 => value.artifact_digest = "AA".repeat(32),
                _ => value.accepted_manifest_digest = "00".repeat(31),
            }
            assert!(value.validate().is_err());
        }
    }
    #[test]
    fn execute_cannot_embed_approval_or_transaction_bytes() {
        for field in ["approved", "pczt_hex", "signatures", "grant_reference"] {
            let mut value = serde_json::json!({"operation":"execute", "lease_id":"11".repeat(32), "authorization_id":"authorization"});
            value[field] = serde_json::json!(true);
            assert!(serde_json::from_value::<AutomaticCommand>(value).is_err());
        }
        assert!(
            serde_json::from_value::<AutomaticCommand>(
                serde_json::json!({"operation":"execute", "lease_id":"11".repeat(32)})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<AutomaticResponse>(serde_json::json!({"status":"retained", "lease_id":"11".repeat(32), "authorization_id":"authorization", "original_consent_ref":"22".repeat(32), "result_digest":"33".repeat(32), "outbox_digest":"44".repeat(32), "signature_bytes":"00"})).is_err());
    }
}
