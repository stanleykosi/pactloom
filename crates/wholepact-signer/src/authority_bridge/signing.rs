//! Actual maintained-library key use. This entry requires the non-deserializable
//! original native continuation, exact authenticated witness permit and a held
//! current signer-owned wallet transaction. No injected verification booleans.
use super::*;
use crate::manifest::{AcceptedManifest, ReviewInputs};
use orchard::keys::SpendAuthorizingKey;
use pczt::{Pczt, roles::signer::Signer};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::Serialize;
use wholepact_wallet::wallet::protected_sync::{
    ProtectedWalletSync,
    key_use::{
        HeldWalletKeyUse, HeldWalletPermission, WalletKeyUseError, WalletKeyUseScope,
        WalletKeyUseTicket,
    },
};
use zeroize::Zeroizing;

#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;

#[derive(Clone, Copy)]
enum KeySource<'a> {
    Generic,
    #[cfg(all(
        feature = "durable-proposal",
        feature = "pending-birth-owner-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    DurableBorn(&'a FreshDurableBornEntryV1),
    // Retain a lifetime in builds without the experimental born branch.
    #[allow(dead_code)]
    Lifetime(std::marker::PhantomData<&'a ()>),
}
impl KeySource<'_> {
    fn check(
        self,
        account: &DedicatedAccount,
        journal: &SignerConsentJournal,
        lease: &OriginalAuthorizationLease<'_>,
    ) -> Result<()> {
        let _ = (journal, lease);
        match self {
            Self::Generic => account
                .require_generic_spending_source()
                .map_err(|_| BridgeError::Permission),
            #[cfg(all(
                feature = "durable-proposal",
                feature = "pending-birth-owner-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            Self::DurableBorn(source) => source
                .require_authorization_identity(account, journal, lease)
                .map_err(|_| BridgeError::Permission),
            Self::Lifetime(_) => Err(BridgeError::Permission),
        }
    }
}

/// Call-local proof created ONLY below the newly committed exact key-use fence.
/// No public constructor, clone, serde or generic callback issuer exists. The
/// private closure binds this actual account/journal, original authorization and
/// permit, current native source and held maintained-wallet transaction.
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) struct DurableBornKeyUseFenceV1<'a> {
    account: &'a DedicatedAccount,
    check: &'a dyn Fn() -> Result<()>,
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    target_os = "linux"
))]
impl DurableBornKeyUseFenceV1<'_> {
    pub(crate) fn require_account(&self, account: &DedicatedAccount) -> crate::Result<()> {
        if !std::ptr::eq(self.account, account) {
            return Err(crate::Error::Authentication);
        }
        (self.check)().map_err(|_| crate::Error::ReviewMismatch)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SignaturePayload<'a> {
    schema_version: u16,
    candidate_id: &'a str,
    manifest_digest: &'a str,
    proved_artifact_digest: &'a str,
    review_binding: &'a str,
    account_id: &'a str,
    signatures: Vec<SignatureRecord>,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SignatureRecord {
    action_index: usize,
    signature_hex: String,
}

impl ReservedAuthorization<'_> {
    fn check_automatic_admission(&self) -> Result<()> {
        match (
            &self.pending.request.reservation.automation,
            &self.automatic_admission,
        ) {
            (None, None) => Ok(()),
            (Some(binding), Some(admission)) => {
                let descriptor = admission.descriptor();
                admission.matches_request(&descriptor.request)?;
                if admission.authenticated_witness_certificate_digest()
                    != self.permit.authenticated_witness_certificate_digest()
                    || &descriptor.request.automation != binding
                    || descriptor.reservation != *self.permit.descriptor()
                    || descriptor.reservation.request != self.pending.request.reservation
                {
                    return Err(BridgeError::Binding);
                }
                let now: u64 = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| BridgeError::Permission)?
                    .as_millis()
                    .try_into()
                    .map_err(|_| BridgeError::Permission)?;
                if now < descriptor.admitted_at_ms
                    || now >= descriptor.request.admission_expires_at_ms
                {
                    return Err(BridgeError::Permission);
                }
                Ok(())
            }
            _ => Err(BridgeError::Permission),
        }
    }
    /// Must be invoked inside ProtectedWalletSync::with_key_use_guard. Returning
    /// only a digest receipt cannot release signatures before durable outbox
    /// commit. A crash/error after the key-use fence is permanently uncertain;
    /// only the already-retained exact result may subsequently be retrieved.
    pub fn sign_and_retain(
        self,
        inputs: &ReviewInputs,
        wallet: &HeldWalletKeyUse<'_>,
    ) -> Result<AuthorizationCommit> {
        self.sign_and_retain_held(inputs, wallet, &|| Ok(()), KeySource::Generic)
    }
    /// Concrete composition: acquire the maintained signer-owned wallet lock and
    /// recheck exactly the original policy, then sign and commit while it is held.
    pub fn authorize_with_wallet(
        self,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
        inputs: &ReviewInputs,
    ) -> Result<AuthorizationCommit> {
        self.authorize_with_wallet_checked(wallet, ticket, inputs, &|| Ok(()))
    }
    /// Store adapters keep their precommitted exact-intent check live through
    /// every real key-use boundary. The callback must not hold its database lock.
    pub(crate) fn authorize_with_wallet_checked(
        self,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
        inputs: &ReviewInputs,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<AuthorizationCommit> {
        self.authorize_with_wallet_source(wallet, ticket, inputs, check, KeySource::Generic)
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "pending-birth-owner-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn authorize_with_wallet_from_durable_born_v1(
        self,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
        inputs: &ReviewInputs,
        check: &dyn Fn() -> Result<()>,
        source: &FreshDurableBornEntryV1,
    ) -> Result<AuthorizationCommit> {
        self.authorize_with_wallet_source(
            wallet,
            ticket,
            inputs,
            check,
            KeySource::DurableBorn(source),
        )
    }
    fn authorize_with_wallet_source(
        self,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
        inputs: &ReviewInputs,
        check: &dyn Fn() -> Result<()>,
        source: KeySource<'_>,
    ) -> Result<AuthorizationCommit> {
        check()?;
        source.check(
            self.pending.account,
            self.pending.journal,
            &self.pending.lease,
        )?;
        let original = self.pending.lease.evidence().original_consent().terms();
        let policy = original
            .wallet_key_use_policy
            .as_ref()
            .ok_or(BridgeError::Permission)?;
        let fvk = self
            .pending
            .account
            .fvk()
            .map_err(|_| BridgeError::Binding)?;
        let permission = OriginalWalletPermission {
            lease: &self.pending.lease,
        };
        wallet.with_key_use_guard(
            &permission,
            ticket,
            &fvk,
            policy,
            original.transaction_expiry_height,
            |held| self.sign_and_retain_held(inputs, held, check, source),
        )
    }
    fn sign_and_retain_held(
        &self,
        inputs: &ReviewInputs,
        wallet: &HeldWalletKeyUse<'_>,
        check: &dyn Fn() -> Result<()>,
        source: KeySource<'_>,
    ) -> Result<AuthorizationCommit> {
        check()?;
        let p = &self.pending;
        source.check(p.account, p.journal, &p.lease)?;
        p.lease.require_current_authorization()?;
        self.check_automatic_admission()?;
        wallet.check_current()?;
        self.permit.matches_request(&p.request.reservation)?;
        let original = p.lease.evidence();
        let t = original.original_consent().terms();
        let bytes = p.request.artifact()?;
        let fvk = p.account.fvk().map_err(|_| BridgeError::Binding)?;
        let wallet_evidence = wallet.evidence();
        if wallet_evidence.account_id() != t.account_id
            || wallet_evidence.fvk().to_bytes() != fvk.to_bytes()
            || wallet.transaction_expiry_height() != t.transaction_expiry_height
        {
            return Err(BridgeError::Binding);
        }
        let context = wallet_evidence.context();
        if context.tip_height != t.wallet_snapshot.tip_height
            || hex::encode(context.tip_hash_protocol) != t.wallet_snapshot.tip_hash
            || context.anchor_height != t.wallet_snapshot.anchor_height
            || hex::encode(context.anchor_hash_protocol) != t.wallet_snapshot.anchor_hash
            || hex::encode(context.anchor_root) != t.wallet_snapshot.anchor_root
            || wallet_evidence.inputs().len() != t.input_bindings.len()
        {
            return Err(BridgeError::Binding);
        }
        for i in &t.input_bindings {
            if !wallet_evidence.inputs().iter().any(|w| {
                w.input_id() == i.input_id
                    && hex::encode(w.nullifier()) == i.nullifier
                    && w.value_zatoshis() == i.value_zatoshis
            }) {
                return Err(BridgeError::Binding);
            }
        }
        validate_original_wallet_policy(t, wallet)?;
        let proposal = wholepact_core::Proposal::validate(
            original.accepted_manifest().proposal_input().clone(),
        )
        .map_err(|_| BridgeError::Binding)?;
        crate::manifest::reconcile(&AcceptedManifest { proposal }, inputs, &t.account_id, &fvk)
            .map_err(|_| BridgeError::Verification)?;
        let reviewed = wholepact_protocol::review::verify_review(&bytes, &inputs.policy)
            .map_err(|_| BridgeError::Verification)?;
        let owner = inputs
            .policy
            .participants
            .iter()
            .position(|p| p.account_id == t.account_id && p.fvk.to_bytes() == fvk.to_bytes())
            .ok_or(BridgeError::Binding)?;
        if reviewed.review_binding() != t.review_binding
            || reviewed.shielded_sighash() != t.effects_digest
            || reviewed.net_debits_zatoshis().get(owner) != Some(&t.maximum_debit_zatoshis)
            || reviewed.fee_zatoshis() != t.transaction_fee_zatoshis
            || inputs.policy.participants[owner].fee_share_zatoshis != t.fee_share_zatoshis
        {
            return Err(BridgeError::Binding);
        }
        let actual: Vec<_> = inputs
            .policy
            .inputs
            .iter()
            .filter(|i| i.participant_index == owner)
            .collect();
        if actual.len() != t.input_bindings.len()
            || actual.iter().any(|i| {
                !t.input_bindings.iter().any(|c| {
                    c.action_index == i.action_index as u64
                        && c.nullifier == hex::encode(i.nullifier)
                        && c.value_zatoshis == i.value_zatoshis
                })
            })
        {
            return Err(BridgeError::Binding);
        }
        wholepact_protocol::proving::verify_proved_candidate(
            &bytes,
            &inputs.policy,
            &t.review_binding,
            wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
        )
        .map_err(|_| BridgeError::Verification)?;
        let parsed = Pczt::parse(&bytes).map_err(|_| BridgeError::Verification)?;
        if inputs.policy.inputs.iter().any(|i| {
            parsed
                .ironwood()
                .actions()
                .get(i.action_index)
                .is_none_or(|a| a.spend().spend_auth_sig().is_some())
        }) {
            return Err(BridgeError::Verification);
        }
        // Commit before deriving the spending key or signing anything. No error
        // below is allowed to clear this fence or produce another signature.
        check()?;
        if self.automatic_admission.is_some() {
            p.journal.bridge_begin_authorized_key_use(
                &p.lease,
                &self.permit,
                self.automatic_admission.as_ref(),
            )?;
        } else {
            p.journal.bridge_begin_key_use(&p.lease, &self.permit)?;
        }
        check()?;
        p.lease.require_current_authorization()?;
        self.check_automatic_admission()?;
        wallet.check_current()?;
        let key_use_check = || {
            check()?;
            source.check(p.account, p.journal, &p.lease)?;
            p.lease.require_current_authorization()?;
            self.check_automatic_admission()?;
            self.permit.matches_request(&p.request.reservation)?;
            wallet.check_current()?;
            Ok(())
        };
        key_use_check()?;
        let sk = match source {
            KeySource::Generic => p
                .account
                .spending_key()
                .map_err(|_| BridgeError::Verification)?,
            #[cfg(all(
                feature = "durable-proposal",
                feature = "pending-birth-owner-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            KeySource::DurableBorn(_) => {
                // The only token constructor is after bridge_begin_key_use.
                // It cannot be reconstructed from the durable row on restart.
                let fence = DurableBornKeyUseFenceV1 {
                    account: p.account,
                    check: &key_use_check,
                };
                p.account
                    .derive_durable_born_spending_key_v1(&fence)
                    .map_err(|_| BridgeError::Verification)?
            }
            KeySource::Lifetime(_) => return Err(BridgeError::Permission),
        };
        let ask = SpendAuthorizingKey::from(&sk);
        let mut signer = Signer::new(parsed).map_err(|_| BridgeError::Verification)?;
        for input in &actual {
            // Recheck each actual action under the same held wallet/native
            // leases; interruption after a prior action retains the fence.
            key_use_check()?;
            signer
                .sign_ironwood(UnwrapErr(SysRng), input.action_index, &ask)
                .map_err(|_| BridgeError::Verification)?;
        }
        let signed = signer.finish();
        let mut signatures = Vec::with_capacity(actual.len());
        for input in actual {
            let signature = signed.ironwood().actions()[input.action_index]
                .spend()
                .spend_auth_sig()
                .ok_or(BridgeError::Verification)?;
            signatures.push(SignatureRecord {
                action_index: input.action_index,
                signature_hex: hex::encode(signature),
            });
        }
        let normalized = pczt::roles::redactor::Redactor::new(signed.clone())
            .redact_ironwood_with(|mut bundle| {
                for input in inputs
                    .policy
                    .inputs
                    .iter()
                    .filter(|i| i.participant_index == owner)
                {
                    bundle.redact_action(input.action_index, |mut action| {
                        action.clear_spend_auth_sig()
                    });
                }
            })
            .finish();
        if pczt::v2::Pczt::try_from(normalized)
            .map_err(|_| BridgeError::Verification)?
            .serialize()
            != *bytes
        {
            return Err(BridgeError::Verification);
        }
        let signed_bytes = Zeroizing::new(
            pczt::v2::Pczt::try_from(signed)
                .map_err(|_| BridgeError::Verification)?
                .serialize(),
        );
        if signed_bytes.len() > protocol::MAX_ARTIFACT_BYTES
            || wholepact_protocol::review::verify_review(&signed_bytes, &inputs.policy)
                .map_err(|_| BridgeError::Verification)?
                .review_binding()
                != t.review_binding
        {
            return Err(BridgeError::Verification);
        }
        let payload = SignaturePayload {
            schema_version: 1,
            candidate_id: &p.request.delivery.candidate_id,
            manifest_digest: &t.manifest_digest,
            proved_artifact_digest: &t.artifact_digest,
            review_binding: &t.review_binding,
            account_id: &t.account_id,
            signatures,
        };
        let outbox_payload =
            Zeroizing::new(serde_json::to_string(&payload).map_err(|_| BridgeError::Binding)?);
        if outbox_payload.len() > protocol::MAX_OUTBOX_BYTES {
            return Err(BridgeError::Limit);
        }
        let result = RetainedAuthorizationResult {
            authorization_id: t.authorization_id.clone(),
            original_consent_ref: original.original_consent().reference().into(),
            request_digest: p.request.reservation.request_digest()?,
            result_digest: hex::encode(Sha256::digest(&signed_bytes)),
            signed_pczt_hex: hex::encode(&signed_bytes),
            outbox_digest: hex::encode(Sha256::digest(outbox_payload.as_bytes())),
            outbox_payload: outbox_payload.to_string(),
        };
        key_use_check()?;
        p.lease.check_current()?;
        p.journal.bridge_retain_result(&p.lease, &result)?;
        Ok(AuthorizationCommit::from(&result))
    }
}

fn validate_original_wallet_policy(
    t: &crate::consent_journal::SpendConsentTerms,
    wallet: &HeldWalletKeyUse<'_>,
) -> Result<()> {
    // The journal owner supplies the exact native-reviewed policy binding. An
    // older/selection-only original cannot silently inherit this permission.
    let approved = t
        .wallet_key_use_policy
        .as_ref()
        .ok_or(BridgeError::Permission)?;
    if approved != wallet.policy() {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

struct OriginalWalletPermission<'a, 'session> {
    lease: &'a OriginalAuthorizationLease<'session>,
}
impl HeldWalletPermission for OriginalWalletPermission<'_, '_> {
    fn check_current(
        &self,
        scope: &WalletKeyUseScope<'_>,
    ) -> std::result::Result<(), WalletKeyUseError> {
        self.lease
            .require_current_authorization()
            .map_err(|_| WalletKeyUseError::Permission)?;
        let original = self.lease.evidence();
        let t = original.original_consent().terms();
        if scope.account_id != t.account_id
            || hex::encode(Sha256::digest(scope.authenticated_fvk.to_bytes()))
                != original.enrollment().account_fvk_digest()
            || t.wallet_key_use_policy.as_ref() != Some(scope.policy)
            || scope.transaction_expiry_height != t.transaction_expiry_height
            || scope.source.source_id != scope.policy.source_id
            || scope.source.endpoint != scope.policy.endpoint
        {
            return Err(WalletKeyUseError::Permission);
        }
        Ok(())
    }
}
