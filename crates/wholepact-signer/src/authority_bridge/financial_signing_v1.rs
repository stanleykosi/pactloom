//! Maintained PCZT/Orchard signing under the original financial source, actual
//! authenticated permit and wallet lock. Started is committed before key use.
use super::super::protocol::{MAX_ARTIFACT_BYTES, MAX_OUTBOX_BYTES, RetainedAuthorizationResult};
use super::*;
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
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "financial_signing_v1/durable_fail_stop_v2.rs"]
mod durable_fail_stop_v2;
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(crate) use durable_fail_stop_v2::arm_durable_financial_started_fail_stop_v2;
#[derive(Serialize)]
struct Payload<'a> {
    schema_version: u16,
    candidate_id: &'a str,
    manifest_digest: &'a str,
    proved_artifact_digest: &'a str,
    review_binding: &'a str,
    account_id: &'a str,
    signatures: Vec<Signature>,
}
#[derive(Serialize)]
struct Signature {
    action_index: usize,
    signature_hex: String,
}
impl ReservedFinancialAuthorizationV1<'_> {
    fn check(&self) -> Result<()> {
        self.source
            .check_custody()
            .map_err(|_| BridgeError::Permission)?;
        self.approved.check_current()?;
        self.permit.matches_request(&self.request.reservation)?;
        Ok(())
    }
    pub(crate) fn sign_and_retain(
        self,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
    ) -> Result<super::super::AuthorizationCommit> {
        self.check()?;
        let account = self
            .source
            .financial_account()
            .map_err(|_| BridgeError::Permission)?;
        let fvk = account.fvk().map_err(|_| BridgeError::Verification)?;
        let terms = self.approved.record().terms();
        let policy = terms
            .wallet_key_use_policy
            .as_ref()
            .ok_or(BridgeError::Permission)?;
        let permission = FinancialWalletPermission { reserved: &self };
        wallet.with_key_use_guard(
            &permission,
            ticket,
            &fvk,
            policy,
            terms.transaction_expiry_height,
            |held| self.sign_held(held),
        )
    }
    fn sign_held(
        &self,
        wallet: &HeldWalletKeyUse<'_>,
    ) -> Result<super::super::AuthorizationCommit> {
        self.check()?;
        wallet.check_current()?;
        let account = self
            .source
            .financial_account()
            .map_err(|_| BridgeError::Permission)?;
        let fvk = account.fvk().map_err(|_| BridgeError::Verification)?;
        let (parsed, actual_indices) = verify_exact_signing_material_kernel(
            self.approved.record(),
            self.approved.fixed(),
            self.approved.inputs(),
            &self.request,
            wallet,
            &fvk,
        )?;
        self.check()?;
        wallet.check_current()?;
        let journal = self
            .source
            .financial_journal()
            .map_err(|_| BridgeError::Permission)?;
        journal.begin_financial_key_use_v1(
            &mut *self
                .source
                .financial_binding()
                .map_err(|_| BridgeError::Permission)?,
            &self.approved,
            &self.permit,
        )?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        durable_fail_stop_v2::after_started_commit(
            &self.request.reservation.account_id,
            &self.request.reservation.authorization_id,
            self.source.original_deadline(),
        )?;
        // There is deliberately no branch that reconstructs this fence from an
        // existing Started row. Any error here preserves exposure and uncertainty.
        let publication = self.approved.publication_lease()?;
        let check = || {
            self.check()?;
            wallet.check_current()?;
            Ok(())
        };
        check()?;
        let fence = FinancialKeyUseFenceV1 {
            source: FinancialKeyUseSourceV1::Native(self.source),
            account,
            check: &check,
        };
        let result = sign_exact_result_kernel(
            self.approved.record(),
            self.approved.inputs(),
            &self.request,
            account,
            &fence,
            parsed,
            &actual_indices,
            &check,
        )?;
        check()?;
        drop(publication);
        journal.retain_financial_result_v1(
            &mut *self
                .source
                .financial_binding()
                .map_err(|_| BridgeError::Permission)?,
            &self.approved,
            &self.permit,
            &result,
        )?;
        check()?;
        Ok((&result).into())
    }
}
struct FinancialWalletPermission<'a, 'b> {
    reserved: &'a ReservedFinancialAuthorizationV1<'b>,
}
impl HeldWalletPermission for FinancialWalletPermission<'_, '_> {
    fn check_current(
        &self,
        scope: &WalletKeyUseScope<'_>,
    ) -> std::result::Result<(), WalletKeyUseError> {
        self.reserved
            .check()
            .map_err(|_| WalletKeyUseError::Permission)?;
        let t = self.reserved.approved.record().terms();
        let fvk = self
            .reserved
            .source
            .financial_account()
            .map_err(|_| WalletKeyUseError::Permission)?
            .fvk()
            .map_err(|_| WalletKeyUseError::Permission)?;
        if scope.account_id != t.account_id
            || scope.authenticated_fvk.to_bytes() != fvk.to_bytes()
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

/// Maintained exact PCZT signature kernel. All values other than the closed
/// account fence are inert inputs; callers must enter their concrete genuine
/// origin's synchronous key-use interval before invoking it. No transport,
/// journal mutation, source reopening or awaits occur in the mathematical
/// kernel. The concrete closed fence determines its currentness checks.
#[allow(clippy::too_many_arguments)]
pub(super) fn sign_exact_result_kernel(
    original: &crate::consent_journal::OriginalSpendConsent,
    inputs: &crate::manifest::ReviewInputs,
    request: &super::super::protocol::RetainedAuthorizationRequest,
    account: &crate::account::DedicatedAccount,
    fence: &FinancialKeyUseFenceV1<'_>,
    parsed: Pczt,
    actual: &[usize],
    check: &dyn Fn() -> Result<()>,
) -> Result<RetainedAuthorizationResult> {
    let t = original.terms();
    let bytes = request.artifact()?;
    let sk = account
        .derive_financial_spending_key_v1(fence)
        .map_err(|_| BridgeError::Verification)?;
    let ask = SpendAuthorizingKey::from(&sk);
    let mut signer = Signer::new(parsed).map_err(|_| BridgeError::Verification)?;
    for &action_index in actual {
        check()?;
        signer
            .sign_ironwood(UnwrapErr(SysRng), action_index, &ask)
            .map_err(|_| BridgeError::Verification)?;
    }
    let signed = signer.finish();
    let mut signatures = Vec::new();
    for &action_index in actual {
        let sig = signed.ironwood().actions()[action_index]
            .spend()
            .spend_auth_sig()
            .ok_or(BridgeError::Verification)?;
        signatures.push(Signature {
            action_index,
            signature_hex: hex::encode(sig),
        });
    }
    let normalized = pczt::roles::redactor::Redactor::new(signed.clone())
        .redact_ironwood_with(|mut b| {
            for &action_index in actual {
                b.redact_action(action_index, |mut a| a.clear_spend_auth_sig());
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
    if signed_bytes.len() > MAX_ARTIFACT_BYTES
        || wholepact_protocol::review::verify_review(&signed_bytes, &inputs.policy)
            .map_err(|_| BridgeError::Verification)?
            .review_binding()
            != t.review_binding
    {
        return Err(BridgeError::Verification);
    }
    let payload = Payload {
        schema_version: 1,
        candidate_id: &request.delivery.candidate_id,
        manifest_digest: &t.manifest_digest,
        proved_artifact_digest: &t.artifact_digest,
        review_binding: &t.review_binding,
        account_id: &t.account_id,
        signatures,
    };
    let outbox =
        Zeroizing::new(serde_json::to_string(&payload).map_err(|_| BridgeError::Binding)?);
    if outbox.len() > MAX_OUTBOX_BYTES {
        return Err(BridgeError::Limit);
    }
    let result = RetainedAuthorizationResult {
        authorization_id: t.authorization_id.clone(),
        original_consent_ref: original.reference().into(),
        request_digest: request.reservation.request_digest()?,
        result_digest: hex::encode(Sha256::digest(&signed_bytes)),
        signed_pczt_hex: hex::encode(&signed_bytes),
        outbox_digest: hex::encode(Sha256::digest(outbox.as_bytes())),
        outbox_payload: outbox.to_string(),
    };
    Ok(result)
}

/// Exact fixed-input/PCZT verification shared by the two closed origin paths.
/// This function issues no authority and performs no key use or journal writes.
pub(super) fn verify_exact_signing_material_kernel(
    original: &crate::consent_journal::OriginalSpendConsent,
    fixed: &wholepact_protocol::durable_proposal_v1::VerifiedFixedProposal,
    inputs: &crate::manifest::ReviewInputs,
    request: &super::super::protocol::RetainedAuthorizationRequest,
    wallet: &HeldWalletKeyUse<'_>,
    fvk: &orchard::keys::FullViewingKey,
) -> Result<(Pczt, Vec<usize>)> {
    let t = original.terms();
    let bytes = request.artifact()?;
    let evidence = wallet.evidence();
    let c = evidence.context();
    if evidence.account_id() != t.account_id
        || evidence.fvk().to_bytes() != fvk.to_bytes()
        || wallet.transaction_expiry_height() != t.transaction_expiry_height
        || Some(wallet.policy()) != t.wallet_key_use_policy.as_ref()
        || c.tip_height != t.wallet_snapshot.tip_height
        || hex::encode(c.tip_hash_protocol) != t.wallet_snapshot.tip_hash
        || c.anchor_height != t.wallet_snapshot.anchor_height
        || hex::encode(c.anchor_hash_protocol) != t.wallet_snapshot.anchor_hash
        || hex::encode(c.anchor_root) != t.wallet_snapshot.anchor_root
        || evidence.inputs().len() != t.input_bindings.len()
    {
        return Err(BridgeError::Binding);
    }
    for i in &t.input_bindings {
        if !evidence.inputs().iter().any(|w| {
            w.input_id() == i.input_id
                && hex::encode(w.nullifier()) == i.nullifier
                && w.value_zatoshis() == i.value_zatoshis
        }) {
            return Err(BridgeError::Binding);
        }
    }
    let owner = inputs
        .policy
        .participants
        .iter()
        .position(|p| p.account_id == t.account_id && p.fvk.to_bytes() == fvk.to_bytes())
        .ok_or(BridgeError::Binding)?;
    fixed
        .verify_action_mappings(&inputs.input_actions, &inputs.output_actions)
        .map_err(|_| BridgeError::Verification)?;
    let reviewed = wholepact_protocol::review::verify_review(&bytes, &inputs.policy)
        .map_err(|_| BridgeError::Verification)?;
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
    Ok((parsed, actual.iter().map(|input| input.action_index).collect()))
}
