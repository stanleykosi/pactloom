//! Selected-own-effects verification, never complete multi-owner approval.
//!
//! The caller supplies independently retained expectations and only its own FVK.
//! Peer attribution, complete own-input coverage, matching, proof validity and
//! chain state remain unknown. No result from this module authorizes key use.
use orchard::{
    Address, Note,
    keys::FullViewingKey,
    note::{NoteVersion, Rho},
    note_encryption::IronwoodDomain,
};
use pczt::{
    Pczt,
    roles::{
        signer::Signer,
        verifier::{OrchardError, Verifier},
    },
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use zcash_note_encryption::{Domain, try_output_recovery_with_pkd_esk};

#[derive(Clone)]
pub struct OwnInputExpectation {
    pub action_index: usize,
    pub nullifier: [u8; 32],
    pub value_zatoshis: u64,
}
#[derive(Clone, Copy)]
pub enum OwnOutputPurpose {
    OwnReturn,
    Recipient,
    PeerReturnUnverified,
}
#[derive(Clone)]
pub struct OwnOutputExpectation {
    pub action_index: usize,
    pub receiver: Address,
    pub value_zatoshis: u64,
    pub memo: [u8; 512],
    pub purpose: OwnOutputPurpose,
}
/// Local expectation input, not an authenticated setup or consent token.
/// Deliberately not serializable or Debug: contains the owner's viewing key.
#[derive(Clone)]
pub struct OwnEffectsPolicy {
    pub account_id: String,
    pub own_fvk: FullViewingKey,
    pub manifest_digest: [u8; 32],
    pub anchor: [u8; 32],
    pub expiry_height: u32,
    pub maximum_selected_net_debit_zatoshis: u64,
    pub exact_selected_net_debit_zatoshis: u64,
    pub declared_fee_share_zatoshis: u64,
    pub exact_transaction_fee_zatoshis: u64,
    pub own_inputs: Vec<OwnInputExpectation>,
    pub outputs: Vec<OwnOutputExpectation>,
}
impl OwnEffectsPolicy {
    /// Exact local expectation commitment, including this owner's viewing key.
    /// This hashes caller-provided data only: it does not verify a transaction,
    /// authenticate policy provenance, or produce OwnEffectsInspection/authority.
    /// Native owners use it to build their own expectations without disclosing
    /// a viewing key to the external author of a request plan.
    pub fn policy_commitment(&self) -> String {
        hex::encode(fingerprint(self))
    }
}
/// Same-byte cryptographic selected-own-effects evidence. No deserialization,
/// public constructor, or conversion to approval/signing authority exists.
pub struct OwnEffectsInspection {
    artifact_digest: String,
    policy_digest: String,
    shielded_sighash: String,
    own_action_indices: Vec<usize>,
    selected_net_debit_zatoshis: u64,
    transaction_fee_zatoshis: u64,
    declared_fee_share_zatoshis: u64,
    own_return_zatoshis: u64,
}
impl OwnEffectsInspection {
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    pub fn shielded_sighash(&self) -> &str {
        &self.shielded_sighash
    }
    pub fn own_action_indices(&self) -> &[usize] {
        &self.own_action_indices
    }
    pub fn selected_net_debit_zatoshis(&self) -> u64 {
        self.selected_net_debit_zatoshis
    }
    pub fn transaction_fee_zatoshis(&self) -> u64 {
        self.transaction_fee_zatoshis
    }
    pub fn declared_fee_share_zatoshis(&self) -> u64 {
        self.declared_fee_share_zatoshis
    }
    pub fn own_return_zatoshis(&self) -> u64 {
        self.own_return_zatoshis
    }
}
fn check(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn plus(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b)
        .filter(|n| *n <= 2_100_000_000_000_000)
        .ok_or_else(|| "Monetary overflow".into())
}
fn fingerprint(p: &OwnEffectsPolicy) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"wholepact:selected-own-effects-policy:v1\0");
    h.update((p.account_id.len() as u64).to_le_bytes());
    h.update(p.account_id.as_bytes());
    h.update(p.own_fvk.to_bytes());
    h.update(p.manifest_digest);
    h.update(p.anchor);
    h.update(p.expiry_height.to_le_bytes());
    for v in [
        p.maximum_selected_net_debit_zatoshis,
        p.exact_selected_net_debit_zatoshis,
        p.declared_fee_share_zatoshis,
        p.exact_transaction_fee_zatoshis,
    ] {
        h.update(v.to_le_bytes());
    }
    h.update((p.own_inputs.len() as u64).to_le_bytes());
    for i in &p.own_inputs {
        h.update((i.action_index as u64).to_le_bytes());
        h.update(i.nullifier);
        h.update(i.value_zatoshis.to_le_bytes());
    }
    h.update((p.outputs.len() as u64).to_le_bytes());
    for o in &p.outputs {
        h.update((o.action_index as u64).to_le_bytes());
        h.update(o.receiver.to_raw_address_bytes());
        h.update(o.value_zatoshis.to_le_bytes());
        h.update(o.memo);
        h.update([match o.purpose {
            OwnOutputPurpose::OwnReturn => 0,
            OwnOutputPurpose::Recipient => 1,
            OwnOutputPurpose::PeerReturnUnverified => 2,
        }]);
    }
    h.finalize().into()
}

/// Checks declared effects using maintained note/value/ciphertext verification.
/// Does not verify the transaction proof or authenticate this policy's provenance.
/// Non-own input attribution and completeness are intentionally not asserted.
pub fn verify_own_effects(
    bytes: &[u8],
    policy: &OwnEffectsPolicy,
) -> Result<OwnEffectsInspection, String> {
    crate::inspect_candidate(bytes)?;
    check(
        !policy.account_id.is_empty() && policy.account_id.len() <= 128,
        "Invalid local account label",
    )?;
    check(
        !policy.own_inputs.is_empty()
            && policy.own_inputs.len() <= 64
            && !policy.outputs.is_empty()
            && policy.outputs.len() <= 64,
        "Invalid own-effects bounds",
    )?;
    for n in [
        policy.maximum_selected_net_debit_zatoshis,
        policy.exact_selected_net_debit_zatoshis,
        policy.declared_fee_share_zatoshis,
        policy.exact_transaction_fee_zatoshis,
    ] {
        plus(0, n)?;
    }
    check(
        policy.exact_selected_net_debit_zatoshis <= policy.maximum_selected_net_debit_zatoshis
            && policy.declared_fee_share_zatoshis <= policy.exact_selected_net_debit_zatoshis
            && policy.declared_fee_share_zatoshis <= policy.exact_transaction_fee_zatoshis,
        "Invalid debit or fee declaration",
    )?;
    let p = Pczt::parse(bytes).map_err(|_| "Invalid candidate")?;
    check(
        *p.global().version_group_id() == 0xd884b698
            && *p.global().tx_modifiable() == 0
            && p.global().fallback_lock_time().unwrap_or(0) == 0,
        "Unsupported mutable transaction",
    )?;
    check(
        *p.global().expiry_height() == policy.expiry_height
            && policy.expiry_height < 500_000_000
            && *p.ironwood().anchor() == Some(policy.anchor)
            && *p.ironwood().flags() == 7,
        "Wrong anchor, expiry or flags",
    )?;
    let n = p.ironwood().actions().len();
    let mut own_indices = BTreeSet::new();
    let mut output_indices = BTreeSet::new();
    for i in &policy.own_inputs {
        check(
            i.action_index < n && i.value_zatoshis > 0 && own_indices.insert(i.action_index),
            "Duplicate or invalid selected input",
        )?;
    }
    for o in &policy.outputs {
        check(
            o.action_index < n && o.value_zatoshis > 0 && output_indices.insert(o.action_index),
            "Duplicate or invalid output",
        )?;
    }
    let mut total_in = 0;
    let mut total_out = 0;
    let mut own_in = 0;
    let mut own_return = 0;
    let mut nullifiers = BTreeSet::new();
    Verifier::new(p.clone())
        .with_ironwood::<String, _>(|bundle| {
            let custom = OrchardError::Custom;
            bundle.verify_cross_address_restriction()?;
            for (index, action) in bundle.actions().iter().enumerate() {
                action.verify_cv_net()?;
                action.output().verify_note_commitment(action.spend())?;
                let s = action.spend();
                let o = action.output();
                let input = s
                    .value()
                    .ok_or_else(|| custom("Missing input value".into()))?
                    .inner();
                let output = o
                    .value()
                    .ok_or_else(|| custom("Missing output value".into()))?
                    .inner();
                total_in = plus(total_in, input).map_err(custom)?;
                total_out = plus(total_out, output).map_err(custom)?;
                check(
                    nullifiers.insert(s.nullifier().to_bytes()),
                    "Duplicate nullifier",
                )
                .map_err(custom)?;
                // This evidence path must never depend on imported real viewing keys.
                check(
                    input == 0 || s.fvk().is_none(),
                    "Embedded real-input FVK forbidden",
                )
                .map_err(custom)?;
                if let Some(expected) = policy.own_inputs.iter().find(|i| i.action_index == index) {
                    check(
                        input == expected.value_zatoshis
                            && s.nullifier().to_bytes() == expected.nullifier
                            && s.spend_auth_sig().is_none(),
                        "Wrong selected own input",
                    )
                    .map_err(custom)?;
                    s.verify_nullifier(Some(&policy.own_fvk))?;
                    s.verify_rk(Some(&policy.own_fvk))?;
                    let note = Option::<Note>::from(Note::from_parts(
                        s.recipient()
                            .ok_or_else(|| custom("Missing own recipient".into()))?,
                        s.value().unwrap(),
                        s.rho().ok_or_else(|| custom("Missing own rho".into()))?,
                        s.rseed().ok_or_else(|| custom("Missing own seed".into()))?,
                        NoteVersion::V3,
                    ))
                    .ok_or_else(|| custom("Invalid own note".into()))?;
                    let witness = s
                        .witness()
                        .as_ref()
                        .ok_or_else(|| custom("Missing own witness".into()))?;
                    check(
                        witness.root(note.commitment().into()).to_bytes() == policy.anchor,
                        "Own witness root mismatch",
                    )
                    .map_err(custom)?;
                    own_in = plus(own_in, input).map_err(custom)?;
                }
                if let Some(expected) = policy.outputs.iter().find(|e| e.action_index == index) {
                    check(
                        output == expected.value_zatoshis
                            && *o.recipient() == Some(expected.receiver),
                        "Output differs from expectation",
                    )
                    .map_err(custom)?;
                    let note = Option::<Note>::from(Note::from_parts(
                        expected.receiver,
                        o.value().unwrap(),
                        Option::<Rho>::from(Rho::from_bytes(&s.nullifier().to_bytes()))
                            .ok_or_else(|| custom("Invalid output rho".into()))?,
                        o.rseed()
                            .ok_or_else(|| custom("Missing output seed".into()))?,
                        NoteVersion::V3,
                    ))
                    .ok_or_else(|| custom("Invalid output note".into()))?;
                    let domain = IronwoodDomain::for_pczt_action(action);
                    let esk = IronwoodDomain::derive_esk(&note)
                        .ok_or_else(|| custom("Missing output encryption seed".into()))?;
                    let recovered = try_output_recovery_with_pkd_esk(
                        &domain,
                        IronwoodDomain::get_pk_d(&note),
                        esk,
                        action,
                    )
                    .ok_or_else(|| custom("Invalid output ciphertext".into()))?;
                    check(
                        recovered.0.value().inner() == output
                            && recovered.1 == expected.receiver
                            && recovered.2 == expected.memo,
                        "Ciphertext or memo mismatch",
                    )
                    .map_err(custom)?;
                    let owned = policy
                        .own_fvk
                        .scope_for_address(&expected.receiver)
                        .is_some();
                    match expected.purpose {
                        OwnOutputPurpose::OwnReturn => {
                            check(owned, "Declared own return is not owned").map_err(custom)?;
                            own_return = plus(own_return, output).map_err(custom)?;
                        }
                        OwnOutputPurpose::Recipient | OwnOutputPurpose::PeerReturnUnverified => {
                            check(!owned, "Own output missing own-return classification")
                                .map_err(custom)?
                        }
                    }
                } else {
                    check(output == 0, "Unmapped value-bearing output").map_err(custom)?;
                }
            }
            Ok(())
        })
        .map_err(|_| "Selected own-effects verification failed")?;
    let fee = total_in
        .checked_sub(total_out)
        .ok_or("Negative transaction fee")?;
    check(
        fee == policy.exact_transaction_fee_zatoshis,
        "Transaction fee mismatch",
    )?;
    // Never turn a negative selected debit into an unsigned wrap or an assurance
    // about complete account net flow. Credit-only shapes need another contract.
    let debit = own_in
        .checked_sub(own_return)
        .ok_or("Negative selected debit unsupported")?;
    check(
        debit == policy.exact_selected_net_debit_zatoshis
            && debit <= policy.maximum_selected_net_debit_zatoshis,
        "Selected net debit mismatch",
    )?;
    let sighash = Signer::new(p)
        .map_err(|_| "Cannot compute exact sighash")?
        .shielded_sighash();
    Ok(OwnEffectsInspection {
        artifact_digest: hex::encode(Sha256::digest(bytes)),
        policy_digest: policy.policy_commitment(),
        shielded_sighash: hex::encode(sighash),
        own_action_indices: own_indices.into_iter().collect(),
        selected_net_debit_zatoshis: debit,
        transaction_fee_zatoshis: fee,
        declared_fee_share_zatoshis: policy.declared_fee_share_zatoshis,
        own_return_zatoshis: own_return,
    })
}
