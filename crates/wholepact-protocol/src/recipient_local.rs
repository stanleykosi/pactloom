//! Recipient-local finalized transaction checking. No coordinator PCZT, witnesses,
//! contributor identities, or retention journals are required. This verifies
//! transaction cryptography and decrypted incoming outputs, never chain inclusion.
use orchard::{bundle::BatchValidator, keys::FullViewingKey, note_encryption::IronwoodDomain};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    Authorization, Authorized, Transaction, TxVersion,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use zcash_protocol::{consensus::BranchId, memo::MemoBytes};
use zeroize::Zeroizing;

pub const NETWORK: &str = "ironwood-testnet-nu7-candidate";
const MAX_MONEY: u64 = 2_100_000_000_000_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientError {
    Instructions,
    Transaction,
    Limit,
    KeyMismatch,
    Amount,
    Memo,
}
pub type Result<T> = std::result::Result<T, RecipientError>;

/// Untrusted intake until the recipient deliberately reviews these exact facts.
/// A method/issuer string from an imported document is not authentication.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivingInstructions {
    pub reference: String,
    pub network_profile_id: String,
    pub denomination: String,
    pub destination: String,
    pub amount_zatoshis: u64,
    pub memo: Option<String>,
    pub valid_until_unix_seconds: u64,
}
impl ReceivingInstructions {
    pub fn validate(&self) -> Result<()> {
        if self.reference.is_empty()
            || self.reference.len() > 128
            || self.reference.chars().any(char::is_control)
            || self.network_profile_id != NETWORK
            || self.denomination != "ZEC"
            || self.amount_zatoshis == 0
            || self.amount_zatoshis > MAX_MONEY
            || self.valid_until_unix_seconds == 0
        {
            return Err(RecipientError::Instructions);
        }
        crate::review::decode_testnet_receiver(&self.destination)
            .map_err(|_| RecipientError::Instructions)?;
        self.memo_bytes()?;
        Ok(())
    }
    fn memo_bytes(&self) -> Result<[u8; 512]> {
        Ok(match &self.memo {
            Some(m) => {
                MemoBytes::from_bytes(m.as_bytes()).map_err(|_| RecipientError::Instructions)?
            }
            None => MemoBytes::empty(),
        }
        .into_bytes())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(self).map_err(|_| RecipientError::Instructions)?);
        let mut hash = Sha256::new();
        hash.update(b"wholepact:recipient-instructions:v1\0");
        hash.update(&*bytes);
        Ok(hex::encode(hash.finalize()))
    }
}

/// Sealed local evidence. It deliberately has no Deserialize implementation and
/// says nothing about mining, spentness, activation or a commercial obligation.
#[derive(Serialize)]
pub struct LocalPaymentEvidence {
    transaction_id: String,
    transaction_digest: String,
    effects_commitment: String,
    instruction_digest: String,
    amount_zatoshis: u64,
    output_references: Vec<String>,
    expiry_height: u32,
}
impl LocalPaymentEvidence {
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub fn transaction_digest(&self) -> &str {
        &self.transaction_digest
    }
    pub fn effects_commitment(&self) -> &str {
        &self.effects_commitment
    }
    pub fn instruction_digest(&self) -> &str {
        &self.instruction_digest
    }
    pub fn amount_zatoshis(&self) -> u64 {
        self.amount_zatoshis
    }
    pub fn expiry_height(&self) -> u32 {
        self.expiry_height
    }
}

/// Structural inspection only; no proof, signature, payment or chain claim.
/// Used before retaining portable imports. The owner verifier still performs all
/// cryptographic and recipient-owned decryption checks on these exact bytes.
pub fn inspect_finalized_encoding(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > 262_144 { return Err(RecipientError::Limit); }
    let branch = BranchId::try_from(0x77190ad9).map_err(|_| RecipientError::Transaction)?;
    let mut cursor = std::io::Cursor::new(bytes);
    let tx = Transaction::read(&mut cursor, branch).map_err(|_| RecipientError::Transaction)?;
    if cursor.position() as usize != bytes.len() || tx.version() != TxVersion::V6
        || tx.consensus_branch_id() != branch || tx.transparent_bundle().is_some()
        || tx.sapling_bundle().is_some() || tx.orchard_bundle().is_some()
        || tx.sprout_bundle().is_some() || u32::from(tx.expiry_height()) == 0 {
        return Err(RecipientError::Transaction);
    }
    let bundle = tx.ironwood_bundle().ok_or(RecipientError::Transaction)?;
    if bundle.actions().len() > 8 { return Err(RecipientError::Limit); }
    let mut canonical = Zeroizing::new(Vec::new());
    tx.write(&mut *canonical).map_err(|_| RecipientError::Transaction)?;
    if canonical.as_slice() != bytes { return Err(RecipientError::Transaction); }
    Ok(())
}

/// Native callers must independently obtain exact, current permission to use the
/// recipient-owned key. This pure cryptographic function grants no such authority.
pub fn verify_finalized_payment(
    bytes: &[u8],
    instructions: &ReceivingInstructions,
    viewing_key: &FullViewingKey,
) -> Result<LocalPaymentEvidence> {
    instructions.validate()?;
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err(RecipientError::Limit);
    }
    let branch = BranchId::try_from(0x77190ad9).map_err(|_| RecipientError::Transaction)?;
    let mut cursor = std::io::Cursor::new(bytes);
    let tx = Transaction::read(&mut cursor, branch).map_err(|_| RecipientError::Transaction)?;
    if cursor.position() as usize != bytes.len()
        || tx.version() != TxVersion::V6
        || tx.consensus_branch_id() != branch
        || tx.transparent_bundle().is_some()
        || tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
        || tx.sprout_bundle().is_some()
        || u32::from(tx.expiry_height()) == 0
    {
        return Err(RecipientError::Transaction);
    }
    let mut canonical = Zeroizing::new(Vec::new());
    tx.write(&mut *canonical)
        .map_err(|_| RecipientError::Transaction)?;
    if canonical.as_slice() != bytes {
        return Err(RecipientError::Transaction);
    }
    let bundle = tx.ironwood_bundle().ok_or(RecipientError::Transaction)?;
    if bundle.actions().len() > 8 {
        return Err(RecipientError::Limit);
    }
    struct ShieldedEffects;
    impl Authorization for ShieldedEffects {
        type TransparentAuth = zcash_transparent::bundle::EffectsOnly;
        type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
        type OrchardAuth = <Authorized as Authorization>::OrchardAuth;
    }
    let effects = (*tx)
        .clone()
        .map_bundles::<ShieldedEffects>(|_| None, |s| s, |o| o);
    let sighash = signature_hash(
        &effects,
        &SignableInput::Shielded,
        &effects.digest(TxIdDigester),
    );
    let vk = orchard::circuit::VerifyingKey::build(bundle.bundle_version().circuit_version());
    let mut validator = BatchValidator::new(&vk);
    validator
        .add_bundle(bundle, *sighash.as_ref())
        .map_err(|_| RecipientError::Transaction)?;
    if !validator.validate(UnwrapErr(SysRng)) {
        return Err(RecipientError::Transaction);
    }
    let receiver = crate::review::decode_testnet_receiver(&instructions.destination)
        .map_err(|_| RecipientError::Instructions)?;
    let scope = viewing_key
        .scope_for_address(&receiver)
        .ok_or(RecipientError::KeyMismatch)?;
    let incoming = viewing_key.to_ivk(scope).prepare();
    let memo = instructions.memo_bytes()?;
    let mut amount = 0u64;
    let mut outputs = Vec::new();
    for (index, action) in bundle.actions().iter().enumerate() {
        if let Some((note, address, actual_memo)) =
            try_note_decryption(&IronwoodDomain::for_action(action), &incoming, action)
        {
            if address != receiver {
                continue;
            }
            if actual_memo != memo {
                return Err(RecipientError::Memo);
            }
            let value = note.value().inner();
            if value == 0 {
                return Err(RecipientError::Amount);
            }
            amount = amount
                .checked_add(value)
                .filter(|v| *v <= MAX_MONEY)
                .ok_or(RecipientError::Amount)?;
            outputs.push(format!(
                "ironwood:{index}:{}",
                hex::encode(action.cmx().to_bytes())
            ));
        }
    }
    if outputs.is_empty() || amount != instructions.amount_zatoshis {
        return Err(RecipientError::Amount);
    }
    Ok(LocalPaymentEvidence {
        transaction_id: tx.txid().to_string(),
        transaction_digest: hex::encode(Sha256::digest(bytes)),
        effects_commitment: hex::encode(sighash.as_ref()),
        instruction_digest: instructions.digest()?,
        amount_zatoshis: amount,
        output_references: outputs,
        expiry_height: tx.expiry_height().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (FullViewingKey, ReceivingInstructions) {
        // Explicit synthetic, never-funded key. No real credential input.
        let key = orchard::keys::SpendingKey::from_bytes([72; 32]).unwrap();
        let fvk = FullViewingKey::from(&key);
        let destination = crate::review::encode_testnet_receiver(
            &fvk.address_at(0u32, orchard::keys::Scope::External),
        );
        (
            fvk,
            ReceivingInstructions {
                reference: "synthetic-recipient-reference".into(),
                network_profile_id: NETWORK.into(),
                denomination: "ZEC".into(),
                destination,
                amount_zatoshis: 1000,
                memo: None,
                valid_until_unix_seconds: 2_000_000_000,
            },
        )
    }
    #[test]
    fn instruction_digest_binds_exact_amount_memo_and_validity() {
        let (_, mut instructions) = fixture();
        let original = instructions.digest().unwrap();
        instructions.amount_zatoshis += 1;
        assert_ne!(original, instructions.digest().unwrap());
        instructions.amount_zatoshis -= 1;
        instructions.memo = Some("different reference".into());
        assert_ne!(original, instructions.digest().unwrap());
        instructions.memo = None;
        instructions.valid_until_unix_seconds += 1;
        assert_ne!(original, instructions.digest().unwrap());
    }
    #[test]
    fn unsupported_network_denomination_and_unbounded_memo_are_rejected() {
        let (_, mut instructions) = fixture();
        instructions.network_profile_id = "mainnet".into();
        assert!(instructions.validate().is_err());
        instructions.network_profile_id = NETWORK.into();
        instructions.denomination = "USD".into();
        assert!(instructions.validate().is_err());
        instructions.denomination = "ZEC".into();
        instructions.memo = Some("x".repeat(513));
        assert!(instructions.validate().is_err());
    }
    #[test]
    fn claims_pczt_and_empty_input_are_not_finalized_payment_evidence() {
        let (key, instructions) = fixture();
        for bytes in [
            b"".as_slice(),
            b"{\"verified\":true}".as_slice(),
            b"PCZT\x02\0\0\0".as_slice(),
        ] {
            assert!(verify_finalized_payment(bytes, &instructions, &key).is_err());
        }
        assert!(matches!(
            verify_finalized_payment(&vec![0; 1_048_577], &instructions, &key),
            Err(RecipientError::Limit)
        ));
    }
}

/// Reuse the existing single-proof synthetic qualification's finalized bytes.
/// No additional proof is generated; this is never a live payment check fixture.
#[cfg(feature = "synthetic-qualification")]
pub(crate) fn qualify_existing_synthetic_transaction(
    bytes: &[u8],
    key: &FullViewingKey,
    destination: String,
    amount: u64,
) -> std::result::Result<(), String> {
    let mut instructions = ReceivingInstructions {
        reference: "synthetic-independent-recipient".into(),
        network_profile_id: NETWORK.into(),
        denomination: "ZEC".into(),
        destination,
        amount_zatoshis: amount,
        memo: None,
        valid_until_unix_seconds: 2_000_000_000,
    };
    let good = verify_finalized_payment(bytes, &instructions, key)
        .map_err(|e| format!("Independent synthetic recipient verification: {e:?}"))?;
    if good.amount_zatoshis() != amount {
        return Err("Synthetic recipient amount mismatch".into());
    }
    instructions.amount_zatoshis += 1;
    if !matches!(
        verify_finalized_payment(bytes, &instructions, key),
        Err(RecipientError::Amount)
    ) {
        return Err("Independent recipient accepted a wrong expected amount".into());
    }
    instructions.amount_zatoshis = amount;
    instructions.memo = Some("wrong synthetic invoice reference".into());
    if !matches!(
        verify_finalized_payment(bytes, &instructions, key),
        Err(RecipientError::Memo)
    ) {
        return Err("Independent recipient accepted a wrong memo".into());
    }
    instructions.memo = None;
    let wrong = FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([72; 32]).unwrap());
    if !matches!(
        verify_finalized_payment(bytes, &instructions, &wrong),
        Err(RecipientError::KeyMismatch)
    ) {
        return Err("Independent recipient accepted another account's key".into());
    }
    let mut corrupt = bytes.to_vec();
    let last = corrupt.last_mut().ok_or("Empty synthetic transaction")?;
    *last ^= 1;
    if verify_finalized_payment(&corrupt, &instructions, key).is_ok() {
        return Err("Independent recipient accepted tampered finalized bytes".into());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    if verify_finalized_payment(&trailing, &instructions, key).is_ok() {
        return Err("Independent recipient accepted trailing finalized bytes".into());
    }
    Ok(())
}

#[cfg(test)]
mod portable_encoding_tests {
    use super::*;
    #[test]
    fn portable_encoding_rejects_empty_oversized_and_untrusted_json() {
        assert_eq!(inspect_finalized_encoding(&[]), Err(RecipientError::Limit));
        assert_eq!(inspect_finalized_encoding(&vec![0; 262_145]), Err(RecipientError::Limit));
        for bytes in [b"{\"verified\":true}".as_slice(), b"PCZT", &[0;32]] {
            assert!(inspect_finalized_encoding(bytes).is_err());
        }
    }
}
