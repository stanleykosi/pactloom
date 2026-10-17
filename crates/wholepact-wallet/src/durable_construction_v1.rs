//! Version-distinct, non-spending construction material. Decoding authenticates
//! mathematical consistency only. The engine must join these bytes to its own
//! authenticated native-disclosure intake before using the fresh wallet checks.
//! No serialized value in this module is a native decision or a signing permit.
use super::*;
use orchard::{
    note::{RandomSeed, Rho},
    tree::MerkleHashOrchard,
    value::NoteValue,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wholepact_core::{Proposal, ProposalInput};
use zcash_client_backend::wallet::Note as WalletNote;
use zeroize::{Zeroize, Zeroizing};

pub const PURPOSE: &str = "durable_fixed_candidate_construction_v1";
pub const MAX_MATERIAL_BYTES: usize = 256 * 1024;
pub const MAX_VALIDITY_SECONDS: u64 = 24 * 60 * 60;
type Result<T> = std::result::Result<T, DurableConstructionError>;

#[derive(Debug, thiserror::Error)]
pub enum DurableConstructionError {
    #[error("invalid bounded historical construction material")]
    Invalid,
    #[error("construction material differs from its exact account or proposal")]
    Binding,
    #[error("fresh exact source, anchor or input eligibility is unavailable")]
    Stale,
    #[error("protected construction wallet storage is unavailable")]
    Storage,
    #[error(transparent)]
    Sync(#[from] SyncError),
}
impl From<WalletError> for DurableConstructionError {
    fn from(e: WalletError) -> Self {
        Self::Sync(e.into())
    }
}
fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2048 && !value.chars().any(char::is_control)
}
fn bytes<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(DurableConstructionError::Invalid);
    }
    hex::decode(value)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(DurableConstructionError::Invalid)
}
fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value)
        .map_err(|_| DurableConstructionError::Invalid)
}

/// Human-reviewed recipients are committed exactly. These labels/fingerprints
/// are not authentication; each export must authenticate its actual recipient.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionRecipientV1 {
    pub principal_id: String,
    /// Hash of the actual ephemeral local pairing grant, NOT a public key or persistent identity.
    pub authenticated_local_grant_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactTransportConstructionReviewerV1 {
    pub account_id: String,
    pub transport_key_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalConstructionReviewerKindV2 {
    LocalInstalledSignerCanonicalAccount,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalInstalledSignerConstructionReviewerV2 {
    pub kind: LocalConstructionReviewerKindV2,
    pub account_id: String,
}
/// Legacy exact transport-key audiences remain byte-for-byte readable. The
/// distinct tagged local-account audience requires explicit scope version 2.
/// Neither category authenticates an export recipient by itself.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConstructionReviewerV1 {
    ExactTransport(ExactTransportConstructionReviewerV1),
    LocalInstalledSigner(LocalInstalledSignerConstructionReviewerV2),
}
impl ConstructionReviewerV1 {
    pub fn account_id(&self) -> &str {
        match self {
            Self::ExactTransport(v) => &v.account_id,
            Self::LocalInstalledSigner(v) => &v.account_id,
        }
    }
    pub fn local_installed_signer(account_id: String) -> Self {
        Self::LocalInstalledSigner(LocalInstalledSignerConstructionReviewerV2 {
            kind: LocalConstructionReviewerKindV2::LocalInstalledSignerCanonicalAccount,
            account_id,
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionScopeV1 {
    pub version: u16,
    pub purpose: String,
    pub proposal: ProposalInput,
    pub account_id: String,
    pub participant_id: String,
    pub privacy_domain: String,
    pub constructor: ConstructionRecipientV1,
    pub prover: ConstructionRecipientV1,
    pub reviewers: Vec<ConstructionReviewerV1>,
    pub protected_destination: String,
    pub retention_policy: String,
    pub valid_from_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub minimum_confirmations: u32,
    pub maximum_scan_blocks: u32,
}
impl DurableConstructionScopeV1 {
    pub fn validate(&self) -> Result<Proposal> {
        let p = Proposal::validate(self.proposal.clone())
            .map_err(|_| DurableConstructionError::Invalid)?;
        if !matches!(self.version, 1 | 2)
            || self.purpose != PURPOSE
            || self.valid_from_unix_seconds == 0
            || self
                .valid_until_unix_seconds
                .checked_sub(self.valid_from_unix_seconds)
                .is_none_or(|v| v == 0 || v > MAX_VALIDITY_SECONDS)
            || !(1..=100).contains(&self.minimum_confirmations)
            || !(1..=1000).contains(&self.maximum_scan_blocks)
            || p.manifest().agreement.network_profile_id
                != wholepact_protocol::construction::PROFILE_ID
            || p.manifest().participants.len() != 2
            || p.manifest().agreement.recipients.len() != 1
            || p.manifest().expiry_height >= 500_000_000
            || !p
                .manifest()
                .participants
                .iter()
                .any(|a| a.account_id == self.account_id && a.participant_id == self.participant_id)
            || !self.protected_destination.starts_with('/')
            || self.protected_destination.ends_with('/')
            || self
                .protected_destination
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(DurableConstructionError::Invalid);
        }
        for s in [
            &self.account_id,
            &self.participant_id,
            &self.privacy_domain,
            &self.constructor.principal_id,
            &self.prover.principal_id,
            &self.protected_destination,
            &self.retention_policy,
        ] {
            if !valid_text(s) {
                return Err(DurableConstructionError::Invalid);
            }
        }
        bytes::<32>(&self.constructor.authenticated_local_grant_digest)?;
        bytes::<32>(&self.prover.authenticated_local_grant_digest)?;
        let accounts = p
            .manifest()
            .participants
            .iter()
            .map(|p| p.account_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut reviewers = BTreeSet::new();
        for reviewer in &self.reviewers {
            match (self.version, reviewer) {
                (1, ConstructionReviewerV1::ExactTransport(v)) => {
                    bytes::<32>(&v.transport_key_digest)?;
                }
                (2, ConstructionReviewerV1::LocalInstalledSigner(v)) => {
                    bytes::<32>(&v.account_id)?;
                }
                _ => return Err(DurableConstructionError::Binding),
            }
            if !reviewers.insert(reviewer.account_id()) {
                return Err(DurableConstructionError::Invalid);
            }
        }
        if reviewers != accounts || self.reviewers.len() != 2 {
            return Err(DurableConstructionError::Binding);
        }
        if serde_json::to_vec(self)
            .map_err(|_| DurableConstructionError::Invalid)?
            .len()
            > 128 * 1024
        {
            return Err(DurableConstructionError::Invalid);
        }
        Ok(p)
    }
    /// Scope permission only, NOT authentication. Export additionally needs the
    /// actual installed signer, fresh paired vault-bound account, protected
    /// original intake, current local consent, and a committed export intent.
    pub fn permits_local_reviewer_account(&self, account: &str) -> Result<bool> {
        self.validate()?;
        Ok(self.version == 2 && self.reviewers.iter().any(|r| {
            matches!(r, ConstructionReviewerV1::LocalInstalledSigner(v) if v.account_id == account)
        }))
    }
    pub fn check_valid_at(&self, now: u64) -> Result<()> {
        self.validate()?;
        if now < self.valid_from_unix_seconds || now >= self.valid_until_unix_seconds {
            return Err(DurableConstructionError::Stale);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:durable-construction-scope:v1", self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceHistoryV1 {
    source_id: String,
    endpoint: String,
    trust_profile: String,
    network: String,
    branch_id: String,
    lightwalletd_version: String,
    backend_subversion: String,
    protocol_version: String,
    request_started: u64,
    observed_at: u64,
    valid_until: u64,
}
impl SourceHistoryV1 {
    fn capture(c: &ChainContext) -> Self {
        Self {
            source_id: c.source().source_id.clone(),
            endpoint: c.source().endpoint.clone(),
            trust_profile: c.source().trust_profile.into(),
            network: c.network().into(),
            branch_id: c.branch_id().into(),
            lightwalletd_version: c.lightwalletd_version().into(),
            backend_subversion: c.backend_subversion().into(),
            protocol_version: c.protocol_version().into(),
            request_started: c.request_started_at_unix_seconds(),
            observed_at: c.observed_at_unix_seconds(),
            valid_until: c.valid_until_unix_seconds(),
        }
    }
    fn matches(&self, c: &ChainContext) -> bool {
        self.source_id == c.source().source_id
            && self.endpoint == c.source().endpoint
            && self.trust_profile == c.source().trust_profile
            && self.network == c.network()
            && self.branch_id == c.branch_id()
            && self.lightwalletd_version == c.lightwalletd_version()
            && self.backend_subversion == c.backend_subversion()
            && self.protocol_version == c.protocol_version()
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalContextV1 {
    tip_height: u32,
    tip_hash_protocol: String,
    anchor_height: u32,
    anchor_hash_protocol: String,
    anchor_root: String,
}
impl HistoricalContextV1 {
    fn capture(c: &SelectionContext) -> Self {
        Self {
            tip_height: c.tip_height,
            tip_hash_protocol: hex::encode(c.tip_hash_protocol),
            anchor_height: c.anchor_height,
            anchor_hash_protocol: hex::encode(c.anchor_hash_protocol),
            anchor_root: hex::encode(c.anchor_root),
        }
    }
    fn decode(&self) -> Result<SelectionContext> {
        if self.anchor_height == 0
            || self.anchor_height > self.tip_height
            || self
                .tip_height
                .checked_add(1)
                .is_none_or(|h| BranchId::for_height(&TEST_NETWORK, h.into()) != BranchId::Nu7)
        {
            return Err(DurableConstructionError::Invalid);
        }
        Ok(SelectionContext {
            tip_height: self.tip_height,
            tip_hash_protocol: bytes(&self.tip_hash_protocol)?,
            anchor_height: self.anchor_height,
            anchor_hash_protocol: bytes(&self.anchor_hash_protocol)?,
            anchor_root: bytes(&self.anchor_root)?,
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalNoteV1 {
    input_id: String,
    txid_protocol: String,
    output_index: u16,
    recipient: String,
    value_zatoshis: u64,
    rho: String,
    rseed: String,
    nullifier: String,
    commitment: String,
    position: u32,
    authentication_path: Vec<String>,
}
impl Drop for HistoricalNoteV1 {
    fn drop(&mut self) {
        self.rseed.zeroize();
        self.rho.zeroize();
        self.recipient.zeroize();
    }
}
impl HistoricalNoteV1 {
    fn decode(
        &self,
        fvk: &FullViewingKey,
        anchor: &[u8; 32],
    ) -> Result<wholepact_protocol::construction::SpendableNote> {
        if self.authentication_path.len() != 32 {
            return Err(DurableConstructionError::Invalid);
        }
        let recipient =
            Option::<Address>::from(Address::from_raw_address_bytes(&bytes(&self.recipient)?))
                .ok_or(DurableConstructionError::Invalid)?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&bytes(&self.rho)?))
            .ok_or(DurableConstructionError::Invalid)?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes(&self.rseed)?, &rho))
            .ok_or(DurableConstructionError::Invalid)?;
        let note = Option::<Note>::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(self.value_zatoshis),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .ok_or(DurableConstructionError::Invalid)?;
        let path = self
            .authentication_path
            .iter()
            .map(|p| {
                Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes(p)?))
                    .ok_or(DurableConstructionError::Invalid)
            })
            .collect::<Result<Vec<_>>>()?;
        let witness = MerklePath::from_parts(
            self.position,
            path.try_into()
                .map_err(|_| DurableConstructionError::Invalid)?,
        );
        let txid = zcash_protocol::TxId::from_bytes(bytes(&self.txid_protocol)?);
        if self.value_zatoshis == 0
            || self.value_zatoshis > MAX_MONEY
            || self.input_id != format!("ironwood:{txid}:{}", self.output_index)
            || fvk.scope_for_address(&recipient).is_none()
            || note.nullifier(fvk).to_bytes() != bytes::<32>(&self.nullifier)?
            || orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes()
                != bytes::<32>(&self.commitment)?
            || witness.root(note.commitment().into()).to_bytes() != *anchor
        {
            return Err(DurableConstructionError::Binding);
        }
        Ok(wholepact_protocol::construction::SpendableNote {
            input_id: self.input_id.clone(),
            note,
            witness,
        })
    }
}

// Exact existing dedicated-account identity derivation. An arbitrary host label
// is not account ownership, even when the rest of the note mathematics agrees.
fn canonical_durable_account_id(fvk: &FullViewingKey) -> String {
    let mut hash = Sha256::new();
    hash.update(b"wholepact:dedicated-testnet-account:legacy-zip32:v1\0");
    hash.update(fvk.to_bytes());
    hex::encode(hash.finalize())
}

/// Inert mathematical evidence for independently reconstructing a complete
/// fixed-proposal review. It conveys neither current eligibility nor anyone's
/// identity, consent, native decision, or spending authority.
pub struct HistoricalConstructionReviewEvidenceV1 {
    pub account_id: String,
    pub fvk: FullViewingKey,
    pub change_address: Address,
    pub context: SelectionContext,
    pub inputs: Vec<HistoricalConstructionInputEvidenceV1>,
}
/// Exact nullifier mapping, never an equal-value host-supplied action mapping.
pub struct HistoricalConstructionInputEvidenceV1 {
    pub input_id: String,
    pub nullifier: [u8; 32],
    pub value_zatoshis: u64,
    pub commitment: [u8; 32],
    pub position: u32,
}

/// Sensitive inert data. It deliberately implements no Debug and exposes no
/// key-use, reservation, authority or native-capability conversion.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalConstructionMaterialV1 {
    version: u16,
    account_id: String,
    fvk_hex: String,
    fvk_digest: String,
    selected_zatoshis: u64,
    requested_debit_zatoshis: u64,
    change_address: String,
    birthday_height: u32,
    context: HistoricalContextV1,
    source: SourceHistoryV1,
    notes: Vec<HistoricalNoteV1>,
}
impl Drop for HistoricalConstructionMaterialV1 {
    fn drop(&mut self) {
        self.fvk_hex.zeroize();
        self.change_address.zeroize();
    }
}
impl HistoricalConstructionMaterialV1 {
    pub fn capture(selected: &ProtectedContribution, sync: &ProtectedWalletSync) -> Result<Self> {
        selected.check_current()?;
        if !Weak::ptr_eq(&selected.generation, &Arc::downgrade(&sync.generation)) {
            return Err(DurableConstructionError::Binding);
        }
        let birthday_height = u32::from(
            sync.wallet
                .db
                .get_account_birthday(sync.account)
                .map_err(|_| DurableConstructionError::Storage)?,
        );
        let c = selected.selection();
        if c.notes.len() != c.local_outpoints.len() {
            return Err(DurableConstructionError::Binding);
        }
        let notes = c
            .notes
            .iter()
            .zip(&c.local_outpoints)
            .map(|(n, (txid, index))| HistoricalNoteV1 {
                input_id: n.input_id.clone(),
                txid_protocol: hex::encode(txid.as_ref()),
                output_index: *index,
                recipient: hex::encode(n.note.recipient().to_raw_address_bytes()),
                value_zatoshis: n.note.value().inner(),
                rho: hex::encode(n.note.rho().to_bytes()),
                rseed: hex::encode(n.note.rseed().as_bytes()),
                nullifier: hex::encode(n.note.nullifier(&c.fvk).to_bytes()),
                commitment: hex::encode(
                    orchard::note::ExtractedNoteCommitment::from(n.note.commitment()).to_bytes(),
                ),
                position: n.witness.position(),
                authentication_path: n
                    .witness
                    .auth_path()
                    .iter()
                    .map(|p| hex::encode(p.to_bytes()))
                    .collect(),
            })
            .collect();
        let value = Self {
            version: 1,
            account_id: c.account_id.clone(),
            fvk_hex: hex::encode(c.fvk.to_bytes()),
            fvk_digest: hex::encode(Sha256::digest(c.fvk.to_bytes())),
            selected_zatoshis: c.selected_zatoshis,
            requested_debit_zatoshis: c.requested_debit_zatoshis,
            change_address: hex::encode(c.change_address.to_raw_address_bytes()),
            birthday_height,
            context: HistoricalContextV1::capture(&c.context),
            source: SourceHistoryV1::capture(selected.observation()),
            notes,
        };
        value.validate()?;
        selected.check_current()?;
        Ok(value)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAX_MATERIAL_BYTES {
            return Err(DurableConstructionError::Invalid);
        }
        let value: Self =
            serde_json::from_slice(raw).map_err(|_| DurableConstructionError::Invalid)?;
        value.validate()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let raw = Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| DurableConstructionError::Invalid)?,
        );
        if raw.len() > MAX_MATERIAL_BYTES {
            return Err(DurableConstructionError::Invalid);
        }
        Ok(raw)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:historical-construction-material:v1", self)
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn fvk_digest(&self) -> &str {
        &self.fvk_digest
    }
    pub fn historical_review_evidence(&self) -> Result<HistoricalConstructionReviewEvidenceV1> {
        let validated = self.validate()?;
        Ok(HistoricalConstructionReviewEvidenceV1 {
            account_id: self.account_id.clone(),
            fvk: validated.fvk,
            change_address: validated.change_address,
            context: self.context.decode()?,
            inputs: self
                .notes
                .iter()
                .map(|note| {
                    Ok(HistoricalConstructionInputEvidenceV1 {
                        input_id: note.input_id.clone(),
                        nullifier: bytes(&note.nullifier)?,
                        value_zatoshis: note.value_zatoshis,
                        commitment: bytes(&note.commitment)?,
                        position: note.position,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }
    pub fn review_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "account_id": self.account_id, "account_fvk_digest": self.fvk_digest,
            "selected_zatoshis": self.selected_zatoshis, "requested_debit_zatoshis": self.requested_debit_zatoshis,
            "change_address_raw": self.change_address, "birthday_height": self.birthday_height,
            "historical_context": self.context, "historical_source": self.source,
            "inputs": self.notes.iter().map(|n| serde_json::json!({"input_id":n.input_id,
                "value_zatoshis":n.value_zatoshis, "nullifier":n.nullifier, "commitment":n.commitment,
                "position":n.position})).collect::<Vec<_>>()
        })
    }
    pub fn input_ids(&self) -> impl Iterator<Item = &str> {
        self.notes.iter().map(|n| n.input_id.as_str())
    }
    pub fn verify_owner(&self, fvk: &FullViewingKey) -> Result<()> {
        self.validate()?;
        if fvk.to_bytes() != bytes::<96>(&self.fvk_hex)? {
            return Err(DurableConstructionError::Binding);
        }
        Ok(())
    }
    pub fn validate_for(&self, scope: &DurableConstructionScopeV1) -> Result<()> {
        let p = scope.validate()?;
        let c = self.validate()?;
        if self.account_id != scope.account_id
            || self.context.tip_height >= p.manifest().expiry_height
        {
            return Err(DurableConstructionError::Binding);
        }
        let allocation = p
            .manifest()
            .participants
            .iter()
            .find(|a| a.account_id == self.account_id)
            .ok_or(DurableConstructionError::Binding)?;
        let debit = p
            .accounting()
            .participant_net_debits
            .get(&scope.participant_id)
            .ok_or(DurableConstructionError::Binding)?
            .as_zatoshis();
        let inputs = p
            .manifest()
            .inputs
            .iter()
            .filter(|n| n.account_id == self.account_id)
            .collect::<Vec<_>>();
        if inputs.len() != self.notes.len()
            || debit != self.requested_debit_zatoshis
            || debit > allocation.maximum_net_debit.as_zatoshis()
            || self
                .context
                .tip_height
                .checked_sub(self.context.anchor_height)
                .and_then(|h| h.checked_add(1))
                .is_none_or(|v| v < scope.minimum_confirmations)
            || inputs.iter().any(|i| {
                i.participant_id != scope.participant_id
                    || !self.notes.iter().any(|n| {
                        n.input_id == i.input_id && n.value_zatoshis == i.amount.as_zatoshis()
                    })
            })
            || c.fvk.scope_for_address(&c.change_address) != Some(Scope::Internal)
        {
            return Err(DurableConstructionError::Binding);
        }
        Ok(())
    }
    fn validate(&self) -> Result<wholepact_protocol::construction::OwnedContribution> {
        if self.version != 1
            || self.birthday_height == 0
            || self.birthday_height > self.context.anchor_height
            || !valid_text(&self.account_id)
            || self.notes.is_empty()
            || self.notes.len() > MAX_SELECTED_NOTES
            || self.requested_debit_zatoshis == 0
            || self.requested_debit_zatoshis > self.selected_zatoshis
            || self.source.network != "test"
            || self.source.trust_profile != "single_tls_provider_report_not_consensus"
            || !self.source.endpoint.starts_with("https://")
            || self.source.request_started == 0
            || self.source.request_started > self.source.observed_at
            || self.source.observed_at >= self.source.valid_until
            || self
                .source
                .valid_until
                .checked_sub(self.source.request_started)
                .is_none_or(|n| n > 300)
        {
            return Err(DurableConstructionError::Invalid);
        }
        for s in [
            &self.source.source_id,
            &self.source.endpoint,
            &self.source.branch_id,
            &self.source.lightwalletd_version,
            &self.source.backend_subversion,
            &self.source.protocol_version,
        ] {
            if !valid_text(s) {
                return Err(DurableConstructionError::Invalid);
            }
        }
        let context = self.context.decode()?;
        let fvk = FullViewingKey::from_bytes(&bytes(&self.fvk_hex)?)
            .ok_or(DurableConstructionError::Invalid)?;
        if hex::encode(Sha256::digest(fvk.to_bytes())) != self.fvk_digest
            || canonical_durable_account_id(&fvk) != self.account_id
        {
            return Err(DurableConstructionError::Binding);
        }
        let change_address = Option::<Address>::from(Address::from_raw_address_bytes(&bytes(
            &self.change_address,
        )?))
        .ok_or(DurableConstructionError::Invalid)?;
        if fvk.scope_for_address(&change_address) != Some(Scope::Internal) {
            return Err(DurableConstructionError::Binding);
        }
        let mut ids = BTreeSet::new();
        let mut nullifiers = BTreeSet::new();
        let mut total = 0u64;
        let mut notes = Vec::new();
        for n in &self.notes {
            if !ids.insert(&n.input_id) || !nullifiers.insert(&n.nullifier) {
                return Err(DurableConstructionError::Binding);
            }
            total = total
                .checked_add(n.value_zatoshis)
                .filter(|n| *n <= MAX_MONEY)
                .ok_or(DurableConstructionError::Invalid)?;
            notes.push(n.decode(&fvk, &context.anchor_root)?);
        }
        if total != self.selected_zatoshis {
            return Err(DurableConstructionError::Binding);
        }
        Ok(wholepact_protocol::construction::OwnedContribution {
            account_id: self.account_id.clone(),
            fvk,
            change_address,
            notes,
        })
    }
}

/// Fresh maintained scanner facts, never native consent. It is local, single
/// attempt and cannot be deserialized or reconstructed from historical clocks.
pub struct FreshDurableConstructionObservationV1 {
    material: HistoricalConstructionMaterialV1,
    scope: DurableConstructionScopeV1,
    observation: ChainContext,
    current: SelectionContext,
    started: Instant,
    generation: Weak<()>,
    account: AccountUuid,
    attempted: std::cell::Cell<bool>,
}
impl FreshDurableConstructionObservationV1 {
    pub fn check_current(&self) -> Result<()> {
        self.scope.check_valid_at(now()?)?;
        self.observation
            .check_fresh_at(now()?)
            .map_err(SyncError::from)?;
        check_observation_elapsed(&self.observation, elapsed_since(self.started)?)?;
        if self.generation.upgrade().is_none()
            || self.current.tip_height >= self.scope.proposal.manifest.expiry_height
        {
            return Err(DurableConstructionError::Stale);
        }
        Ok(())
    }
    pub fn material_digest(&self) -> Result<String> {
        self.material.digest()
    }
    pub fn scope_digest(&self) -> Result<String> {
        self.scope.digest()
    }
}
impl ProtectedWalletSync {
    /// Issue ordinary local wallet key-use evidence for the exact fixed inputs
    /// after an actual fresh synchronization. This is not native consent, does
    /// not authorize export or spending, and does not create construction rights.
    /// The unchanged with_key_use_guard still rechecks the exact maintained rows,
    /// current native permission, recovery state, source policy and expiry while
    /// holding the actual wallet transaction through key use and result storage.
    pub fn exact_durable_review_ticket_v1(
        &mut self,
        material: &HistoricalConstructionMaterialV1,
        scope: &DurableConstructionScopeV1,
        access: &impl LocalWalletAccess,
        authenticated_fvk: &FullViewingKey,
        policy: &crate::WalletKeyUsePolicy,
    ) -> Result<key_use::WalletKeyUseTicket> {
        self.require_access(access, WalletAccessPurpose::SelectPrivateContribution)?;
        material.validate_for(scope)?;
        material.verify_owner(authenticated_fvk)?;
        self.verify_account_fvk(authenticated_fvk)?;
        self.verify_account_birthday_height(material.birthday_height)?;
        scope.check_valid_at(now()?)?;
        let accepted = self
            .accepted
            .as_ref()
            .ok_or(DurableConstructionError::Stale)?;
        if self.phase != SyncPhase::SnapshotMatched
            || !material.source.matches(&accepted.chain)
            || self.minimum_confirmations.get() < scope.minimum_confirmations
            || accepted
                .selection
                .tip_height
                .checked_sub(material.context.tip_height)
                .is_none_or(|blocks| blocks > scope.maximum_scan_blocks)
        {
            return Err(DurableConstructionError::Stale);
        }
        self.wallet
            .backup_identity
            .as_ref()
            .ok_or(DurableConstructionError::Storage)?
            .check()
            .map_err(|_| DurableConstructionError::Storage)?;
        let fresh = FreshDurableConstructionObservationV1 {
            material: material.clone(),
            scope: scope.clone(),
            observation: accepted.chain.clone(),
            current: accepted.selection.clone(),
            started: accepted.monotonic_started,
            generation: Arc::downgrade(&self.generation),
            account: self.account,
            attempted: std::cell::Cell::new(false),
        };
        verify_current_notes(&self.wallet.db, &fresh)?;
        let target = accepted
            .selection
            .tip_height
            .checked_add(1)
            .ok_or(DurableConstructionError::Stale)?;
        let mut local_note_refs = Vec::with_capacity(material.notes.len());
        let mut local_outpoints = Vec::with_capacity(material.notes.len());
        // Retain references read from the maintained wallet, never references
        // deserialized from historical material or synthesized by equal value.
        for historical in &material.notes {
            let txid = zcash_protocol::TxId::from_bytes(bytes(&historical.txid_protocol)?);
            let received = self
                .wallet
                .db
                .get_spendable_note(
                    &txid,
                    ShieldedPool::Ironwood,
                    u32::from(historical.output_index),
                    target.into(),
                    LockFilter::Policy(&LockedInputPolicy::Exclude),
                )
                .map_err(|_| DurableConstructionError::Storage)?
                .ok_or(DurableConstructionError::Stale)?;
            local_note_refs.push(*received.internal_note_id());
            local_outpoints.push((*received.txid(), received.output_index()));
        }
        let owned = material.validate()?;
        let selected = ProtectedContribution {
            monotonic_started: accepted.monotonic_started,
            observation: accepted.chain.clone(),
            generation: Arc::downgrade(&self.generation),
            contribution: WalletContribution {
                account_id: material.account_id.clone(),
                fvk: owned.fvk,
                notes: owned
                    .notes
                    .into_iter()
                    .map(|n| SelectedNote {
                        input_id: n.input_id,
                        note: n.note,
                        witness: n.witness,
                    })
                    .collect(),
                change_address: owned.change_address,
                selected_zatoshis: material.selected_zatoshis,
                requested_debit_zatoshis: material.requested_debit_zatoshis,
                context: accepted.selection.clone(),
                local_note_refs,
                local_outpoints,
            },
        };
        verify_current_notes(&self.wallet.db, &fresh)?;
        self.require_access(access, WalletAccessPurpose::SelectPrivateContribution)?;
        self.wallet
            .backup_identity
            .as_ref()
            .ok_or(DurableConstructionError::Storage)?
            .check()
            .map_err(|_| DurableConstructionError::Storage)?;
        let ticket = selected.key_use_ticket();
        ticket
            .validate_policy(policy)
            .map_err(|_| DurableConstructionError::Stale)?;
        Ok(ticket)
    }
    /// Reopens may use this new data-only profile. Historical bytes never reset
    /// a clock: a fresh complete scan and exact database checks are mandatory.
    /// `access` is the existing trusted provider/privacy policy, not native
    /// disclosure authority. The engine separately requires authenticated intake.
    pub async fn observe_durable_material_v1(
        &mut self,
        material: &HistoricalConstructionMaterialV1,
        scope: &DurableConstructionScopeV1,
        access: &impl LocalWalletAccess,
    ) -> Result<FreshDurableConstructionObservationV1> {
        material.validate_for(scope)?;
        scope.check_valid_at(now()?)?;
        let decoded = material.validate()?;
        self.verify_account_fvk(&decoded.fvk)?;
        self.verify_account_birthday_height(material.birthday_height)?;
        if self.minimum_confirmations.get() < scope.minimum_confirmations
            || self.source.identity().source_id != material.source.source_id
            || self.source.identity().endpoint != material.source.endpoint
            || self.source.identity().trust_profile != material.source.trust_profile
        {
            return Err(DurableConstructionError::Binding);
        }
        self.wallet
            .backup_identity
            .as_ref()
            .ok_or(DurableConstructionError::Storage)?
            .check()
            .map_err(|_| DurableConstructionError::Storage)?;
        let old = material.context.decode()?;
        let deadline = Duration::from_secs(60);
        // New operation, new bounded source observation. Old V3 read owners and
        // their consumed records are neither consulted nor changed.
        self.accepted = None;
        self.generation = Arc::new(());
        self.phase = SyncPhase::Interrupted;
        self.provider_tip_height = None;
        self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        let started = Instant::now();
        let check_context = |c: &ChainContext| -> std::result::Result<(), SyncError> {
            scope
                .check_valid_at(now()?)
                .map_err(|_| SyncError::AccessDenied)?;
            let tip = u32::try_from(c.tip().height).map_err(|_| SyncError::InvalidResponse)?;
            if !material.source.matches(c)
                || tip < old.tip_height
                || tip >= scope.proposal.manifest.expiry_height
                || tip
                    .checked_sub(old.tip_height)
                    .is_none_or(|v| v > scope.maximum_scan_blocks)
            {
                return Err(SyncError::ReconciliationRequired);
            }
            Ok(())
        };
        let result = tokio::time::timeout(
            deadline,
            self.synchronize_inner_restricted(
                access,
                SyncLimits {
                    maximum_blocks: scope.maximum_scan_blocks,
                    anchor_height: Some(old.anchor_height),
                    deadline,
                },
                None,
                check_context,
            ),
        )
        .await
        .map_err(|_| DurableConstructionError::Stale)?;
        if let Err(e) = result {
            self.invalidate_observation();
            return Err(e.into());
        }
        let accepted = self
            .accepted
            .take()
            .ok_or(DurableConstructionError::Stale)?;
        let fresh = FreshDurableConstructionObservationV1 {
            material: material.clone(),
            scope: scope.clone(),
            observation: accepted.chain,
            current: accepted.selection,
            started,
            generation: Arc::downgrade(&self.generation),
            account: self.account,
            attempted: std::cell::Cell::new(false),
        };
        fresh.check_current()?;
        verify_current_notes(&self.wallet.db, &fresh)?;
        Ok(fresh)
    }
}
fn verify_current_notes<D>(db: &D, f: &FreshDurableConstructionObservationV1) -> Result<()>
where
    D: WalletRead<AccountId = AccountUuid>
        + InputSource<AccountId = AccountUuid, NoteRef = ReceivedNoteId>,
{
    f.check_current()?;
    let m = &f.material;
    let owned = m.validate()?;
    let old = m.context.decode()?;
    if f.current.anchor_height != old.anchor_height
        || f.current.anchor_hash_protocol != old.anchor_hash_protocol
        || f.current.anchor_root != old.anchor_root
        || f.current.tip_height < old.tip_height
        || f.current
            .tip_height
            .checked_sub(old.anchor_height)
            .and_then(|h| h.checked_add(1))
            .is_none_or(|n| n < f.scope.minimum_confirmations)
        || db
            .get_account_ids()
            .map_err(|_| DurableConstructionError::Storage)?
            != vec![f.account]
        || u32::from(
            db.get_account_birthday(f.account)
                .map_err(|_| DurableConstructionError::Storage)?,
        ) != m.birthday_height
        || db
            .block_fully_scanned()
            .map_err(|_| DurableConstructionError::Storage)?
            .map(|b| u32::from(b.block_height()))
            != Some(f.current.tip_height)
        || db
            .chain_height()
            .map_err(|_| DurableConstructionError::Storage)?
            != Some(f.current.tip_height.into())
    {
        return Err(DurableConstructionError::Stale);
    }
    let account = db
        .get_account(f.account)
        .map_err(|_| DurableConstructionError::Storage)?
        .ok_or(DurableConstructionError::Binding)?;
    if account
        .ufvk()
        .and_then(|k| k.orchard())
        .is_none_or(|k| k.to_bytes() != owned.fvk.to_bytes())
    {
        return Err(DurableConstructionError::Binding);
    }
    for (height, hash) in [
        (old.tip_height, old.tip_hash_protocol),
        (old.anchor_height, old.anchor_hash_protocol),
        (f.current.tip_height, f.current.tip_hash_protocol),
    ] {
        if db
            .get_block_hash(height.into())
            .map_err(|_| DurableConstructionError::Storage)?
            .map(|b| b.0)
            != Some(hash)
        {
            return Err(DurableConstructionError::Stale);
        }
    }
    let target = f
        .current
        .tip_height
        .checked_add(1)
        .ok_or(DurableConstructionError::Stale)?;
    if target > f.scope.proposal.manifest.expiry_height
        || BranchId::for_height(&TEST_NETWORK, target.into()) != BranchId::Nu7
        || !db
            .anchor_computable(ShieldedPool::Ironwood, old.anchor_height.into())
            .map_err(|_| DurableConstructionError::Storage)?
    {
        return Err(DurableConstructionError::Stale);
    }
    for (historical, expected) in m.notes.iter().zip(&owned.notes) {
        let txid = zcash_protocol::TxId::from_bytes(bytes(&historical.txid_protocol)?);
        let received = db
            .get_spendable_note(
                &txid,
                ShieldedPool::Ironwood,
                u32::from(historical.output_index),
                target.into(),
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .map_err(|_| DurableConstructionError::Storage)?
            .ok_or(DurableConstructionError::Stale)?;
        let WalletNote::Orchard {
            note,
            pool: orchard::ValuePool::Ironwood,
        } = received.note()
        else {
            return Err(DurableConstructionError::Binding);
        };
        if *note != expected.note
            || note.version() != NoteVersion::V3
            || received.txid() != &txid
            || received.output_index() != historical.output_index
            || u64::from(received.note_commitment_tree_position()) != u64::from(historical.position)
            || owned.fvk.scope_for_address(&note.recipient()) != Some(received.spending_key_scope())
            || received
                .mined_height()
                .is_none_or(|h| u32::from(h) > old.anchor_height)
            || note.nullifier(&owned.fvk).to_bytes() != bytes::<32>(&historical.nullifier)?
        {
            return Err(DurableConstructionError::Stale);
        }
    }
    Ok(())
}

pub struct DurableConstructionWalletSlotV1<'a> {
    sync: &'a mut ProtectedWalletSync,
    fresh: &'a FreshDurableConstructionObservationV1,
}
impl<'a> DurableConstructionWalletSlotV1<'a> {
    pub fn material_digest(&self) -> Result<String> {
        self.fresh.material_digest()
    }
    pub fn scope_digest(&self) -> Result<String> {
        self.fresh.scope_digest()
    }
    pub fn new(
        sync: &'a mut ProtectedWalletSync,
        fresh: &'a FreshDurableConstructionObservationV1,
    ) -> Result<Self> {
        fresh.check_current()?;
        if sync.account != fresh.account
            || !Weak::ptr_eq(&fresh.generation, &Arc::downgrade(&sync.generation))
        {
            return Err(DurableConstructionError::Binding);
        }
        Ok(Self { sync, fresh })
    }
    fn check(&self) -> Result<()> {
        self.fresh.check_current()?;
        self.sync
            .wallet
            .backup_identity
            .as_ref()
            .ok_or(DurableConstructionError::Storage)?
            .check()
            .map_err(|_| DurableConstructionError::Storage)
    }
}
trait HeldChecks {
    fn check(&self) -> Result<()>;
}
struct EmptyChecks;
impl HeldChecks for EmptyChecks {
    fn check(&self) -> Result<()> {
        Ok(())
    }
}
struct CheckNode<'a> {
    prior: &'a dyn HeldChecks,
    check: &'a dyn Fn() -> Result<()>,
}
impl HeldChecks for CheckNode<'_> {
    fn check(&self) -> Result<()> {
        self.prior.check()?;
        (self.check)()
    }
}
/// Borrowed all-wallet maintained-lock conjunction. This proves fresh source
/// and local eligibility, NOT disclosure consent or spending authorization.
pub struct HeldDurableConstructionRosterV1<'a> {
    checks: &'a dyn HeldChecks,
}
impl HeldDurableConstructionRosterV1<'_> {
    pub fn check_current(&self) -> Result<()> {
        self.checks.check()
    }
}

pub fn with_durable_construction_roster_v1<R, E, F>(
    mut slots: Vec<DurableConstructionWalletSlotV1<'_>>,
    callback: F,
) -> std::result::Result<R, E>
where
    E: From<DurableConstructionError>,
    F: for<'g> FnOnce(
        &HeldDurableConstructionRosterV1<'g>,
        Vec<wholepact_protocol::construction::OwnedContribution>,
        wholepact_protocol::construction::ConstructionContext,
    ) -> std::result::Result<R, E>,
{
    if slots.len() != 2 {
        return Err(DurableConstructionError::Binding.into());
    }
    let reused = slots.iter().fold(false, |used, slot| {
        slot.fresh.attempted.replace(true) || used
    });
    if reused {
        return Err(DurableConstructionError::Stale.into());
    }
    slots.sort_by(|a, b| {
        a.fresh
            .material
            .account_id
            .cmp(&b.fresh.material.account_id)
    });
    let first = slots[0].fresh;
    let mut accounts = BTreeSet::new();
    let mut fvks = BTreeSet::new();
    let mut inputs = BTreeSet::new();
    let mut nfs = BTreeSet::new();
    let mut materials = Vec::new();
    for (i, slot) in slots.iter().enumerate() {
        slot.check().map_err(E::from)?;
        let f = slot.fresh;
        if !accounts.insert(&f.material.account_id)
            || !fvks.insert(&f.material.fvk_digest)
            || f.scope.proposal != first.scope.proposal
            || f.current != first.current
            || f.scope.constructor.principal_id != first.scope.constructor.principal_id
            || f.scope.prover.principal_id != first.scope.prover.principal_id
            || f.scope.reviewers != first.scope.reviewers
            || slots[..i]
                .iter()
                .any(|s| s.sync.wallet.backup_identity == slot.sync.wallet.backup_identity)
            || f.material
                .notes
                .iter()
                .any(|n| !inputs.insert(&n.input_id) || !nfs.insert(&n.nullifier))
        {
            return Err(DurableConstructionError::Binding.into());
        }
        materials.push(f.material.validate().map_err(E::from)?);
    }
    if inputs.len() > 64 || inputs.len() != first.scope.proposal.manifest.inputs.len() {
        return Err(DurableConstructionError::Binding.into());
    }
    let context = wholepact_protocol::construction::ConstructionContext {
        anchor: first.current.anchor_root,
        anchor_height: first.current.anchor_height,
        anchor_block_hash: first.current.anchor_hash_protocol,
        target_height: first
            .current
            .tip_height
            .checked_add(1)
            .ok_or_else(|| E::from(DurableConstructionError::Stale))?,
    };
    let result = lock_roster(
        &mut slots,
        &EmptyChecks,
        &mut Some((callback, materials, context)),
    )?;
    for slot in slots {
        slot.check().map_err(E::from)?;
    }
    Ok(result)
}
struct TransactionError<E>(E);
impl<E: From<DurableConstructionError>> From<rusqlite::Error> for TransactionError<E> {
    fn from(_: rusqlite::Error) -> Self {
        Self(DurableConstructionError::Storage.into())
    }
}
fn lock_roster<R, E, F>(
    slots: &mut [DurableConstructionWalletSlotV1<'_>],
    prior: &dyn HeldChecks,
    callback: &mut Option<(
        F,
        Vec<wholepact_protocol::construction::OwnedContribution>,
        wholepact_protocol::construction::ConstructionContext,
    )>,
) -> std::result::Result<R, E>
where
    E: From<DurableConstructionError>,
    F: for<'g> FnOnce(
        &HeldDurableConstructionRosterV1<'g>,
        Vec<wholepact_protocol::construction::OwnedContribution>,
        wholepact_protocol::construction::ConstructionContext,
    ) -> std::result::Result<R, E>,
{
    prior.check().map_err(E::from)?;
    for s in slots.iter() {
        s.check().map_err(E::from)?;
    }
    let Some((slot, rest)) = slots.split_first_mut() else {
        let held = HeldDurableConstructionRosterV1 { checks: prior };
        let (callback, contributions, context) = callback
            .take()
            .ok_or_else(|| E::from(DurableConstructionError::Binding))?;
        return callback(&held, contributions, context);
    };
    let fresh = slot.fresh;
    let wallet = &mut slot.sync.wallet;
    let identity = wallet
        .backup_identity
        .as_ref()
        .ok_or_else(|| E::from(DurableConstructionError::Storage))?;
    wallet.db.transactionally_with_extension(|db, extension| {
        fresh.check_current().map_err(|e| TransactionError(E::from(e)))?;
        let owned = fresh.material.validate().map_err(|e| TransactionError(E::from(e)))?;
        db.with_ironwood_tree_mut::<_, _, WalletError>(|tree| {
            let anchor = fresh.current.anchor_height.into();
            let root = tree.root_at_checkpoint_id(&anchor)?.ok_or(WalletError::MissingWitness)?;
            if orchard::Anchor::from(root).to_bytes() != fresh.current.anchor_root { return Err(WalletError::ChainMismatch); }
            for note in &owned.notes {
                let witness: MerklePath = tree.witness_at_checkpoint_id_caching(u64::from(note.witness.position()).into(), &anchor)?
                    .ok_or(WalletError::MissingWitness)?.into();
                if witness.root(note.note.commitment().into()).to_bytes() != fresh.current.anchor_root {
                    return Err(WalletError::InvalidNote);
                }
            }
            Ok(())
        }).map_err(|e| TransactionError(E::from(DurableConstructionError::from(e))))?
            .ok_or_else(|| TransactionError(E::from(DurableConstructionError::Stale)))?;
        let check = || -> Result<()> {
            fresh.check_current()?;
            identity.check().map_err(|_| DurableConstructionError::Storage)?;
            let quarantined: bool = extension.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='wholepact_bundle_quarantine')", [], |r| r.get(0))
                .map_err(|_| DurableConstructionError::Storage)?;
            if quarantined { return Err(DurableConstructionError::Storage); }
            verify_current_notes(db, fresh)
        };
        check().map_err(|e| TransactionError(E::from(e)))?;
        let node = CheckNode { prior, check: &check };
        node.check().map_err(|e| TransactionError(E::from(e)))?;
        let result = lock_roster(rest, &node, callback).map_err(TransactionError)?;
        node.check().map_err(|e| TransactionError(E::from(e)))?;
        Ok(result)
    }).map_err(|e: TransactionError<E>| e.0)
}

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "durable_construction_v1_tests.rs"]
mod tests;
