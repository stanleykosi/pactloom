use crate::{
    envelope::{read_bounded, write_new},
    types::*,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const BACKUP_FORMAT: &str = "wholepact-encrypted-agreement-backup";
const BACKUP_SUITE: &str = "Argon2id-v19-XChaCha20Poly1305";
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;

/// No Debug/Clone/serialization or password persistence. Losing this passphrase
/// makes the backup unrecoverable; the application must warn before exporting.
pub struct BackupPassword(Zeroizing<Vec<u8>>);
impl BackupPassword {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if !(12..=1024).contains(&bytes.len()) {
            return Err(TransportError::WeakPassword);
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupScope {
    pub network_profile_id: String,
    pub agreement_id: String,
}
impl BackupScope {
    fn validate(&self) -> Result<()> {
        validate_id(&self.network_profile_id)?;
        validate_id(&self.agreement_id)
    }
    fn check_expected(&self, expected: &Self) -> Result<()> {
        self.validate()?;
        expected.validate()?;
        if self.network_profile_id != expected.network_profile_id {
            return Err(TransportError::WrongNetwork);
        }
        if self.agreement_id != expected.agreement_id {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupMetadata {
    pub schema_version: u16,
    pub backup_id: String,
    pub scope: BackupScope,
    pub created_at: Timestamp,
    /// Historical source counters only; never activate them as a restored writer.
    pub source_revision: u64,
    pub source_writer_epoch: u64,
}
impl BackupMetadata {
    fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TransportError::UnsupportedVersion);
        }
        validate_hex(&self.backup_id, 16)?;
        self.scope.validate()?;
        if self.source_revision == 0 || self.source_writer_epoch == 0 {
            return Err(TransportError::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSectionKind {
    Agreement,
    Proposals,
    DisclosureConsents,
    AuthorizationJournal,
    Observations,
}

/// One versioned opaque section supplied by the appropriate store/engine adapter.
/// No wallet seed or spending-key section exists. The adapter must not mislabel
/// unrelated secrets as agreement data; this crate cannot inspect opaque records.
pub struct BackupSection {
    kind: BackupSectionKind,
    bytes: Zeroizing<Vec<u8>>,
}
impl BackupSection {
    pub fn new(kind: BackupSectionKind, bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(TransportError::ResourceLimit);
        }
        Ok(Self { kind, bytes })
    }
    pub fn kind(&self) -> BackupSectionKind {
        self.kind
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Complete *section inventory*, not proof that source history is complete/current.
/// All five sections must be present, even if a section encodes an empty list.
pub struct AgreementBackup {
    metadata: BackupMetadata,
    sections: Vec<BackupSection>,
}
impl AgreementBackup {
    pub fn new(metadata: BackupMetadata, mut sections: Vec<BackupSection>) -> Result<Self> {
        metadata.validate()?;
        sections.sort_by_key(|section| section.kind);
        validate_sections(&sections)?;
        Ok(Self { metadata, sections })
    }
    pub fn metadata(&self) -> &BackupMetadata {
        &self.metadata
    }
    pub fn sections(&self) -> &[BackupSection] {
        &self.sections
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupHeader {
    format: String,
    schema_version: u16,
    suite: String,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: String,
    nonce: String,
}
impl BackupHeader {
    fn validate(&self) -> Result<()> {
        if self.format != BACKUP_FORMAT
            || self.schema_version != SCHEMA_VERSION
            || self.suite != BACKUP_SUITE
            || self.memory_kib != MEMORY_KIB
            || self.iterations != ITERATIONS
            || self.lanes != LANES
        {
            return Err(TransportError::UnsupportedVersion);
        }
        validate_hex(&self.salt, 16)?;
        validate_hex(&self.nonce, 24)
    }
    fn aad(&self) -> Result<Vec<u8>> {
        let mut aad = b"wholepact.agreement-backup.v1\0".to_vec();
        aad.extend(encode(self)?);
        Ok(aad)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupEnvelope {
    header: BackupHeader,
    ciphertext: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSection {
    kind: BackupSectionKind,
    data: String,
}
impl Drop for WireSection {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupPlaintext {
    metadata: BackupMetadata,
    sections: Vec<WireSection>,
    contents_digest: String,
}

/// Versioned password-encrypted portable file. It is never uploaded automatically.
pub struct EncryptedBackup(Vec<u8>);
impl EncryptedBackup {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let envelope: BackupEnvelope = parse(&bytes)?;
        envelope.header.validate()?;
        if envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4 {
            return Err(TransportError::ResourceLimit);
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn read_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_bytes(read_bounded(path.as_ref())?)
    }
    pub fn write_new_file(&self, path: impl AsRef<Path>) -> Result<()> {
        write_new(path.as_ref(), &self.0)
    }
}

/// Snapshot authenticity/integrity never establishes freshness of an authority journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreStatus {
    RecoveryRequired,
}
pub struct RestoredBackup {
    archive: AgreementBackup,
}
impl RestoredBackup {
    pub fn archive(&self) -> &AgreementBackup {
        &self.archive
    }
    pub fn status(&self) -> RestoreStatus {
        RestoreStatus::RecoveryRequired
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
}

pub fn encrypt_backup(
    archive: &AgreementBackup,
    password: &BackupPassword,
) -> Result<EncryptedBackup> {
    archive.metadata.validate()?;
    validate_sections(&archive.sections)?;
    let sections: Vec<_> = archive
        .sections
        .iter()
        .map(|section| WireSection {
            kind: section.kind,
            data: b64(&section.bytes),
        })
        .collect();
    let contents_digest = digest(
        b"wholepact.agreement-backup-contents.v1\0",
        &Zeroizing::new(encode(&sections)?),
    );
    let plaintext = Zeroizing::new(encode(&BackupPlaintext {
        metadata: archive.metadata.clone(),
        sections,
        contents_digest,
    })?);
    if plaintext.len() + 16 > MAX_CIPHERTEXT_BYTES {
        return Err(TransportError::ResourceLimit);
    }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut salt).map_err(|_| TransportError::Randomness)?;
    getrandom::fill(&mut nonce).map_err(|_| TransportError::Randomness)?;
    let header = BackupHeader {
        format: BACKUP_FORMAT.into(),
        schema_version: SCHEMA_VERSION,
        suite: BACKUP_SUITE.into(),
        memory_kib: MEMORY_KIB,
        iterations: ITERATIONS,
        lanes: LANES,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
    };
    let key = derive_key(password, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| TransportError::Malformed)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).map_err(|_| TransportError::Malformed)?,
            Payload {
                msg: &plaintext,
                aad: &header.aad()?,
            },
        )
        .map_err(|_| TransportError::Authentication)?;
    Ok(EncryptedBackup(encode(&BackupEnvelope {
        header,
        ciphertext: b64(&ciphertext),
    })?))
}

/// Authenticates and test-restores an archive in memory. Unknown versions/parameters
/// fail before running the bounded KDF. No store, signer or writer is activated.
/// This is also the integrity-verification API; inspect and drop the returned result.
pub fn restore_backup(
    file: &EncryptedBackup,
    password: &BackupPassword,
    expected: &BackupScope,
) -> Result<RestoredBackup> {
    expected.validate()?;
    let envelope: BackupEnvelope = parse(&file.0)?;
    envelope.header.validate()?;
    let ciphertext = unb64(&envelope.ciphertext, MAX_CIPHERTEXT_BYTES)?;
    if ciphertext.len() < 16 {
        return Err(TransportError::Malformed);
    }
    let salt = hex::decode(&envelope.header.salt).map_err(|_| TransportError::Malformed)?;
    let nonce = hex::decode(&envelope.header.nonce).map_err(|_| TransportError::Malformed)?;
    let key = derive_key(password, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| TransportError::Malformed)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::try_from(nonce.as_slice()).map_err(|_| TransportError::Malformed)?,
                Payload {
                    msg: &ciphertext,
                    aad: &envelope.header.aad()?,
                },
            )
            .map_err(|_| TransportError::Authentication)?,
    );
    let restored: BackupPlaintext = parse(&plaintext)?;
    restored.metadata.validate()?;
    restored.metadata.scope.check_expected(expected)?;
    if restored.sections.len() != 5 {
        return Err(TransportError::Malformed);
    }
    if digest(
        b"wholepact.agreement-backup-contents.v1\0",
        &Zeroizing::new(encode(&restored.sections)?),
    ) != restored.contents_digest
    {
        return Err(TransportError::Authentication);
    }
    let sections = restored
        .sections
        .iter()
        .map(|section| BackupSection::new(section.kind, unb64(&section.data, MAX_PAYLOAD_BYTES)?))
        .collect::<Result<Vec<_>>>()?;
    // Do not normalize attacker-supplied ordering during restoration.
    validate_sections(&sections)?;
    Ok(RestoredBackup {
        archive: AgreementBackup {
            metadata: restored.metadata,
            sections,
        },
    })
}
fn derive_key(password: &BackupPassword, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(32))
        .map_err(|_| TransportError::Malformed)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    // Explicitly own and wipe Argon2 workspace; zeroize feature alone does not
    // guarantee the allocation inside hash_password_into is wiped.
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); MEMORY_KIB as usize]);
    argon
        .hash_password_into_with_memory(&password.0, salt, key.as_mut(), &mut *memory)
        .map_err(|_| TransportError::Authentication)?;
    Ok(key)
}
fn validate_sections(sections: &[BackupSection]) -> Result<()> {
    let required = [
        BackupSectionKind::Agreement,
        BackupSectionKind::Proposals,
        BackupSectionKind::DisclosureConsents,
        BackupSectionKind::AuthorizationJournal,
        BackupSectionKind::Observations,
    ];
    if sections.len() != required.len() {
        return Err(TransportError::Malformed);
    }
    let mut bytes = 0usize;
    for (section, kind) in sections.iter().zip(required) {
        if section.kind != kind || section.bytes.is_empty() {
            return Err(TransportError::Malformed);
        }
        bytes = bytes
            .checked_add(section.bytes.len())
            .ok_or(TransportError::ResourceLimit)?;
        if bytes > MAX_PAYLOAD_BYTES {
            return Err(TransportError::ResourceLimit);
        }
    }
    Ok(())
}
