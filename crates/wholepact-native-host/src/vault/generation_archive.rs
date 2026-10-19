//! Storage-only capsule envelopes. Neither format is an ordinary profile vault
//! or legacy backup envelope; restored material never supplies live authority.
use super::*;
use sha2::{Digest, Sha256};

const PENDING_MAGIC: &[u8; 8] = b"WPNGPA01";
const ARCHIVE_MAGIC: &[u8; 8] = b"WPNGBA01";
const QUARANTINE_MAGIC: &[u8; 8] = b"WPNGQR01";
const PAYLOAD: usize = 1 + 32 + 32 + 32;

struct CapsuleMaterial {
    bytes: Zeroizing<Vec<u8>>,
}
impl CapsuleMaterial {
    fn decode(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        if bytes.len() != PAYLOAD || bytes[0] != 1 {
            return Err(Error::Invalid);
        }
        Ok(Self { bytes })
    }
    fn key(&self) -> DatabaseKey {
        DatabaseKey::from_bytes(
            self.bytes[65..97]
                .try_into()
                .expect("validated capsule payload"),
        )
    }
    fn capsule_id(&self) -> String {
        hex::encode(&self.bytes[1..33])
    }
    fn manifest_digest(&self) -> String {
        hex::encode(&self.bytes[33..65])
    }
}
fn digest(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    hex::decode(value)
        .map_err(|_| Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)
}

pub(crate) struct PendingArchiveRecovery(CapsuleMaterial);
pub(crate) struct ArchiveRecovery(CapsuleMaterial);
pub(crate) struct QuarantinedGenerationRecovery(CapsuleMaterial);
impl PendingArchiveRecovery {
    pub(crate) fn new(capsule_id: &str, source_plan_digest: &str, key: &[u8; 32]) -> Result<Self> {
        Ok(Self(
            ArchiveRecovery::new(capsule_id, source_plan_digest, key)?.0,
        ))
    }
    pub(crate) fn seal(&self, password: &[u8]) -> Result<Vec<u8>> {
        envelope(PENDING_MAGIC, password, &self.0.bytes)
    }
    pub(crate) fn open(bytes: &[u8], password: &[u8]) -> Result<Self> {
        Ok(Self(CapsuleMaterial::decode(open(
            PENDING_MAGIC,
            password,
            bytes,
        )?)?))
    }
    pub(crate) fn capsule_id(&self) -> String {
        self.0.capsule_id()
    }
    pub(crate) fn source_plan_digest(&self) -> String {
        self.0.manifest_digest()
    }
    pub(crate) fn finish(&self, manifest_digest: &str) -> Result<ArchiveRecovery> {
        let mut bytes = Zeroizing::new(self.0.bytes.to_vec());
        bytes[33..65].copy_from_slice(&digest(manifest_digest)?);
        Ok(ArchiveRecovery(CapsuleMaterial::decode(bytes)?))
    }
    pub(crate) fn matches_final(&self, final_recovery: &ArchiveRecovery) -> bool {
        self.0.bytes[1..33] == final_recovery.0.bytes[1..33]
            && self.0.bytes[65..97] == final_recovery.0.bytes[65..97]
    }
}
impl ArchiveRecovery {
    pub(crate) fn new(capsule_id: &str, manifest_digest: &str, key: &[u8; 32]) -> Result<Self> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(PAYLOAD));
        bytes.push(1);
        bytes.extend_from_slice(&digest(capsule_id)?);
        bytes.extend_from_slice(&digest(manifest_digest)?);
        bytes.extend_from_slice(key);
        Ok(Self(CapsuleMaterial::decode(bytes)?))
    }
    pub(crate) fn seal(&self, password: &[u8]) -> Result<Vec<u8>> {
        envelope(ARCHIVE_MAGIC, password, &self.0.bytes)
    }
    pub(crate) fn open(bytes: &[u8], password: &[u8]) -> Result<Self> {
        Ok(Self(CapsuleMaterial::decode(open(
            ARCHIVE_MAGIC,
            password,
            bytes,
        )?)?))
    }
    pub(crate) fn key(&self) -> DatabaseKey {
        self.0.key()
    }
    pub(crate) fn capsule_id(&self) -> String {
        self.0.capsule_id()
    }
    pub(crate) fn manifest_digest(&self) -> String {
        self.0.manifest_digest()
    }
    /// Caller must verify the complete capsule before committing a restored root.
    /// Rewrapping keys alone cannot authenticate a capsule or publish a successor.
    pub(crate) fn quarantine_envelope(&self, password: &[u8]) -> Result<Vec<u8>> {
        envelope(QUARANTINE_MAGIC, password, &self.0.bytes)
    }
}
impl QuarantinedGenerationRecovery {
    pub(crate) fn open(bytes: &[u8], password: &[u8]) -> Result<Self> {
        Ok(Self(CapsuleMaterial::decode(open(
            QUARANTINE_MAGIC,
            password,
            bytes,
        )?)?))
    }
    pub(crate) fn key(&self) -> DatabaseKey {
        self.0.key()
    }
    pub(crate) fn capsule_id(&self) -> String {
        self.0.capsule_id()
    }
    pub(crate) fn manifest_digest(&self) -> String {
        self.0.manifest_digest()
    }
}

/// These buffers are written only into independently encrypted capsule objects.
/// There is deliberately no Serialize, Debug, ordinary vault or grant conversion.
pub(crate) fn source_material(source: &Secrets) -> Result<Zeroizing<Vec<u8>>> {
    source.require_portable_legacy()?;
    if source.generation_plan_digest().is_none() {
        return Err(Error::Invalid);
    }
    Ok(Zeroizing::new(source.bytes.to_vec()))
}
pub(crate) fn source_from_material(
    bytes: Zeroizing<Vec<u8>>,
    profile: &str,
    plan_digest: &str,
) -> Result<Secrets> {
    let source = Secrets::from_bytes(bytes)?;
    if source.profile() != profile
        || source.generation_plan_digest() != Some(digest(plan_digest)?.as_slice())
    {
        return Err(Error::Authentication);
    }
    Ok(source)
}
pub(crate) fn financial_material(source: &FinancialSecrets) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(source.bytes.to_vec())
}
pub(crate) fn financial_from_material(
    bytes: Zeroizing<Vec<u8>>,
    owner: &str,
) -> Result<FinancialSecrets> {
    crate::id(owner)?;
    if bytes.len() != FinancialSecrets::LENGTH
        || bytes[0] != 1
        || bytes[1..33] != Sha256::digest(owner.as_bytes())[..]
    {
        return Err(Error::Authentication);
    }
    Ok(FinancialSecrets { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capsule_and_quarantine_envelopes_never_open_as_live_or_legacy_profiles() {
        let password = b"synthetic-capsule-envelope-password";
        let recovery = ArchiveRecovery::new(&"a".repeat(64), &"b".repeat(64), &[41; 32]).unwrap();
        let archive = recovery.seal(password).unwrap();
        let restored = recovery.quarantine_envelope(password).unwrap();
        assert!(Secrets::open(&archive, password).is_err());
        assert!(Secrets::open(&restored, password).is_err());
        assert!(Secrets::open_recovery(&archive, password).is_err());
        assert!(Secrets::open_recovery(&restored, password).is_err());
        assert!(ArchiveRecovery::open(&restored, password).is_err());
        assert!(QuarantinedGenerationRecovery::open(&archive, password).is_err());
        let reopened = ArchiveRecovery::open(&archive, password).unwrap();
        assert_eq!(reopened.capsule_id(), "a".repeat(64));
        assert_eq!(reopened.manifest_digest(), "b".repeat(64));
        let reopened = QuarantinedGenerationRecovery::open(&restored, password).unwrap();
        assert_eq!(reopened.capsule_id(), "a".repeat(64));
        assert_eq!(reopened.manifest_digest(), "b".repeat(64));
        let mut tampered = archive.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(ArchiveRecovery::open(&tampered, password).is_err());
        assert!(ArchiveRecovery::open(&archive, b"synthetic-incorrect-password").is_err());
        assert!(ArchiveRecovery::new(&"A".repeat(64), &"b".repeat(64), &[41; 32]).is_err());
    }
    #[test]
    fn pending_capsule_intent_is_distinct_and_exactly_bound_to_final_key() {
        let password = b"synthetic-pending-capsule-password";
        let pending =
            PendingArchiveRecovery::new(&"a".repeat(64), &"b".repeat(64), &[42; 32]).unwrap();
        let bytes = pending.seal(password).unwrap();
        assert!(ArchiveRecovery::open(&bytes, password).is_err());
        assert!(QuarantinedGenerationRecovery::open(&bytes, password).is_err());
        assert!(Secrets::open(&bytes, password).is_err());
        assert!(Secrets::open_recovery(&bytes, password).is_err());
        let reopened = PendingArchiveRecovery::open(&bytes, password).unwrap();
        assert_eq!(reopened.capsule_id(), "a".repeat(64));
        assert_eq!(reopened.source_plan_digest(), "b".repeat(64));
        let final_recovery = reopened.finish(&"c".repeat(64)).unwrap();
        assert!(pending.matches_final(&final_recovery));
        assert_eq!(final_recovery.manifest_digest(), "c".repeat(64));
        assert!(!pending.matches_final(
            &ArchiveRecovery::new(&"a".repeat(64), &"c".repeat(64), &[43; 32]).unwrap()
        ));
        assert!(!pending.matches_final(
            &ArchiveRecovery::new(&"d".repeat(64), &"c".repeat(64), &[42; 32]).unwrap()
        ));
        assert!(
            PendingArchiveRecovery::open(&final_recovery.seal(password).unwrap(), password)
                .is_err()
        );
        let mut tampered = bytes;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(PendingArchiveRecovery::open(&tampered, password).is_err());
    }
    #[test]
    fn capsule_secret_material_retains_exact_historical_owner_and_generation() {
        let original = Secrets::fresh().unwrap();
        assert!(source_material(&original).is_err());
        let source = original.bind_successor_plan([23; 32]).unwrap();
        let raw = source_material(&source).unwrap();
        let reopened =
            source_from_material(raw, &source.profile(), &hex::encode([23; 32])).unwrap();
        assert!(source.same_recovery_material(&reopened));
        assert!(
            source_from_material(
                source_material(&source).unwrap(),
                "wrong-profile",
                &hex::encode([23; 32])
            )
            .is_err()
        );
        assert!(
            source_from_material(
                source_material(&source).unwrap(),
                &source.profile(),
                &hex::encode([24; 32])
            )
            .is_err()
        );
        let financial = FinancialSecrets::fresh(&source.profile()).unwrap();
        let reopened =
            financial_from_material(financial_material(&financial), &source.profile()).unwrap();
        assert!(financial.same_recovery_material(&reopened));
        assert!(financial_from_material(financial_material(&financial), "wrong-profile").is_err());
    }
}
