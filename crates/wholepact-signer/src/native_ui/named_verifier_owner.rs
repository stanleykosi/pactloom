//! Separate protected attestation identity. It cannot sign transactions and never
//! derives an attestation key from a wallet, transport or witness credential.
//! Creation/use code is source-only in qualification: no keys are generated or
//! signatures executed by the selected synthetic tests.
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::{Error, Result, files::PrivateDirectory, vault};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_offline_bridge::CurrentPreparedNamedVerifierAssertion;
use zeroize::Zeroizing;
mod journal;
mod export_identity;
mod export_setup;
mod export;
mod backup;
mod handoff;
mod request;
mod setup;
pub(super) use setup::SetupWorkspace;
mod ui;
mod worker;
use journal::{Journal, State};
const MAGIC: &[u8; 8] = b"WPNVR001";
const FILE: &str = "named-verifier.wp";
const MAX: usize = 16 * 1024 * 1024;

fn check_validity(start: u64, end: u64) -> Result<()> {
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)?;
    check_validity_at(start, end, now)
}
fn check_validity_at(start: u64, end: u64, now: u64) -> Result<()> {
    if start >= end || now < start || now >= end {
        return Err(Error::Locked);
    }
    Ok(())
}

pub(super) struct PreparedVerifierCreation {
    path: PathBuf,
    source: NativeAuthorityBinding,
    digest: String,
}
impl PreparedVerifierCreation {
    pub(super) fn prepare(path: &Path, source: &NativeAuthority) -> Result<Self> {
        source.check_current()?;
        if !path.is_absolute() || path.as_os_str().len() > 4096 || path.exists() {
            return Err(Error::InvalidData);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-create-named-verifier:v1",
            &(
                path.to_str().ok_or(Error::InvalidData)?,
                source.principal_id(),
                source.measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        Ok(Self {
            path: path.into(),
            source: source.binding(),
            digest,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> String {
        format!(
            "CREATE A DISTINCT NAMED-VERIFIER SIGNING IDENTITY\nExact private directory: {}\nA new independently random Ed25519 attestation key will be encrypted under your passphrase. It cannot sign transactions or grant financial authority. People who explicitly pin this key may trust its assertions; you must protect it and verify complete authorized policy coverage before every assertion. Backup copies can duplicate this identity. Native lock/revocation cannot retract issued assertions or cancel disconnected copies. The bounded immutable journal never drops old request fences. No key or data is sent by creation.\nExact native review: {}",
            self.path.display(),
            self.digest
        )
    }
    pub(super) fn create(
        self,
        decision: NativeDecision,
        native: &NativeAuthority,
        password: &[u8],
    ) -> Result<VerifierOwner> {
        native.check_current()?;
        self.source.check_current()?;
        if decision.binding() != &self.source
            || native.binding() != self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        let publication = self.source.clone();
        let _lease = publication.publication_lease()?;
        let directory = PrivateDirectory::create(&self.path)?;
        let seed = Zeroizing::new(vault::random::<32>()?);
        let key =
            Ed25519KeyPair::from_seed_unchecked(seed.as_slice()).map_err(|_| Error::Crypto)?;
        let public_key =
            <[u8; 32]>::try_from(key.public_key().as_ref()).map_err(|_| Error::Crypto)?;
        let salt = vault::random::<16>()?;
        let encryption_key = vault::derive(password, &salt)?;
        let mut owner = VerifierOwner {
            directory,
            seed,
            encryption_key,
            salt,
            source: self.source,
            journal: Journal {
                version: 1,
                public_key,
                restored_informational: false,
                families: Default::default(),
                rows: Default::default(),
                export_identity: None,
            },
            poisoned: false,
        };
        owner.persist()?;
        Ok(owner)
    }
}
pub(super) struct VerifierOwner {
    directory: PrivateDirectory,
    seed: Zeroizing<[u8; 32]>,
    encryption_key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    source: NativeAuthorityBinding,
    journal: Journal,
    poisoned: bool,
}
impl VerifierOwner {
    fn state_commitment(&self)->Result<String> {
        self.check_current()?;
        self.journal.validate()?;
        let bytes=Zeroizing::new(serde_json::to_vec(&self.journal).map_err(|_|Error::InvalidData)?);
        Ok(hex::encode(Sha256::digest(&*bytes)))
    }

    /// Unlock makes no trust selection or signing decision. Every use still
    /// needs this current native source and exact fresh final review.
    pub(super) fn open(path: &Path, password: &[u8], native: &NativeAuthority) -> Result<Self> {
        native.check_current()?;
        let directory = PrivateDirectory::open_existing(path)?;
        let bytes = directory.read(FILE, MAX)?;
        let (plain, encryption_key, salt) =
            vault::open_password_envelope(MAGIC, password, &bytes, MAX)?;
        if plain.len() < 33 {
            return Err(Error::InvalidData);
        }
        let seed =
            Zeroizing::new(<[u8; 32]>::try_from(&plain[..32]).map_err(|_| Error::InvalidData)?);
        let journal: Journal =
            serde_json::from_slice(&plain[32..]).map_err(|_| Error::InvalidData)?;
        journal.validate()?;
        let key =
            Ed25519KeyPair::from_seed_unchecked(seed.as_slice()).map_err(|_| Error::Crypto)?;
        if key.public_key().as_ref() != journal.public_key {
            return Err(Error::Authentication);
        }
        native.check_current()?;
        Ok(Self {
            directory,
            seed,
            encryption_key,
            salt,
            source: native.binding(),
            journal,
            poisoned: false,
        })
    }
    pub(super) fn public_key(&self) -> [u8; 32] {
        self.journal.public_key
    }
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()?;
        if self.poisoned {
            return Err(Error::Uncertain);
        }
        Ok(())
    }
    fn persist(&mut self) -> Result<()> {
        self.check_current()?;
        self.journal.validate()?;
        let body =
            Zeroizing::new(serde_json::to_vec(&self.journal).map_err(|_| Error::InvalidData)?);
        let mut plain = Zeroizing::new(self.seed.to_vec());
        plain.extend_from_slice(&body);
        if plain.len() > MAX - 128 {
            self.poisoned = true;
            return Err(Error::Unavailable);
        }
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&self.salt);
        let encrypted = vault::encrypt(&self.encryption_key, &header, &plain)?;
        header.extend(encrypted);
        if let Err(e) = self.directory.write(FILE, &header) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }
    pub(super) fn stage<'o, 'p, 'a, 'client>(
        &'o mut self,
        prepared: &'p CurrentPreparedNamedVerifierAssertion<'p, 'a, 'client>,
    ) -> Result<PreparedVerifierSigning<'o, 'p, 'a, 'client>> {
        self.check_current()?;
        prepared.check_current().map_err(|_| Error::Locked)?;
        if prepared.statement().verifier_key_digest
            != hex::encode(Sha256::digest(self.public_key()))
        {
            return Err(Error::ReviewMismatch);
        }
        let key = self.journal.prepare(
            prepared.statement().clone(),
            prepared
                .recipient_artifact()
                .map_err(|_| Error::Locked)?
                .bytes()
                .to_vec(),
        )?;
        let terms = prepared.original_terms().map_err(|_|Error::Locked)?.clone();
        let entry = self.journal.rows.get_mut(&key).ok_or(Error::InvalidData)?;
        if let Some(original) = &entry.original_terms {
            if original != &terms { return Err(Error::ReviewMismatch); }
        } else {
            // Only the genuine current producer supplies metadata for new preparation.
            // A historical Signed/Started row is never retroactively enriched.
            if !matches!(entry.state, State::Prepared) { return Err(Error::Uncertain); }
            entry.original_terms = Some(terms);
        }
        self.persist()?;
        let entry = self.journal.rows.get(&key).ok_or(Error::InvalidData)?;
        if !matches!(entry.state, State::Prepared) {
            return Err(Error::Uncertain);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-sign-named-assertion:v1",
            &(
                &key,
                prepared.statement(),
                self.public_key(),
                self.source.entry_digest(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "SIGN ONE EXACT NAMED-VERIFIER ASSERTION\nVerifier key SHA-256: {}\nExact immutable row: {}\n{}\nEvery participant FVK/account association came from a separate current purpose-specific native disclosure. Full original manifest/economics/proof were rechecked. This statement asserts complete indexed ownership/returns and fixed-contribution economics to the explicitly selecting recipient. It does not establish people, matching eligibility, chain truth, current unspentness or financial permission. No viewing key is included in this assertion. A signature cannot be recalled, and disconnected clones cannot be excluded. The original deadlines never reset. Signing success followed by failed durable output remains unknown; this operation will not be automatically repeated. This decision does not export or transmit the result.\nExact native review: {}",
            hex::encode(Sha256::digest(self.public_key())),
            key,
            serde_json::to_string_pretty(prepared.statement()).map_err(|_| Error::InvalidData)?,
            digest
        );
        Ok(PreparedVerifierSigning {
            owner: self,
            prepared,
            key,
            digest,
            display,
            created: Instant::now(),
        })
    }
}
pub(super) struct PreparedVerifierSigning<'o, 'p, 'a, 'client> {
    owner: &'o mut VerifierOwner,
    prepared: &'p CurrentPreparedNamedVerifierAssertion<'p, 'a, 'client>,
    key: String,
    digest: String,
    display: String,
    created: Instant,
}
impl PreparedVerifierSigning<'_, '_, '_, '_> {
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    pub(super) fn approve(self, decision: NativeDecision) -> Result<String> {
        self.owner.check_current()?;
        self.prepared.check_current().map_err(|_| Error::Locked)?;
        if self.created.elapsed() >= Duration::from_secs(120) {
            return Err(Error::Locked);
        }
        if decision.binding() != &self.owner.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let message = Zeroizing::new(self.prepared.signing_message().map_err(|_| Error::Locked)?);
        // Network/liveness work happens before the local publication fence.
        // The fence linearizes exact key use and durable result against native lock.
        let source = self.owner.source.clone();
        let publication = source.publication_lease()?;
        self.owner.journal.begin(&self.key, &self.digest)?;
        // Once Started is attempted, failure is conservative even if the disk
        // outcome cannot be established. Never reset or repeat this effect.
        let outcome = (|| -> Result<()> {
            self.owner.persist()?;
            drop(publication);
            // Persistence may have consumed the short disclosure lifetime.
            // Refresh the actual peer challenge outside the native fence, then
            // enforce nonrenewable local bounds at the final admitted key use.
            self.prepared.check_current().map_err(|_| Error::Locked)?;
            let _publication = source.publication_lease()?;
            self.prepared
                .check_local_current()
                .map_err(|_| Error::Locked)?;
            check_validity(
                self.prepared.statement().validity_not_before_ms,
                self.prepared.statement().validity_expires_ms,
            )?;
            let key = Ed25519KeyPair::from_seed_unchecked(self.owner.seed.as_slice())
                .map_err(|_| Error::Crypto)?;
            let signature = key.sign(&message).as_ref().to_vec();
            self.owner
                .journal
                .finish(&self.key, &self.digest, signature)?;
            self.owner.persist()
        })();
        if outcome.is_err() {
            self.owner.poisoned = true;
            return Err(Error::Uncertain);
        }
        Ok(self.key)
    }
}

/// A purpose-separated proof that the explicitly selected verifier possesses its
/// key for this actual installed-signer caller channel. It cannot sign arbitrary
/// bytes or a transaction, and cannot authorize disclosure without owner review.
pub(super) struct PreparedVerifierPolicyProof<'a> {
    owner: &'a VerifierOwner,
    request: wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyRequestV1,
    client: &'a wholepact_signer_origin::NativeManualClient,
    digest: String,
    display: String,
    created: Instant,
}
impl VerifierOwner {
    pub(super) fn prepare_policy_proof<'a>(
        &'a self,
        scope: wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1,
        client: &'a wholepact_signer_origin::NativeManualClient,
    ) -> Result<PreparedVerifierPolicyProof<'a>> {
        self.check_current()?;
        scope.validate().map_err(|_| Error::InvalidData)?;
        if self.journal.restored_informational || scope.verifier_public_key != self.public_key() {
            return Err(Error::ReviewMismatch);
        }
        let request =
            wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyRequestV1 {
                scope,
                current_caller_binding_digest: client
                    .current_caller_binding_digest()
                    .map_err(|_| Error::Locked)?,
                verifier_possession_signature: vec![],
            };
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-verifier-policy-proof:v1",
            &(
                &request.scope,
                &request.current_caller_binding_digest,
                self.source.entry_digest(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "REQUEST ONE OWNER'S NAMED-VERIFIER VIEWING DISCLOSURE\n{}\nActual installed-signer caller channel: {}\nThis signs only a domain-separated proof of verifier-key possession for the exact channel and request. That account owner must still separately approve persistent FVK disclosure. It is not an ownership assertion, transaction signature or spending authorization. The original request hash binds its original validity; current disclosure expiry is separate and never renews it.\nExact native review: {}",
            serde_json::to_string_pretty(&request.scope).map_err(|_| Error::InvalidData)?,
            request.current_caller_binding_digest,
            digest
        );
        Ok(PreparedVerifierPolicyProof {
            owner: self,
            request,
            client,
            digest,
            display,
            created: Instant::now(),
        })
    }
}
impl PreparedVerifierPolicyProof<'_> {
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    pub(super) fn approve(
        mut self,
        decision: NativeDecision,
    ) -> Result<wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyRequestV1> {
        self.owner.check_current()?;
        if self.created.elapsed() >= Duration::from_secs(120)
            || decision.binding() != &self.owner.source
            || decision.reviewed_digest() != self.digest
            || self
                .client
                .current_caller_binding_digest()
                .map_err(|_| Error::Locked)?
                != self.request.current_caller_binding_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let message = Zeroizing::new(
            self.request
                .possession_message()
                .map_err(|_| Error::InvalidData)?,
        );
        let source = self.owner.source.clone();
        let _publication = source.publication_lease()?;
        let key = Ed25519KeyPair::from_seed_unchecked(self.owner.seed.as_slice())
            .map_err(|_| Error::Crypto)?;
        check_validity(
            self.request.scope.requested_at_ms,
            self.request.scope.disclosure_expires_at_ms,
        )?;
        check_validity(
            self.request.scope.original_validity_not_before_ms,
            self.request.scope.original_validity_expires_ms,
        )?;
        self.request.verifier_possession_signature = key.sign(&message).as_ref().to_vec();
        self.request.validate().map_err(|_| Error::Verification)?;
        Ok(self.request)
    }
}

#[cfg(test)]
mod validity_tests {
    use super::check_validity_at;
    #[test]
    fn original_validity_has_no_inclusive_expiry_or_refresh() {
        assert!(check_validity_at(100, 200, 100).is_ok());
        assert!(check_validity_at(100, 200, 199).is_ok());
        for now in [0, 99, 200, 201, u64::MAX] {
            assert!(check_validity_at(100, 200, now).is_err());
        }
        assert!(check_validity_at(200, 200, 200).is_err());
        assert!(check_validity_at(201, 200, 200).is_err());
    }
}
