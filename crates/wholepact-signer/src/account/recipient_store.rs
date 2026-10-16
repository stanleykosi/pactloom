//! Private recipient journal. Both files form one backup unit; a missing half
//! fails closed. Imported JSON never creates an authenticated instruction record.
use super::*;
const KEY: &str = "recipient-record-key.wp";
const DATA: &str = "recipient-records.wp";
const MAX: usize = 4 * 1024 * 1024;
impl AccountVault {
    pub(crate) fn read_recipient_records(&self) -> Result<Zeroizing<Vec<u8>>> {
        match (self.directory.exists(KEY)?, self.directory.exists(DATA)?) {
            (false, false) => Ok(Zeroizing::new(b"[]".to_vec())),
            (true, true) => {
                let domain = self.recipient_domain()?;
                let wrapped = self.directory.read(KEY, 1024)?;
                let key = vault::decrypt(&self.encryption_key, &domain, &wrapped)?;
                let key: Zeroizing<[u8; 32]> = Zeroizing::new(
                    key.as_slice()
                        .try_into()
                        .map_err(|_| Error::Authentication)?,
                );
                let encrypted = self.directory.read(DATA, MAX + 1024)?;
                vault::decrypt(&key, &domain, &encrypted)
            }
            _ => Err(Error::RecoveryRequired),
        }
    }
    pub(crate) fn write_recipient_records(&self, bytes: &[u8]) -> Result<()> {
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if self.born_origin.is_some() {
            return Err(Error::Unavailable);
        }
        if bytes.len() > MAX {
            return Err(Error::InvalidData);
        }
        let domain = self.recipient_domain()?;
        let key = match (self.directory.exists(KEY)?, self.directory.exists(DATA)?) {
            (false, false) => {
                let key = Zeroizing::new(vault::random::<32>()?);
                self.directory.write(
                    KEY,
                    &vault::encrypt(&self.encryption_key, &domain, key.as_slice())?,
                )?;
                key
            }
            (true, true) => {
                let wrapped = self.directory.read(KEY, 1024)?;
                let key = vault::decrypt(&self.encryption_key, &domain, &wrapped)?;
                Zeroizing::new(
                    key.as_slice()
                        .try_into()
                        .map_err(|_| Error::Authentication)?,
                )
            }
            _ => return Err(Error::RecoveryRequired),
        };
        self.directory
            .write(DATA, &vault::encrypt(&key, &domain, bytes)?)
    }
    fn recipient_domain(&self) -> Result<Vec<u8>> {
        let mut domain = b"wholepact:recipient-records:v1\0".to_vec();
        domain.extend(self.account_id()?.as_bytes());
        Ok(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recipient_pair_is_encrypted_and_missing_half_is_not_adopted() {
        let temp = tempfile::tempdir().unwrap();
        // Synthetic local storage fixture; never network-funded or a live key.
        let pending = PendingAccount::generate(ProvisioningConsent {
            privacy_domain: "synthetic-recipient-storage".into(),
            account_index: 0,
        })
        .unwrap();
        let words = pending.recovery_words().unwrap();
        let verified = pending.verify_backup(&words).unwrap();
        let vault = AccountVault::create(
            &temp.path().join("account"),
            verified,
            b"synthetic-fixture-password-only",
        )
        .unwrap();
        let canary = b"[{\"private_recipient_reference\":\"never-in-plaintext-fixture\"}]";
        assert_eq!(&*vault.read_recipient_records().unwrap(), b"[]");
        vault.write_recipient_records(canary).unwrap();
        assert_eq!(&*vault.read_recipient_records().unwrap(), canary);
        let ciphertext = vault.directory.read(DATA, MAX + 1024).unwrap();
        assert!(!ciphertext.windows(canary.len()).any(|part| part == canary));
        std::fs::remove_file(vault.directory.root().join(DATA)).unwrap();
        assert!(matches!(
            vault.read_recipient_records(),
            Err(Error::RecoveryRequired)
        ));
        assert!(matches!(
            vault.write_recipient_records(b"[]"),
            Err(Error::RecoveryRequired)
        ));
    }
}
