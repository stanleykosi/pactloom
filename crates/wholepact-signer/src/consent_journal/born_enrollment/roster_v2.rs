//! STAGED, UNCOMPILED. Intended child consent_journal::born_enrollment::roster_v2.
use super::*;
use crate::account::birth::enrollment::roster_v2::publication::BornRosterEnrollmentPublicationV2;

impl SignerConsentJournal {
    pub(crate) fn publish_born_roster_enrollment_v2(
        publication: &BornRosterEnrollmentPublicationV2<'_>,
    ) -> Result<Self> {
        publication
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let path = publication.journal_path();
        let key = publication.journal_key();
        let genesis = publication.genesis();
        let epoch = publication.writer_epoch();
        let namespace = genesis.digest().map_err(|_| JournalError::InvalidBinding)?;
        let intent = publication.intent_digest();
        let plan = PlannedWitnessBirthInitialization::new(&namespace, intent, &path, &key)?;
        let mut connection = match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                wholepact_storage_security::create_encrypted(&path, &key)?.into_connection()
            }
            Err(_) => return Err(JournalError::Database),
            Ok(_) => match plan.inspect(&path, &key, &namespace, intent)? {
                PlannedWitnessBirthInspection::AuthenticatedEmpty => plan
                    .resume(&path, &key, &namespace, intent)?
                    .into_connection(),
                PlannedWitnessBirthInspection::Initialized(read) => {
                    verify_born_initial(read.connection(), genesis, epoch)?;
                    drop(read);
                    publication
                        .check_current()
                        .map_err(|_| JournalError::Permission)?;
                    let existing = Self::open_encrypted(&path, &key, &genesis.identity.account_id)?;
                    verify_born_initial(
                        &*existing
                            .connection
                            .lock()
                            .map_err(|_| JournalError::Database)?,
                        genesis,
                        epoch,
                    )?;
                    return Ok(existing);
                }
            },
        };
        // Creation and immutable account-use genesis share one SQLite commit.
        // A crash before this commit leaves only the authenticated empty page
        // that the exact durable intent above is allowed to retry.
        configure(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        verify_capacity_schema(&tx)?;
        let epoch = i64::try_from(epoch).map_err(|_| JournalError::InvalidBinding)?;
        if epoch <= 0 {
            return Err(JournalError::InvalidBinding);
        }
        tx.execute(
            "INSERT INTO signer_account VALUES(1,?1,?2,0)",
            params![genesis.identity.account_id, epoch],
        )?;
        tx.execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            params![
                genesis.identity.account_id,
                genesis.identity.full_viewing_key_digest,
                namespace,
                encode(genesis)?.as_str()
            ],
        )?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        verify_born_initial(&tx, genesis, epoch as u64)?;
        publication
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        tx.commit()?;
        drop(connection);
        let result = Self::open_encrypted(&path, &key, &genesis.identity.account_id)?;
        verify_born_initial(
            &*result
                .connection
                .lock()
                .map_err(|_| JournalError::Database)?,
            genesis,
            epoch as u64,
        )?;
        Ok(result)
    }
}
