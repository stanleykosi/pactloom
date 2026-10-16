const LEGACY_INBOX_SCHEMA: &str = super::replay_schema::INBOX_SCHEMAS[0].0;
#[cfg(not(feature = "offline-admission-export"))]
const INBOX_SCHEMA_INDEX: usize = 0;
#[cfg(feature = "offline-admission-export")]
const INBOX_SCHEMA_INDEX: usize = 1;
pub(crate) const INBOX_SCHEMA: &str = super::replay_schema::INBOX_SCHEMAS[INBOX_SCHEMA_INDEX].0;
pub(crate) const INBOX_SCHEMA_VERSION: i64 =
    super::replay_schema::INBOX_SCHEMAS[INBOX_SCHEMA_INDEX].1;
include!("replay_core.rs");

#[cfg(test)]
mod schema_contract_tests {
    use super::*;
    // Staged only. These are in-memory schema tests, not encrypted DB qualification.
    #[test]
    fn compiled_inbox_schema_accepts_exact_objects_and_rejects_extra_table() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(INBOX_SCHEMA).unwrap();
        assert!(verify_inbox_schema(&c, INBOX_SCHEMA).is_ok());
        c.execute_batch("CREATE TABLE unexpected(payload BLOB);")
            .unwrap();
        assert!(matches!(
            verify_inbox_schema(&c, INBOX_SCHEMA),
            Err(TransportError::UnsupportedVersion)
        ));
    }
    #[test]
    fn feature_controls_complete_schema_and_backup_version() {
        assert_eq!(
            crate::bundle::INBOX_BACKUP_TEMPLATE.schema_version,
            INBOX_SCHEMA_VERSION
        );
        assert_eq!(
            crate::bundle::INBOX_BACKUP_TEMPLATE.create_sql,
            INBOX_SCHEMA
        );
        #[cfg(feature = "offline-admission-export")]
        {
            assert_eq!(INBOX_SCHEMA_VERSION, 3);
            assert!(INBOX_SCHEMA.contains("offline_control_outcomes"));
        }
        #[cfg(not(feature = "offline-admission-export"))]
        {
            assert_eq!(INBOX_SCHEMA_VERSION, 2);
            assert!(!INBOX_SCHEMA.contains("offline_control_outcomes"));
        }
    }
    #[cfg(not(feature = "offline-admission-export"))]
    #[test]
    fn feature_disabled_open_refuses_control_bearing_v3_format() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(LEGACY_INBOX_SCHEMA).unwrap();
        c.execute_batch("CREATE TABLE offline_control_outcomes(stream TEXT,sequence INTEGER,control_digest TEXT); PRAGMA application_id=1464879426; PRAGMA user_version=3;").unwrap();
        assert!(matches!(
            SqliteReplayLedger::from_connection(
                c,
                MailboxProtection::CiphertextOnlyMetadataUnencrypted,
                None
            ),
            Err(TransportError::UnsupportedVersion)
        ));
    }
}

// Synthetic protected-storage boundary tests only. No account, network,
// signing, proof execution, enrollment or live credential is created.
#[cfg(all(test, target_os = "linux"))]
mod internal_name_filter_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wholepact-schema-SqliteReplayLedger-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn sqlite_prefix_user_table_and_trigger_cannot_admit_initialization() {
        for trigger in [false, true] {
            let dir = Temp::new();
            let path = dir.0.join("synthetic.sqlite");
            let key = DatabaseKey::from_bytes([0x75; 32]);
            let encrypted = create_encrypted(&path, &key).unwrap();
            encrypted.connection().execute_batch("CREATE TABLE sqliteXextra(value TEXT); INSERT INTO sqliteXextra VALUES('synthetic-preserved');").unwrap();
            if trigger {
                encrypted.connection().execute_batch("CREATE TRIGGER sqliteXtrigger AFTER INSERT ON sqliteXextra BEGIN SELECT 1; END;").unwrap();
            }
            assert!(matches!(
                SqliteReplayLedger::from_encrypted_connection(encrypted),
                Err(TransportError::UnsupportedVersion)
            ));
            let reopened = open_encrypted(&path, &key).unwrap();
            let c = reopened.connection();
            let app: i64 = c
                .pragma_query_value(None, "application_id", |r| r.get(0))
                .unwrap();
            let version: i64 = c
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert_eq!((app, version), (0, 0));
            let preserved: String = c
                .query_row("SELECT value FROM sqliteXextra", [], |r| r.get(0))
                .unwrap();
            assert_eq!(preserved, "synthetic-preserved");
            let initialized: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='receipts')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!initialized);
        }
    }
    #[test]
    fn legitimate_sqlite_internal_objects_allow_initialization_and_exact_reopen() {
        let dir = Temp::new();
        let path = dir.0.join("synthetic.sqlite");
        let key = DatabaseKey::from_bytes([0x76; 32]);
        let encrypted = create_encrypted(&path, &key).unwrap();
        encrypted.connection().execute_batch("ANALYZE;").unwrap();
        let stats: bool = encrypted
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sqlite_stat1')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stats);
        let journal = SqliteReplayLedger::from_encrypted_connection(encrypted).unwrap();
        drop(journal);
        let reopened = open_encrypted(&path, &key).unwrap();
        reopened.connection().execute_batch("ANALYZE;").unwrap();
        let journal = SqliteReplayLedger::from_encrypted_connection(reopened).unwrap();
        drop(journal);
    }
}

#[cfg(test)]
mod exact_internal_name_filter_tests {
    use super::*;
    #[test]
    fn existing_inbox_rejects_sqlite_prefix_extra_table_or_trigger() {
        for sql in [
            "CREATE TABLE sqliteXextra(value TEXT)",
            "CREATE TRIGGER sqliteXextra AFTER INSERT ON receipts BEGIN SELECT 1; END",
        ] {
            let c = Connection::open_in_memory().unwrap();
            c.execute_batch(INBOX_SCHEMA).unwrap();
            verify_inbox_schema(&c, INBOX_SCHEMA).unwrap();
            c.execute_batch(sql).unwrap();
            assert!(matches!(
                verify_inbox_schema(&c, INBOX_SCHEMA),
                Err(TransportError::UnsupportedVersion)
            ));
        }
    }
}
