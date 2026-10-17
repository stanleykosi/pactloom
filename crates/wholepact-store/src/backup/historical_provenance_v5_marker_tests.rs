//! Restriction-only encoding fixtures. No Store, key, file, current observation,
//! native owner, migration, or construction admission is manufactured here.
use super::*;
use crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3;
use wholepact_storage_security::bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID;

#[test]
fn historical_provenance_v5_append_guards_accept_only_explicit_markers() {
    let c = Connection::open_in_memory().unwrap();
    for application in [
        0,
        RECOVERED_GENERATION_APPLICATION_ID,
        ARCHIVE_APPLICATION_ID,
        1,
    ] {
        for version in 0..=10 {
            c.pragma_update(None, "application_id", application)
                .unwrap();
            c.pragma_update(None, "user_version", version).unwrap();
            let before = c.total_changes();
            let current = application == 0 && version == 5;
            let recovered = application == RECOVERED_GENERATION_APPLICATION_ID;
            assert_eq!(
                require_construction_v3_encoding(&c).is_ok(),
                current || (recovered && matches!(version, 4 | 5 | 6 | 7 | 8 | 9)),
                "v3 append guard: application {application}, version {version}"
            );
            assert_eq!(
                require_construction_v4_encoding(&c).is_ok(),
                current || (recovered && matches!(version, 6 | 7 | 8 | 9)),
                "v4 append guard: application {application}, version {version}"
            );
            assert_eq!(
                require_construction_v5_encoding(&c).is_ok(),
                current || (recovered && matches!(version, 8 | 9)),
                "v5 append guard: application {application}, version {version}"
            );
            assert_eq!(c.total_changes(), before);
            assert_eq!(
                c.pragma_query_value::<i64, _>(None, "application_id", |r| r.get(0))
                    .unwrap(),
                application
            );
            assert_eq!(
                c.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                version
            );
        }
    }
}

#[test]
fn historical_provenance_v5_legacy_encoding_refuses_new_field_before_decode() {
    for payload in [
        serde_json::json!({"version": 5}),
        serde_json::json!({"version": 3, "historical_provenance": null}),
        serde_json::json!({"version": 4, "historical_provenance": {}}),
    ] {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(include_str!("../schema.sql")).unwrap();
        let exact = serde_json::to_string(&payload).unwrap();
        c.execute(
            "INSERT INTO records VALUES(?1,'inert-marker-fixture',0,?2,0,0)",
            params![CONSTRUCTION_CLAIM_V3, exact],
        )
        .unwrap();
        let before = c.total_changes();
        // Each supported old encoding class must refuse the explicit new claim
        // or field before a missing typed field can mask the marker boundary.
        for (v3, v4) in [(false, false), (true, false), (true, true)] {
            assert!(matches!(
                validate_construction_encoding(&c, v3, v4, false),
                Err(StoreError::RecoveryRequired)
            ));
        }
        assert_eq!(c.total_changes(), before);
        let retained: String = c
            .query_row("SELECT payload FROM records", [], |r| r.get(0))
            .unwrap();
        assert_eq!(retained, exact);
    }
}
