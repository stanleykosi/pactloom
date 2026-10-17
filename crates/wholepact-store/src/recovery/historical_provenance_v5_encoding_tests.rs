//! Pure marker/template classification only. These tests do not issue a native
//! owner, migrate a journal, or turn historical provenance into live authority.
use super::*;

#[test]
fn historical_provenance_v5_support_matrix_is_explicit_and_closed() {
    for (application, entries) in [
        (
            0,
            vec![
                (1, (false, false, false)),
                (2, (false, false, false)),
                (3, (true, false, false)),
                (4, (true, true, false)),
                (5, (true, true, true)),
            ],
        ),
        (
            RECOVERED_GENERATION_APPLICATION_ID,
            vec![
                (2, (false, false, false)),
                (3, (false, false, false)),
                (4, (true, false, false)),
                (5, (true, false, false)),
                (6, (true, true, false)),
                (7, (true, true, false)),
                (8, (true, true, true)),
                (9, (true, true, true)),
            ],
        ),
    ] {
        for version in -1..=11 {
            let expected = entries.iter().find(|(marker, _)| *marker == version);
            match expected {
                Some((_, support)) => assert_eq!(
                    construction_encoding_support(application, version).unwrap(),
                    *support
                ),
                None => assert!(construction_encoding_support(application, version).is_err()),
            }
        }
    }
    for application in [1, -1, 0x57504241] {
        for version in 0..=11 {
            assert!(construction_encoding_support(application, version).is_err());
        }
    }
}

#[test]
fn historical_provenance_v5_classification_detects_presence_even_under_old_version() {
    let kind = crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3;
    for payload in [
        serde_json::json!({"version": 5}),
        serde_json::json!({"version": 3, "historical_provenance": null}),
        serde_json::json!({"version": 4, "historical_provenance": {}}),
        serde_json::json!({"historical_provenance": []}),
    ] {
        assert!(is_construction_v5_claim(kind, &payload));
        assert!(!is_construction_v5_claim("unrelated_record", &payload));
        assert!(!is_construction_v5_claim(
            crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3,
            &payload
        ));
    }
    for payload in [
        serde_json::json!({"version": 3}),
        serde_json::json!({"version": 4}),
        serde_json::json!({}),
    ] {
        assert!(!is_construction_v5_claim(kind, &payload));
    }
}

#[test]
fn historical_provenance_v5_support_cannot_downgrade_any_inherited_encoding() {
    let classes = [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, true, true),
    ];
    for (destination_rank, destination) in classes.iter().enumerate() {
        for (source_rank, source) in classes.iter().enumerate() {
            assert_eq!(
                require_construction_support(*destination, *source).is_ok(),
                destination_rank >= source_rank
            );
        }
    }
}

#[test]
fn historical_provenance_v5_templates_preserve_exact_historical_sql_and_forms() {
    let ordinary_v1 = "7e235d3af973fabe1521098972302d9521a3a5545f242f468d1498e959b6e44a";
    let ordinary_v2 = "d94b68ac4d54397aa05140dbfa994b2580d5c334034e793b7f6aea8066a477be";
    let single = "5a67749bab5ea460ee8e2686e17df6ad547eb16d4986ce3fbb9fb29b0ac7ca79";
    let layered = "a6194913276f59f49ac38847c3f6855b83f7508d134dcbea40c2af82d93a454d";
    for version in -1..=11 {
        let ordinary = crate::bundle::coordination_template_for_schema(version);
        let recovered = coordination_successor_template_for_schema(version);
        let recursive = coordination_layered_successor_template_for_schema(version);
        assert_eq!(ordinary.is_ok(), matches!(version, 1 | 2 | 3 | 4 | 5));
        assert_eq!(recovered.is_ok(), matches!(version, 2 | 4 | 6 | 8));
        assert_eq!(recursive.is_ok(), matches!(version, 3 | 5 | 7 | 9));
        for (template, expected_application, expected_digest) in [
            (
                ordinary,
                0,
                if version == 1 {
                    ordinary_v1
                } else {
                    ordinary_v2
                },
            ),
            (recovered, RECOVERED_GENERATION_APPLICATION_ID, single),
            (recursive, RECOVERED_GENERATION_APPLICATION_ID, layered),
        ] {
            if let Ok(template) = template {
                assert_eq!(template.schema_version, version);
                assert_eq!(template.application_id, expected_application);
                assert_eq!(
                    hex::encode(Sha256::digest(template.create_sql.as_bytes())),
                    expected_digest
                );
            }
        }
    }
    let markers: Vec<_> = recovered_templates()
        .iter()
        .map(|template| template.schema_version)
        .collect();
    assert_eq!(markers, [2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(crate::bundle::coordination_template().schema_version, 5);
    assert_eq!(coordination_successor_template().schema_version, 8);
    assert_eq!(coordination_layered_successor_template().schema_version, 9);
}
