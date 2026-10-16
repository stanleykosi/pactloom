use super::*;
fn binding() -> NamedReviewBindingV1 {
    NamedReviewBindingV1 {
        schema_version: 1,
        disclosure_profile: NAMED_REVIEW_DISCLOSURE_PROFILE_V1.into(),
        owner_setup_digest: "11".repeat(32),
        assertion_package_digest: "22".repeat(32),
        original_context_digest: "33".repeat(32),
    }
}
#[test]
fn named_header_commits_all_profile_fields_in_its_distinct_domain() {
    let original = binding();
    let bytes = original.canonical_bytes().unwrap();
    assert!(NamedReviewBindingV1::parse(&bytes).unwrap() == original);
    assert_eq!(
        original.review_package_digest().unwrap(),
        "1f0454b19615b420f4af9f25d46effa26bb91d7282f98f783b0e30f26f936339"
    );
    for change in 0..3 {
        let mut altered = original.clone();
        match change {
            0 => altered.owner_setup_digest = "44".repeat(32),
            1 => altered.assertion_package_digest = "44".repeat(32),
            _ => altered.original_context_digest = "44".repeat(32),
        }
        assert_ne!(
            altered.review_package_digest().unwrap(),
            original.review_package_digest().unwrap()
        );
        assert!(
            altered
                .matches_expected(
                    &original.owner_setup_digest,
                    &original.assertion_package_digest,
                    &original.original_context_digest
                )
                .is_err()
        );
    }
    assert_ne!(
        hex::encode(Sha256::digest(&bytes)),
        original.review_package_digest().unwrap()
    );
}
#[test]
fn named_header_refuses_unknown_noncanonical_oversize_and_wrong_profile() {
    let original = binding();
    let bytes = original.canonical_bytes().unwrap();
    let mut spaced = bytes.clone();
    spaced.push(b' ');
    assert!(NamedReviewBindingV1::parse(&spaced).is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("verified".into(), true.into());
    assert!(NamedReviewBindingV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(
        NamedReviewBindingV1::parse(&vec![b' '; MAX_NAMED_REVIEW_BINDING_BYTES_V1 + 1]).is_err()
    );
    for change in 0..3 {
        let mut altered = original.clone();
        match change {
            0 => altered.schema_version = 2,
            1 => altered.disclosure_profile = "independent".into(),
            _ => altered.owner_setup_digest = "AA".repeat(32),
        }
        assert!(altered.canonical_bytes().is_err());
    }
}
