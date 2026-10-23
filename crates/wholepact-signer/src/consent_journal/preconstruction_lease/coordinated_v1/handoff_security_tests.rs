//! Synthetic tests of the additional purpose-identity restriction used by all
//! five real typed lease operations. Enum values and booleans here are inert:
//! no Final, PairPeer, provenance or purpose lease is fabricated or acquired.
//! Real callers derive pointer equality from their retained nominal Final and
//! then execute currentness/provenance checks; integration must test that path.
use super::*;

const PURPOSES: [CoordinatedPurposeKind; 5] = [
    CoordinatedPurposeKind::Read,
    CoordinatedPurposeKind::Prepare,
    CoordinatedPurposeKind::AdmitRead,
    CoordinatedPurposeKind::Admit,
    CoordinatedPurposeKind::Export,
];

#[test]
fn handoff_purpose_identity_rejects_every_cross_purpose_even_with_same_pointer() {
    let mut accepted = 0;
    let mut rejected = 0;
    for held in PURPOSES {
        for requested in PURPOSES {
            let result: Result<()> = require_purpose_identity(held, requested, true);
            if held == requested {
                result.unwrap();
                accepted += 1;
            } else {
                assert!(matches!(result, Err(JournalError::Permission)),
                    "cross-purpose restriction missing: {held:?} -> {requested:?}");
                rejected += 1;
            }
        }
    }
    assert_eq!((accepted, rejected), (5, 20));
}

#[test]
fn handoff_purpose_identity_rejects_every_distinct_final_pointer() {
    for held in PURPOSES {
        for requested in PURPOSES {
            assert!(matches!(require_purpose_identity(held, requested, false),
                Err(JournalError::Permission)),
                "different-Final restriction missing: {held:?} -> {requested:?}");
        }
    }
}
