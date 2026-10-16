//! Pure arithmetic/identity projection tests only. Modeled facts below cannot
//! manufacture a maintained selection, native lease, source lifetime or opaque
//! UnreviewedManualCandidate. No key, socket, wallet, witness or funds are used.
use super::*;
use wholepact_core::{
    ParticipantAllocation,
    born_recipient_policy_v2::{
        BornChargeLimitV2, BornConstructionRecipientPolicyV2, BornOriginalLimitsV2,
        BornOwnReturnRuleV2, BornRecipientLimitV2,
    },
    proposal::ChargeConsent,
};
fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn hash(c: char) -> String {
    c.to_string().repeat(64)
}
struct Fixture {
    intent: ManualCandidateEconomicIntent,
    invocation: ManualCandidateInvocation,
    inputs: [Vec<ManualConstructionInput>; 2],
    contexts: [ManualSelectionContext; 2],
}
impl Fixture {
    fn new(charges: bool) -> Self {
        let mut agreement: wholepact_core::AgreementDraft = wholepact_core::parse_typed_json(
            include_bytes!("../../../../wholepact-core/tests/fixtures/agreement.json"),
        )
        .unwrap();
        agreement.network_profile_id = wholepact_protocol::construction::PROFILE_ID.into();
        let mut participants = vec![
            ParticipantAllocation {
                participant_id: "alice".into(),
                account_id: "11".repeat(32),
                contribution: amount(400_000_000),
                fee_share: amount(12_000),
                fee_cap: amount(12_000),
                maximum_net_debit: amount(400_012_000),
                charges: vec![],
            },
            ParticipantAllocation {
                participant_id: "bob".into(),
                account_id: "22".repeat(32),
                contribution: amount(600_000_000),
                fee_share: amount(18_000),
                fee_cap: amount(18_000),
                maximum_net_debit: amount(600_018_000),
                charges: vec![],
            },
        ];
        if charges {
            participants[0].charges.push(ChargeConsent {
                charge_id: "synthetic-service".into(),
                address: "uSyntheticCharge".into(),
                amount: amount(7),
                purpose: "Exact synthetic charge purpose".into(),
            });
            participants[0].maximum_net_debit = amount(400_012_007);
        }
        let intent = ManualCandidateEconomicIntent {
            version: 1,
            candidate_id: "synthetic-candidate".into(),
            candidate_revision: 7,
            proposal_id: "synthetic-proposal".into(),
            previous_proposal_id: None,
            created_at: "2026-10-13T14:00:00Z".into(),
            agreement,
            participants,
            transaction_fee: amount(30_000),
            expiry_height: 3_000_100,
            own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        };
        let invocation = ManualCandidateInvocation {
            version: 1,
            operation_id: "synthetic-invocation".into(),
            idempotency_key_digest: hash('a'),
            invocation_nonce: hash('b'),
            economic_intent_digest: intent.digest().unwrap(),
            checkpoint_destination: "/synthetic/checkpoint".into(),
            requested_at_ms: 2000,
            construction_expires_at_ms: 100_000,
        };
        let context = ManualSelectionContext {
            tip_height: 3_000_000,
            tip_hash_protocol: hash('a'),
            anchor_height: 2_999_990,
            anchor_hash_protocol: hash('b'),
            anchor_root: hash('c'),
        };
        Self {
            intent,
            invocation,
            inputs: [
                vec![ManualConstructionInput {
                    input_id: "synthetic-alice-note".into(),
                    nullifier: hash('1'),
                    value_zatoshis: 500_000_000,
                }],
                vec![ManualConstructionInput {
                    input_id: "synthetic-bob-note".into(),
                    nullifier: hash('2'),
                    value_zatoshis: 700_000_000,
                }],
            ],
            contexts: [context.clone(), context],
        }
    }
    fn facts(&self) -> Vec<CandidateInputFacts<'_>> {
        let debits = self.intent.validate().unwrap();
        self.intent
            .participants
            .iter()
            .enumerate()
            .map(|(n, p)| CandidateInputFacts {
                participant_id: &p.participant_id,
                account_id: &p.account_id,
                requested_debit_zatoshis: debits[&p.participant_id].as_zatoshis(),
                selected_zatoshis: self.inputs[n].iter().map(|i| i.value_zatoshis).sum(),
                inputs: &self.inputs[n],
                context: &self.contexts[n],
                // This pure projection does not validate or claim a real receiver.
                // Production receives only maintained, encoded and decoded receivers
                // from the actual collector; that path has no modeled-facts factory.
                change_address: if n == 0 {
                    "uSyntheticReturnAlice"
                } else {
                    "uSyntheticReturnBob"
                },
            })
            .collect()
    }
    fn policy(&self, n: usize) -> BornConstructionRecipientPolicyV2 {
        let own = &self.intent.participants[n];
        BornConstructionRecipientPolicyV2 {
            version: 2,
            account_id: own.account_id.clone(),
            participant_id: own.participant_id.clone(),
            agreement_id: self.intent.agreement.agreement_id.clone(),
            obligation_id: self.intent.agreement.obligation_id.clone(),
            network_profile_id: self.intent.agreement.network_profile_id.clone(),
            recipients: self
                .intent
                .agreement
                .recipients
                .iter()
                .map(|r| BornRecipientLimitV2 {
                    recipient_id: r.recipient_id.clone(),
                    address: r.address.clone(),
                    memo: r.memo.clone(),
                    instruction_provenance: r.instruction_provenance.clone(),
                    maximum_amount_zatoshis: r.amount.as_zatoshis(),
                })
                .collect(),
            charges: self
                .intent
                .participants
                .iter()
                .flat_map(|p| {
                    p.charges.iter().map(|c| BornChargeLimitV2 {
                        participant_id: p.participant_id.clone(),
                        account_id: p.account_id.clone(),
                        charge_id: c.charge_id.clone(),
                        address: c.address.clone(),
                        purpose: c.purpose.clone(),
                        maximum_amount_zatoshis: c.amount.as_zatoshis(),
                    })
                })
                .collect(),
            original_limits: BornOriginalLimitsV2 {
                aggregate_budget_zatoshis: 2_000_000_000,
                per_operation_limit_zatoshis: 800_000_000,
                maximum_fee_share_zatoshis: 30_000,
                maximum_transaction_fee_zatoshis: 30_000,
                maximum_permit_lifetime_ms: 120_000,
                policy_expires_at_ms: 500_000,
            },
            own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        }
    }
}
#[test]
fn complete_actual_projection_preserves_economics_and_exact_returns() {
    let f = Fixture::new(true);
    let proposal = reconcile_actual_facts(&f.intent, &f.facts()).unwrap();
    assert!(proposal.input().artifact_digest.is_none());
    assert!(proposal.input().effects_commitment.is_none());
    assert_eq!(proposal.manifest().participants, f.intent.participants);
    assert_eq!(proposal.manifest().agreement, f.intent.agreement);
    assert_eq!(
        proposal.accounting().participant_net_debits["alice"],
        amount(400_012_007)
    );
    assert_eq!(
        proposal.accounting().participant_net_debits["bob"],
        amount(600_018_000)
    );
    assert!(!proposal.accounting().authorization_allowed);
    assert_eq!(proposal.manifest().inputs.len(), 2);
    assert_eq!(
        proposal.manifest().inputs[0].input_id,
        f.inputs[0][0].input_id
    );
    assert_eq!(proposal.manifest().inputs[0].amount, amount(500_000_000));
    assert!(
        proposal
            .manifest()
            .inputs
            .iter()
            .all(|i| i.ownership_evidence_ref.is_none())
    );
    let alice = f.policy(0).validate_candidate(proposal.input()).unwrap().1;
    let bob = f.policy(1).validate_candidate(proposal.input()).unwrap().1;
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].amount_zatoshis, 99_987_993);
    assert_eq!(alice[0].address, "uSyntheticReturnAlice");
    assert_eq!(bob[0].amount_zatoshis, 99_982_000);
    assert!(proposal.manifest().outputs.iter().any(|o| matches!(&o.allocation,
        OutputAllocation::Charge { participant_id, charge_id } if participant_id == "alice" && charge_id == "synthetic-service")
        && o.amount == amount(7) && o.address == "uSyntheticCharge"));
}
#[test]
fn owner_order_is_irrelevant_but_missing_extra_or_duplicate_owners_fail() {
    let f = Fixture::new(false);
    let expected = reconcile_actual_facts(&f.intent, &f.facts()).unwrap();
    let mut reordered = f.facts();
    reordered.reverse();
    assert_eq!(
        reconcile_actual_facts(&f.intent, &reordered).unwrap(),
        expected
    );
    let mut missing = f.facts();
    missing.pop();
    assert!(reconcile_actual_facts(&f.intent, &missing).is_err());
    let mut extra = f.facts();
    extra.push(f.facts().remove(0));
    assert!(reconcile_actual_facts(&f.intent, &extra).is_err());
    let mut duplicate = f.facts();
    duplicate[1] = f.facts().remove(0);
    assert!(reconcile_actual_facts(&f.intent, &duplicate).is_err());
    let mut relabeled = f.facts();
    relabeled[1].participant_id = "unlisted";
    assert!(reconcile_actual_facts(&f.intent, &relabeled).is_err());
    let mut aliased = f.facts();
    aliased[1].account_id = aliased[0].account_id;
    assert!(reconcile_actual_facts(&f.intent, &aliased).is_err());
    let mut swapped = f.facts();
    swapped[0].account_id = &f.intent.participants[1].account_id;
    swapped[1].account_id = &f.intent.participants[0].account_id;
    assert!(reconcile_actual_facts(&f.intent, &swapped).is_err());
}
#[test]
fn same_common_intent_and_every_invocation_field_are_required() {
    let f = Fixture::new(false);
    require_common_intent(&f.intent, &f.invocation, &f.intent, &f.invocation).unwrap();
    let mut changed = f.intent.clone();
    changed.candidate_revision += 1;
    assert!(require_common_intent(&f.intent, &f.invocation, &changed, &f.invocation).is_err());
    for n in 0..8 {
        let mut changed = f.invocation.clone();
        match n {
            0 => changed.operation_id.push_str("-other"),
            1 => changed.idempotency_key_digest = hash('c'),
            2 => changed.invocation_nonce = hash('c'),
            3 => changed.economic_intent_digest = hash('c'),
            4 => changed.checkpoint_destination.push_str("-other"),
            5 => changed.requested_at_ms += 1,
            6 => changed.construction_expires_at_ms += 1,
            _ => changed.version += 1,
        }
        assert!(require_common_intent(&f.intent, &f.invocation, &f.intent, &changed).is_err());
    }
}
#[test]
fn duplicate_input_or_nullifier_across_actual_accounts_is_rejected() {
    for duplicate_nullifier in [false, true] {
        let mut f = Fixture::new(false);
        if duplicate_nullifier {
            f.inputs[1][0].nullifier = f.inputs[0][0].nullifier.clone();
        } else {
            f.inputs[1][0].input_id = f.inputs[0][0].input_id.clone();
        }
        assert!(reconcile_actual_facts(&f.intent, &f.facts()).is_err());
    }
    let mut f = Fixture::new(false);
    let duplicate = f.inputs[0][0].clone();
    f.inputs[0].push(duplicate);
    assert!(reconcile_actual_facts(&f.intent, &f.facts()).is_err());
}
#[test]
fn amount_shortfall_selected_sum_mismatch_and_noncanonical_inputs_are_rejected() {
    let f = Fixture::new(false);
    let mut mismatched = f.facts();
    mismatched[0].selected_zatoshis += 1;
    assert!(reconcile_actual_facts(&f.intent, &mismatched).is_err());
    let mut debit = f.facts();
    debit[0].requested_debit_zatoshis -= 1;
    assert!(reconcile_actual_facts(&f.intent, &debit).is_err());
    for n in 0..5 {
        let mut f = Fixture::new(false);
        match n {
            0 => f.inputs[0][0].value_zatoshis = 1,
            1 => f.inputs[0][0].value_zatoshis = 0,
            2 => f.inputs[0][0].nullifier = hash('A'),
            3 => f.inputs[0][0].input_id = "not a canonical input id".into(),
            _ => f.inputs[0][0].value_zatoshis = wholepact_core::MAX_MONEY + 1,
        }
        assert!(reconcile_actual_facts(&f.intent, &f.facts()).is_err());
    }
}
#[test]
fn exact_funding_does_not_invent_a_zero_value_return() {
    let mut f = Fixture::new(true);
    f.inputs[0][0].value_zatoshis = f.intent.validate().unwrap()["alice"].as_zatoshis();
    let p = reconcile_actual_facts(&f.intent, &f.facts()).unwrap();
    assert!(
        f.policy(0)
            .validate_candidate(p.input())
            .unwrap()
            .1
            .is_empty()
    );
    assert!(
        p.manifest()
            .outputs
            .iter()
            .all(|o| o.amount != Amount::ZERO)
    );
}
#[test]
fn all_actual_tip_and_anchor_fields_must_match_and_cover_expiry() {
    for n in 0..5 {
        let mut f = Fixture::new(false);
        match n {
            0 => f.contexts[1].tip_height += 1,
            1 => f.contexts[1].tip_hash_protocol = hash('d'),
            2 => f.contexts[1].anchor_height -= 1,
            3 => f.contexts[1].anchor_hash_protocol = hash('d'),
            _ => f.contexts[1].anchor_root = hash('d'),
        }
        assert!(reconcile_actual_facts(&f.intent, &f.facts()).is_err());
    }
    for n in 0..4 {
        let mut f = Fixture::new(false);
        match n {
            0 => f.contexts[0].tip_height = f.intent.expiry_height,
            1 => f.contexts[0].tip_height = u32::MAX,
            2 => f.contexts[0].anchor_height = 0,
            _ => f.contexts[0].anchor_root = hash('A'),
        }
        f.contexts[1] = f.contexts[0].clone();
        assert!(reconcile_actual_facts(&f.intent, &f.facts()).is_err());
    }
}
#[test]
fn full_actual_candidate_is_rechecked_against_each_original_policy() {
    let f = Fixture::new(true);
    let p = reconcile_actual_facts(&f.intent, &f.facts()).unwrap();
    for n in 0..2 {
        let policy = f.policy(n);
        policy.validate_candidate(p.input()).unwrap();
        let mut changed = policy.clone();
        changed.recipients[0].address = "uOtherRecipient".into();
        assert!(changed.validate_candidate(p.input()).is_err());
        let mut changed = policy.clone();
        changed.charges[0].purpose = "different charge".into();
        assert!(changed.validate_candidate(p.input()).is_err());
        let mut changed = policy;
        changed.original_limits.maximum_transaction_fee_zatoshis -= 1;
        assert!(changed.validate_candidate(p.input()).is_err());
    }
}

#[test]
fn authenticated_identity_projection_rejects_renamed_viewing_authority() {
    use wholepact_core::manual_enrollment::ManualAccountIdentity;
    // Inert projections only: no native owner or approval is manufactured.
    // Production obtains this exact identity from each held native request,
    // after the bridge authenticates its maintained FVK against the digest.
    let first = ManualAccountIdentity {
        account_id: hash('1'),
        full_viewing_key_digest: hash('a'),
        network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
        derivation_domain: "synthetic-domain-one".into(),
    };
    let mut alias = first.clone();
    alias.account_id = hash('2');
    alias.derivation_domain = "synthetic-renamed-domain".into();
    let mut distinct = alias.clone();
    distinct.full_viewing_key_digest = hash('b');
    let mut seen = BTreeSet::new();
    require_unique_viewing_authority(&mut seen, &first).unwrap();
    assert!(require_unique_viewing_authority(&mut seen, &alias).is_err());
    assert!(require_unique_viewing_authority(&mut seen, &first).is_err());
    require_unique_viewing_authority(&mut seen, &distinct).unwrap();
    assert_eq!(seen.len(), 2);
    let mut noncanonical = distinct.clone();
    noncanonical.full_viewing_key_digest = hash('B');
    assert!(require_unique_viewing_authority(&mut seen, &noncanonical).is_err());
}
