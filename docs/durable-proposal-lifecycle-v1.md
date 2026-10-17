# Durable fixed-proposal lifecycle

Status: implementation contract, not a qualified capability. Existing V3 financial gates and historical records remain unchanged until a separately reviewed replacement is qualified.

## Product invariant

Independent account owners authorize their assigned debit in one exact joint shielded transaction. The coordinator holds no spending keys and cannot redirect, increase, or detach the approved effects. Agreement progress, released authorization exposure, and chain observations are separate state axes. Completion is not guaranteed.

## Initial qualification profile

- Two separately controlled contribution accounts, one recipient, manual approval and one authoritative writer per account. Account attribution does not establish distinct people or independent economic sources.
- Existing pinned testnet transaction/pool profile, finite block-height expiry, fixed canonical candidate and anchor.
- Prove before collecting signatures. No post-sign reanchoring, permissive merge, automatic replacement, automation or shared writer in this first slice.
- Use real engine interfaces and genuine signer/authority adapters with synthetic accounts first. Test seams cannot manufacture production authority.
- Matching, larger groups, offline modes, automation and platform support remain separate full-product qualification obligations, not deleted requirements.

## Minimal account-attribution profile

The first slice accepts only plain fixed contributions. The genuinely accepted immutable manifest pins canonical account IDs, derived with the existing domain-separated account-ID hash of each full viewing key. The verifier recomputes those IDs and verifies every real input, note/value/witness, nullifier, randomized verification key, ownership/action mapping, recipient/change output, allocation and fee against the exact fixed artifact. Constructor-supplied labels or selected-own-effects checks cannot substitute for this verification.

Final required spend signatures demonstrate executable control of the attributed accounts. Before those signatures exist, the state is awaiting authorization, not peer approval. This profile makes no claims about legal identity, separate people, sponsor eligibility or matching conditions. Such clauses are rejected rather than silently treated as ordinary contributions; richer profiles remain future qualification obligations.

Private viewing material is a separate disclosure boundary. Mathematical verification does not authorize onward disclosure. Any constructor, prover or local reviewer audience must be explicitly scoped by genuine native consent and authenticated delivery. Recovery to a new recipient grant requires a fresh disclosure decision, retaining the original material, audience limits and deadline rather than extending them.

## Pre-proof construction is part of the repair

Persistence after proving does not solve the existing pre-proof construction failure. A new contribution/material admission path must independently capture each participant's explicitly approved private disclosure, its authenticated account/owner/terms binding and durable provenance. The data is encrypted and remains historical; saved data does not imply current spendability or permission to use a spending key.

The coordinator must obtain fresh exact all-input eligibility and ancestry evidence before construction without requiring all participants' old native UI/read leases to overlap. Every trusted issuer and verification step must be explicit. An arbitrary DTO, callback, serialized live owner or saved verified flag cannot issue authority. The new construction material must be incapable of authorizing signing, export of spend authority, submission, replacement or clearing old exposure.

This is a new reviewed profile. It must not bypass an old V3 guard or reinterpret a V3 permit. Until this path exists and is exercised end to end, post-proof durable helpers are incomplete work, not a working payment flow.

## Durable state and short-lived capabilities

The immutable proposal records its manifest revision, canonical candidate, complete private review policy, ownership/action mapping, network profile, finite expiry, proved artifact and domain-separated fingerprints. Protected artifacts and durable jobs survive process restart.

Fresh local permissions authorize immediate actions such as private disclosure, key use or submission. They do not remain alive while another participant decides. Each actual signing operation performs authenticated review of the exact persisted proposal and reconciles writer authority and outstanding exposure. Expired capabilities cannot be renewed, reconstructed or accepted as new authority.

Current chain evidence is checked at the boundary that needs it. Historical provenance is retained as historical evidence. Coordination deadlines, local capability/freshness limits and consensus transaction expiry are distinct.

## Release and recovery ordering

1. Before spend-authority release or key use, freshly reconcile the account's authoritative writer and independent exposure fence. Uncertain, stale, cloned or restored state cannot issue authorization from its local ledger alone. Earlier non-spending material admission does not acquire or retain a live writer capability across construction or human delays.
2. Prepare permitted contribution data, then construct and prove an exact candidate. Private disclosure, unsigned local planning reservations and potentially executable spend authority remain distinct records.
3. Verify full manifest coverage, actual recipients, contribution and fee allocations, maximum debit, change ownership, attribution, network, expiry and conditions. Selected-own-effects evidence alone is insufficient.
4. Durably reserve the exact obligation and record release intent before usable authorization crosses the signer boundary. Persist the exact signed result/outbox. An uncertain key-use attempt cannot obtain a new authorization ID to evade existing exposure.
5. Intake only authenticated signatures for the expected proposal, account and assigned real input/action positions. Identical duplicate intake is idempotent; conflicting intent or signatures fail closed.
6. Verify the complete artifact, current chain eligibility and expiry margin. Persist exact transaction bytes, identity and submission intent before RPC submission.
7. Treat a lost response as unknown outcome. Reconcile the original transaction; resubmit identical bytes only when eligible. Never fund a new revision because one backend is unaware of the original.

Every cross-boundary operation requires explicit before/after crash states. Local commits do not imply distributed exactly-once execution. Cancellation cannot revoke exported signatures. Stopping the UI/service does not cancel settlement. A pre-approval pause/resume test does not prove safe recovery after an uncertain key-use operation.

## Signature-only transformation

Retain the existing canonical proved base. Accept signatures only at the authenticated owner's assigned real spend positions and verify them through the pinned implementation. Remove only permitted added spend-authorization signatures and require byte-for-byte equality with the saved base. Recheck the complete policy/review binding.

Reject mutations of inputs, outputs, allocations, ordering, network, expiry, anchor, proof, mandatory metadata or review scope. Current modification flags must remain zero. In V6, anchors and proofs are not economic-effect signature commitments: fixing them is an application assembly policy, not a false consensus claim. Application identity and arbitrary manifest text need separate authenticated bindings.

## Trust boundaries, compatibility and cleanup

Keep the keyless engine, participant signers, independently durable writer/exposure fence and replaceable transport/chain adapters distinct. Encrypted SQLite provides durability and confidentiality, not proof that a restored ledger is current. No local-state fallback replaces an unavailable independent fence.

New invocations use an explicit new profile/version. Existing permits, consumed records, disclosures and exposure are not refunded, rewritten or migrated into new authority. Historical records remain readable. Settled debit is not refunded merely because it is no longer outstanding. Remove obsolete code only after compatibility and recovery tests establish that it is unnecessary.

Generated/private/runtime files and investigation logs stay outside the source tree. Preserve funded test wallets, recovery data, meaningful failure evidence and unrelated user files. Never publish keys, private raw PCZTs, viewing material or private journals. Publish small allowlisted source checkpoints, accurately marked untested until verification completes.

## Evidence required before activation

- Real two-owner construction, proof, independent exact-effects authorization, signature intake, extraction and recipient verification through production interfaces.
- Delays beyond the old 60-second ceremony, process closure/restart and continuation of the same still-valid proposal. Expired/conflicted proposals refuse honestly.
- Crash injection around fence reservation, release intent, key use, result persistence, export, intake, transaction persistence, submission and result recording.
- Refusal of wrong recipients/debits/fees/change, account mappings, expiry, network, proof, metadata, duplicated/conflicting inputs, missing signatures and malformed artifacts.
- Same request key with changed intent rejects; identical repeats never multiply authority.
- Stale/cloned writers cannot use saved state as authority. Revocation prevents new grants but never erases released exposure.
- Unknown submission, input conflict and reorganization preserve conservative history and block unsafe replacement.
- Privacy refusal exports nothing forbidden. Logs contain only bounded public diagnostics.
- Separate reporting of synthetic cryptography, native attended acceptance, testnet submission, inclusion, recipient observation, confirmation policy and platform qualification.

No production or live-settlement flag is enabled merely because a component test or synthetic happy path passes.
