# Durable fixed-proposal lifecycle

Status: implementation contract, not a qualified capability. Existing V3 financial gates and historical records remain unchanged until a separately reviewed replacement is qualified.

## Product invariant

Independent account owners authorize their assigned debit in one exact joint shielded transaction. The coordinator holds no spending keys and cannot redirect, increase, or detach the approved effects. Agreement progress, released authorization exposure, and chain observations are separate state axes. Completion is not guaranteed.

## Initial qualification profile

- Two independent contributors, one recipient, manual approval and one authoritative writer per account.
- Existing pinned testnet transaction/pool profile, finite block-height expiry, fixed canonical candidate and anchor.
- Prove before collecting signatures. No post-sign reanchoring, permissive merge, automatic replacement, automation or shared writer in this first slice.
- Use real engine interfaces and genuine signer/authority adapters with synthetic accounts first. Test seams cannot manufacture production authority.
- Matching, larger groups, offline modes, automation and platform support remain separate full-product qualification obligations, not deleted requirements.

## Pre-proof construction is part of the repair

Persistence after proving does not solve the existing pre-proof construction failure. A new contribution/material admission path must independently capture each participant's explicitly approved private disclosure, its authenticated account/owner/terms binding and durable provenance. The data is encrypted and remains historical; saved data does not imply current spendability or permission to use a spending key.

The coordinator must obtain fresh exact all-input eligibility and ancestry evidence before construction without requiring all participants' old native UI/read leases to overlap. Every trusted issuer and verification step must be explicit. An arbitrary DTO, callback, serialized live owner or saved verified flag cannot issue authority. The new construction material must be incapable of authorizing signing, export of spend authority, submission, replacement or clearing old exposure.

This is a new reviewed profile. It must not bypass an old V3 guard or reinterpret a V3 permit. Until this path exists and is exercised end to end, post-proof durable helpers are incomplete work, not a working payment flow.

## Durable state and short-lived capabilities

The immutable proposal records its manifest revision, canonical candidate, complete private review policy, ownership/action mapping, network profile, finite expiry, proved artifact and domain-separated fingerprints. Protected artifacts and durable jobs survive process restart.

Fresh local permissions authorize immediate actions such as private disclosure, key use or submission. They do not remain alive while another participant decides. Each actual signing operation performs authenticated review of the exact persisted proposal and reconciles writer authority and outstanding exposure. Expired capabilities cannot be renewed, reconstructed or accepted as new authority.

Current chain evidence is checked at the boundary that needs it. Historical provenance is retained as historical evidence. Coordination deadlines, local capability/freshness limits and consensus transaction expiry are distinct.

## Release and recovery ordering

1. Reconcile the account's authoritative writer and independent exposure fence. Uncertain, stale, cloned or restored state cannot issue authorization from its local ledger alone.
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
