# Inert financial review observation model

This crate is a dependency-free, source-only reference model. **No value, including
an admission observation, is an executable permission.** It has no live product
dependencies, permission-trait implementations, `NativeDecision` conversion,
effect closures, network/IPC listeners, GUI, credentials, installation, timers,
clock reads, randomness, serialization, journal access, or financial effects.
Workspace registration does not integrate this crate into an existing issuer.

## Small public state-machine surface

- `ReviewTrace::new(scope, original_bounds)` records one immutable original
  account/principal/role/process/worker/channel/source/session/review/action scope.
- `observe(Event)` checks exact descriptor equality and contiguous processed event
  sequence. `scope`, `original_bounds`, `status`, and `records` are read-only views.
- `InitialHumanReviewed` only arms the finite action. `PrepareEffect` describes the
  exact next dynamic payload, initial review anchor, completed predecessor, batch
  width, effect ID, and challenge. Neither is final effect admission.
- `FinalAdmit` must match the entire prepared descriptor and consumes its single
  admission irreversibly. It does not prove execution. No actual dispatch occurs.
- Historical `WorkerStartedObservation` and `OutcomeObserved` report only that
  admitted effect. `InFlight` is not the real durable `CommitStarted` fence.
- Completed effects require a **separate** exact next preparation and admission.
  Known-no-effect and unknown outcomes are terminal, not retry/reissue instructions.
  Unknown cannot be rewritten to known within this model.
- Any blur in a focus batch invalidates even if that batch ends focused. Processed
  cancel, close, expiry, clock rollback, or bad scope/order cannot be undone by
  refocus. Peer death/restart quarantines outstanding admissions as unknown.

Each complete native `FocusBatch` must be processed before admission observations
queued in that same batch. `observe(Event)` checks the supplied processed order;
it cannot detect omitted or misordered native batches or prove actual GUI delivery.

The linearization point is the coordinator's **processed** `FinalAdmit` versus its
processed revocation, not a physical GUI event or an RPC launch. Revocation before
admission rejects it. Admission before revocation can leave that one exact bounded
effect in flight, but never its next subeffect. A delayed historical start/outcome
report after blur does not give the worker permission to ignore local cancellation,
death, source mismatch, or expiry. A worker may instead establish known no effect.
Cancellation is not proof that a previously admitted effect did not start.

Original wall and monotonic absolute issuance/expiry readings are supplied once;
either expiry equality is invalid. No new duration or expiry policy is selected.
Both supplied clocks retain high-water marks. Values near integer limits never
use wrapping deadline arithmetic. The model reads no clocks and proves no real
clock provenance.

## Bounded session composition, not a whole lifecycle

`SessionTrace` fixes at most five distinct original roles (Host, two signers, two
Witnesses), with **one fixed review/action per role** and one contiguous global
observation order. Registration requires the same coordinator, session epoch, and
physical `review_surface_instance` (the unified window, not a role-local panel),
distinct roles/review/action labels, and unused member traces. Registration cannot
be expanded, replaced, reconnected, or reset. Each member still needs its own human
review and exact admissions. Effect IDs/challenges cannot be reused across members,
including prepared-only records.

Processed blur/cancel/close/death/restart is broadcast before any later admission.
An unknown/known-no-effect member outcome, invalid message, or binding/order
violation quarantines all remaining admissions, while exact already-admitted
outcomes may still be observed. Broadcasting a member's expiry/clock rollback to
the group is an explicit conservative **model composition policy**, not a changed
production rule. Time observations apply only to the already-created original
bounds; no original deadline is extended.

This does not establish cross-action workflow causality or verify semantic
relationships between members' account/source labels. It does not prove that a
concurrent implementation is linearizable. Each trace's event counter is local;
the session owns and verifies the global order before routing observations.
Different owner-slot labels do not establish different real people/accounts, and
matching signer/Witness slot labels do not establish the same real account.

## Source-grounded abstract obligations at cp89

These finite entries are obligations to review, not claims that present live
functions are atomic, fully decomposed, or already gated. In particular, a prepared
future result digest cannot be required at initial human review. Payload binding
and predecessor equality model a later backend assertion only; actual derivation
and authentication must be implemented and reviewed separately.

- Signer `ContinueExact`: retain one original continuation intent.
  `AdmitExact`: send one already retained continuation request.
  `AcquireExact` / `ActivateExact`: one original checked RPC/mutation each, never
  new source/session renewal.
- `SignExact`: consent-release retention → exact-request retention → Reserve
  request send → authenticated-permit retention → Started fence retention → exact
  key-use batch (the reviewed 1–8 participant actions) → exact-result retention.
  The Started fence is not key authority. A failure after it must preserve the real
  recovery fence, never recreate or retry it through this model.
- Witness append: one exact locked append obligation. A matching historical
  committed response is a narrow completion observation, never renewed openness.
- Signer `ReturnExact`: one exact bounded payload disclosure on the original
  pinned Host stream. Ready/Current/Finish are not Host mutation authority.
- `HostIntakeExact`: separately reviewed original signer-result intake. A Return
  grant cannot become an intake grant, nor be shared by another owner/source.
- `HostCompleteExact`: union payload retention → separate union lineage retention
  → extraction-intent fence → exact extraction → completed-transaction retention.
  An existing intent without a result requires actual authenticated recovery;
  this model provides no extraction replay/recreation path.
- `HostDispatchExact`: pair-intent retention → first Witness admission request →
  its matching receipt retention → second Witness admission request → its matching
  receipt retention → exact saved-byte handoff → original attempt retention → one
  final transaction request send. Outcome bookkeeping is not another send grant.

Source anchors:

- `crates/wholepact-signer/src/authority_bridge/financial_continuation_v1.rs`
  (original continuation and sign chain, especially lines 118–216).
- `crates/wholepact-signer/src/authority_bridge/financial_signing_v1.rs`
  (Started/exact key-use boundaries at lines 165–188, and result retention at
  lines 260–271).
- `crates/wholepact-authority/src/durable_financial_continuation_journal_v1.rs`
  (locked Witness append, lines 40–80).
- `crates/wholepact-native-host/src/host/financial/private_financial_v1.rs`
  (Host completion obligations, lines 854–949).
- `crates/wholepact-protocol/src/authorization/retention/transaction.rs`
  (extraction intent/recovery behavior, lines 253–356).
- `crates/wholepact-chain/src/submission_flow.rs` lines 403–414 and
  `crates/wholepact-authority/src/transport/financial_signing_server_v1.rs`
  lines 93–108 establish the two narrow drain
  observations: exact dispatch outcome recording and matching Witness committed
  response completion. They are not generalized to signer result retention or
  Return Finish, which still have their existing currentness checks.

The source paths/line ranges identify review evidence, not integrations in this
crate. Read the current source before implementing any live boundary. The actual
late final-send seam, original journal reconciliation, independent role focus,
peer authentication, and GUI batching remain separate production work. Financial
enum coverage here does not establish V3 Receive/Admit/History/detach coverage.

## Verification scope

The test source enumerates both cancel/admit orders, all six cancel/blur/admit
permutations for both source families and signer owner positions, the other
revocations, exact mismatch/replay/order cases, both clocks and expiry equality,
terminal/unknown no-retry rules, Started-to-key-use fencing, all finite plans,
Return/intake separation, narrow drain exceptions, and cross-role session closure.

Tests are sequential reference traces, not process-race or durable crash tests.
Constructing or copying caller-provided labels cannot authenticate them; creating
another model object cannot establish a fresh real review or bypass a live fence.
The crate deliberately offers no production authorization adapter or effect hook.
