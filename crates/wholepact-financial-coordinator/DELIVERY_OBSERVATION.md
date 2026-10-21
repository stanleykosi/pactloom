# Delivery CI observation profile

`--cfg wholepact_delivery_ci` is a separate observer-only build of the positive
`coordinated-witness-delivery-append` profile. It cannot combine with bootstrap
fault instrumentation or a different profile. The uninstrumented production
artifact is built and accepted independently. The same one pinned observed image
and app_id serve cancel, blur and at-most-one-append cases; there is no runtime
case, role, source, input, click, grant or permit importer.

## Actual identity and bounded logging

The fixed bootstrap remains the only genuine origin entry. Each process starts
one additional observer-only writer thread after the global release decision and
its own subtree/leaf barrier completion. C starts it only after its required
single-threaded display-coordinate restoration. These threads do not exist in
the production build and are not part of a production thread-count claim. No
observer state, FD, thread or held lock exists during any fork.

`RetainedBindings` records derive directly from actual retained DirectChild and
original-parent custody after the barrier. They are not timestamps purporting to
witness the historical fork syscall. C records H+13W and H records S1/S2. Child
original-parent binding remains distinct from actual current PPID after death.
OwnedReap records occur only after the exact parent's real waitpid succeeds and
state whether the last-resort termination path was used.

Every hook captures sequence, original monotonic elapsed time and finite data
before a bounded nonblocking enqueue. Native Arm/A does no observer filesystem
I/O or waiting. A lock-free combined stamp gives per-process monotone sequence
and time; the writer restores sequence order if concurrent enqueue delivery is
reordered. The queue holds at most 128 inert records. Allocation/scheduling and
observer threads are instrumentation overhead, not a claim of identical timing.

The fixed private directory is `/run/wholepact-delivery-evidence`, UID-owned0700.
Each actual process writes only `{pid}.jsonl`, created exclusively with0600 and
O_NOFOLLOW. Each record opens, validates regular-file type, owner, mode, single
link and exact expected length, writes, then closes. No observer FD is inherited
or used as product authority. Error, overflow or missing records invalidates
qualification only; the observer never cancels/restricts the product, extends a
clock, changes an outcome or invokes an effect. A separate evidence-only final
flush waits at most250ms, capped by the retained session+cleanup hard ceiling,
after product terminal ownership. All observation producers are then quiescent:
C's native loop returned and driver joined; H/S/inert W have only the finishing
main thread; selected W records only from its monitor, never from its possibly
blocked source worker. Its worker-joined observation is emitted by the monitor
only on actual successful join. Error exits may lack source disposal, but cannot
leave another observation producer running. Late hooks are refused; panic paths
missing final flush cannot claim complete evidence. Incomplete flush is missing evidence, not a
successful run or a new product cleanup allowance.

Per process: at most512records including terminal records,256changed widget
snapshots,256KiB/file and16KiB/record. The external private projector additionally
requires at most32files,4096records and4MiB per case. Every role must have a final
RoleFinished and successful EvidenceClosed record. Overflow/malformed/missing
records fail closed. The supervisor archives or clears a case's evidence only
after its entire actual process graph has been reaped, without changing the pin.

## Closed evidence schema

Envelope fields: version1, sequence, actual role, actual PID, current PPID,
original_parent_pid, elapsed_ms, event and detail. All identities and raw records
remain private in the disposable container. The source enum in
`wholepact-financial-coordinator-origin/src/delivery_observer.rs` is the exact
schema. No event carries form values, key bytes/paths, request/display text or
raw error strings.

Finite channel events record actual successful send/receive boundaries, with
Native reserved for genuine native Arm/A transitions. Review/Ready bind exact
public presentation/effect/source/request/owner/head facts and retained original
wall/monotonic bounds. Outcome classification is independently authenticated and
is not overwritten by FirstFailure or cleanup records. The first-failure pair
is an operation termination observation, not proof of a backend malfunction.
Authority records WorkerJoined only after successful actual worker join and
owned custody drop, before its diagnostic/outcome/Disposed sends. Panic or forced
termination does not manufacture that event or successful disposal.

C observations include whole raw interruption facts (including explicit blur
plus final focus), irreversible local presentation clearing, and the sole driver
join after the native loop. Missing terminal outcome after A remains uncertain;
observer records cannot create or recall admission.

A WidgetSnapshot is emitted only at the final eligible visible, non-sizing,
non-discarded native pass and only when painted phase, geometry or observed state
changes. It includes cumulative frame/pass, pixels-per-point, finite phase,
optional exact presentation digest, viewport rectangle, final focus, explicit
raw blur, revoked/read-to-end/Continue/ack state, and at most20 closed widget IDs.
Each widget records actual Response.rect intersected with its current clip rect
and actual enabled state. No state is set by observation. A same-pass cancellation
can be recorded as locally cleared while the already-built paint commands still
contain that pass's earlier review; a subsequent cleared frame must be observed.

The controller must independently require supported scale/geometry and a later
real target Wayland buffer commit and compositor output frame. A phase or
rectangle record alone is not paint evidence. This establishes the source paint
path plus actual region change, not exact displayed text or physical human
consent. Raw records and pixels are never published; only strict finite projected
results leave the disposable gate. All native/runtime qualification remains
isolated approved CI only; local source work executes none of it.
