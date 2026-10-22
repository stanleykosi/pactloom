# Rendered Host semantic qualification

`coordinated-financial-rendered-host-semantic-v1` is a distinct,
semantic-assisted financial qualification profile. It is not a passing result
for the legacy pixel/OCR profiles. Those profiles retain their original schemas
and OCR acquisition and reject the semantic records and snapshot extension.
There is no automatic fallback between profiles.

## Observation, not authority

The new profile observes the exact escaped ASCII suffix selected from the same
Host output galley used for native painting. It preserves actual source line
feeds, not soft-wrap line breaks. It does not read a second terminal stream,
construct a fixture transcript, repair text, classify native permissions, or
inject replies. Only eligible focused, visible, unprotected, non-discarded
frames can emit a semantic view. Hidden, invalid, or protected presentation
clears its active binding.

The harness uses this suffix instead of Host screenshot/OCR acquisition. Exact
prompt grammar, source-occurrence replay protection, and editor-context checks
still apply. All replies—including blank replies and both passphrases—still
use actual Begin, protected editor, keyboard, and Submit actions. Genuine
approval challenges, independent signer endpoints, native review/approval
checks, original authority deadlines, final proof, and cleanup requirements
are unchanged. A semantic record cannot satisfy a milestone or grant authority.
This qualification does not establish physical human consent or every-pixel
legibility.

## Closed record linkage

Only Coordinator may emit `HostRenderedView`, with exactly these facts:

```
{id, view_generation, revision, nonws_end, view, text}
view = {rect, nonws, rows}
```

IDs are bounded to 1–512. Text is bounded to 8192 printable ASCII bytes or line
feeds; its non-whitespace count must equal `view.nonws`, and its line-feed count
must be less than `view.rows`. Existing record, file, sequence, and total-byte
limits remain enforced. No truncation converts overflow into valid evidence.

Only the new profile adds nullable `host_view_id` to `UiSnapshot`. A usable
reference joins an earlier Coordinator view record with matching ID, output
revision/end, and exact view metadata. The first referencing snapshot has the
record's frame generation; subsequent references may use later generations.
The snapshot must also be focused, Idle, context-valid, and unprotected.
Missing, forward, stale, or mismatched references fail closed. An unpaired view
at a partial read is not independently usable; final evidence cannot end with
an unpaired view. New IDs after hidden/discarded presentation do not renew a
consumed source occurrence, even when the text is identical.

## Privacy and failure bounds

Semantic records remain in the existing private, owner-checked disposable
observer files. They and their text, paths, and content hashes are not public
logs, diagnostic output, or uploaded evidence. Retention remains bounded by the
existing private-file limits and original cleanup. Native owned staging buffers zeroize on drop or suppression. The Python
mutable active cache is wiped on replacement, observed unavailable/protected
state, and read failure; a suppressed frame cannot instantaneously notify
Python. Immutable Python strings, JSON copies, and historical private file
contents cannot be claimed completely erased from memory or storage by those
wipes.

Each awaited startup slot receives a fixed harness wait ceiling, at most the
existing `ACTION_NS` and capped by the original fixture deadline. Both blocking
observer waits and controller transport waits honor it. Captures, output,
navigation, and repeated observations cannot renew it. Only the existing
successful guarded submission transition advances to the next slot; the final
slot's bound remains through Writing until actual Idle. The bound is then
removed, leaving the unchanged original ceilings. Expiration fails closed:
there is no input retry or renewal of native authority. A single unrecognized
intermediate terminal chunk is not assumed to be a complete failed prompt.

## Layered verification and result scope

Pure contract, linkage, full startup, input, and watchdog tests run with:

```
PYTHONDONTWRITEBYTECODE=1 python3 -I -B -m unittest discover \
  -s scripts/tests -p 'test*financial*.py'
PYTHONDONTWRITEBYTECODE=1 python3 -I -B scripts/ci-financial-launch-tests.py
```

The complete discovery includes the pathname-socket preflight; a restricted
local environment must report any denied test explicitly, not present its
subset as complete CI qualification. Native same-galley and final-frame tests
cover clipping, protected/suppressed frames, exact text binding, and cache
lifecycle. Focus, masking, rendered click boundaries, and genuine input remain
separate UI regression obligations.

Fresh native compilation and the approved isolated producer/runtime gate are
required for this profile; older binaries without the semantic channel cannot
qualify it. Compilation and unit tests are not full-workflow proof. This
checkpoint records implementation and test obligations, not a successful full
semantic-assisted financial run or a passing legacy pixel-only gate.

## Native failure-boundary diagnostics

Semantic CI can retain fixed-enum, first-local failure boundaries from the
Coordinator's UI, driver, transport and core components. Emission requires an
existing UI/driver failure; these records forbid a successful qualification.
They do not identify a globally first cause or a remote process's cause. Failure
reporting uses only cached observations, with missing evidence marked unavailable.
The original normal-completion proof remains required; absence of a boundary
record is not evidence of success.
