# Coordinated Signer Continue origin, source-only

`coordinated-signer-continue` is a separate, mutually exclusive custody profile.
No coordinator binary feature or main call activates it. Existing bootstrap,
Witness positive, cancel-only, legacy native Signer decisions and installed-pin
semantics are unchanged when this feature is absent. Typechecking is not runtime
qualification and does not qualify a final financial transition by itself.

## Exact trust and ownership

The whole independently pinned common image is trusted, including the eventual
private native controller and H relay. The argument-free one-use startup still
hardens first, checks single-threaded entry, verifies the installed image and
creates the fixed original tree before any role source or key access. Its trusted,
uninjected, credential-free initial launch assumption is unchanged.

C consumes its actual root custody into a thread-bound native issuer and a sole
endpoint/tree owner. H consumes its own actual C edge and S1/S2 child owners into
a finite relay. S consumes only its genuine fork-return custody. There is no
public constructor/import of a PID, FD, role origin, arbitrary packet, callback,
claimed consent, NativeDecision or legacy ParentChannel. The two C begin methods
select only the two already-owned slots, not a caller-defined role plan.

H is explicitly a trusted relay, not direct C authentication at S. Every real
receive authenticates the immediate original sender's PID/UID credentials and
retained pidfd before/after the packet. The inherited socket creator is never
used as the actual sender. Unexpected ancillary rights are closed before failure.
S also privately retains original C's actual pidfd through the genuine H fork
branch. It does not retain a C-facing socket. C/H channel loss must be detected by
H's role monitor and propagated through loss of the original H/S edge; C process
death is checked directly by S. No polling scheme claims instantaneous detection.
The source retains and compares its actual protected-result Host PeerProcess,
which is not reconstructed from the bootstrap channel creator or an inert string.

C owns H+13W reapers; H alone owns S1/S2 reapers. A relay error drops the actual H
custody, invalidating existing verifier custody before any child reap. No verifier
or token becomes a reaper or permits a replacement process or source.

## One exact Continue slot, twice fixed

The two fixed slots share one atomic phase word with global revocation R. Each
slot is Prepare -> complete frozen Display -> native Arm -> exact Ready -> native
A -> at most one actual received Final. Human reading/acknowledgment and the final
focused primary click belong to the eventual reviewed private GUI. Arm is inert.
A is the native visible event-loop-tail CAS after complete raw input/cancel
handling, not endpoint dequeue, H forwarding, or a timestamp claim.

Inert source preparation precedes Display/Arm and freezes the complete original
request, terms/history/source/revision and prepared digest. Source guards must be
dropped before display/Ready/A. Ordinary source facts passed to begin_review are
not authenticated by that data API: the Signer's source owner independently
matches every fact to its retained original custody. Origin fills only its own
actual process/role/image/session challenge facts. The full display, canonical
request bytes, prepared digest and all 15 review fields have a separate
presentation commitment. This avoids a circular hash in the frozen request's
semantic review preimage. Request-byte commitment is intentionally distinct from
Authority's financial record request digest; the source checks canonical equality.

Only an authenticated Ready mints C's opaque ticket. Native A consumes that exact
ticket once. R-before-A permanently prevents admission. A-before-R retains the
one admitted outbound grant; C must send or abandon it before Cancel. H forwards
the original ordered Final before Cancel on the same exact S edge, with no retry.
Only actual matching S receive mints non-Clone SignerContinueFinalV1. Its source
consumer must consume it at the exact profile19->20 Continue mutation, match the
same prepared/presentation/review/source/peer facts and original Instants, and
perform current source checks. It is not Admit, signing, payment, network-send or
Witness append authority. An admitted attempt without authenticated outcome is
uncertain, not canceled/no-effect. Outcome and cleanup are independent facts.

## Original bounds and terminal drain

S retains the source-supplied original source/review Instants exactly, separately
from its more restrictive local cap. Wire offsets refer to the original pre-fork
monotonic epoch and round down to milliseconds, never receive-time budgets. C/H
only shorten them by native/session bounds. Wall expiry and nonregression also
restrict. No Arm/Ready/A refreshes the original preparation clock or starts a new
120-second review. The future C driver must anchor its native ceiling before
queueing prepare; an expired queued ceiling is refused before sending.

The original 30-second bootstrap limit is unchanged. Active exchange ends at the
original five-minute session ceiling. H permits only terminal traffic afterward,
never Prepare/Arm/Final/Display/Ready. C uses one cleanup budget capped by original
session+5s. H/S use subordinate one-shot min(Cancel receipt+5s, session+5s) drain
bounds; these do not renew C's budget or permit an effect. Disposed is only a
reported source-worker join/drop result, not proof from process death. Terminal
Cancel must be consumed before generic STOP/EXIT, preventing grammar crossover.
Forced termination cannot prove successful source disposal. Final kernel reap
may remain unbounded even though protocol waits and escalation are bounded.

## Fixed descriptor changes, requiring new CI

With this feature only, each S retains one additional check-only original-C
pidfd before READY. The copied H C-facing channel and every sibling channel/pidfd
are still dropped before READY. C/H and all W pre-READY inventories are unchanged.
After barrier, C adds exactly 16 check-only descriptors: original H channel+pidfd
and all 14 root-child pidfds. Each S adds exactly two: its original H channel and
H pidfd; its already-retained C pidfd moves into shared check custody. Tokens share
those handles rather than duplicating more. H adds none for this relay. If the
separately gated provider bridge was issued before relay conversion, its existing
four check-only pidfds remain a separate documented inventory.

Endpoint loss actively shuts down its original socket so check-only duplicates
cannot suppress EOF or outlive endpoint authority. Normal STOP first invalidates
shared local capability state, completes the exact owned protocol, then closes
checks. No observation or monitor thread exists before the barrier. Old bootstrap
and delivery CI cfgs are compile-incompatible with this new profile; their prior
results cannot qualify this changed inventory or the new relay/kernel behavior.

## Validation boundary

The new pure tests exercise only ordinary data, finite state and deadline
arithmetic. They never manufacture an origin or open a socket/process/source.
Required later isolated CI must exercise genuine C/H/S branch custody, exact new
FD inventories, per-frame credentials, original C/H/S death, wrong-role and
reordered/duplicate grants, original-clock expiry, both A/R orders, terminal
Cancel/STOP crossing, source currentness and actual retained Host peer matching.
The native UI, source owner/worker orchestration, protected Host continuation and
actual final source transition require their own paired review before activation.
