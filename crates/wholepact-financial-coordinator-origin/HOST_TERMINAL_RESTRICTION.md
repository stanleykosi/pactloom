# Original Host terminal and Coordinator restriction

The full-workflow Linux x86_64 profile retains a genuine fresh controlling PTY
for the original Host. It does not replace typed Host consent with a C click,
automatically answer a prompt, import a descriptor, launch a shell, or enable a
binary route. Other bootstrap, Witness and narrow Continue profiles are unchanged.

After ambient descriptor discard and original clock capture, the private fixed
bootstrap creates one PTY pair and one anonymous shared aligned atomic word.
All fixed forks still happen before threads, runtime, role sources or secrets.
Every S/W branch drops both PTY ends before READY. W unmaps its copied word;
each S retains only a sealed check-only reader of that same original word.
After both S forks, H closes its master, establishes its own session/controlling
terminal/foreground group, and retains only the original slave. C closes its
slave after all fixed forks and before barrier collection. No child owns a new
reaper and no process obtains a raw FD/path/pointer constructor.

## Restriction ordering and trusted actors

Only the genuine C branch receives the private shared-word writer. C's Created
guard publishes permanent restriction on every error/drop even before the full
Core exists; inherited H/S/W guards only unmap. C retains the writer across the
barrier and puts it before reaper-owning fields. Full C Core construction moves
it into Phases before fallible endpoint setup. Every local C revoke first stores
shared R with SeqCst ordering, then changes the existing local atomic restriction
word. Writer Drop also publishes R. Nothing resets either word or a purpose.

The original H observer checks actual H PID/UID, its retained original C channel
and pidfd, and the original session ceiling before its final SeqCst zero-load.
That load is a restriction observation for one exact, independently TTY-approved
physical attempt, not a cached permit. A-before-R may finish or become uncertain;
R-before-A denies. No later refusal proves an earlier effect did not occur and
no failure permits an automatic retry.

The mapping is RW in C, H and both S roles. H/S are part of the trusted pinned
whole image; their sealed Rust APIs expose only checks. This is explicitly not OS
isolation against malicious H/S code rewriting the mapping. Actual actor/channel lifetimes
and original deadlines remain independently mandatory, including after C dies
without executing user-space Drop. No shared word replaces native consent,
source checks, publication gates or any action-specific bound.

## Finite custody handoff

HostOrigin's one-shot, argument-free take_host_terminal_custody consumes its
actual slave holder and restriction observer before fallible checks. The same H
may then issue its original fixed Signer verifiers once and move into the relay;
H alone still owns S reapers. The actual Host Terminal must separately open
/dev/tty and match the retained kernel terminal, session and foreground group.
Its held approvals need the observer at their existing exact effect boundaries.

The full C conversion keeps its (native, endpoint) return shape. The endpoint's
one-shot take_host_terminal privately binds the actual master to the same Core
before exposing transport. Public I/O refuses an unbound, expired, dead or
restricted workflow. Bound close/error/Drop publishes Core restriction before
closing input/master custody. The sole owned driver performs bounded nonblocking
I/O; the native event tail performs none. A real panel must queue only the user's
exact completed line, keep source-password input separate, and use independent
bounded output transport so PTY traffic cannot displace security/outcome events.

The raw PTY disables echo and all maintained input/output translations. The C
panel must display Host-written bytes without executing escape commands, hiding
text or rewriting the transcript. It cannot infer a secret mode or synthesize
answers from prompt text. Transient input and bounded output use zeroizing owned
buffers; accepted write prefixes are zeroed and never resent. Closing after a
partial write is not proof that H did not consume it.

## Exact additional inventory

The shared mapping owns no descriptor. The pre-fork PTY adds two descriptors.
After each branch's pruning and before READY:

- C retains master plus one check-only actual H pidfd: two added descriptors and
  its mapping. With stdio, image and fourteen child edges/pidfds, C has 34 FDs.
- H retains slave plus one actual C pidfd for terminal, and two C observer handles
  (original edge duplicate and pidfd): four added descriptors and its mapping.
  With stdio, C edge and two S edges, H has 13 FDs.
- S1/S2 retain no PTY descriptor, but retain a check-only reader of the original
  shared mapping. All thirteen W unmap it. The full-profile S original-C pidfd
  remains; retaining the shared word adds no descriptor.

Post-barrier C's existing 16 check-only handles make its fixed retained count 50;
S's existing two H check handles remain unchanged. Optional fork-provider verifier
copies add the separately reviewed four H handles. The temporary C lifetime used
inside H restriction construction is closed before READY. No logging/input queue
adds a descriptor. Future source/TLS/listener descriptors are separate reviewed
role operations, not part of this bootstrap inventory.

No cleanup deadline is changed. Shared restriction precedes C tree disposal;
actual child owners still perform exact STOP/Stopped/Exit/reap. Forced process
death is not source disposal, and a final kernel reap may remain unbounded in an
uninterruptible state. Actual mmap/PTY/fork/session behavior and this inventory
need a separate isolated qualification. Pure byte/mask/atomic tests do not prove
kernel behavior or full product readiness.

## Original Signer transport restriction

The actual H-to-S fork-return consumes its inherited shared mapping into a private
reader after checking the fixed S role, actual S PID/UID and retained original C
identity/liveness. The existing H edge, C pidfd and session remain in the same
Core; there is no C-facing S socket or new descriptor. W still unmaps the word.
Each Entry/Read and nonfinal Continue action check samples the shared C word as
its last restriction observation. It does not wait for H to forward Cancel.

SignerOriginalCustodyLifetimeV1 can return a non-Clone SignerOriginalRestrictionV1
for the actual retained source/client. Its check first observes original actors,
channel, source and session bounds, then local R and the final shared SeqCst load.
It has no short Read/Admit phase or renewed action deadline. Retaining it in a
client Arc supplies restrictions only: every physical attempt still needs its
own genuine action checks. An attempt already started may finish or be uncertain;
R forbids later unsent attempts. No retry or no-effect inference follows.

Generic Core/custody checks intentionally omit ordinary R. The already-admitted
local Continue Final keeps its specifically reviewed exception; new purposes,
Entry/Read completion and transport checks do not inherit it. A queued prior
Final is still transported in original order; conservative refusal before local
admission never creates a replacement grant or a retry.

HostFinancialWorkflowRelayV1::finish consumes the sole relay and returns its
existing capped STOP/Stopped/Exit/reap result instead of exiting from a worker
thread. Its complete wrapper still delegates that result to the existing branch
exit. The H foreground must join the monitor and drop actual foreground custody
before process exit. Neither method proves source disposal from process death.
