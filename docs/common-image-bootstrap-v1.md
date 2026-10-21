# Common-image coordinator bootstrap, inert source milestone

This is an opt-in binary-only source increment, not an activated financial
coordinator. The `wholepact-financial-coordinator` executable requires the
`common-image-bootstrap` feature. There is no library entry, external worker
argument, role environment variable, imported-origin constructor, later exec,
reconnect or replacement path. No existing default/standalone entry changes.

## Trust boundary and start

The initial native launch must be trusted, uninjected and credential-free. The
launcher must exec C with only the approved minimal nonsecret environment and
arguments, and no secret inherited input. The fixed image pin
selects installed bytes under the OS/installer assumption; it cannot detect or
undo earlier dynamic-loader injection, arbitrary inherited memory or a hostile
launcher. No hostile-launcher immunity, human attendance or financial consent is
claimed.

Before role creation the private main call graph applies exactly the existing
fail-closed RLIMIT_CORE=0 and PR_SET_DUMPABLE=0 hardening. It checks the actual
`/proc/self/task` inventory for one task, rejects extra arguments, closes ambient
FDs >=3 and replaces all stdio with `/dev/null`, then clears the environment bindings. `clearenv` does not erase original
environment strings or historical loader/libc/allocator memory. It is not secret
scrubbing; absence of ambient secrets is an explicit initial-launch precondition.
This binary itself loads no role keys or source owners before fork.
Every child rechecks PR_GET_DUMPABLE==0, both RLIMIT_CORE limits==0 and its
retained original parent lifetime before reporting PREPARED; H does so before
creating descendants. The inventory is checked again before the fork phase and
before every fixed fork.
No thread-capable runtime, GUI, key/source opener or other initialization follows
these checks. The check is supplemental to that private startup structure, not a
historical no-injection proof. SIGCHLD must have default disposition, no
SA_NOCLDWAIT and not be blocked; no competing reaper exists.

The only pin input is the read-only fixed
`/etc/wholepact/financial-coordinator-common-image-v1.json`. No installer,
configuration writer, credential generator or deployment command is provided.
Its strict capped JSON fields are schema_version=1,
profile="financial-coordinator-common-image-linux-v1", executable_device,
executable_inode, executable_size and lowercase executable_sha256. Duplicate or
unknown fields fail. Descriptor-relative O_NOFOLLOW traversal checks root-owned,
non-group/world-writable parent directories and the regular pin file. The
kernel's executing `/proc/self/exe` must match exact metadata and SHA256, be
root-owned and non-group/world-writable, and retain stable pre/post metadata.
C holds the opened image; every child drops its inherited copy. This is a new
nominal provenance boundary, not an InstalledSignerProvider pin or conversion.

## Fixed process and FD inventory

The conservative supplied-originals-through-completed-pair birth inventory has
exactly 17 processes if startup succeeds (not a minimum or account-creation/
recovery architecture):

- C owns and reaps H and thirteen fixed Witness-purpose children (14 children).
- H owns and reaps S1 and S2 (2 children).
- For each of owner1 and owner2 the six distinct Witness births are
  BootstrapHistory, V3DeliveryAdmission, DeliveryAuditHistory,
  FinancialReadHistory, FinancialContinuationAdmission and FinancialSigning.
- The thirteenth Witness birth is CompletedPair.

Birth order is not service activation order. Future integration must preserve the
source-faithful per-owner workflow/interleaving and sequential drain/stop/reap
before the next namespace opener. This milestone opens no namespace, source,
key, financial owner or service, and does not claim readiness for any of them.

Each parent-child edge is one private nonblocking CLOEXEC AF_UNIX
SOCK_SEQPACKET pair with SO_PASSCRED enabled before fork. Each final parent edge
owns one channel FD and the actual direct-child pidfd. Each final child edge
owns its channel FD and a pidfd opened by its actual parent for itself before
fork. SO_PEERPIDFD on inherited socketpairs is deliberately not used: that would
identify the creator, not necessarily the eventual sender. Actual unreaped
fork-return child PID ownership prevents PID reuse during pidfd acquisition.

Final descriptor ownership, excluding the three `/dev/null` stdio FDs:

- C: 14 channels, 14 child pidfds, one opened common image.
- H: C channel/parent pidfd plus S1 and S2 channel/child pidfd pairs.
- Each S or Witness leaf: only its direct-parent channel/pidfd pair.

C uses a fixed array of 14 owners, H a fixed array of 2, and the Witness inventory
is a compiled array of 13 roles. The maximum root fork setup inventory is 33
FDs including stdio; the exact intended final C inventory is 32. No caller-sized
role list or arbitrary task closure exists. Every later Witness child explicitly
drops all copied prior sibling owners/channels and the image before PREPARED.
Each signer drops H's C-facing origin; S2 also drops the copied S1 owner. A copied
DirectChild first checks its recorded owning PID and never signals/reaps/shuts
down a sibling; its copied FDs close normally. Child branches terminate with
_exit and never fall back into the parent's spawn loop.

Private non-Clone ForkOriginV1 is constructed solely in the actual fork child
branch. It proves that construction relationship only. It grants no role source
access, financial approval, native focus, V3 admission or legacy signer identity.
The actual H-to-S edges are direct, not proxied through C, and H retains the
actual signer child lifetimes. No existing financial transport is connected yet;
future adapters must preserve these original direct processes and independently
satisfy the existing transport, source and approval checks.

## Inert barrier and message checks

All forks and explicit branch FD pruning precede each local PREPARED. H reports
subtree PREPARED only after both original signers do. C records all 14 direct
children, checks their retained lifetimes and makes one release decision. Every
message is an exact eight-byte closed bootstrap packet with protocol version,
message kind and sender role. Every receive authenticates exactly one kernel
SCM_CREDENTIALS against the retained actual PID/UID and checks the same pidfd
before and after. Missing, duplicate, foreign or wrong-role data, unknown
ancillary data, unexpected SCM_RIGHTS, truncation, EOF and peer death all fail.
Unexpected installed SCM_RIGHTS FDs are closed even on rejected packets.

RELEASE delivery is not distributed atomicity: a subset may receive/ACK before
another child or edge fails. RELEASE permits only inert ACK and teardown. There
is no financial successor authority or activation to partially perform. The
private barrier rejects missing/duplicate PREPARED, double release, duplicate
ACK and attempted completion after only partial release.

One original monotonic 30-second ceiling covers every role's startup, message
wait and clean-exit wait, including all thirteen sequential Witness observations.
It is never renewed per child. Fixed flow is PREPARED, RELEASE, RELEASED, STOP,
STOPPED, EXIT. Children remain alive after STOPPED until the exact parent sends
EXIT so acknowledgment verification does not race normal early exit. On success
the coordinator exits with status 78 (activation unavailable), not a live service.

## Failure and cleanup limits

An owned edge shuts down before last-resort pidfd-targeted SIGKILL/reap. Graceful
waits use WNOHANG/poll until the same original deadline; expiry triggers cleanup.
Before a pidfd exists, acquisition failure can signal only the still-unreaped
actual direct fork-return child, then reap it. No arbitrary PID is accepted.
Final kernel exit/reap after termination can still block if the kernel leaves a
child uninterruptible; the protocol ceiling is not a wall-time kill guarantee.

C cannot reap S1/S2 after H dies: they are H's children. Exact parent lifetime or
channel loss makes inert leaves exit; OS adoption/reaping after a parent crash
is the OS's responsibility. No subreaper, parent-death signal, privilege change
or new machine security setting is introduced. There is no financial work that
an orphan can continue. No strong immediate destruction/zeroization guarantee
is claimed.

## Qualification and next gates

This change has not launched a process, socket, native window or financial
workflow locally. Pure tests cover only untrusted pin-data parsing and closed graph/packet/barrier
predicates;
they cannot certify runtime provenance, FD closure or kernel behavior. Actual
process/socket/pidfd/fault/ancestry tests require separately approved isolated CI.
Do not run this binary or native/process tests merely to validate this source.

No GUI, Host controlling PTY, display coordinates, role runtime, live model-token
conversion, financial effect adapter or approval route is present. Future GUI
work needs a reviewed minimal display allowlist and fresh genuine PTY ownership,
not restored arbitrary ambient FDs/environment. The current all-env clearing and
null stdio are intentionally only suitable for this inert milestone. Later live
integration and installation remain distinct reviewed/authorized work.

## Bootstrap-only disposable CI contract

The production executable, built with the CI cfg entirely absent, must first
independently complete its actual private startup and return 78. The fixed
nonsecret pin is generated only in a disposable container against that runtime
filesystem's actual executable metadata and digest. It is not a user or persistent
installation. Product processes run with ordinary numeric UID, cleared effective,
permitted, inheritable and ambient capabilities, no-new-privileges and no network.
The setup harness's narrowly retained capabilities and exact bounding-set policy
must be reported independently; setup privileges are not product privileges.

Additional artifacts compile the same main/private fork path with only the
`wholepact_bootstrap_ci` rustc cfg and a fixed compile-time
`WHOLEPACT_BOOTSTRAP_CI_CASE`. They are never launched through the Rust test
harness. The product build contains neither that module nor its diagnostic and
fault hooks. No runtime argument, environment value or imported FD selects a
role, origin or scenario. The CI module cannot construct ForkOriginV1 or
DirectChild. This suite has no financial dependency, credential, source storage,
service, GUI, PTY or live adapter.

The fourteen finite variants are observed_success, wrong_role, wrong_version,
oversized_packet, duplicate_prepared, rights, rights_truncated,
later_wrong_sender, missing_credentials, coordinator_death, host_death,
child_exit_after_released, timeout_before_prepared and stall_after_stopped.
Wire faults replace one actual packet on Owner1BootstrapHistory's actual channel.
The missing-credentials variant disables PASSCRED on that selected receiving
endpoint only in its compiled negative image. The unchanged actual receiver must
report missing credentials; a nonzero exit alone cannot pass any negative case.
Rights variants compare the receiver's actual FD inventory immediately before
recvmsg and after the real ancillary-rejection path. The truncated variant needs
actual MSG_CTRUNC plus matching inventory, not a fabricated later truncation
branch. CI's descriptor resource limit must accommodate temporary received rights
above the normal 33-FD construction bound.

The late-wrong-sender variant adds one explicitly adversarial test-only process,
not an eighteenth role and not a new origin. After a genuine first exchange, it
writes a Released packet through an inherited channel and exits. The original W
records and reaps that exact attacker. A bounded cfg-only observation wait lets C
wait for that reaping record before its unchanged recvmsg; this is negative-fixture
scheduling, never origin or permission input. The real credentials comparison must
then reject the attacker while the intended W's retained pidfd is still live.
The child-exit-after-released variant proves eventual retained-peer death after
prior valid exchange; scheduling does not guarantee that queued bytes were
rejected before delivery, and no such stronger claim is made.

Private bounded diagnostic records are written to per-PID files in the disposable
evidence tmpfs. Each open closes before returning; no logger FD, mutex or thread
survives a fork. Records have a monotonically increasing per-process sequence,
finite event/role/case fields and a per-file 64-KiB cap. The verifier enforces at
most 32 files, 256 records and 512 KiB total, rejecting malformed, missing,
duplicate, out-of-order or unrecognized evidence. Actual PID/FD observations stay
inside the container; only finite validated counts/phases/results are projected.
Current PPID may become PID1 after parent death; the original parent binding is
kept separately in birth/readiness/peer observations and is not reconstructed from
that changed PPID.

The observed-success variant requires the real 17-process graph, 16 parent birth
records, the actual original H-to-S edges, exact C/H/leaf FD sets, all 96 real
validated packet receives, one inert release decision, clean direct-child reaping
and no adopted descendants. Negative cases require their exact injected fault
and actual first rejecting boundary. Timeout and clean-drain failure use the same
original 30-second ceiling, not a test-only deadline extension. An ordinary-UID
PID1 test harness may collect normally adopted children after parent-death
fixtures, but must distinguish that from product-owned reaping. No remaining
live/zombie descendant is allowed before cleanup. Forced whole-container cleanup
is an error, never a passing product-reap result. Kernel-uninterruptible tasks
remain an external supervisor limit, not a claimed process-control guarantee.

All native execution is restricted to the separately approved isolated CI run.
Local work for this increment is source inspection, compilation and reviewed
pure data tests only. Passing this gate would establish bootstrap/kernel facts,
not installed-launch provenance against a hostile launcher, financial authority,
human review, source readiness or normal-desktop payment readiness.
