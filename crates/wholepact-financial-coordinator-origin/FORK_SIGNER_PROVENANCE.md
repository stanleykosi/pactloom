# Gated original Signer provenance bridge

This source-only feature adds no runtime call site, role activation, installation,
credential, native consent, source permission, pairing grant or effect permit.
It is not evidence that the complete financial product flow is connected or
qualified. The existing bootstrap-only, cancel-only and one-append profiles do
not enable `common-image-fork-provider` themselves.

## Exact boundary

- The one whole-image loader privately retains the exact already-verified
  device, inode, size and SHA-256. Only the actual H fork return retains a copy
  for this bridge; S children discard their copied facts before READY. C still
  alone retains the opened executing-image descriptor.
- After the global barrier, genuine `HostOriginV1` may attempt
  `take_original_signer_verifiers` once. It returns exactly S1 then S2, with no
  caller role, PID, descriptor, hash, path, callback or success flag. Failure
  consumes the attempt too. H keeps both original DirectChild reapers.
- Each non-Clone `OriginalForkSignerVerifier` owns only check copies of its
  original S child pidfd and original C pidfd. Total extra retained descriptors
  are four, created after the barrier, outside the unchanged bootstrap FD
  inventory. No channel copy can suppress EOF. No PID lookup creates a peer.
- Every check requires the original H process/UID, the unchanged session ceiling,
  live original C and S lifetimes, and a monotone H-custody flag. H invalidates
  this flag before terminal finish or any owned child drop/reap. A blocked final
  kernel reap remains potentially unbounded, as in the existing bootstrap.
- `verify_connected_signer` observes an actual fresh direct UnixStream using
  SO_PEERCRED and mandatory SO_PEERPIDFD, matching the exact original S child
  and rechecking both retained and observed lifetimes. It does not authenticate
  the creator of an inherited socketpair as the eventual child.
- `InstalledSignerProvider::load_for_original_fork` consumes that verifier but
  independently loads `/etc/wholepact/signer-provider.json` through the unchanged
  installed loader. The same opened root-controlled executable is checked
  against both the installed pin and the retained common-image identity. Its
  installed enrollment reference is preserved, not synthesized or replaced.
  The resulting provider also uses existing `PeerProcess::observe` on each
  actual fresh stream. No fork error falls through to procfs or exec provenance.
  `launch_native` and `wait_native_endpoint` refuse this distinct provenance.

## Explicit remaining joins

A pin selecting a standalone Signer image is incompatible with a different
common image and fails closed. Selecting a whole C/H/S/W image also changes the
historical dedicated-Signer installation meaning: any eventual authorized
installer must review that selection and legacy consumers independently. This
source neither rewrites pins nor supplies a new enrollment reference. Ordinary
legacy load/exec/procfs behavior is unchanged, including denied-procfs refusal;
it is not the common-image bridge.

No original Signer service or endpoint is started by this change. Real role-local
unlock/review/runtime and fresh endpoint reporting remain separate reviewed
joins. Existing clients retain providers and authenticate per-frame credentials;
the verifier does not replace those grants, original-channel checks or per-effect
currentness. Its C-liveness check is deny-only. The future Host session must move
actual provider/client custody through its concrete phases: repeated legacy
loads cannot silently recreate this one-shot pair. No verifier cloning,
replacement child or C-to-S direct-edge fiction is introduced.

Three new tests cover inert identity facts, one-shot state and monotone drop
restriction only. They open no file/socket, fork no process, create no origin or
verifier, and prove no installed/kernel/native qualification. Compilation and
these exact pure selectors are lead-owned; native/runtime qualification is
isolated approved CI only.
