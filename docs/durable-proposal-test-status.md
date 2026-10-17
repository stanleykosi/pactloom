# Durable proposal qualification status

Updated: 2026-10-17, 23:48 UTC.

**Incomplete implementation. No native end-to-end, public testnet settlement, or production activation is claimed.** Source checkpoints are recoverable work in progress, not releases.

## Observed local results

Pinned Rust 1.99.0, release builds, locked dependencies, maintained PCZT/proof implementation and encrypted SQLCipher journals were used. Tests used synthetic, never-funded accounts and no public-chain submission.

- Canonical fixed-proposal protocol: **10 passed**, 32.49 seconds, including the explicitly enabled ignored real-proof test. Checks include genuine FVK-derived canonical account IDs, relabeling/substitution refusal, exact same-owner input mappings, full manifest reconciliation and signature-only changes. These two protocol source files are included in checkpoint `456d263943d07d9eba85b507f328bbee1f6bd221`.
- Durable signature intake: **2 passed**, 201.17 seconds, on the earlier protocol slice. Includes saved subset reopening and full verification. Later canonical-account changes require a fresh combined regression run; this result is not silently carried forward.
- Durable construction material: **6 passed**, 2.88 seconds. Includes exact private material round-trip without authority, tampered/duplicate note rejection, account relabeling refusal, consent recipient/destination/manifest bindings and explicitly versioned local reviewer audiences.
- Payment engine synthetic lifecycle: **1 passed**, 431.88 seconds. Real proof, first-owner retention, encrypted saved state close/reopen, second-owner intake, exact union/extraction and unknown-submission recovery were exercised. This test begins at a trusted embedded construction boundary and uses synthetic signing/chain issuers. It does **not** qualify the new initial native disclosure, native key-use or operating-system process restart.
- Store backup regression suite: **18 passed**, 14.97 seconds, including four private-material scope guards. Private material cannot enter a legacy coordination-only archive; older encrypted archive history and quarantine/refusal behavior remain exercised.

Engine and wallet builds passed in the active working tree. Some files were being implemented concurrently, so these results are not a reproducible full-tree qualification of a published commit. A final frozen-source build and regression pass remain required.

## Still required

1. Genuine sequential native initial disclosure, bounded wallet preparation, acknowledged end of the original read, and independently approved durable material intake for both owners.
2. Authenticated, explicitly consented private review delivery; fresh native review of all exact effects; independent writer/exposure reconciliation and signature release through production issuers.
3. Compatibility between fresh local native consent and the exact original born enrollment/payment policy, without weakening witness policy or reviving old capabilities.
4. Native session/owner teardown and reopening without retained grants. This must be distinguished from a separate **actual OS-process exit/relaunch** recovery test.
5. Crash/refusal cases at exposure, key-use, export, intake and submission boundaries, against frozen source on the authorized Linux qualification runner.
6. Explicit profile activation and attended UI acceptance, followed separately by testnet submission, inclusion, recipient observation and confirmation policy.

Native IPC execution is not available in the current local sandbox. Component tests are not a substitute for the authorized native Linux run. Funded wallets and secrets must not be placed in source checkpoints.
