# Durable proposal qualification status

Updated: 2026-10-18, 01:34 UTC.

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

## Subsequent checks: 2026-10-18

- Frozen checkpoint `aeb067047db6e2f7de8fe745d004d535468d39f0` Rust sources compiled successfully for the native-host all-features library test executable (7 minutes 41 seconds). This was compilation only, not local native execution.
- The 43 existing source-reviewed pure Host regressions passed. They create no native, IPC, network or payment owners.
- Default signer library test compilation passed. After correcting only invalid test fixture permissions/lifetimes and respecting immutable genesis, eight policy tests passed. Four default migration/refusal tests passed, including refusal of signed historical verification when its verifier feature is disabled. Positive signed-history verification still requires its separate feature-enabled test run.
- Four strict JSON tests passed, including the explicit aggregate limit retaining the default limit and strict depth/node/duplicate-key protections.
- Isolated native baseline run: [39082330109](https://github.com/stanleykosi/pactloom/actions/runs/39082330109), pinned to the exact checkpoint above. It completed with a native-entry failure after all 53 initial setup inputs, before pairing, material disclosure, Engine intake or proof. Its preceding 71 Python, 35 signer, six renderer, three authority, 43 pure Host and encrypted-bootstrap checks passed. Process/root cleanup was verified. The fixture collapsed the underlying open error into `SignerRecoveryRequired`, so this code alone is not evidence of corrupt wallet state. Its scope is genuine signer disclosure, saved contributions and native-owner/session reopening. Host-local privacy permissions and chain responses are synthetic. It does not prove full native signing, a usable foreground Host workflow, OS-process restart or testnet settlement.

The new stable-V2 birth-policy mapping is a later source change and is not covered by the earlier policy test pass. It must retain the original allowlisted stable policy digest while independently binding and verifying the exact concrete payment and own returns.

Production usability also requires genuine candidate-free own-wallet input discovery and separately consented inert projections before a complete manifest exists, followed by a usable coordinator command with genuine foreground Host consent. Synthetic funding outpoints and test-local permission matchers are not substitutes for these product paths.

## Latest diagnosis and feature-enabled component checks

A source defect consistent with the native-entry failure was found: activation created `local-apps` inside an immutable original vault root, then immediately revalidated a root inventory that correctly forbids directories. Temporary IPC state must live in a separately owned endpoint container, without weakening the original inventory checks. Finite closed stage/error reporting is being added because the original fixture discarded the underlying error. A rerun is required to establish whether this was the first or only blocker.

The later stable-V2 signer all-features test executable compiled. Eight bridge/return-ownership tests, six feature-enabled migration/backup tests, ten durable-born journal tests and one redisclosure request test passed. The policy group passed 14 of 15; the remaining negative-test fixture used a receiving-address string with forbidden hyphens and failed before its intended assertion. A test-only literal correction is pending rerun. These are not genuine native writer/reserve/key-use results.

The scanner contact regression currently passes the context-to-channel case but fails the post-channel case; closed diagnostics are being added before diagnosing or changing its test synchronization. Both must pass before this regression is considered covered.

The cloud checkout and build cache were lost again on 2026-10-18 around 00:52 UTC. The published checkpoint was restored and its commit/tree verified. Unpublished source edits are being recovered and separately checkpointed. Earlier test observations remain historical results; they are not claims that the restored workspace has already repeated those runs.

## Rebuilt checkpoint and focused rerun

After restoring the workspace, checkpoint `354a961c6d8573198730bed032040626a94a94d1` compiled for native-host all-features tests (9 minutes 33 seconds) and signer all-features tests (4 minutes 52 seconds). The corrected signer groups then passed: 15 policy, eight bridge/return-ownership, six feature-enabled migration, ten born-journal and one redisclosure test, 40 total. The IPC endpoint regression was deliberately not executed locally.

The isolated native retry is [39084949525](https://github.com/stanleykosi/pactloom/actions/runs/39084949525), pinned to that checkpoint. It failed at session startup after all 53 initial inputs, with `SignerPollCancelled` and no new `DurableEntry` stage observed. Its preceding 72 Python, 35 signer, six renderer, three authority, 43 pure Host and encrypted-bootstrap checks passed; child/process-group/root and outer-container cleanup were verified. This does not establish that endpoint activation was reached. Session lifecycle diagnosis is required before another retry. No full native signing, OS-process restart or testnet settlement follows from these component passes.

Future CI ordering runs the existing output/privacy self-tests, Host pure checks and encrypted bootstrap before the bounded native baseline, then requires all remaining signer/authority gates before overall success. The additional endpoint-isolation selector is a separate CI-only real-IPC test, never part of a local pure selection. Parser/selection mock tests passed 83 cases; the new CI gate itself still requires execution.

Inactive production leaves remain incomplete and unregistered. Discovery planning now separates immutable historical discovery context from a newly approved common pre-proof construction anchor; post-proof anchor rules remain unchanged. The proposed ephemeral born viewing cache is explicitly limited by the remaining native-owner lifetime and short-history account envelope, not a general long-history availability solution. Production discovery/derived-manifest privacy must also be protected by an exclusive purpose-specific coordinator facade or equivalent complete view/export fencing, not only a hidden raw receipt field.

The post-channel contact diagnostic observed three permission checks, four accepted connections and four context RPCs before unsupported-wallet access. The corrected component test injects denial at the actual third permission check rather than assuming a fifth server accept is an awaited client boundary. Its renamed claim is post-channel permission denial before wallet reads or further RPCs. The corrected wallet all-features library compiled in 4 minutes 5 seconds and both exact contact regressions passed in 3.29 seconds. These are component ordering tests, not native disclosure qualification.

Source review of the second native failure establishes that `SignerPollCancelled` is emitted by explicit worker cleanup, not owner-lifetime expiry. It can be secondary to an earlier Host preproof error that was collapsed into a generic failure. Closed first-error diagnostics are required; no semantic cancellation change is justified by this result alone.

Additional inactive discovery, journal and private-workspace source is backed up in `fb3a7a184561fbe3d8a199d3d873c0699aef00d4`. None of those issuers/facades are registered or qualified. The facade limits application-level escape through exclusive ownership and sanitized views, not confidentiality from its authorized constructor or database key holder. Activation remains denied pending complete original/dependency path exclusion, inventory, backup and recovery coverage.

The inert discovery core DTO, economic-shape helper and wallet exact-recapture modules were registered separately from native issuers. Their combined all-features library test build passed in 3 minutes 27 seconds. Four core and seven protocol tests passed. Wallet recapture passed one of three: one fixture returned `Invalid` before its intended assertion, and another did not observe the expected anchor advance. Both failures remain under investigation; no successful recapture qualification is claimed.
