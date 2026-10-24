# D62: source-bound Admit review layout diagnostic

This is **not H62 artifact reuse, a live qualification, a deadline extension, or
evidence of native approval**. Baseline: P59b native source plus H61's unchanged
Python flow and additive test-only layout/DTO code. Never activate a full run or
reuse a qualified native artifact for this changed native source.

## One targeted experiment

The native worker supplies one complete, material-derived, validated
`SignerV3AdmitPresentationV1` through `WHOLEPACT_CI_EGUI_ADMIT_FIXTURE`. It is a
private, owned regular file, mode `0600`, at most 61,440 bytes. The Python bridge
checks metadata only; it never reads or publishes the DTO. The native test uses
the actual 1,280 × 800 egui composition, literal effective header, `CentralPanel`,
`ci_panel!`, 390-point `review_display`, acknowledgement and Arm gate. It does
not construct a native Window, approval ticket, Final, or original owner.

The initial two observer frames provide an essential negative control: read,
acknowledgement, enabled Arm and clicked Arm must all be false. The **unchanged
H61 `FullFlow.review/seek/scroll/press` and `NativeScenario.stable/point`** then
drive that same composition. The original `Controller.click/scroll_up/scroll_down`
methods are inherited, including MOVE, button-down/up, fixed wheel and rendered
click barrier counts. Only transport, progress receipts, fixture and observer
are explicit test doubles. A real gated Arm click is intercepted as a dry
reachability event; Final is unavailable.

This first diagnostic starts at a **fresh outer-scroll offset of zero**. The live
failed review inherited its prior phase's scroll position, which is not known.
Top-start reachability cannot resolve that retained-offset difference.

## Fixed clock and input model

- Every input or progress stub advances one actual egui frame by 16 simulated ms.
- Observer calls advance enough **empty actual frames** to maintain a fixed
  minimum 100 simulated ms since the previous observation, rounding to 16 ms
  frames. The source `financial_ci.finish_impl` 100 ms emission-throttle branch
  is checked before execution. This is not the real emission path or wall clock.
- No state-dependent waiting, settling-until-success, stable-check retry,
  scroll-position setter, read setter or acknowledged setter is permitted.
- Weston smooth +120 down maps to egui `Point` delta −120; up is +120. The Rust
  adapter preserves first `Start`, subsequent `Move`, and no invented axis-stop.
- The test starts one non-renewed **120-second wall bound**, using the unchanged
  `ACTION_NS`. This is a new diagnostic process bound, not the retained native
  operation's clock. Simulated elapsed time and wall elapsed time are separate.
- The child is bounded to 4,096 frame requests. A budget rejection is a diagnostic
  boundary, not evidence that the real operation timed out.

## Hosted build and exact invocation

No Rust toolchain is available locally. Build only after source review, in the
existing hosted dependency graph. Keep compile stdout/stderr private; do not
publish raw failures. The fixed Coordinator compile command is:

```sh
WHOLEPACT_FINANCIAL_BUILD_MODE=observed-semantic cargo test --locked \
  -p wholepact-financial-coordinator --bin wholepact-financial-coordinator \
  --no-default-features --features coordinated-financial-runtime \
  --no-run --message-format=json
```

Select the **single executable** from Cargo JSON with all of:

- `reason == "compiler-artifact"`, `profile.test == true`;
- target name `wholepact-financial-coordinator`, target kind `["bin"]`;
- exact Coordinator `Cargo.toml` and `src/main.rs` in this D62 source checkout;
- expected `coordinated-financial-runtime` feature and its existing dependency
  features; the Coordinator build-script row has exactly
  `wholepact_financial_ci`, `wholepact_financial_external_ci`, and
  `wholepact_financial_rendered_host_semantic_ci`;
- the executable is an existing regular executable file. Do not guess its name.

With a bounded private `--list --format terse` invocation, assert that this exact
test name is present once:

```
financial_source_ui::egui_layout_tests::actual_admit_review_layout_protocol
```

Use the native worker's separate reviewed fixture-author test to export the DTO;
do not copy runtime userdata, invent DTO fields, or truncate the display. Then:

```sh
WHOLEPACT_CI_EGUI_ADMIT_FIXTURE="$PRIVATE_DTO" \
  python3 -I -B scripts/ci-financial-egui-layout.py \
  --coordinator-test-binary "$EXACT_CARGO_JSON_EXECUTABLE" \
  --output "$NEW_PRIVATE_REPORT"
```

The bridge invokes only that binary and exact test with `--exact`, `--ignored`,
`--nocapture`, `--test-threads=1`. Its ordinary `#[ignore]` prevents generic test
runs from blocking on stdin. The selected invocation actually runs it; zero tests
or missing protocol frames cannot pass. The bridge removes its identity-checked
DTO on exit and terminates/reaps the owned process group. The enclosing hosted
driver must also remove the private material/DTO workspace on every exit.

## Closed protocol and output

Input: newline JSON `{kind:"Frame",dt_ms:16,event:null|Move|Wheel|Button}` or
`{kind:"Stop"}`. `Move` has integer `x,y`; `Wheel` has only `delta_y:±120`;
`Button` has only `pressed:boolean`.

Frame output has the fixed `EGUI_LAYOUT_FRAME_V1 ` prefix and exact fields
`seq`, `elapsed_ms`, `snapshot`, `geometry`, `state`. Snapshot is the actual
content-free semantic-profile clipped-widget schema; Host is explicitly the
Idle/zero/no-view test context. Geometry contains `inner_rect`, `content_height`,
`viewport_height`, `offset_y`, `outer_rect`, `outer_content_height`,
`outer_viewport_height`, `outer_offset_y`, `end_label_rect`, `end_label_visible`.
State contains `read_to_end`, `acknowledged`, `arm_enabled`, `arm_clicked`.
All geometry must be finite and bounded; no DTO/display/text field is accepted.

The report is created exclusively, mode `0600`. It retains actual frame geometry,
input-event delivery, state transitions, original traversal counters, per-review
counter checkpoints, source pins, fixed clock assumptions and closed failure
codes. A delivered event means it entered the egui frame; actual scroll response
must be read from the reported offsets. Raw child stdout/stderr is bounded and
discarded, including on failures. No raw panic or display text is forwarded.
Stdout contains only a bounded, closed summary: outcome/code, frame/event counts,
separate wall/simulated elapsed time, fixed timing/initial-scroll assumptions,
final state and geometry, the three review widgets' clipped rectangles/enabled
flags, original counters, first state-transition sequence numbers and cleanup
status. It does not publish the full frame trace. Setup failures use only
`{"schema":1,"outcome":"diagnostic_setup_rejected"}`.
The outer hosted driver must import the bridge and call `validate_summary(value)`
before re-emitting that stdout object; it rejects extra keys, arbitrary failure
text, nonfinite geometry, altered timing constants and inconsistent outcomes.

### D62b startup observation after D62's pre-frame EOF

D62 built both test binaries and exported a validated 37,220-byte DTO, then
returned `child_protocol_eof` before any frame or input event was observed. That
result did not identify a layout failure. D62b adds no retry or application
change: only a bounded native panic-location record and its bridge projection.

The supplemental `startup` summary is null if unavailable; otherwise it has
exact fields `selected_test_count` (null, 0 or 1), `first_frame_request_sent`
(true only after the complete JSON write and flush), `failure_record_status`
(`Absent`, `Valid`, `Rejected`), `failure` (null or the record below), and
`precleanup_exit`. The latter is `{state,code,signal}` with `Unobserved`/`Running`
and null values, `Exited` with a 0–255 exit code, or `Signaled` with a 1–64 signal.
Cleanup termination never overwrites this original-child observation. The exact
libtest selected-count line is an observation, not proof that a test executed.

The Rust hook suppresses the original panic payload and emits only
`EGUI_LAYOUT_FAILURE_V1 {checkpoint,source,line,column}` on stderr. Checkpoints:
`Metadata`, `ReadDto`, `ParseDto`, `ValidateDto`, `FormatReview`, `CreateContext`,
`ReadCommand`, `ParseCommand`, `RunFrame`, `ReadSnapshot`, `EncodeFrame`,
`WriteFrame`, `Stop`. Source classes: `Harness`, `Observer`, `SourceUi`,
`EguiContext`, `EguiUi`, `EguiScrollArea`, `EpaintText`, `Other`. Line and column
are bounded integers 0–1,000,000; no path, panic message, stack or DTO is emitted.
Duplicate or malformed markers are rejected without retaining their payload.
The same original panic is resumed after restoring the previous hook.

On EOF the bridge may drain at most one second of remaining stderr, still within
the unchanged 120-second wall deadline and 1 MiB discarded-output ceiling. The
original EOF/controller failure remains primary. One benign real-pipe regression
covers stdout EOF arriving before the finite panic record and original exit 101;
it does not claim to reproduce the unknown native panic or qualify layout.

`source_bound_arm_reachable` establishes only this composition's reachability
under the disclosed timing/transport model. `controller_rejected` preserves the
original closed rejection code and last actual geometry/counters. Neither
outcome establishes live failure causation, a live 120-second fit, native
admission success, or qualification.

## Local checks (not layout evidence)

```sh
python3 -I -B -m unittest discover -s scripts/tests -p test_ci_financial_egui_layout.py -v
python3 -I -B -m unittest discover -s scripts/tests -p test_ci_financial_scenario.py -v
```

These check seven source/protocol/input/cadence/benign-process-cleanup contracts and
the six existing NativeScenario guards. The real egui test must still be built
and executed in the reviewed hosted graph.
