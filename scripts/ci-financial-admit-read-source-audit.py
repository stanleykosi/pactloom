#!/usr/bin/env python3
"""Fixed P52 source equivalence, excluding explicitly authorized early close.

Static only. The exact kernel hashes and owned fault traces complement actual
compile/tests; no native Final, TLS, socket, authority or fullflow is fabricated.
"""
import argparse, hashlib, json, re
from pathlib import Path
MACROS_SHA = '05c11286278f5eabf1316ecacd9e1facf3fd21b964f1969bbbba88d31192f216'
HOOK_SHA = '8de23863fb427932352fcd4ebdfdc371fc36c2f9daba3dc0fa391febf584a62e'
BASELINE = "27e668bfcf84fe809b6bca4a1c15a5e8e6dd1caf"
BASE_TOKEN_HASHES = {'crates/wholepact-signer/src/native_ui/runtime/coordinated_delivery_admission_v1.rs': '41cd3566bb9b2c6833efd24cd66c40df064ac5f3114f4462a837bec9e4286c30', 'crates/wholepact-signer/src/native_ui/witness_workspace/durable_delivery_v3/coordinated_admit_read_v1.rs': '3ade12cef9c580fc056125e29d895d6cfdb25377e8832dd55e5e86d26da84dda', 'crates/wholepact-signer/src/account/birth/enrollment/roster_v2/prepared_delivery_v3/coordinated_source_entry_v1/coordinated_delivery_source_v1/coordinated_admission_v1.rs': '84ec29dc3e0486ebef8d3003fc56f51585e58587c2b93e7e9fb1ec2a92e434fc', 'crates/wholepact-financial-coordinator-origin/src/signer_v3_admit_read_origin.rs': '11c38d2d80ef49e5fb2cab5bdad391b816383a54b67d8b271281ea07334863aa'}
UNCHANGED_FILES = {'crates/wholepact-financial-coordinator-origin/src/signer_continue_state.rs': 'f22c0ad3452dc038b0e34f45f8fbd1182c11113d6977d15b1bb347e838fe6cea', 'crates/wholepact-financial-coordinator-origin/src/financial_observer.rs': '67a92e04a03df01257be85ee99c8544be4f627c05c3800a6b5ae9b82cbd6dc4a', 'crates/wholepact-signer/src/ipc/coordinated_pair_v1.rs': '6025d99c16c02c3925c6053f554b85560a070a1ad800d977f8d203639965af4d', 'crates/wholepact-authority/src/transport.rs': '2c58ec5ae515ce13786ec81661901c9ba1c72a5f9827d3c925e4fbc48e4f2716', 'crates/wholepact-authority/src/transport/history_diagnostics_v1.rs': '0c7a3d7c5337c59c573ea85fd5d2cb6a85d09ebb0123007a9e09f4310304d324'}
HISTORY_BLOCK_SHA = '46e6069be3bfa405a7066fa64a38f7c66120e0bf70364b8cde0ec0b046394324'
OLD_HISTORY_BLOCK = '        let mut callback_error = None;\n        let result = self.opened.client.reconcile_history_checked_until(\n            action.original_read_deadline(),\n            || {\n                check().and_then(|_| check_source()).map_err(|error| {\n                    if callback_error.is_none() {\n                        callback_error = Some(error);\n                    }\n                    wholepact_authority::AuthorityError::Permission\n                })\n            },\n        );\n'
FINISH_SHA = 'b297cdf4bf324809ff50552bdfc4a192029a07c150679e8ffce6133dceba8d9e'
OLD_FINISH = '    pub fn finish_read(mut self) -> Result<()> {\n        self.check_current()?;\n        self.binding.owner.pair.entry.core.phase.step(\n            self.binding.owner.pair.entry.slot(),\n            151,\n            152,\n        )?;\n        self.consumed = true;\n        Ok(())\n    }'

# Exact P67 worker-result preservation delta. No deadline/currentness change.
READY_WORKER_CURRENT_SHA = '45ca71f1653973ed6909fc2011506ecef4f88ef291dfe5862857dba6d1f61f8c'
READY_WORKER_NEW = '            // Sender teardown can precede publication of thread completion.\n            // The unchanged nonblocking driver joins only after is_finished;\n            // its original actor, cancellation and transport checks keep running.\n            Err(std::sync::mpsc::TryRecvError::Disconnected) => Ok(None),'
READY_WORKER_OLD = '            Err(std::sync::mpsc::TryRecvError::Disconnected) if self.finished() => Ok(None),\n            Err(_) => Err(Error::Unavailable),'
READY_WORKER_TEST_INCLUDE = '\n#[cfg(test)]\n#[path = "coordinated_delivery_admission_v1/ready_disconnect_tests.rs"]\nmod ready_disconnect_tests;\n'
def restore_ready_worker(text):
    assert hashlib.sha256(text.encode()).hexdigest()==READY_WORKER_CURRENT_SHA
    assert text.count(READY_WORKER_NEW)==1 and text.count(READY_WORKER_TEST_INCLUDE)==1
    return text.replace(READY_WORKER_NEW,READY_WORKER_OLD,1).replace(READY_WORKER_TEST_INCLUDE,'',1)


W_STAGES='HistoryMonitorCheck HistoryCleanupDeadline HistoryRequestReceive HistoryRequestOrder HistoryWorkerStart HistoryServeHandoff HistoryEventOrder HistoryDisplaySend HistoryServingSend HistoryWorkerJoin HistoryWorkerFailure HistoryWorkerUnexpectedReturn HistoryFailureSend HistoryDisposedSend HistoryPurposeClosedSend HistoryCleanupRetain'.split()
C_ERROR_STAGES='HistoryRetainedReceiveError HistoryFinishError HistoryRetirementPrepareError HistoryRetirementError'.split()

def remove_region(text,start,end,expected):
    assert text.count(start)==1 and text.count(end)==1,(start,end)
    a=text.index(start);b=text.index(end,a)
    assert hashlib.sha256(text[a:b].encode()).hexdigest()==expected,start
    return text[:a]+text[b:]

def restore_history_observer(text):
    text=remove_region(text,'/// Failure-only C snapshot after original shared restriction','/// Only the new observation is isolated. This does not catch panic=abort,','875b1b55997c122b9b3a4d4266510e9a4aec1ab6ce581a768d597e376b7e10d2')
    text=remove_region(text,' #[test] fn pre_cleanup_flush_never_waits_for_owned_writer_lock() {',' #[test] fn success_and_unwind_return_to_original_teardown() {','743c06724dc42ded2b678d799339f962dde780bc84ada27dc40f48e4451027bb')
    new='reporter.flush_failure(crate::financial_ci_actor_diagnostics::sample_failure(),|f|best_effort_diagnostic_append(||emit_locked(w,"ActorFailureBoundary",&f).map_err(|_|())));'
    old='reporter.flush_failure(crate::financial_ci_actor_diagnostics::sample_failure(),|f|emit_locked(w,"ActorFailureBoundary",&f).map_err(|_|()));'
    assert text.count(new)==1
    return text.replace(new,old)

def restore_history_actor(text):
    # Exact P71 finite retirement domain and actual first-detail test only.
    assert text.count('HistoryRetirementError,HistoryRetirementNativePauseTicket,HistoryRetirementNativePauseWait,HistoryRetirementHostQuiescence,HistoryRetirementPurposeClose,HistoryRetirementOwnedStopReap,HistoryRetirementHostResume,HistoryRetirementNativeResume});')==1
    text=text.replace('HistoryRetirementError,HistoryRetirementNativePauseTicket,HistoryRetirementNativePauseWait,HistoryRetirementHostQuiescence,HistoryRetirementPurposeClose,HistoryRetirementOwnedStopReap,HistoryRetirementHostResume,HistoryRetirementNativeResume});','HistoryRetirementError});',1)
    text=remove_region(text,' #[test] fn retirement_actual_error_enables_first_finite_detail_without_rewrite() {',' #[test] fn early_append_panic_keeps_first_worker_class_without_retry() {','08b66a3ef146bfcb37cb7ff0fce913f48cab40654afd4ad11e22a8c888d2206d')
    stages=','+','.join(W_STAGES+C_ERROR_STAGES)
    assert text.count(stages)==1
    text=text.replace(stages,'')
    return remove_region(text,' #[test] fn early_append_panic_keeps_first_worker_class_without_retry() {',' #[test] fn detail_and_normal_cleanup_never_enable_failure()','deee34a4b48bba22631013dc7e98bfedfe3d9571bab753de1706661089c65db0')

# Exact cfg(test)-only shared-wall regression; production helper stays pinned.
SHARED_WALL_REGRESSION = '\n    // Atomic-only regression: models the removed fetch_max kernel, not a\n    // protocol ticket, actor, grant, lease, or successful source audit.\n    fn legacy_fetch_max_projection(\n        last: &AtomicU64,\n        deadline: Instant,\n        mut wall_ms: impl FnMut() -> Result<u64>,\n    ) -> Result<Option<u64>> {\n        let wall = wall_ms()?;\n        let prior = last.fetch_max(wall, Ordering::AcqRel);\n        Ok((wall >= prior && Instant::now() < deadline).then_some(wall))\n    }\n\n    fn forced_publication_reordering(legacy: bool) -> (Option<u64>, Option<u64>, u64, usize) {\n        let last = Arc::new(AtomicU64::new(99));\n        let sampled = Arc::new(Barrier::new(2));\n        let release = Arc::new(Barrier::new(2));\n        let deadline = Instant::now() + Duration::from_secs(60);\n        let first = {\n            let last = Arc::clone(&last);\n            let sampled = Arc::clone(&sampled);\n            let release = Arc::clone(&release);\n            std::thread::spawn(move || {\n                let mut samples = 0;\n                let mut sample = || {\n                    samples += 1;\n                    if samples == 1 {\n                        let wall = 100;\n                        sampled.wait();\n                        release.wait();\n                        Ok(wall)\n                    } else {\n                        Ok(101)\n                    }\n                };\n                let observed = if legacy {\n                    legacy_fetch_max_projection(&last, deadline, &mut sample)\n                } else {\n                    observe_shared_wall(&last, deadline, &mut sample)\n                }.unwrap();\n                (observed, samples)\n            })\n        };\n        sampled.wait();\n        let second = if legacy {\n            legacy_fetch_max_projection(&last, deadline, || Ok(101))\n        } else {\n            observe_shared_wall(&last, deadline, || Ok(101))\n        }.unwrap();\n        release.wait();\n        let (first, samples) = first.join().unwrap();\n        (first, second, last.load(Ordering::Acquire), samples)\n    }\n\n    #[test]\n    fn delayed_sample_reproduces_legacy_false_rollback_and_existing_helper_repairs_it() {\n        assert_eq!(forced_publication_reordering(true), (None, Some(101), 101, 1));\n        assert_eq!(forced_publication_reordering(false), (Some(101), Some(101), 101, 2));\n    }\n'

def restore_shared_wall_regression(text):
    assert hashlib.sha256(text.encode()).hexdigest()=="33c4b1f180f6f4093fd195a65a27921bceea06cde078b9917e22f3a3048b0079"
    assert text.count(SHARED_WALL_REGRESSION)==1
    return text.replace(SHARED_WALL_REGRESSION,"",1)

# Exact P71 repaint relocation and cfg(test)-only child declaration. The
# pre-existing raw hook, every guard and the original 20 ms cadence stay pinned.
UI_REPAINT_CURRENT_SHA = '930e2e54c6429bde08d5bddd6dc671c5a8b335777cb5e00bcc7763b6d11d5a27'
UI_REPAINT_INSERTED = '        // Poll inside every egui pass, including retirement/eligibility returns.\n        // A pre-pass raw-hook request can be suppressed before begin_pass resets\n        // its delay; it is not a substitute for this in-pass lifecycle wakeup.\n        ctx.request_repaint_after(Duration::from_millis(20));\n'
UI_REPAINT_TEST_INCLUDE = '\n#[cfg(test)]\n#[path = "financial_source_ui/repaint_tests.rs"]\nmod repaint_tests;\n'
UI_REPAINT_BOTTOM = '        ctx.request_repaint_after(Duration::from_millis(20));\n'
UI_REPAINT_BOUNDARY = '    }\n    fn apply_intent(&mut self, intent: Intent, frame: u64, ctx: &egui::Context) -> Result<()> {'
# Exact P72 ordinary-selector routing delta; no source region is ignored.
UI_SELECTOR_EXPORT_CURRENT_SHA = 'a04c0d0394c63ffe1e93ca1a1f7295c570e5346576c9f018fc2f00dd8ffd88ce'
UI_SELECTOR_EXPORT_INVERSE_PAIRS = (('                | Phase::FinancialSetupConfiguring\n        ) {\n            ctx.input_mut(|input| {\n                scrub_unrequested_payloads(&mut input.events);', '                | Phase::FinancialSetupConfiguring\n        ) || selector_export_phase(painted_phase) {\n            ctx.input_mut(|input| {\n                scrub_unrequested_payloads(&mut input.events);'), ('        } else if self.phase == Phase::Configuring && self.focused_last && !self.native.is_revoked()\n        {\n            if !selector_events_bounded(&raw.events) {', '        } else if (self.phase == Phase::Configuring && self.focused_last && !self.native.is_revoked())\n            || selector_export_input_allowed(\n                self.phase,\n                self.focused_last,\n                self.native.is_revoked(),\n                self.host_entry,\n                self.retained_continue.iter().any(Option::is_some)\n                    || self.result_selectors.iter().any(Option::is_some),\n            )\n        {\n            if !selector_events_bounded(&raw.events) {'), ('', 'fn selector_export_phase(phase: Phase) -> bool {\n    matches!(phase, Phase::SetupNeeded | Phase::Selecting | Phase::SignCommitted\n        | Phase::SignedRetired | Phase::ReturnCompleted)\n}\nfn selector_export_input_allowed(\n    phase: Phase,\n    focused: bool,\n    revoked: bool,\n    host_entry: HostEntry,\n    has_selector: bool,\n) -> bool {\n    // Ordinary destinations for actual retained metadata only. Protected input\n    // routing stays first; editing a path is not consent or a deadline renewal.\n    selector_export_phase(phase) && focused && !revoked\n        && !host_entry_blocks_source(host_entry) && has_selector\n}\n'), ('', '\n#[cfg(test)]\n#[path = "financial_source_ui/selector_export_tests.rs"]\nmod selector_export_tests;\n'))
def restore_selector_export_ui(text):
    assert hashlib.sha256(text.encode()).hexdigest()==UI_SELECTOR_EXPORT_CURRENT_SHA
    for before,after in reversed(UI_SELECTOR_EXPORT_INVERSE_PAIRS):
        assert text.count(after)==1
        text=text.replace(after,before,1)
    assert hashlib.sha256(text.encode()).hexdigest()==UI_REPAINT_CURRENT_SHA
    return text

# Exact P73 distinct ScrollArea identity and its cfg(test)-only child.
UI_ADMISSION_SCROLL_CURRENT_SHA = '564479de74dffffc910e0860a6b51100270fb31fa197de30dcdcccc148946ab6'
UI_ADMISSION_SCROLL_SALT = '        .id_salt(_ci_tag)\n'
UI_ADMISSION_SCROLL_TEST_INCLUDE = '\n#[cfg(test)]\n#[path = "financial_source_ui/admission_scroll_tests.rs"]\nmod admission_scroll_tests;\n'
def restore_admission_scroll_ui(text):
    assert hashlib.sha256(text.encode()).hexdigest()==UI_ADMISSION_SCROLL_CURRENT_SHA
    assert text.count(UI_ADMISSION_SCROLL_SALT)==1 and text.endswith(UI_ADMISSION_SCROLL_TEST_INCLUDE)
    text=text.replace(UI_ADMISSION_SCROLL_SALT,'',1)[:-len(UI_ADMISSION_SCROLL_TEST_INCLUDE)]
    assert hashlib.sha256(text.encode()).hexdigest()==UI_SELECTOR_EXPORT_CURRENT_SHA
    return text

def restore_ui_repaint(text):
    text=restore_admission_scroll_ui(text)
    text=restore_selector_export_ui(text)
    assert hashlib.sha256(text.encode()).hexdigest()==UI_REPAINT_CURRENT_SHA
    assert text.count(UI_REPAINT_INSERTED)==1 and text.count(UI_REPAINT_TEST_INCLUDE)==1
    assert text.count(UI_REPAINT_BOUNDARY)==1
    text=text.replace(UI_REPAINT_INSERTED,'',1).replace(UI_REPAINT_TEST_INCLUDE,'',1)
    return text.replace(UI_REPAINT_BOUNDARY,UI_REPAINT_BOTTOM+UI_REPAINT_BOUNDARY,1)

def digest(text): return hashlib.sha256(text.encode()).hexdigest()
def tokens(text):
    return ''.join(token for token in re.findall(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/|[^\s]', text, re.S)
                   if not token.startswith(('//', '/*')))
def balanced_end(text, opening, left='(', right=')'):
    depth=0; quoted=False; escaped=False
    for i in range(opening,len(text)):
        c=text[i]
        if quoted:
            if escaped: escaped=False
            elif c=='\\': escaped=True
            elif c=='"': quoted=False
            continue
        if c=='"': quoted=True; continue
        if c==left: depth+=1
        elif c==right:
            depth-=1
            if depth==0:return i+1
    raise AssertionError('unbalanced selected kernel')
def unwrap(text):
    pattern=re.compile(r'actor_admit_read_(detail_)?result!\(')
    while True:
        matches=list(pattern.finditer(text))
        if not matches:return text
        match=matches[-1]; opening=match.end()-1; end=balanced_end(text,opening)
        body=text[opening+1:end-1]; stack=[]; quoted=False; escaped=False; commas=[]
        for i,c in enumerate(body):
            if quoted:
                if escaped:escaped=False
                elif c=='\\':escaped=True
                elif c=='"':quoted=False
                continue
            if c=='"':quoted=True
            elif c in '([{':stack.append(c)
            elif c in ')]}':stack.pop()
            elif c==',' and not stack:commas.append(i)
        n=1 if match.group(1) else 2
        assert len(commas)==n,(body,commas,n)
        text=text[:match.start()]+body[commas[-1]+1:].strip()+text[end:]
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True)
    root=parser.parse_args().source.resolve(); evidence=[]
    for relative,expected in UNCHANGED_FILES.items():
        raw=(root/relative).read_text()
        if relative.endswith("/financial_observer.rs"):raw=restore_history_observer(raw)
        if relative.endswith("/signer_continue_state.rs"):raw=restore_shared_wall_regression(raw)
        assert hashlib.sha256(raw.encode()).hexdigest()==expected,relative
    for relative,expected in BASE_TOKEN_HASHES.items():
        raw=(root/relative).read_text(); restored=raw
        if relative.endswith('/runtime/coordinated_delivery_admission_v1.rs'):
            restored=restore_ready_worker(restored)
        restored=restored.replace('        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        let _observation = crate::financial_ci_actor::AdmitReadObservation::enter();\n','')
        if relative.endswith('coordinated_admit_read_v1.rs'):
            start=restored.index('        let mut callback_error = None;')
            end=restored.index('        if let Some(error) = callback_error {',start)
            assert digest(restored[start:end])==HISTORY_BLOCK_SHA
            restored=restored[:start]+OLD_HISTORY_BLOCK+restored[end:]
            observed='        #[cfg(all(wholepact_financial_rendered_host_semantic_ci, feature = "synthetic-qualification"))]\n        if let Some(detail) = history_failure {\n            crate::financial_ci_actor::admit_read_detail_value(detail);\n        }\n'
            assert restored.count(observed)==1;restored=restored.replace(observed,'')
        if relative.endswith('signer_v3_admit_read_origin.rs'):
            start=restored.index('    /// Semantic failure reporting only.')
            end=restored.index('    pub fn finish_read(mut self)',start)
            hook=restored[start:end]
            assert digest(hook)==HOOK_SHA
            assert hook.count('self.binding.owner.pair.entry.core.close_with_failure_observation();')==1
            assert '#[cfg(wholepact_financial_rendered_host_semantic_ci)]' in hook
            restored=restored[:start]+restored[end:]
            start=restored.index('    pub fn finish_read(mut self)')
            end=restored.index('\n}\nimpl Drop for SignerV3AdmitReadFinalV1',start)
            assert digest(restored[start:end])==FINISH_SHA
            restored=restored[:start]+OLD_FINISH+restored[end:]
        restored=unwrap(restored)
        assert digest(tokens(restored))==expected,relative
        evidence.append({'path':relative,'baseline_token_sha256':expected,'current_sha256':digest(raw)})
    lib=(root/'crates/wholepact-signer/src/lib.rs').read_text()
    start=lib.index('macro_rules! actor_admit_read_result {')
    end=lib.index('macro_rules! actor_driver_detail_result {',start)
    assert digest(lib[start:end])==MACROS_SHA
    # Existing diagnosed history performs the same kernel once; only the
    # preexisting diagnostic observer additionally samples costs. None emitted.
    transport=(root/'crates/wholepact-authority/src/transport.rs').read_text()
    start=transport.index('    pub fn reconcile_history_diagnosed_checked_until(')
    end=transport.index('    fn reconcile_history_inner(',start)
    selected=transport[start:end]
    assert selected.count('self.reconcile_history_inner(')==1
    assert 'require_before_caller_deadline(deadline)' in selected
    assert 'result.map_err(|error| observer.into_failure(error))' in selected
    print(json.dumps({'source_audit_passed':True,'baseline':BASELINE,'normalized_files':evidence,
        'unchanged_kernel_files':UNCHANGED_FILES,'runtime_execution':False,
        'intentional_semantic_delta':'Terminal owned error advances existing restrictive close before automatic drops.'},sort_keys=True))
if __name__=='__main__':main()
