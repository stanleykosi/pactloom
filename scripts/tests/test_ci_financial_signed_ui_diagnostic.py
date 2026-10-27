"""Exact finite-only UI observation wiring; no product, socket or native launch."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
UI=ROOT/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs'
CURRENT='214e27ddee4efed85aa34827729e67e947734f5ac911a5a6960723fc1bc8bdfb'
BASELINE='bd73b2ec32ed3b5e16e017e8a795b6f7757b75ab4a4a3cd9f8c23e3c3f4247a8'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module
G=load('signed_ui_block_reader',ROOT/'scripts/ci-financial-parked-material-ordering-trace.py')
A=load('signed_ui_strict_audit',ROOT/'scripts/ci-financial-admit-read-source-audit.py')

class SignedUiDiagnosticTests(unittest.TestCase):
    def source(self):
        raw=UI.read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),CURRENT)
        return raw.decode('utf-8')
    def test_exact_entire_ui_inverse_preserves_all_unrelated_native_logic(self):
        source=self.source();restored=A.restore_fatal_ui_diagnostic(source)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),BASELINE)
        for bad in (source+'// unrelated\n',source.replace('current_for_restriction','unreviewed_current',1)):
            with self.assertRaises(AssertionError):A.restore_fatal_ui_diagnostic(bad)
    def test_shared_current_kernel_retains_absence_and_and_order(self):
        source=self.source();old=A.restore_fatal_ui_diagnostic(source)
        prior=G.block(old,'    fn current(&self) -> bool {')
        kernel=G.block(source,'    fn current_with_signed_check(')
        header=kernel.split('{',1)[0]
        restored=kernel.replace(header,'    fn current(&self) -> bool ',1).replace('check(s).is_ok()','s.check_current().is_ok()',1)
        self.assertEqual(restored,prior)
        self.assertEqual(kernel.count('check(s)'),1)
        self.assertEqual(G.block(source,'    fn current(&self) -> bool {'),
                         '    fn current(&self) -> bool {\n        self.current_with_signed_check(|s| s.check_current())\n    }')
        self.assertEqual(G.block(source,'    fn current_for_restriction(&self) -> bool {'),
                         '    fn current_for_restriction(&self) -> bool {\n        self.current_with_signed_check(|s| signed_result_fatal_check!(s))\n    }')
    def test_macro_has_one_call_per_profile_and_no_authority_or_clock_work(self):
        macro=G.block(self.source(),'macro_rules! signed_result_fatal_check ')
        self.assertEqual(macro.count('::check_signed_result_for_fatal_restriction($custody)'),1)
        self.assertEqual(macro.count('($custody).check_current()'),1)
        self.assertIn('#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]',macro)
        for forbidden in ('revoke(', 'mark_failed(', 'Instant::now', 'wall_ms(', 'sleep(', 'unsafe'):
            self.assertNotIn(forbidden,macro)
    def test_hot_monitors_replace_only_original_calls_before_same_revoke(self):
        source=self.source();old=A.restore_fatal_ui_diagnostic(source)
        current=G.block(source,'    fn check_current(&mut self) {')
        prior=G.block(old,'    fn check_current(&mut self) {')
        self.assertEqual(current.count('!p.current_for_restriction()'),2)
        self.assertEqual(current.count('signed_result_fatal_check!(s).is_err()'),1)
        restored=current.replace('!p.current_for_restriction()','!p.current()').replace('signed_result_fatal_check!(s).is_err()','s.check_current().is_err()')
        self.assertEqual(restored,prior)
    def test_action_and_event_fatal_propagation_is_source_bound(self):
        source=self.source();old=A.restore_fatal_ui_diagnostic(source)
        action=G.block(source,'    fn apply_intent(&mut self, intent: Intent, frame: u64, ctx: &egui::Context) -> Result<()> {')
        self.assertEqual(action.count('current_for_restriction()'),2)
        self.assertEqual(action.count('signed_result_fatal_check!('),2)
        self.assertEqual(source.count('self.apply_intent(intent, frame, &ctx).is_err()'),1)
        self.assertIn('if self.apply_intent(intent, frame, &ctx).is_err() {\n                self.revoke(',source)
        accept=G.block(source,'    fn accept_return(')
        self.assertEqual(accept.count('signed_result_fatal_check!('),1)
        self.assertEqual(source.count('if self.route_return(event,ctx.cumulative_frame_nr()).is_err(){self.revoke('),1)
        poll=G.block(source,'    fn poll_driver(')
        self.assertEqual(poll.count('signed_result_fatal_check!(&custody).is_err()'),1)
        self.assertIn('|| signed_result_fatal_check!(&custody).is_err() {\n                        self.revoke(',poll)
        self.assertEqual(G.block(source,'    fn route_return('),G.block(old,'    fn route_return('))
    def test_handled_display_and_conditional_terminal_pair_probes_stay_silent(self):
        source=self.source();old=A.restore_fatal_ui_diagnostic(source)
        self.assertEqual(source.count('self.financial_parked.iter().all(|p| p.as_ref().is_some_and(|p| p.current()))'),1)
        self.assertEqual(G.block(source,'    fn require_pair_original('),G.block(old,'    fn require_pair_original('))
        pair=G.block(source,'    fn require_pair_original(')
        self.assertIn('custody.check_current()?;',pair);self.assertNotIn('signed_result_fatal_check!',pair)

if __name__=='__main__':unittest.main()
