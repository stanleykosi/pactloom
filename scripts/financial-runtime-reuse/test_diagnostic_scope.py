"""Explicit fixed-target scope; preserves and documents unrelated baseline drift."""
import importlib.util
import pathlib
import re
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
W=load('scope_wrapper',ROOT/'scripts/ci-synthetic-output.py')
Q=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
class ScopeTests(unittest.TestCase):
 def test_global_outcomes_exact_and_known_unrelated_boundary_gap_explicit(self):
  text=(Q/'safe_diagnostics_v1.rs').read_text()
  def labels(k):return {x.strip() for x in re.search(r'labels! \{ '+k+r' \{(.*?)\} \}',text,re.S).group(1).split(',') if x.strip()}
  self.assertEqual(labels('Outcome'),W.OUTCOMES)
  self.assertEqual(labels('Boundary')-W.BOUNDARIES,set('PristineOriginalHistory PristineProspectiveScope PristineSignerDrain PristineHostRevoke PristineOriginalPreservation PristineCustodyHandoff PristineSetupRoot PristineOriginalCutoff PristinePredecessorProcess PristineCustodyValidation PristineOriginalAudit'.split()))
  self.assertFalse(W.BOUNDARIES-labels('Boundary'))
 def test_selected_parent_starts_only_delivery_children(self):
  text=(Q/'durable_proposal_v1/delivery_admission_v2.rs').read_text();parent=text.split('fn run_two_processes_v2()',1)[1].split('\nfn directory(',1)[0]
  self.assertEqual(re.findall(r'PrivateWorkspaceStageV1::(\w+)',parent),['DeliveryProducer','DeliveryReader'])
  self.assertNotIn('Pristine',parent);self.assertNotIn('FinancialProducer',parent)
  child=(Q/'durable_proposal_v1/private_fixed_v2.rs').read_text().split('fn produce_delivery_child(',1)[1].split('\n}\n',1)[0]
  self.assertIn('CompletedPreparationV2::DeliveryAdmission',child)
 def test_missing_global_reasons_are_disabled_financial_only_capture(self):
  text=Q.with_suffix('.rs').read_text()
  variants=set(re.findall(r'^    ([A-Za-z0-9]+),$',re.search(r'enum HarnessFailureReason \{([^}]+)\}',text).group(1),re.M))
  self.assertEqual(variants-W.HARNESS_FAILURE_REASONS,{'FinancialPhaseDeadline','FinancialProgressInvalid'})
  start=text.index('if matches!(stage, PrivateWorkspaceStageV1::PristineCoordinator)');scope=text[start:].split('// This creates a temporary terminal',1)[0]
  self.assertRegex(scope,r'if matches!\(stage, PrivateWorkspaceStageV1::PristineCoordinator\) \{\s*transcript.enable_pristine_first_failure\(\);')
  self.assertEqual(re.findall(r'if matches!\(stage, PrivateWorkspaceStageV1::(\w+)\) \{\s*transcript.enable_financial_v2',scope),['FinancialProducer','FinancialReader'])
  rolling=(Q/'rolling_transcript_v1.rs').read_text()
  self.assertIn('financial_progress: None,',rolling)
  for fn,method in [('financial_progress_check','failure_at(now)'),('financial_progress_failure','failure()')]:
   body=rolling.split('fn '+fn+'(',1)[1].split('\n    }',1)[0]
   self.assertIn('.and_then(|capture| capture.'+method+')',body)
def load_tests(loader,tests,pattern):
 historical=load('scope_historical_tests',ROOT/'scripts/ci-synthetic-output-tests.py')
 for cls in (historical.DurableDeliveryOutputTests,historical.DurableDeliveryRetainedExporterOutputTests):tests.addTests(loader.loadTestsFromTestCase(cls))
 for name in ('test_projection_does_not_search_inside_private_text','test_oversized_physical_line_never_promotes_its_marker_suffix'):
  tests.addTest(historical.PublicOutputTests(name))
 return tests
if __name__=='__main__':unittest.main()
