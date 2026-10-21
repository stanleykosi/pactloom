"""Pure fabricated JSON projection tests; no product, socket, Docker or fixture."""
import copy
import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location('ci_ui_output', pathlib.Path(__file__).parents[1] / 'ci-ui-output.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def fixture_case(name):
    value = {key: True for key in P.FIXTURE_BOOL_KEYS}
    positive = int(name == 'append')
    value.update(name=name, product_exit=0, owned_roles=17, owned_reaps=16,
        original_account_histories=3, target_events=4+positive,
        unchanged_non_target_histories=2, exact_retained_request_appends=positive,
        native_arm_count=positive, native_admit_count=positive,
        w_final_admit_count=positive, authenticated_committed_count=positive,
        focus_out=name == 'blur', refocused=name == 'blur', no_reactivation=True)
    return value


def result(mode='fixture'):
    cases = [fixture_case(name) for name in P.CASES] if mode == 'fixture' else [
        dict(name='smoke', product_exit=0, surface_bound=True, frame_observed=True,
             natural_tree_drain=True)]
    return dict(schema_version=1, mode=mode, outcome='passed', first_failure=None,
                setup_elapsed_ms=12000, cases=cases, natural_empty=True)


class Projection(unittest.TestCase):
    def test_closed_positive_shapes(self):
        for mode in ('smoke', 'fixture'):
            self.assertEqual(P.validate_runtime_result(result(mode), mode), result(mode))

    def test_duplicate_json_refused(self):
        with self.assertRaises(P.Rejected) as got:
            P.loads(b'{"mode":"smoke","mode":"fixture"}')
        self.assertEqual(got.exception.code, 'duplicate_key')

    def test_nonfinite_json_refused(self):
        for value in (b'NaN', b'Infinity', b'-Infinity'):
            with self.assertRaises(P.Rejected): P.loads(value)

    def test_byte_limit_and_invalid_utf8(self):
        for raw in (b'"' + b'a' * 8192 + b'"', b'\xff'):
            with self.assertRaises(P.Rejected): P.loads(raw)

    def test_unknown_extra_and_raw_failure_values_refused(self):
        good = P.failure('fixture', 'prepare', 'source_failure', 'cancel')
        for key, value in (('code', '/private/key'), ('stage', []), ('delivery_stage', 'password')):
            bad = copy.deepcopy(good); bad[key] = value
            with self.assertRaises(P.Rejected): P.validate_failure(bad, 'fixture')
        good['raw'] = '/private/key'
        with self.assertRaises(P.Rejected): P.validate_failure(good, 'fixture')

    def test_source_pair_must_be_complete(self):
        with self.assertRaises(P.Rejected):
            P.failure('fixture', 'setup', 'setup_source', source_boundary='PristineOriginalHistory')

    def test_nonterminal_setup_labels_cannot_be_failures(self):
        for value in ('Begin', 'Complete', 'AuthorityInputEmpty', 'AuthorityInputWithinBound', 'AuthorityInputOverBound'):
            with self.assertRaises(P.Rejected):
                P.failure('fixture', 'setup', 'setup_source',
                    source_boundary='PristineOriginalHistory', source_outcome=value)

    def test_cannot_merge_independent_source_failures(self):
        with self.assertRaises(P.Rejected):
            P.failure('fixture', 'setup', 'setup_source', source_boundary='PristineOriginalHistory',
                source_outcome='AuthorityAuthentication', delivery_stage='TlsRequest',
                delivery_class='Authentication')

    def test_first_failure_survives_cleanup_and_late_measurement(self):
        value = result(); value.update(outcome='error', natural_empty=False,
            setup_elapsed_ms=900123, cases=[])
        first = P.failure('fixture', 'setup', 'setup_source',
            source_boundary='PristineOriginalHistory', source_outcome='AuthorityAuthentication')
        value['first_failure'] = first
        self.assertEqual(P.validate_runtime_result(value, 'fixture')['first_failure'], first)

    def test_unavailable_error_measurement_is_honest(self):
        value = result('smoke'); value.update(outcome='error', cases=[], setup_elapsed_ms=None,
            natural_empty=False, first_failure=P.failure('smoke', 'root', 'root_identity'))
        P.validate_runtime_result(value, 'smoke')

    def test_cleanup_failure_cannot_pass(self):
        value = result(); value['natural_empty'] = False
        with self.assertRaises(P.Rejected): P.validate_runtime_result(value, 'fixture')

    def test_cancel_cannot_contain_positive_action(self):
        for key in ('native_arm_count', 'native_admit_count', 'w_final_admit_count',
                    'authenticated_committed_count', 'exact_retained_request_appends'):
            value = result(); value['cases'][0][key] = 1
            with self.assertRaises(P.Rejected): P.validate_runtime_result(value, 'fixture')

    def test_positive_cannot_be_inferred_from_history_alone(self):
        for key in ('native_arm_count', 'native_admit_count', 'w_final_admit_count',
                    'authenticated_committed_count'):
            value = result(); value['cases'][2][key] = 0
            with self.assertRaises(P.Rejected): P.validate_runtime_result(value, 'fixture')

    def test_blur_requires_actual_out_refocus_and_no_reactivation(self):
        for key in ('focus_out', 'refocused', 'no_reactivation'):
            value = result(); value['cases'][1][key] = False
            with self.assertRaises(P.Rejected): P.validate_runtime_result(value, 'fixture')

    def test_exact_order_and_three_originals(self):
        value = result(); value['cases'].reverse()
        with self.assertRaises(P.Rejected): P.validate_runtime_result(value, 'fixture')
        for key, bad in (('owned_roles', 18), ('owned_reaps', 15),
                         ('original_account_histories', 4), ('unchanged_non_target_histories', 1)):
            value = result(); value['cases'][0][key] = bad
            with self.assertRaises(P.Rejected): P.validate_runtime_result(value, 'fixture')

    def test_bool_is_not_integer(self):
        value = result(); value['cases'][2]['native_admit_count'] = True
        with self.assertRaises(P.Rejected): P.validate_runtime_result(value, 'fixture')

    def test_shape_validation_does_not_claim_container_removal(self):
        value = result(); value['container_removed'] = True
        with self.assertRaises(P.Rejected): P.validate_runtime_result(value, 'fixture')


if __name__ == '__main__':
    unittest.main()
