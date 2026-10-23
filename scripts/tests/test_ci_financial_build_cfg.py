"""Pure cfg/provenance regressions: no Cargo, network, native fixture or sockets."""
import copy
import importlib.util
import itertools
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
S=load('cfg_supervisor',ROOT/'ci-financial-supervisor.py');A=S.A
LEGACY=load('cfg_legacy_artifacts',ROOT/'financial-runtime-reuse/producer_artifacts.py')


class BuildCfgTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.target=pathlib.Path(self.tmp.name)/'target';self.target.mkdir()

    def records(self,name='coordinator-observed',profile=A.SEMANTIC_PROFILE):
        delivery=A.recipe(profile)['cfg_delivery'];rows=[]
        for crate in delivery['artifact_script_crates'][name]:
            out=self.target/crate/'out';out.mkdir(parents=True,exist_ok=True)
            package='path+file:///exact/'+crate+'#'+crate+'@0.1.0'
            rows.extend([
                dict(reason='compiler-artifact',package_id=package,
                    manifest_path=str(S.REPO/'crates'/crate/'Cargo.toml'),fresh=True,
                    target=dict(kind=['custom-build'],name='build-script-build',src_path=str(S.REPO/'crates'/crate/'build.rs'))),
                dict(reason='build-script-executed',package_id=package,cfgs=delivery['effective_cfgs'][name],
                    linked_libs=[],linked_paths=[],env=[],out_dir=str(out))])
        return rows

    def validate(self,rows,name='coordinator-observed',profile=A.SEMANTIC_PROFILE):
        return S.validate_compiler_cfg(b'\n'.join(json.dumps(row).encode() for row in rows),name,self.target,profile)

    def test_all_three_artifact_closures_both_profiles(self):
        for name,profile in itertools.product(A.NAMES,(A.PIXEL_PROFILE,A.SEMANTIC_PROFILE)):
            rows=self.records(name,profile);self.validate(rows,name,profile)
            self.assertEqual(len(rows),2 if name=='pristine-setup' else 6)
        self.assertEqual(A.SCRIPT_SCOPES['pristine-setup'],['wholepact-native-host'])

    def test_transition_environments_reset_without_global_flags(self):
        choices=list(itertools.product(A.NAMES,(A.PIXEL_PROFILE,A.SEMANTIC_PROFILE)))
        for first,second in itertools.product(choices,choices):
            before=S.select_build_environment({'PATH':'/usr/bin'},*first);snapshot=dict(before)
            after=S.select_build_environment(before,*second)
            self.assertEqual(before,snapshot)
            self.assertEqual(after[A.MODE_ENV],A.recipe(second[1])['cfg_delivery']['artifact_modes'][second[0]])
            self.assertNotIn('RUSTFLAGS',after);self.assertNotIn('CARGO_ENCODED_RUSTFLAGS',after)
        for env in ({'RUSTFLAGS':''},{'CARGO_ENCODED_RUSTFLAGS':''},{A.MODE_ENV:'invalid'},{'PATH':1},{'PRIVATE_TOKEN':'x'}):
            with self.assertRaises(S.Failure):S.select_build_environment(env,A.NAMES[0],A.PIXEL_PROFILE)

    def test_missing_duplicate_wrong_package_or_path_is_rejected(self):
        good=self.records()
        variants=[good[1:],good[:-1],good+[good[0]],good+[good[1]]]
        for key,value in [('package_id','other'),('manifest_path','/wrong/Cargo.toml')]:
            rows=copy.deepcopy(good);rows[0][key]=value;variants.append(rows)
        for key,value in [('src_path','/wrong/build.rs'),('kind',['lib']),('name','other')]:
            rows=copy.deepcopy(good);rows[0]['target'][key]=value;variants.append(rows)
        for rows in variants:
            with self.assertRaises(S.Failure):self.validate(rows)

    def test_changed_cfgs_or_side_effects_or_output_escape_rejected(self):
        for key,value in [('cfgs',[]),('cfgs',list(reversed(A.FINANCIAL_CFGS))),('cfgs',['wholepact_financial_ci="x"']),
                          ('linked_libs',['other']),('linked_paths',['/tmp']),('env',[['TOKEN','value']]),
                          ('out_dir','/tmp'),('out_dir',[]),('package_id',[]),('cfgs',[1])]:
            rows=self.records();rows[1][key]=value
            with self.assertRaises(S.Failure):self.validate(rows)

    def test_out_of_scope_financial_cfg_rejected(self):
        rows=self.records();foreign=copy.deepcopy(rows[1]);foreign['package_id']='unapproved'
        with self.assertRaises(S.Failure):self.validate(rows+[foreign])
        foreign['cfgs']=['ordinary_cfg'];self.validate(rows+[foreign])
        # The setup graph must not silently grow a coordinator script.
        with self.assertRaises(S.Failure):self.validate(self.records(), 'pristine-setup')

    def test_unknown_source_local_build_script_rejected(self):
        rows=self.records();foreign=copy.deepcopy(rows[0]);foreign['package_id']='unknown-local'
        foreign['manifest_path']=str(S.REPO/'crates/unreviewed/Cargo.toml')
        foreign['target']['src_path']=str(S.REPO/'crates/unreviewed/build.rs')
        with self.assertRaises(S.Failure):self.validate(rows+[foreign])

    def test_duplicate_cfg_identifier_rejected(self):
        rows=self.records();rows[1]['cfgs']=list(A.FINANCIAL_CFGS)+[A.FINANCIAL_CFGS[0]]
        with self.assertRaises(S.Failure):self.validate(rows)

    def test_production_and_setup_cannot_accept_observed_cfgs(self):
        for name in ('coordinator-production','pristine-setup'):
            rows=self.records(name);rows[1]['cfgs']=list(A.FINANCIAL_CFGS)
            with self.assertRaises(S.Failure):self.validate(rows,name)

    def test_scoped_scripts_are_identical_explicit_and_source_complete(self):
        raw=[(S.REPO/path).read_bytes() for path in A.BUILD_SCRIPTS]
        self.assertTrue(all(item==raw[0] for item in raw))
        for crate in A.CFG_CRATES:
            self.assertIn('build = "build.rs"',(S.REPO/'crates'/crate/'Cargo.toml').read_text())
        consumers=set()
        for path in (S.REPO/'crates').rglob('*.rs'):
            if path.name!='build.rs' and any(cfg in path.read_text() for cfg in A.FINANCIAL_CFGS):
                consumers.add(path.relative_to(S.REPO/'crates').parts[0])
        self.assertEqual(consumers,set(A.CFG_CRATES))

    def test_v2_recipe_and_legacy_bundle_are_not_interchangeable(self):
        from test_ci_financial_artifacts import IDENTITY,CLOSURE
        inputs=pathlib.Path(self.tmp.name)/'inputs';inputs.mkdir()
        for name in A.NAMES:(inputs/name).write_bytes(b'\x7fELFfabricated never executable')
        new=pathlib.Path(self.tmp.name)/'new.tar';old=pathlib.Path(self.tmp.name)/'old.tar'
        value=A.export_bundle(inputs,new,IDENTITY,CLOSURE)
        self.assertEqual(value['version'],2)
        LEGACY.export_bundle(inputs,old,IDENTITY,CLOSURE)
        with self.assertRaises(A.Rejected):A.verify_bundle(old,IDENTITY,CLOSURE)
        with self.assertRaises(LEGACY.Rejected):LEGACY.verify_bundle(new,IDENTITY,CLOSURE)
        changed=copy.deepcopy(value);changed['version']=1
        with self.assertRaises(A.Rejected):A.validate_manifest(changed,IDENTITY,CLOSURE)
        changed=copy.deepcopy(value);changed['recipe']=LEGACY.RECIPE
        with self.assertRaises(A.Rejected):A.validate_manifest(changed,IDENTITY,CLOSURE)

    def test_v2_cfg_recipe_and_script_closure_are_exact(self):
        from test_ci_financial_artifacts import IDENTITY,CLOSURE
        value=dict(version=2,identity=IDENTITY,closure=CLOSURE,recipe=A.recipe(A.PIXEL_PROFILE),
            files={name:dict(size=4,sha256='a'*64) for name in A.NAMES})
        A.validate_manifest(value,IDENTITY,CLOSURE)
        for key,val in [('mechanism','other'),('mode_environment','OTHER'),('build_scripts',[]),
                        ('artifact_script_crates',{}),('artifact_modes',{}),('effective_cfgs',{}),
                        ('global_financial_cfgs_permitted',True)]:
            bad=copy.deepcopy(value);bad['recipe']['cfg_delivery'][key]=val
            with self.assertRaises(A.Rejected):A.validate_manifest(bad,IDENTITY,CLOSURE)
        for version in (1,True,'2'):
            bad=copy.deepcopy(value);bad['version']=version
            with self.assertRaises(A.Rejected):A.validate_manifest(bad,IDENTITY,CLOSURE)
        missing={key:val for key,val in CLOSURE.items() if key not in A.BUILD_SCRIPTS}
        bad=copy.deepcopy(value);bad['closure']=missing
        with self.assertRaises(A.Rejected):A.validate_manifest(bad,IDENTITY,missing)
        for path in A.BUILD_SCRIPTS:
            bad=copy.deepcopy(value);bad['closure'][path]='d'*64
            with self.assertRaises(A.Rejected):A.validate_manifest(bad,IDENTITY,CLOSURE)


if __name__=='__main__':unittest.main()
