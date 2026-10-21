#!/usr/bin/env python3
"""Fabricated API/source records only. No requests, binaries or native calls."""
import copy
import importlib.util
import pathlib
import unittest
spec = importlib.util.spec_from_file_location('ui_reuse', pathlib.Path(__file__).parents[1] / 'ci-ui-reuse.py')
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
PIN = dict(version=1,repository=R.REPOSITORY,source='a'*40,source_tree='b'*40,
           run_id=10,attempt=2,job_id=20,artifact_id=30,archive_sha256='c'*64,bundle_sha256='d'*64)

def records():
    repo = dict(full_name=R.REPOSITORY,id=100)
    run = dict(id=10,run_attempt=2,head_sha='a'*40,head_branch=R.BRANCH,event='push',status='completed',
               path=R.WORKFLOW,repository=repo,head_repository=repo,conclusion='failure')
    job = dict(id=20,run_id=10,run_attempt=2,head_sha='a'*40,name='synthetic-only',status='completed',
               steps=[dict(name=R.UPLOAD_STEP,status='completed',conclusion='success')],conclusion='failure')
    artifact = dict(id=30,name='ui-build-10-2-'+ 'a'*40,expired=False,size_in_bytes=100,
                    digest='sha256:'+'c'*64,workflow_run=dict(id=10,head_sha='a'*40,head_branch=R.BRANCH,
                                                           repository_id=100,head_repository_id=100))
    return run,job,artifact

class Provenance(unittest.TestCase):
    def test_failed_runtime_does_not_discard_successful_exact_build_upload(self):
        self.assertEqual(R.validate_provenance(PIN,*records(),'b'*40)['attempt'],2)

    def test_wrong_repository_source_attempt_branch_and_event_refused(self):
        for key,value in [('id',11),('run_attempt',1),('event','pull_request'),('head_sha','e'*40),
                          ('head_branch','main'),('status','in_progress'),('path','other.yml')]:
            run,job,artifact=records();run[key]=value
            with self.assertRaises(R.Rejected):R.validate_provenance(PIN,run,job,artifact,'b'*40)
        run,job,artifact=records();run['head_repository']=dict(full_name='fork/repo',id=101)
        with self.assertRaises(R.Rejected):R.validate_provenance(PIN,run,job,artifact,'b'*40)

    def test_upload_and_artifact_are_exact(self):
        for key,value in [('id',31),('expired',True),('expired',0),('digest','sha256:'+'e'*64),
                          ('name','latest'),('size_in_bytes',True)]:
            run,job,artifact=records();artifact[key]=value
            with self.assertRaises(R.Rejected):R.validate_provenance(PIN,run,job,artifact,'b'*40)
        for conclusion in ('failure','skipped',None):
            run,job,artifact=records();job['steps'][0]['conclusion']=conclusion
            with self.assertRaises(R.Rejected):R.validate_provenance(PIN,run,job,artifact,'b'*40)
        run,job,artifact=records();job['steps']*=2
        with self.assertRaises(R.Rejected):R.validate_provenance(PIN,run,job,artifact,'b'*40)

    def test_pin_requires_explicit_identity_and_digests(self):
        for key in PIN:
            pin=dict(PIN);del pin[key]
            with self.assertRaises(R.Rejected):R.validate_pin(pin)
        with self.assertRaises(R.Rejected):R.validate_pin({**PIN,'attempt':True})

    def test_closure_only_allows_named_runtime_files(self):
        base={name:'a'*64 for name in ('Cargo.lock','Cargo.toml','scripts/ci-ui-supervisor.py','crates/x/src/lib.rs')}
        self.assertEqual(R.validate_closure(base,base),[])
        changed={**base,'scripts/ci-ui-output.py':'b'*64}
        self.assertEqual(R.validate_closure(base,changed),['scripts/ci-ui-output.py'])
        for path in base:
            with self.assertRaises(R.Rejected):R.validate_closure(base,{**base,path:'b'*64})
        for path in ('crates/x/build.rs','scripts/encrypted-storage-env.sh','scripts/new.py'):
            with self.assertRaises(R.Rejected):R.validate_closure(base,{**base,path:'b'*64})
        missing=dict(base);del missing['Cargo.toml']
        with self.assertRaises(R.Rejected):R.validate_closure(base,missing)

if __name__=='__main__':unittest.main()
