"""PRIVATE proof-only option. No downloads, extraction, execution or CI activation.

Caller must acquire metadata and reviewed pins from authenticated GitHub API and
original producer logs, not from an artifact's own claims. No current-run reuse
claim is possible until actual artifact ID/archive/bundle hashes are pinned.
"""
import hashlib
import importlib.util
import pathlib
import subprocess
import os
import stat
import zipfile

HERE=pathlib.Path(__file__).resolve().parent
PARSER_SHA='c6d12ee5a132083ee97f5aee7fcda3b3dc270a794b90d3d65e18b271c3426682'
# Source-bound callback executes verified parser bytes without bytecode.
assert hashlib.sha256((HERE/'producer_artifacts.py').read_bytes()).hexdigest()==PARSER_SHA
A=_reviewed_parser()
QUALIFICATION_PROFILE='coordinated-financial-rendered-host-semantic-v1'
POLICY='p32-crate-local-cfg-reuse-v2'

PRODUCER=dict(repository='stanleykosi/pactloom',source='53a05883325fad2ee66886adea5cf67d34b7600b',
 source_tree='559d863aa9b42239f6585f9a92d3160052f1a456',run_id=39896992026,attempt=1)
JOB_ID=120229616977
# Exact existing runtime files, NOT a suffix/directory exclusion. Contract,
# output projection, fixture profile/scenario, image and orchestration are fixed.
# Original eight paths unchanged. Only the exact two-file P33 diagnostic annex is accepted.
RUNTIME_ONLY=frozenset((
 'scripts/ci-financial-container.py',
 'scripts/ci-financial-fixture.py',
 'scripts/ci-financial-flow.py',
 'scripts/ci-financial-observer.py',
 'scripts/ci-financial-controller.py',
 'scripts/ci-financial-external-operator.py',
 'scripts/tests/test_ci_financial_observer.py',
 'scripts/tests/test_ci_financial_fixture_diagnostics.py',
))


DIAGNOSTIC_COMPATIBILITY={'version': 1, 'name': 'p33-exact-input-budget-diagnostics-v1', 'files': {'scripts/ci-financial-contract.py': {'producer_git_blob': '1d5fb517546e188f4b79a0d0d4ea5b24094c7920', 'producer_sha256': 'f33248f7e0b2b9690ce1a51580f7dc2739632154b09978e65f21375cd67b5b8e', 'producer_mode': '100644', 'producer_mode_sha256': '3c2a63ebedc9474df32bcf779c377780ae6832448fcc85334aeab8bf2a4a92a2', 'harness_git_blob': 'f09c0a2bd451a67a697299ceacd65e4b3219acdb', 'harness_sha256': 'f596d32a62f66736aa46cc36b156545af3b0a2b21f6a80e04de8a24458aef97e', 'harness_mode': '100644', 'harness_mode_sha256': 'c54d4419942fd87ec69036347bb0668b308643399f68129fcfa8952487313b07'}, 'scripts/ci-financial-supervisor.py': {'producer_git_blob': '19eaf548f5e60f5cbafb5220e004ce32aec16ffe', 'producer_sha256': '69fb9e10ae160f930a558ae499fe0a35bf40f422ea8111e1abc3c6c37b32f2ac', 'producer_mode': '100644', 'producer_mode_sha256': '37e1a0cd930e2220d4598460fbb53195fbbc82563c1a9cf0d4f87d1fa7c19faa', 'harness_git_blob': 'f40fe647fd629a334818db3309792aa0aa9a4fed', 'harness_sha256': '2b251c9f0bcce7a227d7e7f37f2a7a51c049f6b0e30e36ee3c11adce19c6dce0', 'harness_mode': '100644', 'harness_mode_sha256': '94ed576bb1569ef2ecd418aaf3094299111bf1fac2379bc1543b9fe2806eec4b'}}}

def require(ok,reason):
    if not ok:raise A.Rejected(reason)


def inventory_checkout(root,commit):
    """Must be independently run on both exact clean Git checkouts."""
    root=pathlib.Path(root).resolve()
    def git(*args):return subprocess.check_output(['git','-C',str(root),*args],
        env={'PATH':os.environ['PATH'],'HOME':'/nonexistent','GIT_CONFIG_NOSYSTEM':'1',
             'GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0'})
    require(A.COMMIT.fullmatch(commit) is not None,'commit')
    require(git('rev-parse','HEAD').strip().decode()==commit,'checkout_commit')
    require(git('status','--porcelain','--untracked-files=all')==b'','dirty_checkout')
    # A -B interpreter can still READ stale bytecode. Refuse ignored extras in
    # all execution sources, so H's unchanged import helpers cannot read one.
    require(git('ls-files','--others','--ignored','--exclude-standard','-z')==b'','ignored_checkout_input')
    tree=git('rev-parse','HEAD^{tree}').strip().decode()
    result={}
    for row in git('ls-tree','-rz','--full-tree','HEAD').split(b'\0'):
        if not row:continue
        fields,path=row.split(b'\t',1);mode,kind,oid=fields.split(b' ')
        require(mode in (b'100644',b'100755') and kind==b'blob','source_kind')
        name=path.decode('ascii');A.closure({name:'0'*64})
        # Read the tracked Git blob, bind its declared mode, compare working bytes.
        data=git('cat-file','blob',oid.decode())
        local=root/name
        require(not local.is_symlink() and local.is_file() and local.read_bytes()==data
            and stat.S_IMODE(local.stat().st_mode)==(int(mode,8)&0o777),'source_bytes')
        result[name]=hashlib.sha256(mode+b'\0'+data).hexdigest()
    A.closure(result)
    return tree,result


def validate_diagnostic_compatibility(annex):
    require(type(annex) is dict and set(annex)=={'version','name','files'},'diagnostic_annex_schema')
    require(type(annex['version']) is int and annex['version']==1 and type(annex['name']) is str,'diagnostic_annex_type')
    require(type(annex['files']) is dict and set(annex['files'])==set(DIAGNOSTIC_COMPATIBILITY['files']),'diagnostic_annex_paths')
    for path,pair in annex['files'].items():
        require(type(pair) is dict and set(pair)==set(DIAGNOSTIC_COMPATIBILITY['files'][path]),'diagnostic_annex_pair')
        require(all(type(v) is str for v in pair.values()),'diagnostic_annex_type')
    require(annex==DIAGNOSTIC_COMPATIBILITY,'diagnostic_annex_pin')
    return annex


def equivalent(producer,current,diagnostic_compatibility=None):
    A.closure(producer);A.closure(current)
    require(set(producer)==set(current),'tracked_path_set')
    changed=sorted(name for name in producer if producer[name]!=current[name])
    exceptions=set()
    if diagnostic_compatibility is not None:
        annex=validate_diagnostic_compatibility(diagnostic_compatibility)
        for path,pair in annex['files'].items():
            require(path in changed and producer.get(path)==pair['producer_mode_sha256']
                and current.get(path)==pair['harness_mode_sha256'],'diagnostic_annex_source')
            exceptions.add(path)
    require(set(changed)<=RUNTIME_ONLY|exceptions,'native_or_unreviewed_input_changed')
    return changed


def archive_digest(archive,pins):
    archive=pathlib.Path(archive)
    require(archive.is_file() and not archive.is_symlink(),'archive_file')
    require(0<archive.stat().st_size<=A.MAX_TOTAL+A.MAX_MANIFEST+1024*1024,'archive_size')
    with archive.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    require(digest==pins['archive_sha256'],'archive_digest')
    with zipfile.ZipFile(archive) as zipped:
        entries=zipped.infolist()
        require(len(entries)==1 and entries[0].filename=='build.tar' and not entries[0].is_dir()
            and entries[0].file_size<=A.MAX_TOTAL+A.MAX_MANIFEST+65536,'zip_entries')
        with zipped.open(entries[0]) as stream:tar_digest=hashlib.file_digest(stream,'sha256').hexdigest()
        require(tar_digest==pins['bundle_sha256'],'zip_bundle_digest')
    return digest


def qualify(bundle,archive,pins,run,artifact,producer_inventory,current_inventory,harness,diagnostic_compatibility=None,*,binding=None,job=None):
    """Pins are independently reviewed API/log facts; never manifest-supplied.

    ZIP must contain exactly build.tar with independently pinned bytes.
    Both archive and TAR are checked; no extraction or execution occurs.
    """
    validate_binding(binding)
    require(diagnostic_compatibility==binding['diagnostic_compatibility'],'diagnostic_binding')
    require(harness==binding['harness'],'harness_binding')
    authenticate_metadata(run,artifact,job)
    require(pins==ARTIFACT_PINS,'exact_artifact_pins')
    require(hashlib.sha256(A.canonical(producer_inventory)).hexdigest()==SOURCE_INVENTORY_SHA,'producer_inventory_pin')
    require(type(pins) is dict and set(pins)=={'artifact_id','archive_sha256','bundle_sha256'},'pin_set')
    require(type(pins['artifact_id']) is int and pins['artifact_id']>0,'artifact_pin')
    for key in ('archive_sha256','bundle_sha256'):
        require(type(pins[key]) is str and A.SHA.fullmatch(pins[key]) is not None,'digest_pin')
    archive_digest(archive,pins)
    require(run.get('id')==PRODUCER['run_id'] and type(run.get('id')) is int
        and run.get('run_attempt')==1 and type(run.get('run_attempt')) is int
        and run.get('head_sha')==PRODUCER['source']
        and run.get('head_branch')=='qualification/durable-proposal-v1'
        and run.get('event')=='push' and run.get('status')=='completed'
        and run.get('path')=='.github/workflows/durable-native-linux.yml'
        and run.get('repository',{}).get('full_name')==PRODUCER['repository'],'producer_run')
    # A runtime-failed job is expected and does not invalidate its pre-fixture build.
    require(run.get('conclusion') in ('failure','success'),'producer_terminal')
    name='financial-build-39896992026-1-'+PRODUCER['source']
    origin=artifact.get('workflow_run',{})
    require(artifact.get('id')==pins['artifact_id'] and type(artifact.get('id')) is int
        and artifact.get('name')==name and artifact.get('expired') is False
        and origin.get('id')==PRODUCER['run_id'] and type(origin.get('id')) is int
        and origin.get('head_sha')==PRODUCER['source']
        and artifact.get('digest')=='sha256:'+pins['archive_sha256'],'artifact_origin')
    with pathlib.Path(bundle).open('rb') as stream:bundle_digest=hashlib.file_digest(stream,'sha256').hexdigest()
    require(bundle_digest==pins['bundle_sha256'],'bundle_digest')
    # Original full closure stays exact, including all old runtime files.
    original=A.verify_bundle(bundle,PRODUCER,producer_inventory,QUALIFICATION_PROFILE)
    require(type(harness) is dict and set(harness)=={'repository','source','source_tree'},'harness_identity')
    require(harness['repository']==PRODUCER['repository'] and
        A.COMMIT.fullmatch(harness['source']) is not None and
        A.COMMIT.fullmatch(harness['source_tree']) is not None,'harness_identity')
    changes=equivalent(producer_inventory,current_inventory,diagnostic_compatibility)
    require({name:current_inventory[name] for name in changes if name in RUNTIME_ONLY}==binding['reviewed_runtime_changes'],'reviewed_changes_binding')
    require(not changes or (harness['source']!=PRODUCER['source'] and
        harness['source_tree']!=PRODUCER['source_tree']),'contradictory_harness_identity')
    evidence=dict(schema=6,policy=POLICY,qualification_profile=QUALIFICATION_PROFILE,native_producer=PRODUCER.copy(),harness=harness.copy(),
        original_manifest=original,current_source_inventory=current_inventory.copy(),
        permitted_runtime_changes=[name for name in changes if name in RUNTIME_ONLY],
        permitted_diagnostic_changes=[name for name in changes if name not in RUNTIME_ONLY],artifact_pins=pins.copy(),
        native_binaries_reused=True,native_binaries_freshly_compiled=False,
        runtime_verified=False,synthetic_full_native_verified=False,
        public_chain_verified=False,dispatch_requested=False)
    if diagnostic_compatibility is not None:evidence['diagnostic_compatibility']=diagnostic_compatibility.copy()
    return evidence

ARTIFACT_PINS={'archive_sha256': '0b158864d3fce1ced7fc2fea83f60de9acc7492a408e869cb34f369a57ce11f3', 'artifact_id': 12478314302, 'bundle_sha256': 'b9879f8d296f8871a38c647585a05fd533268de28082061ad7c00c87235a23f9'}
API_PINS={'artifact': 'a58c518bd520ce0e8c5a8eda235046b3cc4bb8797f9435b32de3e808ef16dd27', 'job': '1c90c60a502040068dae78374a62da1f3aa4dae985c4fdd2fa198ae149b5bb96', 'run': '0d1486278632939d4980d90e5dec68ea83e9a3e02e5911514c010a9034b6e5c9'}
SOURCE_INVENTORY_SHA='d94c8f37f5c83af4b54d3aa36d7e39f41e4c2ceebd72cd936ec8101134e80fa2'


def authenticate_metadata(run,artifact,job):
    for name,value in [('run',run),('artifact',artifact),('job',job)]:
        require(type(value) is dict and hashlib.sha256(A.canonical(value)).hexdigest()==API_PINS[name],'api_custody_'+name)
    require(artifact['node_id']=='MDg6QXJ0aWZhY3QxMjQ3ODMxNDMwMg==','artifact_node')
    require(run['head_commit']['tree_id']==PRODUCER['source_tree'],'producer_tree')
    require(job['id']==JOB_ID and job['run_id']==PRODUCER['run_id'],'producer_job')
    for name in ('Preserve exact credential-free compiled financial bundle','Verify financial containers, temporary images and build cache removed'):
        rows=[s for s in job['steps'] if s['name']==name]
        require(len(rows)==1 and rows[0]['conclusion']=='success','producer_step')


def validate_binding(plan):
    keys={'version','policy','qualification_profile','manifest_version','build_recipe_version','producer','harness','artifact_pins','api_pins','producer_inventory_sha256','parser_sha256','reviewed_runtime_changes','diagnostic_compatibility'}
    require(type(plan) is dict and set(plan)==keys,'binding_schema')
    require(type(plan['version']) is int and plan['version']==6 and plan['policy']==POLICY,'binding_policy')
    require(type(plan['manifest_version']) is int and plan['manifest_version']==2 and type(plan['build_recipe_version']) is int and plan['build_recipe_version']==2,'recipe_version')
    require(plan['qualification_profile']==QUALIFICATION_PROFILE and type(plan['producer']) is dict and A.canonical(plan['producer'])==A.canonical(PRODUCER),'binding_producer')
    require(plan['artifact_pins']==ARTIFACT_PINS and plan['api_pins']==API_PINS and plan['producer_inventory_sha256']==SOURCE_INVENTORY_SHA and plan['parser_sha256']==PARSER_SHA,'binding_pins')
    validate_diagnostic_compatibility(plan['diagnostic_compatibility'])
    h=plan['harness']
    require(type(h) is dict and set(h)=={'repository','source','source_tree'} and h['repository']==PRODUCER['repository'] and all(type(h[k]) is str and A.COMMIT.fullmatch(h[k]) for k in ('source','source_tree')),'harness_unbound')
    changes=plan['reviewed_runtime_changes'];A.closure(changes)
    require(set(changes)<=RUNTIME_ONLY,'reviewed_change_set')
    return plan
