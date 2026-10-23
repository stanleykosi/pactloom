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
POLICY='p40-crate-local-cfg-reuse-v2'

PRODUCER=dict(repository='stanleykosi/pactloom',source='99501f5853a4516fc94a6361f39cb4373048f01f',
 source_tree='82ce41c35e40b259f7237efc534768fc889782db',run_id=39928103023,attempt=1)
JOB_ID=120329364170
# Exact existing runtime files, NOT a suffix/directory exclusion. Contract,
# output projection, fixture profile/scenario, image and orchestration are fixed.
# Original eight paths unchanged. No diagnostics annex is reviewed for P40.
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


def equivalent(producer,current,diagnostic_compatibility=None):
    A.closure(producer);A.closure(current)
    require(set(producer)==set(current),'tracked_path_set')
    changed=sorted(name for name in producer if producer[name]!=current[name])
    require(diagnostic_compatibility is None,'diagnostic_annex_not_reviewed')
    require(set(changed)<=RUNTIME_ONLY,'native_or_unreviewed_input_changed')
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
    name='financial-build-39928103023-1-'+PRODUCER['source']
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

ARTIFACT_PINS={'archive_sha256': '84bd634ca6b1560958e21f2bfc41849dd12265c98d3d55dfaa6cee645b2f500c', 'artifact_id': 12491706804, 'bundle_sha256': '76c38bfe548b5e49933d4b2ded10a351de205b531d50ecf21b59a620faf33b7f'}
API_PINS={'artifact': 'b0ef215a12449f6cc8fd54795c8868f7dbafec02fcd32aa9867101994a1b3154', 'job': 'de3af51065dc8bac72f46cfcad430fd36a4104631dd99a69a4e44eac0c0e766a', 'run': '3c97285ed104bb52550eb2fff3f5389602a9a65515c40cdb05c78a0b3e01e904'}
SOURCE_INVENTORY_SHA='f063e53d8a5ebd607ffcbbdb28d6e108eb481e90c0d8967c8c3dbc0578b67491'


def authenticate_metadata(run,artifact,job):
    for name,value in [('run',run),('artifact',artifact),('job',job)]:
        require(type(value) is dict and hashlib.sha256(A.canonical(value)).hexdigest()==API_PINS[name],'api_custody_'+name)
    require(artifact['node_id']=='MDg6QXJ0aWZhY3QxMjQ5MTcwNjgwNA==','artifact_node')
    require(run['head_commit']['tree_id']==PRODUCER['source_tree'],'producer_tree')
    require(job['id']==JOB_ID and job['run_id']==PRODUCER['run_id'],'producer_job')
    for name in ('Preserve exact credential-free compiled financial bundle','Verify financial containers, temporary images and build cache removed'):
        rows=[s for s in job['steps'] if s['name']==name]
        require(len(rows)==1 and rows[0]['conclusion']=='success','producer_step')


def validate_binding(plan):
    keys={'version','policy','qualification_profile','manifest_version','build_recipe_version','producer','harness','artifact_pins','api_pins','producer_inventory_sha256','parser_sha256','reviewed_runtime_changes'}
    require(type(plan) is dict and set(plan)==keys,'binding_schema')
    require(type(plan['version']) is int and plan['version']==6 and plan['policy']==POLICY,'binding_policy')
    require(type(plan['manifest_version']) is int and plan['manifest_version']==2 and type(plan['build_recipe_version']) is int and plan['build_recipe_version']==2,'recipe_version')
    require(plan['qualification_profile']==QUALIFICATION_PROFILE and type(plan['producer']) is dict and A.canonical(plan['producer'])==A.canonical(PRODUCER),'binding_producer')
    require(plan['artifact_pins']==ARTIFACT_PINS and plan['api_pins']==API_PINS and plan['producer_inventory_sha256']==SOURCE_INVENTORY_SHA and plan['parser_sha256']==PARSER_SHA,'binding_pins')
    h=plan['harness']
    require(type(h) is dict and set(h)=={'repository','source','source_tree'} and h['repository']==PRODUCER['repository'] and all(type(h[k]) is str and A.COMMIT.fullmatch(h[k]) for k in ('source','source_tree')),'harness_unbound')
    changes=plan['reviewed_runtime_changes']
    require(type(changes) is dict,'reviewed_change_set')
    if changes:A.closure(changes)
    else:require(A.canonical(h)==A.canonical({k:PRODUCER[k] for k in ('repository','source','source_tree')}),'empty_delta_requires_producer_harness')
    require(set(changes)<=RUNTIME_ONLY,'reviewed_change_set')
    return plan
