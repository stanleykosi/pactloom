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
PARSER_SHA='53ae1125701112917530d45c04df18e785afa8e973a9d9b7d0de0a77a95dee50'
# Source-bound callback executes verified parser bytes without bytecode.
assert hashlib.sha256((HERE/'producer_artifacts.py').read_bytes()).hexdigest()==PARSER_SHA
A=_reviewed_parser()
QUALIFICATION_PROFILE='coordinated-financial-rendered-host-semantic-v1'
POLICY='p23-rendered-host-semantic-reuse-v1'

PRODUCER=dict(repository='stanleykosi/pactloom',source='a3b40f43db0f4fefbd7755e434708584351cbe46',
 source_tree='cb2635fe8983f4c040bc86cc9b3d1d5b58cb74b1',run_id=39847893540,attempt=1)
JOB_ID=120065963455
# Exact existing runtime files, NOT a suffix/directory exclusion. Contract,
# output projection, fixture profile/scenario, image and orchestration are fixed.
# The functional scenario exception requires the exact semantic v3 annex below.
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


# Separate reviewed functional Python transition exception; never part of the eight paths.
# Exact reviewed mode-bound blobs only; AST review is offline evidence, not policy.
TRANSITION_COMPATIBILITY={'version': 1, 'name': 'host-transition24-v1', 'path': 'scripts/ci-financial-scenario.py', 'producer_git_blob': 'c16c62df6e0c8e8efb2906a701db046ba5cdebd0', 'producer_sha256': '8810d9496fb7ff53b1e27872df8123f4240ccb46aa788794edf1aa1becc89ea3', 'producer_mode': '100644', 'producer_mode_sha256': 'eecd8b488dfdcf707a91ef0ad55ca5f51eb6de579a18d4b6c2bfc3a970f7814e', 'harness_git_blob': 'ce1b21e4323b5e14757c3bcab51a0d2958d518d6', 'harness_sha256': '6a2af05769f06ffe7328bc7cf35add437e061c8185cc9d9cf0d394a006330ba2', 'harness_mode': '100644', 'harness_mode_sha256': '5ca7671a7356542f7070964664e9fb042dde6a8162777c2fb6975286b00b0445'}

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


def validate_transition_compatibility(annex):
    require(type(annex) is dict and set(annex)==set(TRANSITION_COMPATIBILITY),
        'transition_annex_schema')
    require(type(annex['version']) is int and annex['version']==1,
        'transition_annex_version')
    for key in set(annex)-{'version'}:
        require(type(annex[key]) is str,'transition_annex_type')
    for side in ('producer','harness'):
        require(A.COMMIT.fullmatch(annex[side+'_git_blob']) is not None,'transition_annex_blob')
        require(annex[side+'_mode']=='100644','transition_annex_mode')
        for suffix in ('sha256','mode_sha256'):
            require(A.SHA.fullmatch(annex[side+'_'+suffix]) is not None,'transition_annex_digest')
    require(annex==TRANSITION_COMPATIBILITY,'transition_annex_pin')
    return annex


def equivalent(producer,current,transition_compatibility=None):
    A.closure(producer);A.closure(current)
    require(set(producer)==set(current),'tracked_path_set')
    changed=sorted(name for name in producer if producer[name]!=current[name])
    exceptions=set()
    if transition_compatibility is not None:
        annex=validate_transition_compatibility(transition_compatibility)
        path=annex['path']
        require(path in changed and producer.get(path)==annex['producer_mode_sha256']
            and current.get(path)==annex['harness_mode_sha256'],'transition_annex_source')
        exceptions.add(path)
    require(set(changed)<=RUNTIME_ONLY|exceptions,'native_or_unreviewed_input_changed')
    # Empty change is valid; it does not imply runtime acceptance.
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


def qualify(bundle,archive,pins,run,artifact,producer_inventory,current_inventory,harness,transition_compatibility=None):
    """Pins are independently reviewed API/log facts; never manifest-supplied.

    ZIP must contain exactly build.tar with independently pinned bytes.
    Both archive and TAR are checked; no extraction or execution occurs.
    """
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
    name='financial-build-39847893540-1-'+PRODUCER['source']
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
    changes=equivalent(producer_inventory,current_inventory,transition_compatibility)
    require(not changes or (harness['source']!=PRODUCER['source'] and
        harness['source_tree']!=PRODUCER['source_tree']),'contradictory_harness_identity')
    evidence=dict(schema=3,policy=POLICY,qualification_profile=QUALIFICATION_PROFILE,native_producer=PRODUCER.copy(),harness=harness.copy(),
        original_manifest=original,current_source_inventory=current_inventory.copy(),
        permitted_runtime_changes=[name for name in changes if name in RUNTIME_ONLY],artifact_pins=pins.copy(),
        native_binaries_reused=True,native_binaries_freshly_compiled=False,
        runtime_verified=False,synthetic_full_native_verified=False,
        public_chain_verified=False,dispatch_requested=False)
    if transition_compatibility is not None:
        evidence['transition_compatibility']=transition_compatibility.copy()
    return evidence
