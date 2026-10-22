#!/usr/bin/env python3
"""Stage one exact offline financial image context; never execute Docker/Cargo.

The caller owns the authorized CI gate and exact source/artifact provenance.
All packages and private Weston headers are individually pinned before staging.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import sys
import time

ROOT=pathlib.Path(__file__).resolve().parent

def load(name):
    key=name.replace('-','_');spec=importlib.util.spec_from_file_location(key,ROOT/(name+'.py'))
    module=importlib.util.module_from_spec(spec);sys.modules[key]=module;spec.loader.exec_module(module);return module
B=load('ci-ui-image');O=load('ci-financial-ocr-image')
BASE_IMAGE=B.BASE_IMAGE
ARTIFACT_FILES=('coordinator-production','coordinator-observed','pristine-setup')
MODULE_SOURCE='ci-financial-weston-module.c'
MODULE_BINARY='ci-financial-weston-module.so'
IMAGE_ROOT='/opt/ci-financial'

def literal(path,name):
    for node in ast.parse(path.read_text()).body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in node.targets):
            return ast.literal_eval(node.value)
    raise B.Rejected('manifest')

def runtime_files():
    names=literal(ROOT/'ci-financial-container.py','RUNTIME_FILES')
    B._require(type(names) is tuple and MODULE_BINARY in names and len(names)==len(set(names)),'input_allowlist')
    B._require(all(type(n) is str and re.fullmatch(r'ci-financial-[a-z-]+\.(py|so)',n) for n in names),'input_allowlist')
    return tuple(n for n in names if n!=MODULE_BINARY)

def profile():
    gate=(ROOT/'qualification-gate-mode').read_bytes()
    B._require(gate in (b'financial-ui\n',b'financial-semantic\n'),'qualification_gate')
    return literal(ROOT/'ci-financial-contract.py',
        'SEMANTIC_PROFILE' if gate==b'financial-semantic\n' else 'EXTERNAL_PROFILE')

def pin(raw):return {'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def metadata(base,ocr,pins,source_commit):
    B._require(re.fullmatch('[0-9a-f]{40}',source_commit) is not None,'source_commit')
    B._require(set(pins)==set(runtime_files())|set(ARTIFACT_FILES)|{MODULE_SOURCE},'input_allowlist')
    packages={r['name']:r for r in base['packages']}
    packages.update({r['name']:r for r in ocr['additional_packages']})
    runtime=set(base['closures']['runtime'])|set(ocr['ocr_closure'])
    return dict(base=B.expected_packages(base,'base'),build=B.expected_packages(base,'build'),
        runtime=O.expected_runtime_packages(ocr,base),
        packages={'build':[packages[n] for n in base['closures']['build'] if packages[n]['origin']!='pinned-base'],
                  'runtime':[packages[n] for n in sorted(runtime) if packages[n]['origin']!='pinned-base']},
        inputs=pins,headers={n:dict(size=s,sha256=h) for n,(s,h) in B.PRIVATE_HEADERS.items()},
        source_commit=source_commit,profile=profile(),ocr_executable=ocr['executable'])

def installer():
    # Preserve the already reviewed offline install, pinned-package audit,
    # process/service denial, ABI compiler and privilege-stripping program.
    script=B._INSTALL_SCRIPT.replace('/opt/ci-ui','/opt/ci-financial').replace('ci-ui-weston-module','ci-financial-weston-module')
    script=re.sub(r'^RUNTIME_FILES = .*$', 'RUNTIME_FILES = '+repr(runtime_files()),script,flags=re.M)
    script=script.replace("LOCK_SHA256 = '"+B.LOCK_SHA256+"'", "LOCK_SHA256 = '"+O.LOCK_SHA256+"'")
    start=script.index('def finalize(meta):');end=script.index('\ndef main():',start)
    script=script[:start]+_FINALIZE+script[end:]
    # The build inputs include the artifact pins in metadata but the artifacts
    # themselves are copied only in the terminal runtime stage.
    script=script.replace("need({p.name for p in pathlib.Path('/ci-inputs').iterdir()} == set(meta['inputs']), 'input_set')", "need({p.name for p in pathlib.Path('/ci-inputs').iterdir()} == set(RUNTIME_FILES) | {'ci-financial-weston-module.c'}, 'input_set')")
    script=script.replace("for name, pin in meta['inputs'].items():\n        verify(pathlib.Path('/ci-inputs') / name, pin)","for name in (*RUNTIME_FILES, 'ci-financial-weston-module.c'):\n        verify(pathlib.Path('/ci-inputs') / name, meta['inputs'][name])")
    return script

_FINALIZE=r'''def finalize(meta):
    global PHASE
    PHASE = 'manifest'
    need(installed() == meta['runtime'], 'installed_package_set')
    need(set(meta['inputs']) == set(RUNTIME_FILES) | set(ARTIFACT_FILES) | {'ci-financial-weston-module.c'}, 'input_set')
    path = ROOT / 'foundation-manifest.json'
    need(path.is_file() and not path.is_symlink(), 'input_file')
    foundation = json.loads(path.read_bytes())
    need(set(foundation) == {'schema_version','package_lock_sha256','files'} and
         foundation['schema_version'] == 1 and foundation['package_lock_sha256'] == LOCK_SHA256 and
         set(foundation['files']) == set(RUNTIME_FILES) | {'ci-financial-weston-module.so'}, 'manifest')
    files = foundation['files']
    for name, value in files.items():
        verify(ROOT / name, value)
        if name in RUNTIME_FILES:need(value == meta['inputs'][name], 'input_digest')
    for name in ARTIFACT_FILES:
        verify(ROOT / name, meta['inputs'][name]);files[name] = meta['inputs'][name]
        need((ROOT / name).stat().st_uid == (10001 if name == 'pristine-setup' else 0), 'artifact_owner')
    ocr = meta['ocr_executable']
    verify(pathlib.Path(ocr['path']), {'size':ocr['bytes'],'sha256':ocr['sha256']})
    manifest = {'schema':1,'profile':meta['profile'],'source_commit':meta['source_commit'],'files':files}
    target = ROOT / 'manifest.json'
    need(not target.exists(), 'manifest')
    target.write_text(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n');target.chmod(0o444)
    path.unlink()
'''

def dockerfile():
    scripts='\n'.join(f'COPY --chown=0:0 --chmod=0444 inputs/{n} {IMAGE_ROOT}/{n}' for n in runtime_files())
    artifacts='\n'.join(f'COPY --chown={"10001:10001" if n=="pristine-setup" else "0:0"} --chmod=0555 artifacts/{n} {IMAGE_ROOT}/{n}' for n in ARTIFACT_FILES)
    mounts='--mount=type=bind,source=packages,target=/ci-packages,readonly --mount=type=bind,source=image-build,target=/ci-build,readonly --mount=type=bind,source=headers,target=/ci-headers,readonly --mount=type=bind,source=inputs,target=/ci-inputs,readonly'
    return f'''# Offline exact-source financial qualification only; no floating frontend.
FROM --platform=linux/amd64 {BASE_IMAGE} AS module-build
RUN --network=none {mounts} python3 -I -B /ci-build/install.py build
RUN --network=none {mounts} python3 -I -B /ci-build/install.py module
FROM --platform=linux/amd64 {BASE_IMAGE} AS foundation
RUN --network=none {mounts} python3 -I -B /ci-build/install.py runtime
COPY --from=module-build --chown=0:0 --chmod=0444 /ci-output/{MODULE_BINARY} {IMAGE_ROOT}/{MODULE_BINARY}
COPY --from=module-build --chown=0:0 --chmod=0444 /ci-output/manifest.json {IMAGE_ROOT}/foundation-manifest.json
{scripts}
FROM foundation AS runtime
{artifacts}
RUN --network=none --mount=type=bind,source=image-build,target=/ci-build,readonly python3 -I -B /ci-build/install.py finalize
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1
WORKDIR {IMAGE_ROOT}
USER 0:0
ENTRYPOINT ["/usr/local/bin/python3","-I","-B","{IMAGE_ROOT}/ci-financial-container.py"]
CMD []
'''

def build_context(target,source_commit,artifacts):
    base=B.validate_manifest((ROOT/'ci-ui-packages.json').read_bytes())
    ocr,_=O.validate_manifest((ROOT/'ci-financial-ocr-packages.json').read_bytes(),(ROOT/'ci-ui-packages.json').read_bytes())
    B._require(set(artifacts)==set(ARTIFACT_FILES),'input_allowlist')
    B._require(re.fullmatch('[0-9a-f]{40}',source_commit) is not None,'source_commit')
    target=pathlib.Path(target);B._fresh_directory(target)
    deadline=time.monotonic()+B.MAX_STAGE_SECONDS
    B.stage_packages(base,target/'packages',deadline=deadline)
    for row in O.download_plan(ocr):
        path=target/'packages'/row['filename']
        with path.open('xb') as stream:B._download(row,stream,deadline)
        path.chmod(0o444)
    B.stage_private_headers(target/'headers',deadline=deadline)
    (target/'inputs').mkdir(mode=0o700);(target/'artifacts').mkdir(mode=0o700);(target/'image-build').mkdir(mode=0o700)
    pins={}
    for name,path in [(n,ROOT/n) for n in (*runtime_files(),MODULE_SOURCE)]+[(n,pathlib.Path(artifacts[n])) for n in ARTIFACT_FILES]:
        info=path.stat(follow_symlinks=False)
        B._require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=512*1024*1024,'input_file')
        raw=path.read_bytes();B._require(len(raw)==info.st_size,'input_file');pins[name]=pin(raw)
        B._write_file(target/('artifacts' if name in ARTIFACT_FILES else 'inputs')/name,raw)
    meta=metadata(base,ocr,pins,source_commit)
    B._write_file(target/'image-build/metadata.json',B._canonical(meta)+b'\n')
    program=installer();compile(program,'financial-image-install','exec')
    B._write_file(target/'image-build/install.py',program.encode('ascii'))
    B._write_file(target/'Dockerfile',dockerfile().encode('ascii'))
    allowed=['Dockerfile','.dockerignore','image-build/','image-build/metadata.json','image-build/install.py','inputs/','artifacts/','packages/','headers/','headers/libweston/','headers/libweston/backend-drm/']
    allowed+=['inputs/'+n for n in (*runtime_files(),MODULE_SOURCE)]+['artifacts/'+n for n in ARTIFACT_FILES]
    allowed+=['packages/'+r['filename'] for r in (*B.download_plan(base),*O.download_plan(ocr))]
    allowed+=['headers/'+n for n in B.PRIVATE_HEADERS]
    B._write_file(target/'.dockerignore',('**\n'+''.join('!'+n+'\n' for n in allowed)).encode('ascii'))
    return meta

def main():
    parser=argparse.ArgumentParser(description='Stage pinned offline financial image context; no Docker execution.')
    parser.add_argument('--output',required=True);parser.add_argument('--source-commit',required=True)
    for name in ARTIFACT_FILES:parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    build_context(args.output,args.source_commit,{name:getattr(args,name.replace('-','_')) for name in ARTIFACT_FILES})
    print('{"financial_image_context_staged":true,"image_built":false}',flush=True)

if __name__=='__main__':
    try:main()
    except Exception:
        print('{"financial_image_context_staged":false,"code":"image_stage"}',file=sys.stderr,flush=True)
        raise SystemExit(1)
