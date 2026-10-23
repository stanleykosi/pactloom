"""Fixed P35 diagnostic image; stage only, never execute Docker or native code."""
import hashlib
import importlib.util
import pathlib
import stat
import sys
import time

SOURCE='8f145cf7a4f90346fad22fc1dd2c600aa8f7db02'
PINS={
 'ci-ui-image.py':'181ebc76e3d15d02381ac6a7338346ea333c9026630968098dc3d25ee58b551b',
 'ci-financial-ocr-image.py':'5dd479e0def902357714b07d1116a83f2c9ad215ea462493032502e29d564d67',
 'ci-synthetic-output.py':'16531ec93aa8b9b978f2c92a6b5a7d48e27259e30cb7bb39e5a58edac6f0b1c7',
 'pristine-setup':'836dc6337802b537f341804247b2f3f88efb8463a69227fe3105f9c8e031e698'}
ENTRY=['/usr/local/bin/python3','-I','-B','/opt/ci-financial/ci-synthetic-output.py','/opt/ci-financial/pristine-setup','durable-delivery-admission']

def need(ok):
    if not ok: raise ValueError('preparation_image')

def read(path,name):
    path=pathlib.Path(path);info=path.stat(follow_symlinks=False)
    need(stat.S_ISREG(info.st_mode) and 0<info.st_size<=512*1024*1024)
    raw=path.read_bytes();need(len(raw)==info.st_size and hashlib.sha256(raw).hexdigest()==PINS[name]);return raw

def modules(source):
    root=pathlib.Path(source)/'scripts'
    # Verify both before either executes (OCR imports its pinned sibling).
    for name in ('ci-ui-image.py','ci-financial-ocr-image.py'):read(root/name,name)
    result=[]
    for name in ('ci-ui-image','ci-financial-ocr-image'):
        spec=importlib.util.spec_from_file_location('preparation_'+name.replace('-','_'),root/(name+'.py'))
        mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod);result.append(mod)
    return tuple(result)

def installer(B):
    script=B._INSTALL_SCRIPT.replace('/opt/ci-ui','/opt/ci-financial')
    start=script.index('def verify_inputs(meta):');end=script.index('def main():',start)
    script=script[:start]+'''def verify_inputs(meta):
    need(set(meta['inputs']) == {'ci-synthetic-output.py','pristine-setup'}, 'input_set')
    need({p.name for p in pathlib.Path('/ci-inputs').iterdir()} == set(meta['inputs']), 'input_set')
    for name, pin in meta['inputs'].items():
        verify(pathlib.Path('/ci-inputs') / name, pin)

'''+script[end:]
    script=script.replace("sys.argv[1] in ('build', 'runtime', 'module', 'finalize')","sys.argv[1] == 'runtime'")
    script=script.replace("    if mode == 'finalize':\n        finalize(meta)\n        return\n",'').replace("    if mode == 'module':\n        build_module(meta)\n        return\n",'')
    old="""        pathlib.Path('/etc/passwd').unlink()
        pathlib.Path('/etc/passwd').symlink_to('/run/ci-account/passwd')
        need(not pathlib.Path('/run/ci-account').exists(), 'account_tmpfs_target')"""
    new="""        with pathlib.Path('/etc/passwd').open('a') as stream:
            stream.write('wholepact-ci:x:10001:10001::/tmp:/usr/sbin/nologin\\n')
        for name, pin in meta['inputs'].items():
            target = ROOT / name
            shutil.copyfile(pathlib.Path('/ci-inputs') / name, target)
            target.chmod(0o555 if name == 'pristine-setup' else 0o444)
            os.chown(target, 10001 if name == 'pristine-setup' else 0, 10001 if name == 'pristine-setup' else 0)
            verify(target, pin)"""
    need(old in script);script=script.replace(old,new)
    script=script.replace('login, password or credentials are baked in. PID1 owns tmpfs passwd.', 'login password or credentials are baked in. The diagnostic uses a fixed nonlogin account.')
    compile(script,'preparation-install','exec');return script

def dockerfile(base):
    import json
    return f'''FROM --platform=linux/amd64 {base} AS runtime
COPY image-build/ /ci-build/
COPY packages/ /ci-packages/
COPY inputs/ /ci-inputs/
RUN ["/usr/local/bin/python3","-I","-B","/ci-build/install.py","runtime"]
ENV CARGO_TARGET_DIR=/opt/ci-financial TMPDIR=/tmp HOME=/tmp PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/ci-financial
USER 10001:10001
ENTRYPOINT {json.dumps(ENTRY,separators=(',',':'))}
'''

def build_context(target,source_root,source_commit,setup_path):
    need(source_commit==SOURCE)
    source=pathlib.Path(source_root)/'scripts'
    inputs={'ci-synthetic-output.py':read(source/'ci-synthetic-output.py','ci-synthetic-output.py'),
            'pristine-setup':read(setup_path,'pristine-setup')}
    B,O=modules(source_root)
    base=B.validate_manifest((source/'ci-ui-packages.json').read_bytes())
    ocr,_=O.validate_manifest((source/'ci-financial-ocr-packages.json').read_bytes(),(source/'ci-ui-packages.json').read_bytes())
    names=set(base['closures']['runtime'])|set(ocr['ocr_closure'])
    rows={r['name']:r for r in base['packages']};rows.update({r['name']:r for r in ocr['additional_packages']})
    packages=[rows[n] for n in sorted(names) if rows[n]['origin']!='pinned-base']
    plan={r['name']:r for r in (*B.download_plan(base),*O.download_plan(ocr))}
    meta={'base':B.expected_packages(base,'base'),'runtime':O.expected_runtime_packages(ocr,base),
          'packages':{'runtime':packages},'inputs':{n:{'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for n,raw in inputs.items()},'source_commit':source_commit}
    target=pathlib.Path(target);B._fresh_directory(target)
    for name in ('packages','inputs','image-build'):(target/name).mkdir(mode=0o700)
    deadline=time.monotonic()+B.MAX_STAGE_SECONDS
    for row in packages:
        record=plan[row['name']];path=target/'packages'/record['filename']
        with path.open('xb') as stream:B._download(record,stream,deadline)
        path.chmod(0o444)
    for name,raw in inputs.items():B._write_file(target/'inputs'/name,raw)
    B._write_file(target/'image-build/metadata.json',B._canonical(meta)+b'\n')
    B._write_file(target/'image-build/install.py',installer(B).encode('ascii'))
    B._write_file(target/'Dockerfile',dockerfile(B.BASE_IMAGE).encode('ascii'))
    allowed=['Dockerfile','.dockerignore','image-build/','image-build/install.py','image-build/metadata.json','inputs/','packages/']
    allowed+=['inputs/'+n for n in inputs]+['packages/'+plan[r['name']]['filename'] for r in packages]
    B._write_file(target/'.dockerignore',('**\n'+''.join('!'+n+'\n' for n in allowed)).encode('ascii'))
    return meta
