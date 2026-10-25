#!/usr/bin/env python3
"""Real pinned ChainAdapter native-root TLS regression, not a wallet/fullflow test.

Only the authorized preflight calls run(). No Cargo/product source changes, host
trust writes, host mounts, or external runtime networking. Each case gets a fresh
network-none container. Generated CA/private keys exist only in its tmpfs.
"""
import ast
import hashlib
import json
import pathlib
import re
import shutil
import stat
import textwrap
import tempfile
import time
import tomllib

HERE = pathlib.Path(__file__).resolve().parent
RUSTC = 'rustc 1.99.0 (b940084d7 2026-09-28)'
CASES = ('missing_ca', 'matching_ca', 'wrong_ca', 'wrong_name')
TMPFS = {
    '/etc/wholepact':'rw,noexec,nosuid,nodev,size=64k,mode=0755',
    '/ci-fixture':'rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700',
    '/tmp':'rw,noexec,nosuid,nodev,size=1m,mode=1777',
}
CHAIN_FEATURES = ('default', 'submission-dispatch')
TOKIO_FEATURES = ('bytes', 'default', 'fs', 'full', 'io-std', 'io-util', 'libc', 'macros',
                  'mio', 'net', 'parking_lot', 'process', 'rt', 'rt-multi-thread',
                  'signal', 'signal-hook-registry', 'socket2', 'sync', 'time', 'tokio-macros')
HELPERS = ('fixture_effective_identity', 'read_fixture_provider_ca',
           'validate_fixture_provider_ca', 'install_fixture_provider_ca')
RUST = r'''use std::time::Duration;
use wholepact_chain::{ChainAdapter, ChainError, NetworkPolicy};
fn main() {
    if std::env::vars_os().next().is_some() { std::process::exit(30); }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 || !args[1].starts_with("https://127.0.0.1:") {
        std::process::exit(31);
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let policy = NetworkPolicy { request_timeout: Duration::from_secs(3), retries: 0,
                                 ..NetworkPolicy::default() };
    let chain = ChainAdapter::testnet("public-fixture-tls-probe", &args[1], policy).unwrap();
    let connected = runtime.block_on(async {
        match chain.public_sync_channel().await {
            Ok(channel) => {
                // Keep the genuine transport polled long enough for its HTTP/2
                // preface. No RPC, wallet, authorization or financial action.
                tokio::time::sleep(Duration::from_millis(100)).await;
                drop(channel);
                true
            }
            Err(ChainError::TransportUnavailable) => false,
            Err(_) => std::process::exit(32),
        }
    });
    println!("{}", if connected { "CONNECTED" } else { "TLS_REJECTED" });
    std::process::exit(if connected { 0 } else { 10 });
}
'''

# Separate UID10001 server process: neither PID1 nor the installer reads a key.
# HTTP/2 SETTINGS only; this test deliberately claims TLS establishment, not RPC.
RUNNER = r'''import ctypes, hashlib, importlib.util, json, os, pathlib, resource
import socket, ssl, stat, subprocess, sys, time
spec=importlib.util.spec_from_file_location('ca_helpers','/probe/ca_helpers.py')
helpers=importlib.util.module_from_spec(spec);sys.modules[spec.name]=helpers;spec.loader.exec_module(helpers)
install_fixture_provider_ca=helpers.install_fixture_provider_ca
PROVIDER_CA=helpers.PROVIDER_CA;PROVIDER_CA_LINK=helpers.PROVIDER_CA_LINK
ROOT=pathlib.Path('/ci-fixture/full-parent/f-probe')
TLS=ROOT/'synthetic-provider-tls-v1'
CASES=('missing_ca','matching_ca','wrong_ca','wrong_name')
def need(ok):
    if not ok: raise RuntimeError('provider_tls_probe')
def openssl(*args):
    subprocess.run(['/usr/bin/openssl',*args],stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={},check=True,timeout=5)
def generate():
    need(os.getresuid()==(10001,10001,10001));os.umask(0o077)
    for path in (ROOT.parent,ROOT,TLS):path.mkdir(mode=0o700)
    for name in ('ca','other'):
        openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
            '-sha256','-days','1','-nodes','-subj','/CN=wholepact-public-tls-probe-'+name,
            '-addext','basicConstraints=critical,CA:TRUE',
            '-addext','keyUsage=critical,keyCertSign,cRLSign',
            '-keyout',str(TLS/(name+'.key')),'-out',str(TLS/(name+'.pem')))
    for name,issuer,ip in (('matching_ca','ca','127.0.0.1'),('wrong_ca','other','127.0.0.1'),
                           ('wrong_name','ca','127.0.0.2')):
        openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
            '-sha256','-nodes','-subj','/CN='+ip,'-keyout',str(TLS/(name+'.key')),
            '-out',str(TLS/(name+'.csr')))
        extension=TLS/(name+'.ext')
        extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
            'extendedKeyUsage=serverAuth\nsubjectAltName=IP:'+ip+'\n')
        openssl('x509','-req','-in',str(TLS/(name+'.csr')),'-CA',str(TLS/(issuer+'.pem')),
            '-CAkey',str(TLS/(issuer+'.key')),'-set_serial',str(1+len(name)),
            '-days','1','-sha256','-extfile',str(extension),'-out',str(TLS/(name+'.pem')))
    for path in TLS.iterdir():path.chmod(0o600)
def exact(stream,n):
    data=b''
    while len(data)<n:
        part=stream.recv(n-len(data))
        if not part:return None
        data+=part
    return data
def serve(case):
    need(os.getresuid()==(10001,10001,10001))
    name='matching_ca' if case=='missing_ca' else case
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.set_alpn_protocols(['h2'])
    ctx.load_cert_chain(TLS/(name+'.pem'),TLS/(name+'.key'))
    result={'tcp':False,'tls':False,'h2':False}
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(5)
        print(listener.getsockname()[1],flush=True)
        conn,_=listener.accept();result['tcp']=True;conn.settimeout(4)
        try:
            with ctx.wrap_socket(conn,server_side=True) as stream:
                result['tls']=True
                need(stream.selected_alpn_protocol()=='h2')
                stream.sendall(b'\x00\x00\x00\x04\x00\x00\x00\x00\x00')
                result['h2']=exact(stream,24)==b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                need(result['h2'])
                for _ in range(16):
                    header=exact(stream,9)
                    if header is None:break
                    size=int.from_bytes(header[:3],'big');need(size<=65536)
                    body=exact(stream,size);need(body is not None)
                    if header[3]==4 and not header[4]&1:
                        stream.sendall(b'\x00\x00\x00\x04\x01\x00\x00\x00\x00')
        except ssl.SSLError:
            need(not result['tls'])
        finally:conn.close()
    print(json.dumps(result,sort_keys=True),flush=True)
def main(case):
    need(os.getpid()==1 and os.getresuid()==(0,0,0) and case in CASES)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077);os.environ.clear()
    deadline=time.monotonic_ns()+15_000_000_000
    meta=json.loads(pathlib.Path('/probe/metadata.json').read_bytes())
    bundle=pathlib.Path('/etc/ssl/certs/ca-certificates.crt')
    before=hashlib.sha256(bundle.read_bytes()).hexdigest()
    for name in meta['needed']:ctypes.CDLL(name)
    subprocess.run(['/usr/local/bin/python3','-I','-B','/probe/runner.py','generate'],
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        user=10001,group=10001,extra_groups=[],env={},check=True,timeout=7)
    need(PROVIDER_CA_LINK.is_symlink() and not PROVIDER_CA.exists())
    if case!='missing_ca':
        selected=ROOT/'coordinated-financial-pre-v3-fixture-v1.json'
        install_fixture_provider_ca(selected,deadline)
        info=PROVIDER_CA.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0 and
             info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o444)
    server=subprocess.Popen(['/usr/local/bin/python3','-I','-B','/probe/runner.py','serve',case],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        user=10001,group=10001,extra_groups=[],env={},text=True)
    try:
        import select
        need(select.select([server.stdout],[],[],3)[0])
        line=server.stdout.readline();need(line.strip().isdigit())
        port=int(line);need(0<port<65536)
        client=subprocess.run(['/probe/client','https://127.0.0.1:'+str(port)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            user=10001,group=10001,extra_groups=[],env={},timeout=5,check=False)
        output,_=server.communicate(timeout=5);need(server.returncode==0)
        observation=json.loads(output)
        success=case=='matching_ca'
        need(client.returncode==(0 if success else 10))
        need(client.stdout==(b'CONNECTED\n' if success else b'TLS_REJECTED\n'))
        need(observation=={'tcp':True,'tls':success,'h2':success})
        need(hashlib.sha256(bundle.read_bytes()).hexdigest()==before)
        need(time.monotonic_ns()<deadline)
        print('CI_PROVIDER_TLS_CASE '+json.dumps({'case':case,'passed':True,
            'empty_client_environment':True,'tcp_reached':True,'tls_connected':success,
            'distro_bundle_unchanged':True,'fullflow':False},sort_keys=True),flush=True)
    finally:
        if server.poll() is None:server.kill()
        server.wait(timeout=2)
if sys.argv[1]=='generate':generate()
elif sys.argv[1]=='serve':serve(sys.argv[2])
else:main(sys.argv[1])
'''


def source_inputs():
    """Exact current production bodies, not an independently maintained model."""
    source=(HERE/'ci-financial-container.py').read_text()
    tree=ast.parse(source);lines=source.splitlines(keepends=True);parts=[]
    for name in HELPERS:
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
        assert len(nodes)==1
        node=nodes[0];start=min([node.lineno]+[n.lineno for n in node.decorator_list])
        parts.append(''.join(lines[start-1:node.end_lineno]))
    constants={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name in ('UID','PROVIDER_CA','PROVIDER_CA_LINK'):
                constants[name]=''.join(lines[node.lineno-1:node.end_lineno])
    assert set(constants)=={'UID','PROVIDER_CA','PROVIDER_CA_LINK'}
    prelude='import base64, contextlib, importlib.util, os, pathlib, re, ssl, stat, subprocess, sys, tempfile, time\n'
    for short,name in [('C','contract'),('F','fixture')]:
        prelude+=f"s=importlib.util.spec_from_file_location('probe_{name}','/probe/ci-financial-{name}.py')\n{short}=importlib.util.module_from_spec(s);sys.modules[s.name]={short};s.loader.exec_module({short})\n"
    helpers=prelude+''.join(constants.values())+'\n'+'\n'.join(parts)+'\n'
    image=ast.parse((HERE/'ci-financial-image.py').read_text())
    finals=[ast.literal_eval(n.value) for n in image.body if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=='_FINALIZE' for t in n.targets)]
    assert len(finals)==1
    program=finals[0]
    start=program.index("    certs = pathlib.Path('/etc/ssl/certs')\n")
    end=program.index("    manifest = ",start)
    block=textwrap.dedent(program[start:end])
    assert "link.symlink_to('/etc/wholepact/fixture-provider-ca.pem')" in block
    link_program='import os, pathlib, stat\ndef need(value,code):\n    if not value: raise RuntimeError(code)\n'+block
    compile(helpers,'actual-ca-helpers','exec');compile(link_program,'actual-image-link','exec')
    return helpers,link_program


def artifacts(raw,target,repo,sqlcipher):
    """Use only the existing validated Cargo invocation, never filename globbing."""
    rows=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    found={};native=set();observed={}
    lock=tomllib.loads((repo/'Cargo.lock').read_text())
    expected={'tokio':'1.53.2','tonic':'0.14.6','rustls':'0.23.45',
              'rustls-native-certs':'0.8.5','openssl-probe':'0.2.1'}
    for name,version in expected.items():
        assert [p['version'] for p in lock['package'] if p['name']==name]==[version]
    for row in rows:
        if row.get('reason')=='build-script-executed':
            for item in row.get('linked_paths',[]):
                # Only job-owned static archives. System paths from unrelated UI
                # dependencies are not needed by this narrow transport client.
                value=item.removeprefix('native=');path=pathlib.Path(value)
                if path.is_absolute() and any(path.resolve().is_relative_to(p.resolve()) for p in (target,sqlcipher)):
                    assert path.is_dir() and not path.is_symlink();native.add(value)
        if row.get('reason')!='compiler-artifact':continue
        package=row.get('package_id','');t=row.get('target',{});name=t.get('name')
        if name in ('wholepact_chain','tokio') and t.get('kind')==['lib'] and not row.get('profile',{}).get('test'):
            assert name not in found
            features=tuple(sorted(row['features']))
            if name=='wholepact_chain':
                assert row['manifest_path']==str(repo/'crates/wholepact-chain/Cargo.toml')
                assert t['src_path']==str(repo/'crates/wholepact-chain/src/lib.rs')
                assert features==tuple(sorted(CHAIN_FEATURES))
            else:
                assert package.endswith('#tokio@1.53.2') and features==tuple(sorted(TOKIO_FEATURES))
            paths=[pathlib.Path(p) for p in row['filenames'] if p.endswith('.rlib')]
            assert len(paths)==1 and paths[0].is_file() and not paths[0].is_symlink()
            assert paths[0].resolve().is_relative_to((target/'debug/deps').resolve())
            found[name]=paths[0]
        for wanted,version in expected.items():
            if package.endswith('#'+wanted+'@'+version) and t.get('kind')==['lib']:
                observed[wanted]=version
    assert set(found)=={'wholepact_chain','tokio'} and observed==expected
    return found,sorted(native)


def run(root,env,raw,S):
    """Called only by the existing authorized preflight; hard 480s incl cleanup."""
    root=pathlib.Path(root).resolve();repo=HERE.parent
    assert root.is_dir() and pathlib.Path(env['CARGO_TARGET_DIR']).resolve()==root/'target-shared'
    started=time.monotonic();deadline=started+480;work=root/'provider-tls-probe'
    assert not work.exists();work.mkdir(mode=0o700)
    def checked(args,seconds=30,limit=1024*1024,cleanup=False):
        # Reserve one minute for owned Docker cleanup before starting more work.
        left=deadline-time.monotonic()-(0 if cleanup else 60)
        # The maintained command runner reserves up to five seconds to kill/reap
        # its own process group on timeout; include that in the absolute cap.
        assert left>6
        return S.checked(args,'compile',env=env,seconds=min(seconds,left-6),limit=limit)
    assert checked(['rustup','run','1.99.0','rustc','--version']).decode().strip()==RUSTC
    libs,native=artifacts(raw,root/'target-shared',repo,root/'sqlcipher')
    helpers,link_program=source_inputs()
    source=work/'client.rs';source.write_text(RUST)
    command=['rustup','run','1.99.0','rustc','--edition=2021','--crate-name','provider_tls_probe',
        str(source),'-o',str(work/'client'),'-L','dependency='+str(root/'target-shared/debug/deps')]
    for name,path in sorted(libs.items()):command+=['--extern',name+'='+str(path)]
    for path in native:command+=['-L','native='+path]
    checked(command,120,4*1024*1024)
    elf=checked(['readelf','-l','-d',str(work/'client')]).decode()
    assert '[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]' in elf
    needed=sorted(set(re.findall(r'\(NEEDED\).*\[([^\]]+)\]',elf)))
    packages={'libc.so.6':'libc6','libm.so.6':'libc6','libdl.so.2':'libc6',
        'libpthread.so.0':'libc6','librt.so.1':'libc6','ld-linux-x86-64.so.2':'libc6',
        'libgcc_s.so.1':'libgcc-s1','libcrypto.so.3':'libssl3t64','libssl.so.3':'libssl3t64'}
    assert needed and set(needed)<=set(packages)
    pins=json.loads((HERE/'ci-ui-packages.json').read_bytes())
    pinned_base={p['name'] for p in pins['packages'] if p['origin']=='pinned-base'}
    assert {packages[n] for n in needed}<=pinned_base
    context=work/'context';context.mkdir()
    shutil.copyfile(work/'client',context/'client');(context/'client').chmod(0o555)
    for name,value in [('runner.py',RUNNER),('ca_helpers.py',helpers),('image_link.py',link_program)]:
        (context/name).write_text(value)
    for name in ('ci-financial-contract.py','ci-financial-fixture.py'):
        shutil.copyfile(HERE/name,context/name)
    (context/'metadata.json').write_text(json.dumps({'needed':needed}))
    (context/'Dockerfile').write_text(f'FROM --platform=linux/amd64 {S.I.BASE_IMAGE}\n'
        'COPY --chown=0:0 --chmod=0555 . /probe/\nRUN --network=none python3 -I -B /probe/image_link.py\n'
        'ENTRYPOINT ["/usr/local/bin/python3","-I","-B","/probe/runner.py"]\n')
    token=hashlib.sha256((str(root)+str(started)).encode()).hexdigest()[:20]
    tag='wholepact-provider-tls-probe:'+token;label='org.wholepact.provider-tls-probe='+token
    names=[];image_attempted=False;passed=[];cleanup_ok=True;first=None
    try:
        image_attempted=True
        checked(['docker','build','--network=none','--label',label,'--tag',tag,str(context)],180,4*1024*1024)
        image=json.loads(checked(['docker','image','inspect',tag],10))[0]
        image_id=image['Id'];assert re.fullmatch(r'sha256:[0-9a-f]{64}',image_id)
        assert image['Config']['Labels'].get('org.wholepact.provider-tls-probe')==token
        for case in CASES:
            name='wholepact-provider-tls-'+token+'-'+case.replace('_','-');names.append(name)
            command=['docker','create','--name',name,'--label',label,'--user','0:0','--network=none','--read-only',
                '--cap-drop=ALL','--cap-add=SETUID','--cap-add=SETGID','--security-opt=no-new-privileges:true','--log-driver=none','--ipc=private','--cgroupns=private',
                '--pids-limit=32','--memory=256m','--memory-swap=256m','--cpus=1','--ulimit','core=0:0']
            for path,options in TMPFS.items():command+=['--tmpfs',path+':'+options]
            command+=[tag,case]
            checked(command,10)
            created=json.loads(checked(['docker','inspect',name],10))[0]
            host=created['HostConfig'];config=created['Config']
            assert created['Image']==image_id and config['Image']==tag and config['User']=='0:0'
            assert config['Entrypoint']==['/usr/local/bin/python3','-I','-B','/probe/runner.py']
            assert config['Cmd']==[case] and not host.get('Privileged')
            assert host['NetworkMode']=='none' and host['ReadonlyRootfs']
            assert host['CapDrop']==['ALL']
            assert sorted(x.removeprefix('CAP_') for x in host['CapAdd'])==['SETGID','SETUID']
            assert host['SecurityOpt']==['no-new-privileges:true'] and not host.get('Binds')
            assert host['LogConfig']=={'Type':'none','Config':{}}
            assert host['PidMode']=='' and host['IpcMode']=='private' and host['CgroupnsMode']=='private'
            assert not host.get('Devices') and not host.get('DeviceRequests') and not host.get('Mounts')
            assert all(m['Type']=='tmpfs' and m['Destination'] in ('/etc/wholepact','/ci-fixture','/tmp') and not m.get('Source') for m in created['Mounts'])
            assert set(host['Tmpfs'])==set(TMPFS)
            for path,expected in TMPFS.items():
                options=host['Tmpfs'][path].split(',')
                assert len(options)==len(set(options)) and set(options)==set(expected.split(','))
            assert host['Ulimits']==[{'Name':'core','Hard':0,'Soft':0}]
            assert host['PidsLimit']==32 and host['Memory']==256*1024*1024
            assert host['MemorySwap']==host['Memory'] and host['NanoCpus']==1_000_000_000
            output=checked(['docker','start','--attach',name],20,65536).decode()
            lines=output.splitlines();assert len(lines)==1 and lines[0].startswith('CI_PROVIDER_TLS_CASE ')
            value=json.loads(lines[0].split(' ',1)[1]);success=case=='matching_ca'
            assert value==dict(case=case,passed=True,empty_client_environment=True,tcp_reached=True,
                               tls_connected=success,distro_bundle_unchanged=True,fullflow=False)
            state=json.loads(checked(['docker','inspect',name],10))[0]
            assert state['State']['Status']=='exited' and state['State']['ExitCode']==0
            assert state['Config']['Labels'].get('org.wholepact.provider-tls-probe')==token
            passed.append(value)
    except BaseException as error:
        first=error
        raise
    finally:
        # Even a failed create/build owns these exact unique names. Never prune
        # shared objects or use rm --volumes; no volumes/mounts were requested.
        for name in names:
            try:
                left=deadline-time.monotonic();assert left>6
                status,_=S.command(['docker','rm','--force',name],'compile',env=env,
                    seconds=min(5,left-6),limit=65536)
                listed=checked(['docker','ps','--all','--quiet','--filter','name=^/'+name+'$'],10,cleanup=True)
                assert not listed.strip()
            except BaseException:cleanup_ok=False
        if image_attempted:
            try:
                left=deadline-time.monotonic();assert left>6
                S.command(['docker','image','rm','--force',tag],'compile',env=env,
                    seconds=min(5,left-6),limit=65536)
                listed=checked(['docker','image','ls','--quiet',tag],10,cleanup=True)
                assert not listed.strip()
                # This test never prunes shared Docker build cache. Its copied
                # image inputs contain no generated CA, keys, fixture or secrets.
            except BaseException:cleanup_ok=False
        cleanup_ok=cleanup_ok and time.monotonic()<=deadline
        if not cleanup_ok:
            if first is None:raise AssertionError('provider_tls_owned_cleanup')
            # Preserve the original failure and disclose separate uncertainty.
            try:
                first.add_note('provider_tls_owned_cleanup_unverified')
                print('CI_PROVIDER_TLS_CLEANUP '+json.dumps(dict(verified=False,fullflow=False)),flush=True)
            except BaseException:pass
    assert len(passed)==4
    for value in passed:print('CI_PROVIDER_TLS_CASE '+json.dumps(value,sort_keys=True),flush=True)
    print('CI_PROVIDER_TLS_PROBE '+json.dumps(dict(actual_chain_adapter=True,cases=4,
        empty_client_environment=True,owned_containers_removed=True,owned_image_removed=True,
        source_bound_helpers=list(HELPERS),fullflow=False),sort_keys=True),flush=True)
    return 4


def source_only():
    """Inert source/metadata checks only. Never sockets, compiler or containers."""
    helpers,image=source_inputs()
    compile(RUNNER,'provider-tls-runner','exec')
    assert all('def '+name+'(' in helpers for name in HELPERS)
    assert 'original_bundle = bundle.read_bytes()' in image
    assert "need(bundle.read_bytes() == original_bundle, 'input_digest')" in image
    assert CASES==('missing_ca','matching_ca','wrong_ca','wrong_name')
    assert 'ChainAdapter::testnet(' in RUST and 'chain.public_sync_channel().await' in RUST
    chain=(HERE.parent/'crates/wholepact-chain/src/lib.rs').read_text()
    rpc=(HERE.parent/'crates/wholepact-chain/src/rpc.rs').read_text()
    assert 'self.rpc.connect().await?' in chain
    assert '.tls_config(ClientTlsConfig::new().with_native_roots())' in rpc
    assert 'if std::env::vars_os().next().is_some()' in RUST
    checked=2
    # Empty fake rlibs exercise only the closed Cargo-metadata selector; they
    # are never linked/executed and are not presented as a native regression.
    with tempfile.TemporaryDirectory(prefix='provider-tls-source-') as temporary:
        base=pathlib.Path(temporary);target=base/'target';deps=target/'debug/deps';deps.mkdir(parents=True)
        sql=base/'sqlcipher';sql.mkdir()
        rows=[]
        versions={'tokio':'1.53.2','tonic':'0.14.6','rustls':'0.23.45',
            'rustls-native-certs':'0.8.5','openssl-probe':'0.2.1'}
        for name,version in versions.items():
            row={'reason':'compiler-artifact','package_id':'registry+test#'+name+'@'+version,
                 'target':{'name':name.replace('-','_'),'kind':['lib']},'profile':{'test':False}}
            if name=='tokio':
                path=deps/'libtokio-test.rlib';path.touch()
                row.update(features=list(TOKIO_FEATURES),filenames=[str(path)])
            rows.append(row)
        path=deps/'libwholepact_chain-test.rlib';path.touch()
        rows.append({'reason':'compiler-artifact','package_id':'path+test#wholepact-chain@0.1.0',
            'manifest_path':str(HERE.parent/'crates/wholepact-chain/Cargo.toml'),
            'target':{'name':'wholepact_chain','kind':['lib'],
                      'src_path':str(HERE.parent/'crates/wholepact-chain/src/lib.rs')},
            'profile':{'test':False},'features':list(CHAIN_FEATURES),'filenames':[str(path)]})
        encode=lambda: ('\n'.join(json.dumps(r) for r in rows)).encode()
        found,_=artifacts(encode(),target,HERE.parent,sql)
        assert set(found)=={'tokio','wholepact_chain'};checked+=1
        for change,restore in (
            (lambda: rows[-1]['features'].append('synthetic-qualification'),lambda: rows[-1]['features'].pop()),
            (lambda: rows[-1]['filenames'].append(str(path)),lambda: rows[-1]['filenames'].pop()),
            (lambda: rows.append(rows[-1]),lambda: rows.pop()),
        ):
            change()
            try:artifacts(encode(),target,HERE.parent,sql)
            except AssertionError:checked+=1
            else:raise AssertionError('metadata selector did not fail closed')
            finally:restore()
    assert checked==6
    print('CI_PROVIDER_TLS_SOURCE '+json.dumps(dict(source_checks=checked,passed=True,
        actual_tls_executed=False,actual_tls_status='NOT RUN',fullflow=False),sort_keys=True))


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only',action='store_true')
    options=parser.parse_args()
    if not options.source_only:parser.error('actual execution is mandatory through the authorized preflight run() hook')
    source_only()
