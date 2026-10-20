#!/usr/bin/env bash
# Narrow real AF_UNIX framing integration, not native/payment qualification.
# Disposable CI only. No cache, wallet, GUI, proof, SQLCipher or runtime archive.
set -euo pipefail
umask 077
ulimit -c 0
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]]
[[ "${GITHUB_REPOSITORY:-}" == stanleykosi/pactloom ]]
[[ "${GITHUB_REF:-}" == refs/heads/qualification/durable-proposal-v1 ]]
[[ "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" && "$(uname -m)" == x86_64 ]]
for program in rustup python3 timeout sha256sum; do command -v "$program" >/dev/null; done
build_root="$(mktemp -d "${RUNNER_TEMP:?}/pactloom-origin-build.XXXXXX")"
export CARGO_HOME="$build_root/cargo" CARGO_TARGET_DIR="$build_root/target"
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0
unset RUST_MIN_STACK RUST_BACKTRACE RUST_LOG RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
printf 'CI_ORIGIN_BUILD source=%s profile=dev features=none native_payment_verified=false\n' "$GITHUB_SHA"
timeout --signal=TERM --kill-after=30s 600s rustup toolchain install 1.99.0 --profile minimal --no-self-update
[[ "$(rustup run 1.99.0 rustc --version)" == 'rustc 1.99.0 (b940084d7 2026-09-28)' ]]
rustup run 1.99.0 rustc -Vv
sha256sum Cargo.lock
# Only this crate's test image, no --all-features and no release optimization.
# Build output contains public source/compiler data, never a runtime execution.
if timeout --signal=TERM --kill-after=30s 600s rustup run 1.99.0 cargo test \
  --locked -p wholepact-signer-origin --no-default-features --lib --no-run \
  --message-format=json > "$build_root/build-metadata.jsonl"; then
  :
else
  status=$?
  python3 -B - "$build_root/build-metadata.jsonl" <<'PY_BUILD'
import json, pathlib, re, sys
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    try: row=json.loads(line)
    except Exception: continue
    message=row.get('message',{})
    if row.get('reason')!='compiler-message' or message.get('level')!='error': continue
    code=(message.get('code') or {}).get('code','unclassified')
    if not re.fullmatch(r'E[0-9]{4}|unclassified',code): code='unclassified'
    for span in message.get('spans',[]):
        path=span.get('file_name',''); number=span.get('line_start')
        if span.get('is_primary') and re.fullmatch(r'crates/wholepact-signer-origin/src/[a-zA-Z0-9_/]+\.rs',path) and type(number) is int and 0<number<100000:
            print(f'CI_ORIGIN_COMPILE code={code} file={path} line={number}',flush=True)
PY_BUILD
  exit "$status"
fi
python3 -B - "$build_root/build-metadata.jsonl" "$CARGO_TARGET_DIR" <<'PY'
import hashlib, json, os, pathlib, re, resource, selectors, subprocess, sys, time
assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
candidates=[]
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    row=json.loads(line)
    if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='wholepact_signer_origin' and row.get('profile',{}).get('test') and row.get('executable'):
        candidates.append(pathlib.Path(row['executable']).resolve(strict=True))
assert len(set(candidates))==1
exe=candidates[0]
assert exe.is_file() and exe.is_relative_to(pathlib.Path(sys.argv[2]).resolve(strict=True))
print('CI_ORIGIN_IMAGE sha256='+hashlib.sha256(exe.read_bytes()).hexdigest(), flush=True)
name='client::framing_integration_tests::production_frames_real_peer_contract'
listed=subprocess.run([str(exe),'--ignored','--exact',name,'--list'],capture_output=True,timeout=10)
assert listed.returncode==0 and not listed.stderr
assert [line for line in listed.stdout.decode().splitlines() if line.endswith(': test')]==[name+': test']
cases=['Success','Large','Eof','Deadline','MissingCredentials','WrongPeer','PeerExit','Cancel','BrokenPipe']
receivers={'Frame','ReadClosed','Unclassified','Deadline','Eof','CredentialsMissing','CredentialsMismatch','AncillaryRejected','Truncated','PeerNotLive','CurrentCheck','Io','FrameLimit','InvalidFrame','InvalidBudget','Root','Bind','Passcred','Nonblocking','Image','Spawn','Accept','Timeout','KernelPeerUnavailable','Start','Shutdown','Wait','WaitDeadline','Release'}
writers={'Sent','Idle','Closed','BrokenPipe','Reset','Timeout','Budget','OtherFailure','Unobserved'}
pattern=re.compile(r'ORIGIN_INTEGRATION attempt=(\d+) case=([A-Za-z]+) receiver=([A-Za-z]+) writer=([A-Za-z]+) elapsed_ms=(\d+) cleanup=(true|false) passed=(true|false)')
# One known direct process. Never emit panic output, arbitrary stderr or paths.
# Each test owns/reaps its direct child. If the outer deadline fires, no runtime
# cleanup claim is made; disposable runner teardown remains responsible.
process=subprocess.Popen([str(exe),'--ignored','--exact',name,'--test-threads=1','--nocapture'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
selector=selectors.DefaultSelector()
selector.register(process.stdout,selectors.EVENT_READ)
raw=bytearray(); pending=bytearray(); rows=[]; deadline=time.monotonic()+45
failure=False
try:
    while selector.get_map():
        if time.monotonic()>=deadline: raise TimeoutError()
        for key,_ in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
            chunk=os.read(key.fileobj.fileno(),4096)
            if not chunk:
                selector.unregister(key.fileobj); continue
            raw.extend(chunk); pending.extend(chunk)
            if len(raw)>65536 or len(pending)>8192: raise ValueError()
            while b'\n' in pending:
                line,_,remaining=pending.partition(b'\n');pending=bytearray(remaining)
                # libtest can prefix the first uncaptured line with its test name.
                offset=line.find(b'ORIGIN_INTEGRATION ')
                if offset<0: continue
                match=pattern.fullmatch(line[offset:].decode('ascii'))
                if not match: raise ValueError()
                attempt,case,receiver,writer,elapsed,cleanup,passed=match.groups()
                if int(attempt)!=len(rows) or len(rows)>=len(cases) or case!=cases[len(rows)] or receiver not in receivers or writer not in writers or int(elapsed)>45000: raise ValueError()
                rows.append(match.groups())
                print('CI_'+match.group(0),flush=True)
    status=process.wait(timeout=max(0.1,deadline-time.monotonic()))
    ok=status==0 and len(rows)==9 and all(row[-2:]==('true','true') for row in rows)
    ok=ok and b'test result: ok. 1 passed; 0 failed;' in raw
except Exception:
    failure=True; ok=False
    # Popen retains exact direct-child ownership; poll reaps before a possible
    # kill. No process-group signal or cleanup of uncertain runtime paths.
    if process.poll() is None:
        process.kill()
        try: process.wait(timeout=5)
        except Exception: pass
finally:
    selector.close()
    if process.stdout: process.stdout.close()
print('CI_ORIGIN_RESULT passed='+str(ok).lower()+' native_payment_verified=false full_product_verified=false outer_failure='+str(failure).lower(),flush=True)
if not ok: sys.exit(1)
PY
