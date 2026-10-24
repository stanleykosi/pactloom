#!/usr/bin/env python3
"""Fixed P52 source equivalence, excluding explicitly authorized early close.

Static only. The exact kernel hashes and owned fault traces complement actual
compile/tests; no native Final, TLS, socket, authority or fullflow is fabricated.
"""
import argparse, hashlib, json, re
from pathlib import Path
MACROS_SHA = '05c11286278f5eabf1316ecacd9e1facf3fd21b964f1969bbbba88d31192f216'
HOOK_SHA = '8de23863fb427932352fcd4ebdfdc371fc36c2f9daba3dc0fa391febf584a62e'
BASELINE = "27e668bfcf84fe809b6bca4a1c15a5e8e6dd1caf"
BASE_TOKEN_HASHES = {'crates/wholepact-signer/src/native_ui/runtime/coordinated_delivery_admission_v1.rs': '41cd3566bb9b2c6833efd24cd66c40df064ac5f3114f4462a837bec9e4286c30', 'crates/wholepact-signer/src/native_ui/witness_workspace/durable_delivery_v3/coordinated_admit_read_v1.rs': '3ade12cef9c580fc056125e29d895d6cfdb25377e8832dd55e5e86d26da84dda', 'crates/wholepact-signer/src/account/birth/enrollment/roster_v2/prepared_delivery_v3/coordinated_source_entry_v1/coordinated_delivery_source_v1/coordinated_admission_v1.rs': '84ec29dc3e0486ebef8d3003fc56f51585e58587c2b93e7e9fb1ec2a92e434fc', 'crates/wholepact-financial-coordinator-origin/src/signer_v3_admit_read_origin.rs': '11c38d2d80ef49e5fb2cab5bdad391b816383a54b67d8b271281ea07334863aa'}
UNCHANGED_FILES = {'crates/wholepact-financial-coordinator-origin/src/signer_continue_state.rs': 'f22c0ad3452dc038b0e34f45f8fbd1182c11113d6977d15b1bb347e838fe6cea', 'crates/wholepact-financial-coordinator-origin/src/financial_observer.rs': '67a92e04a03df01257be85ee99c8544be4f627c05c3800a6b5ae9b82cbd6dc4a', 'crates/wholepact-signer/src/ipc/coordinated_pair_v1.rs': '6025d99c16c02c3925c6053f554b85560a070a1ad800d977f8d203639965af4d', 'crates/wholepact-authority/src/transport.rs': '2c58ec5ae515ce13786ec81661901c9ba1c72a5f9827d3c925e4fbc48e4f2716', 'crates/wholepact-authority/src/transport/history_diagnostics_v1.rs': '0c7a3d7c5337c59c573ea85fd5d2cb6a85d09ebb0123007a9e09f4310304d324'}
HISTORY_BLOCK_SHA = '46e6069be3bfa405a7066fa64a38f7c66120e0bf70364b8cde0ec0b046394324'
OLD_HISTORY_BLOCK = '        let mut callback_error = None;\n        let result = self.opened.client.reconcile_history_checked_until(\n            action.original_read_deadline(),\n            || {\n                check().and_then(|_| check_source()).map_err(|error| {\n                    if callback_error.is_none() {\n                        callback_error = Some(error);\n                    }\n                    wholepact_authority::AuthorityError::Permission\n                })\n            },\n        );\n'
FINISH_SHA = 'b297cdf4bf324809ff50552bdfc4a192029a07c150679e8ffce6133dceba8d9e'
OLD_FINISH = '    pub fn finish_read(mut self) -> Result<()> {\n        self.check_current()?;\n        self.binding.owner.pair.entry.core.phase.step(\n            self.binding.owner.pair.entry.slot(),\n            151,\n            152,\n        )?;\n        self.consumed = true;\n        Ok(())\n    }'

# Exact P67 worker-result preservation delta. No deadline/currentness change.
READY_WORKER_CURRENT_SHA = '45ca71f1653973ed6909fc2011506ecef4f88ef291dfe5862857dba6d1f61f8c'
READY_WORKER_NEW = '            // Sender teardown can precede publication of thread completion.\n            // The unchanged nonblocking driver joins only after is_finished;\n            // its original actor, cancellation and transport checks keep running.\n            Err(std::sync::mpsc::TryRecvError::Disconnected) => Ok(None),'
READY_WORKER_OLD = '            Err(std::sync::mpsc::TryRecvError::Disconnected) if self.finished() => Ok(None),\n            Err(_) => Err(Error::Unavailable),'
READY_WORKER_TEST_INCLUDE = '\n#[cfg(test)]\n#[path = "coordinated_delivery_admission_v1/ready_disconnect_tests.rs"]\nmod ready_disconnect_tests;\n'
def restore_ready_worker(text):
    assert hashlib.sha256(text.encode()).hexdigest()==READY_WORKER_CURRENT_SHA
    assert text.count(READY_WORKER_NEW)==1 and text.count(READY_WORKER_TEST_INCLUDE)==1
    return text.replace(READY_WORKER_NEW,READY_WORKER_OLD,1).replace(READY_WORKER_TEST_INCLUDE,'',1)

def digest(text): return hashlib.sha256(text.encode()).hexdigest()
def tokens(text):
    return ''.join(token for token in re.findall(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/|[^\s]', text, re.S)
                   if not token.startswith(('//', '/*')))
def balanced_end(text, opening, left='(', right=')'):
    depth=0; quoted=False; escaped=False
    for i in range(opening,len(text)):
        c=text[i]
        if quoted:
            if escaped: escaped=False
            elif c=='\\': escaped=True
            elif c=='"': quoted=False
            continue
        if c=='"': quoted=True; continue
        if c==left: depth+=1
        elif c==right:
            depth-=1
            if depth==0:return i+1
    raise AssertionError('unbalanced selected kernel')
def unwrap(text):
    pattern=re.compile(r'actor_admit_read_(detail_)?result!\(')
    while True:
        matches=list(pattern.finditer(text))
        if not matches:return text
        match=matches[-1]; opening=match.end()-1; end=balanced_end(text,opening)
        body=text[opening+1:end-1]; stack=[]; quoted=False; escaped=False; commas=[]
        for i,c in enumerate(body):
            if quoted:
                if escaped:escaped=False
                elif c=='\\':escaped=True
                elif c=='"':quoted=False
                continue
            if c=='"':quoted=True
            elif c in '([{':stack.append(c)
            elif c in ')]}':stack.pop()
            elif c==',' and not stack:commas.append(i)
        n=1 if match.group(1) else 2
        assert len(commas)==n,(body,commas,n)
        text=text[:match.start()]+body[commas[-1]+1:].strip()+text[end:]
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True)
    root=parser.parse_args().source.resolve(); evidence=[]
    for relative,expected in UNCHANGED_FILES.items():
        raw=(root/relative).read_bytes();assert hashlib.sha256(raw).hexdigest()==expected,relative
    for relative,expected in BASE_TOKEN_HASHES.items():
        raw=(root/relative).read_text(); restored=raw
        if relative.endswith('/runtime/coordinated_delivery_admission_v1.rs'):
            restored=restore_ready_worker(restored)
        restored=restored.replace('        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        let _observation = crate::financial_ci_actor::AdmitReadObservation::enter();\n','')
        if relative.endswith('coordinated_admit_read_v1.rs'):
            start=restored.index('        let mut callback_error = None;')
            end=restored.index('        if let Some(error) = callback_error {',start)
            assert digest(restored[start:end])==HISTORY_BLOCK_SHA
            restored=restored[:start]+OLD_HISTORY_BLOCK+restored[end:]
            observed='        #[cfg(all(wholepact_financial_rendered_host_semantic_ci, feature = "synthetic-qualification"))]\n        if let Some(detail) = history_failure {\n            crate::financial_ci_actor::admit_read_detail_value(detail);\n        }\n'
            assert restored.count(observed)==1;restored=restored.replace(observed,'')
        if relative.endswith('signer_v3_admit_read_origin.rs'):
            start=restored.index('    /// Semantic failure reporting only.')
            end=restored.index('    pub fn finish_read(mut self)',start)
            hook=restored[start:end]
            assert digest(hook)==HOOK_SHA
            assert hook.count('self.binding.owner.pair.entry.core.close_with_failure_observation();')==1
            assert '#[cfg(wholepact_financial_rendered_host_semantic_ci)]' in hook
            restored=restored[:start]+restored[end:]
            start=restored.index('    pub fn finish_read(mut self)')
            end=restored.index('\n}\nimpl Drop for SignerV3AdmitReadFinalV1',start)
            assert digest(restored[start:end])==FINISH_SHA
            restored=restored[:start]+OLD_FINISH+restored[end:]
        restored=unwrap(restored)
        assert digest(tokens(restored))==expected,relative
        evidence.append({'path':relative,'baseline_token_sha256':expected,'current_sha256':digest(raw)})
    lib=(root/'crates/wholepact-signer/src/lib.rs').read_text()
    start=lib.index('macro_rules! actor_admit_read_result {')
    end=lib.index('macro_rules! actor_driver_detail_result {',start)
    assert digest(lib[start:end])==MACROS_SHA
    # Existing diagnosed history performs the same kernel once; only the
    # preexisting diagnostic observer additionally samples costs. None emitted.
    transport=(root/'crates/wholepact-authority/src/transport.rs').read_text()
    start=transport.index('    pub fn reconcile_history_diagnosed_checked_until(')
    end=transport.index('    fn reconcile_history_inner(',start)
    selected=transport[start:end]
    assert selected.count('self.reconcile_history_inner(')==1
    assert 'require_before_caller_deadline(deadline)' in selected
    assert 'result.map_err(|error| observer.into_failure(error))' in selected
    print(json.dumps({'source_audit_passed':True,'baseline':BASELINE,'normalized_files':evidence,
        'unchanged_kernel_files':UNCHANGED_FILES,'runtime_execution':False,
        'intentional_semantic_delta':'Terminal owned error advances existing restrictive close before automatic drops.'},sort_keys=True))
if __name__=='__main__':main()
