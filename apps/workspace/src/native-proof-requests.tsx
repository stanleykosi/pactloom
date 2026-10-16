import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { WholepactClient, type AgreementView, type CapabilitySet, type NativeProofRequestView } from '@wholepact/sdk';
import { Notice } from './components';
import { errorText } from './App';
import { nativeCommand, nativeCommandVersion, subscribeNativeCommand, beginNativeCommand, finishNativeCommand } from './native-request-session';
import { nativeProofRequestMetadata, canRequestProofReconciliation } from './native-proof-request-model';

export function NativeProofReconciliationPanel({view,client,capabilities,permissions,stale,onChanged}:{
  view:AgreementView;client:WholepactClient;capabilities:CapabilitySet|null;permissions:string[];stale:boolean;onChanged:(message:string)=>Promise<void>;
}) {
  const agreement=view.agreement.agreement_id;
  const version=useSyncExternalStore(useCallback(listener=>subscribeNativeCommand(client,agreement,listener),[client,agreement]),useCallback(()=>nativeCommandVersion(client,agreement),[client,agreement]));
  const command=nativeCommand(client,agreement);
  const [requests,setRequests]=useState<NativeProofRequestView[]|null>(null);
  const [inventoryVersion,setInventoryVersion]=useState(-1);
  const [candidate,setCandidate]=useState('');const [job,setJob]=useState('');const [error,setError]=useState('');
  const generation=useRef(0);const lifetime=useRef(0);
  useEffect(()=>{lifetime.current++;return()=>{lifetime.current++;};},[client,agreement]);
  const available=capabilities?.features.native_proof_reconciliation_requests?.api_access==='local_http_request_only';
  const allowed=available&&permissions.includes('coordinate')&&permissions.includes('disclose')&&!stale&&inventoryVersion===version;
  const busy=command?.phase==='pending';const uncertain=command?.phase==='uncertain';
  const read=async()=>{
    const current=++generation.current;const readVersion=nativeCommandVersion(client,agreement);
    try { const result=nativeProofRequestMetadata(await client.nativeProofRequests(agreement),agreement);
      if(current===generation.current&&readVersion===nativeCommandVersion(client,agreement)){setRequests(result);setInventoryVersion(readVersion);setError('');}
    } catch(caught){if(current===generation.current){setRequests(null);setError(errorText(caught));}}
  };
  useEffect(()=>{if(available)void read();return()=>{generation.current++;};},[client,agreement,available,view.revision,version]);
  const submit=async(withdrawal?:NativeProofRequestView)=>{
    if(withdrawal ? !allowed||busy||uncertain||withdrawal.state!=='queued' : !canRequestProofReconciliation(requests,candidate,job,allowed,busy,uncertain))return;
    const attempt={kind:withdrawal?'proof_withdraw' as const:'proof_reconcile' as const,candidate:withdrawal?.candidate_id??candidate,jobId:withdrawal?.job_id??job,revision:view.revision,key:`proof-request-${crypto.randomUUID()}`,requestId:withdrawal?.request_id};
    if(!beginNativeCommand(client,agreement,attempt))return;
    const currentLifetime=lifetime.current;setError('');
    try {
      if(withdrawal)await client.withdrawNativeProofRequest(agreement,withdrawal.request_id,{idempotencyKey:attempt.key,expectedRevision:attempt.revision});
      else await client.requestNativeProofReconciliation(agreement,{candidate_id:attempt.candidate,job_id:attempt.jobId},{idempotencyKey:attempt.key,expectedRevision:attempt.revision});
      if(currentLifetime===lifetime.current){await onChanged(withdrawal?'Never-started proof inspection request withdrawn. Original artifacts are unaffected.':'Exact job inspection request recorded. Separate native consent is still required; no prover has run.');if(currentLifetime===lifetime.current)await read();}
      finishNativeCommand(client,agreement,attempt.key,true);
    } catch(caught){finishNativeCommand(client,agreement,attempt.key,false);if(currentLifetime===lifetime.current){setError(errorText(caught));await read();}}
  };
  if(!available)return null;
  return <section aria-label="Native proof status reconciliation">
    <h3>Refresh exact retained proof-job metadata</h3>
    <Notice>This requests native inspection of an existing encrypted job, not proof generation. Stop and drain the service, open the existing financial profile if needed, then run native-proof-reconcile-request. Original native consent and receipt checks apply. Cached status never establishes live worker state, chain validity or complete account exposure.</Notice>
    <label>Exact candidate<select value={candidate} onChange={event=>{setCandidate(event.target.value);setJob('');}} disabled={busy||uncertain}><option value="">Choose candidate</option>{(view.candidates??[]).map(item=><option key={item.candidate_id} value={item.candidate_id}>{item.candidate_id}</option>)}</select></label>
    <label>Original retained job ID<input value={job} onChange={event=>setJob(event.target.value)} disabled={busy||uncertain} placeholder="proof-…"/></label>
    <p>Use the exact ID printed by the native host, including when its coordination cache is missing. Never paste private artifacts, viewing keys or witnesses.</p>
    <button className="button secondary" disabled={!canRequestProofReconciliation(requests,candidate,job,allowed,busy,uncertain)} onClick={()=>void submit()}>Request native job inspection</button>
    <button className="button secondary" disabled={busy} onClick={()=>void read()}>Read retained inspection requests</button>
    {error&&<p role="alert">{error}</p>}
    {command&&<Notice warning>{command.kind}: {command.phase}. Preserve browser command key {command.key}, candidate {command.candidate}, original job {command.jobId??'not supplied'}, revision {command.revision}. Do not create a replacement after an uncertain response; inspect retained native state.</Notice>}
    {requests?.map(item=><div key={item.request_id}><p>Request {item.request_id}; job {item.job_id}; state {item.state}; reconciliation {item.reconciliation_status}. Account exposure remains unknown.</p>
      {item.reconciliation_status==='cached_reconciliation_recorded'&&<p>Exact coordination operation {item.reconciliation_operation_id} is retained. This is cached metadata, not current private-worker liveness.</p>}
      {item.state==='queued'&&<><p>{item.queued_revision===view.revision?'Awaiting native review.':'Stale revision; withdraw before requesting a fresh inspection.'}</p><button className="button secondary" disabled={!allowed||busy||uncertain} onClick={()=>void submit(item)}>Withdraw never-started inspection</button></>}
      {item.reconciliation_status==='unknown'&&<p>The attempt may have read private state. No exact reconciliation result is established; do not reset or run a prover.</p>}
    </div>)}
  </section>;
}
