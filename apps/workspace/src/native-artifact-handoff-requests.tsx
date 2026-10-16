import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { WholepactClient, type AgreementView, type CapabilitySet, type NativeArtifactHandoffRequestView } from '@wholepact/sdk';
import { Notice } from './components';
import { errorText } from './App';
import { nativeCommand, nativeCommandVersion, subscribeNativeCommand, beginNativeCommand, finishNativeCommand } from './native-request-session';
import { nativeArtifactHandoffRequestMetadata, canRequestArtifactHandoff } from './native-artifact-handoff-request-model';

export function NativeArtifactHandoffPanel({view,client,capabilities,permissions,stale,onChanged}:{
  view:AgreementView;client:WholepactClient;capabilities:CapabilitySet|null;permissions:string[];stale:boolean;onChanged:(message:string)=>Promise<void>;
}) {
  const agreement=view.agreement.agreement_id;
  const version=useSyncExternalStore(useCallback(listener=>subscribeNativeCommand(client,agreement,listener),[client,agreement]),useCallback(()=>nativeCommandVersion(client,agreement),[client,agreement]));
  const command=nativeCommand(client,agreement);
  const [requests,setRequests]=useState<NativeArtifactHandoffRequestView[]|null>(null);
  const [inventoryVersion,setInventoryVersion]=useState(-1);
  const [kind,setKind]=useState<'signer_review'|'signature_intake'>('signer_review');
  const [candidate,setCandidate]=useState('');const [job,setJob]=useState('');const [error,setError]=useState('');
  const generation=useRef(0);const lifetime=useRef(0);
  useEffect(()=>{lifetime.current++;return()=>{lifetime.current++;};},[client,agreement]);
  const available=capabilities?.features.native_artifact_handoff_requests?.api_access==='local_http_request_only';
  const allowed=available&&permissions.includes('coordinate')&&permissions.includes('disclose')&&!stale&&inventoryVersion===version;
  const busy=command?.phase==='pending';const uncertain=command?.phase==='uncertain';
  const read=async()=>{
    const current=++generation.current;const readVersion=nativeCommandVersion(client,agreement);
    try { const result=nativeArtifactHandoffRequestMetadata(await client.nativeArtifactHandoffRequests(agreement),agreement);
      if(current===generation.current&&readVersion===nativeCommandVersion(client,agreement)){setRequests(result);setInventoryVersion(readVersion);setError('');}
    } catch(caught){if(current===generation.current){setRequests(null);setError(errorText(caught));}}
  };
  useEffect(()=>{if(available)void read();return()=>{generation.current++;};},[client,agreement,available,view.revision,version]);
  const submit=async(withdrawal?:NativeArtifactHandoffRequestView)=>{
    if(withdrawal ? !allowed||busy||uncertain||withdrawal.state!=='queued' : !canRequestArtifactHandoff(requests,candidate,job,kind,allowed,busy,uncertain))return;
    const attempt={kind:withdrawal?'artifact_handoff_withdraw' as const:'artifact_handoff' as const,handoffKind:withdrawal?.kind??kind,candidate:withdrawal?.candidate_id??candidate,jobId:withdrawal?.job_id??job,revision:view.revision,key:`artifact-handoff-${crypto.randomUUID()}`,requestId:withdrawal?.request_id};
    if(!beginNativeCommand(client,agreement,attempt))return;
    const currentLifetime=lifetime.current;setError('');
    try {
      if(withdrawal)await client.withdrawNativeArtifactHandoffRequest(agreement,withdrawal.request_id,{idempotencyKey:attempt.key,expectedRevision:attempt.revision});
      else await client.requestNativeArtifactHandoff(agreement,{candidate_id:attempt.candidate,job_id:attempt.jobId,kind:attempt.handoffKind},{idempotencyKey:attempt.key,expectedRevision:attempt.revision});
      if(currentLifetime===lifetime.current){await onChanged(withdrawal?'Never-started native handoff withdrawn. Original artifacts are unaffected.':'Exact native handoff request recorded. Independent owner consent is still required.');if(currentLifetime===lifetime.current)await read();}
      finishNativeCommand(client,agreement,attempt.key,true);
    } catch(caught){finishNativeCommand(client,agreement,attempt.key,false);if(currentLifetime===lifetime.current){setError(errorText(caught));await read();}}
  };
  if(!available)return null;
  return <section aria-label="Native artifact handoff">
    <h3>Hand off the original proved artifact</h3>
    <Notice>Queue exact signer review or intake of existing signatures. Stop and drain the service, then run native-artifact-handoff-request. Each owner separately approves actual disclosure or retained-result use in the native app. Only never-started requests can be withdrawn. An attempted handoff does not establish review completion, signatures or payment. No viewing keys, private artifacts or endpoint configuration belong in this form.</Notice>
    <label>Native workflow<select value={kind} onChange={event=>setKind(event.target.value as 'signer_review'|'signature_intake')} disabled={busy||uncertain}><option value="signer_review">Signer review</option><option value="signature_intake">Intake existing signatures</option></select></label>
    <label>Exact candidate<select value={candidate} onChange={event=>{setCandidate(event.target.value);setJob('');}} disabled={busy||uncertain}><option value="">Choose candidate</option>{(view.candidates??[]).map(item=><option key={item.candidate_id} value={item.candidate_id}>{item.candidate_id}</option>)}</select></label>
    <label>Original retained job ID<input value={job} onChange={event=>setJob(event.target.value)} disabled={busy||uncertain} placeholder="proof-…"/></label>
    <p>Use the exact ID printed by the native host, after reconciling its coordination checkpoint metadata. Never paste private artifacts, viewing keys or witnesses.</p>
    <button className="button secondary" disabled={!canRequestArtifactHandoff(requests,candidate,job,kind,allowed,busy,uncertain)} onClick={()=>void submit()}>Request separate native handoff</button>
    <button className="button secondary" disabled={busy} onClick={()=>void read()}>Read retained handoff requests</button>
    {error&&<p role="alert">{error}</p>}
    {command&&<Notice warning>{command.kind}: {command.phase}. Preserve browser command key {command.key}, candidate {command.candidate}, original job {command.jobId??'not supplied'}, revision {command.revision}. Do not create a replacement after an uncertain response; inspect retained native state.</Notice>}
    {requests?.map(item=><div key={item.request_id}><p>Request {item.request_id}; job {item.job_id}; state {item.state}; {item.kind} handoff {item.handoff_status}. Account exposure remains unknown.</p>
      {item.state==='queued'&&<><p>{item.queued_revision===view.revision?'Awaiting native review.':'Stale revision; withdraw before requesting a fresh request.'}</p><button className="button secondary" disabled={!allowed||busy||uncertain} onClick={()=>void submit(item)}>Withdraw never-started handoff</button></>}
      {item.handoff_status==='attempted_outcome_unknown'&&<p>The handoff may have disclosed private bytes or retained signatures. Inspect the original native owners and exact journals; do not reset the request or infer no effect.</p>}
    </div>)}
  </section>;
}
