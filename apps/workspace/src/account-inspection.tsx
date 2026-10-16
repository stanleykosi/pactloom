import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { WholepactClient, type AgreementView, type CapabilitySet, type NativeAccountInspectionRequestView, type OwnerInspectionSnapshot } from '@wholepact/sdk';
import { Badge, Money, Notice } from './components';
import { errorText } from './App';
import { inspectionRejectedBeforeCommit } from './account-inspection-outcome';
import { nativeCommand, nativeCommandVersion, subscribeNativeCommand, beginNativeCommand, finishNativeCommand, retryNativeCommand, type NativeCommand } from './native-request-session';

export function AccountInspection({ agreements, client, capabilities, permissions, stale, onChanged }: { agreements:AgreementView[]; client:WholepactClient; capabilities:CapabilitySet|null; permissions:string[]; stale:boolean; onChanged:(message:string)=>Promise<void> }) {
  const [agreement, setAgreement] = useState('');
  const view = agreements.find(v => v.agreement.agreement_id === agreement);
  const supported = capabilities?.features.native_account_inspection_requests?.api_access === 'local_http_request_only';
  return <section className="panel"><div className="section-heading"><h2>Owner-reviewed account audit</h2><Badge>Historical metadata</Badge></div><div className="panel-text">
    <Notice>Inspect retained local authorization, sponsor and automation metadata under a separate signer-native disclosure review. Balance, account-wide pending exposure, settled spending and remaining budget stay unknown. Empty results cannot establish that another instance or missing history has no authorizations.</Notice>
    {!supported ? <p>This service has no native inspection request queue. Account-wide figures remain unavailable.</p> : <><label>Agreement scope<select value={agreement} onChange={event => setAgreement(event.target.value)}><option value="">Choose an agreement</option>{agreements.map(v => <option key={v.agreement.agreement_id} value={v.agreement.agreement_id}>{v.agreement.purpose}</option>)}</select></label>{view && <InspectionScope key={`${agreement}`} view={view} client={client} permissions={permissions} stale={stale} onChanged={onChanged}/>}</>}
  </div></section>;
}
function InspectionScope({ view, client, permissions, stale, onChanged }:{ view:AgreementView; client:WholepactClient; permissions:string[]; stale:boolean; onChanged:(message:string)=>Promise<void> }) {
  const agreement = view.agreement.agreement_id;
  const version = useSyncExternalStore(useCallback(listener => subscribeNativeCommand(client, agreement, listener), [client, agreement]), useCallback(() => nativeCommandVersion(client, agreement), [client, agreement]));
  const command = nativeCommand(client, agreement);
  const [candidateId, setCandidateId] = useState(''); const [participantId, setParticipantId] = useState('');
  const [inventory, setInventory] = useState<{ revision:number; version:number; items:NativeAccountInspectionRequestView[] }|null>(null);
  const [error, setError] = useState(''); const generation = useRef(0); const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; generation.current++; }; }, [client, agreement]);
  const candidate = view.candidates?.find(c => c.candidate_id === candidateId);
  const read = async () => {
    const current = ++generation.current; const v = nativeCommandVersion(client, agreement);
    try { const items = await client.nativeAccountInspectionRequests(agreement); if (alive.current && current === generation.current && v === nativeCommandVersion(client, agreement)) { setInventory({ revision:view.revision, version:v, items }); setError(''); } }
    catch (caught) { if (alive.current && current === generation.current) { setInventory(null); setError(errorText(caught)); } }
  };
  useEffect(() => { void read(); return () => { generation.current++; }; }, [client, agreement, view.revision, version]);
  const current = inventory?.revision === view.revision && inventory.version === version;
  const allowed = !stale && current && permissions.includes('coordinate') && permissions.includes('disclose');
  const execute = async (attempt:NativeCommand) => {
    try {
      if (attempt.kind === 'owner_inspection_withdraw') await client.withdrawNativeAccountInspection(agreement, attempt.requestId!, { idempotencyKey:attempt.key, expectedRevision:attempt.revision });
      else await client.requestNativeAccountInspection(agreement, { candidate_id:attempt.candidate, participant_id:attempt.participantId! }, { idempotencyKey:attempt.key, expectedRevision:attempt.revision });
      finishNativeCommand(client, agreement, attempt.key, true);
      if (alive.current) await onChanged('Original account inspection request acknowledged. Native review remains separate; no financial authority was granted.');
    } catch (caught) {
      const rejected = inspectionRejectedBeforeCommit(caught);
      finishNativeCommand(client, agreement, attempt.key, rejected);
      if (alive.current) {
        setError(errorText(caught));
        if (rejected) await onChanged('The service rejected this inspection command before commit. Refresh the agreement before creating a new request.');
      }
    }
  };
  const submit = (withdrawal?:NativeAccountInspectionRequestView) => {
    if (!allowed || command || !withdrawal && !candidate?.proposal.manifest.participants.some(p => p.participant_id === participantId) || withdrawal && withdrawal.state !== 'queued') return;
    const attempt = { kind:withdrawal ? 'owner_inspection_withdraw' as const : 'owner_inspection' as const,
      candidate:withdrawal?.request.candidate_id ?? candidateId, participantId:withdrawal?.request.participant_id ?? participantId,
      requestId:withdrawal?.request.request_id, revision:view.revision, key:`account-inspection-${crypto.randomUUID()}` };
    if (beginNativeCommand(client, agreement, attempt)) void execute({ ...attempt, phase:'pending' });
  };
  const retry = () => { if (!command || !['owner_inspection','owner_inspection_withdraw'].includes(command.kind)) return; const original = retryNativeCommand(client, agreement, command.key); if (original) void execute(original); };
  return <>
    <label>Exact candidate<select value={candidateId} disabled={!!command} onChange={event => { setCandidateId(event.target.value); setParticipantId(''); }}><option value="">Choose a candidate</option>{view.candidates?.map(c => <option key={c.candidate_id} value={c.candidate_id}>{c.candidate_id}</option>)}</select></label>
    <label>Participant scope<select value={participantId} disabled={!!command || !candidate} onChange={event => setParticipantId(event.target.value)}><option value="">Choose a participant</option>{candidate?.proposal.manifest.participants.map(p => <option key={p.participant_id} value={p.participant_id}>{p.participant_id}</option>)}</select></label>
    <p>The signer derives its account from the unlocked vault and approved pairing. Candidate account labels are not ownership evidence. This request cannot read an arbitrary account.</p>
    <button className="button secondary" disabled={!allowed || !!command || !participantId} onClick={() => submit()}>Request native account inspection</button>
    <button className="button secondary" disabled={command?.phase === 'pending'} onClick={() => void read()}>Read original saved results</button>
    {command && <Notice warning>Pending original command: {command.kind}, {command.phase}. Key {command.key}; revision {command.revision}; candidate {command.candidate}; participant {command.participantId ?? 'not specified'}. Navigation and reads preserve this command. {command.phase === 'uncertain' && ['owner_inspection','owner_inspection_withdraw'].includes(command.kind) && <button className="button secondary" onClick={retry}>Retry exact original command</button>}</Notice>}
    <p>Stop and drain the local service, then use native-account-inspection-request in the native host. An existing installed-signer session and separate owner disclosure approval are required. Restart the service to read results here. native-account-inspection-status returns only the original committed result. A started request is never executed again, even if its result is missing.</p>
    {error && <p className="form-error" role="alert">{error}</p>}
    {current && inventory.items.map(item => <section className="saved-review" key={item.request.request_id}><p>Request {item.request.request_id} · {item.state}</p><p>Original candidate {item.request.candidate_id}; participant {item.request.participant_id}; original journal revision {item.original_revision}; manifest {item.request.manifest_digest}.</p>
      {item.state === 'queued' && <button className="button secondary" disabled={!allowed || !!command} onClick={() => submit(item)}>Withdraw never-started request</button>}
      {item.result ? <InspectionResult result={item.result}/> : <p>No committed original inspection result. All account-wide figures remain unknown.{item.state === 'attempt_started' && ' An interrupted native read may have occurred; do not reset or retry native execution.'}</p>}
    </section>)}
  </>;
}
function InspectionResult({ result:s }:{result:OwnerInspectionSnapshot}) {
  return <><p>Native-approved local journal snapshot: {new Date(s.inspected_at_ms).toISOString()}. Historical, with no live witness or chain observation.</p><p>Account {s.account_id}; native source owner {s.source_principal_id}; receiving client {s.request.principal_id}; writer epoch {s.writer_epoch}; recovery required: {s.recovery_required ? 'yes' : 'not recorded in this snapshot'}.</p><Notice warning>Account balance, aggregate pending exposure, settled debit, remaining budget and present automation eligibility: unknown. Recorded expiry and settlement labels do not clear exposure.</Notice>
    <h3>Scoped original authorization metadata</h3>{s.authorizations.length === 0 && <p>No original authorizations in this scoped snapshot. This is not evidence of zero exposure.</p>}{s.authorizations.map(a => <div key={a.authorization_id}><p>{a.authorization_id} · maximum approved debit <Money value={a.maximum_debit}/></p><p>Proposal {a.proposal_id}; expiry height {a.transaction_expiry_height}; original consent {a.original_consent_ref}. Result retained: {a.result_retained ? 'yes' : 'not recorded'}. Latest historical settlement label: {a.latest_settlement_record ?? 'none'}. Automation grant: {a.automation_grant_id ?? 'none'}.</p></div>)}
    <h3>Native sponsor constraints</h3>{s.sponsor_policies.length === 0 && <p>No scoped native sponsor policy recorded.</p>}{s.sponsor_policies.map(p => <div key={p.policy_key}><p>Policy {p.policy_key}, version {p.version}: {p.status}. Budget ceiling <Money value={p.aggregate_budget}/>; remaining budget unknown. Policy expiry: {p.expires_at ?? 'not specified'}.</p><p>Terms {p.terms_digest}; witness {p.witness_id}; witness policy {p.witness_policy_digest}. This identifies saved policy provenance, not a current witness observation.</p></div>)}
    <h3>Native automation grant audit</h3>{s.automation_grants.length === 0 && <p>No scoped native automation grant recorded.</p>}{s.automation_grants.map(g => <div key={g.grant_id}><p>{g.grant_id}, revision {g.revision}: {g.status}. Application {g.application_id}. Expiry {new Date(g.expires_at_ms).toISOString()}.</p><p>Per-payment cap <Money value={g.maximum_payment_debit}/>; outstanding-debit ceiling <Money value={g.maximum_outstanding_debit}/>. Terms {g.terms_digest}. Saved status does not grant current signing eligibility; activation, pause, revocation and renewal remain separate native controls.</p></div>)}
  </>;
}
