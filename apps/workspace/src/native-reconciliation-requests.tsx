import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { WholepactClient, nativeDispatchRequestMetadata, type AgreementView, type CapabilitySet, type NativeDispatchRequestView, type NativeReconciliationRequest, type NativeReconciliationRequestView } from '@wholepact/sdk';
import { Notice } from './components';
import { errorText } from './App';
import { nativeCommand, nativeCommandVersion, subscribeNativeCommand, beginNativeCommand, finishNativeCommand } from './native-request-session';
import { nativeReconciliationRequestMetadata, originalReconciliationDispatch, canRequestNativeReconciliation, validateReconciliationOriginals, reconciliationObservationLabel } from './native-reconciliation-request-model';

type Inventory = { client: WholepactClient; agreement: string; revision: number; version: number; requests: NativeReconciliationRequestView[]; dispatches: NativeDispatchRequestView[] };
export function NativeReconciliationPanel({ view, client, capabilities, permissions, stale, onChanged }: {
  view: AgreementView; client: WholepactClient; capabilities: CapabilitySet | null; permissions: string[]; stale: boolean; onChanged: (message: string) => Promise<void>;
}) {
  const agreement = view.agreement.agreement_id;
  const version = useSyncExternalStore(useCallback(listener => subscribeNativeCommand(client, agreement, listener), [client, agreement]), useCallback(() => nativeCommandVersion(client, agreement), [client, agreement]));
  const command = nativeCommand(client, agreement);
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [dispatchId, setDispatchId] = useState('');
  const [kind, setKind] = useState<NativeReconciliationRequest['kind']>('provider_observation');
  const [participantId, setParticipantId] = useState(''); const [recordId, setRecordId] = useState('');
  const [error, setError] = useState(''); const generation = useRef(0); const lifetime = useRef(0);
  useEffect(() => { lifetime.current++; return () => { lifetime.current++; }; }, [client, agreement]);
  const available = capabilities?.features.native_reconciliation_requests?.api_access === 'local_http_request_only';
  const currentInventory = inventory?.client === client && inventory.agreement === agreement && inventory.revision === view.revision && inventory.version === version ? inventory : null;
  const requests = currentInventory?.requests ?? null; const dispatches = currentInventory?.dispatches ?? null;
  const allowed = available && permissions.includes('coordinate') && permissions.includes('disclose') && !stale && currentInventory !== null;
  const busy = command?.phase === 'pending'; const uncertain = command?.phase === 'uncertain';
  const request: NativeReconciliationRequest = kind === 'provider_observation' ? { kind, dispatch_request_id: dispatchId }
    : { kind, dispatch_request_id: dispatchId, participant_id: participantId, record_id: recordId };
  const read = async () => {
    const current = ++generation.current; const readVersion = nativeCommandVersion(client, agreement);
    try {
      const [rawRequests, rawDispatches] = await Promise.all([client.nativeReconciliationRequests(agreement), client.nativeDispatchRequests(agreement)]);
      const checkedRequests = nativeReconciliationRequestMetadata(rawRequests, agreement);
      const checkedDispatches = nativeDispatchRequestMetadata(rawDispatches, agreement);
      validateReconciliationOriginals(checkedRequests, checkedDispatches);
      if (current === generation.current && readVersion === nativeCommandVersion(client, agreement)) {
        setInventory({ client, agreement, revision: view.revision, version: readVersion, requests: checkedRequests, dispatches: checkedDispatches }); setError('');
      }
    } catch (caught) { if (current === generation.current) { setInventory(null); setError(errorText(caught)); } }
  };
  useEffect(() => { if (available) void read(); return () => { generation.current++; }; }, [client, agreement, available, view.revision, version]);
  const submit = async (withdrawal?: NativeReconciliationRequestView) => {
    if (withdrawal ? !allowed || busy || uncertain || withdrawal.state !== 'queued' : !canRequestNativeReconciliation(requests, dispatches, request, allowed, busy, uncertain)) return;
    const exact: NativeReconciliationRequest = withdrawal === undefined ? request : withdrawal.kind === 'provider_observation'
      ? { kind: withdrawal.kind, dispatch_request_id: withdrawal.dispatch_request_id }
      : { kind: withdrawal.kind, dispatch_request_id: withdrawal.dispatch_request_id, participant_id: withdrawal.participant_id, record_id: withdrawal.record_id };
    const original = originalReconciliationDispatch(dispatches, exact.dispatch_request_id);
    if (!original) return;
    const attempt = {
      kind: withdrawal ? 'reconciliation_withdraw' as const : 'settlement_reconciliation' as const,
      reconciliationKind: exact.kind, dispatchRequestId: exact.dispatch_request_id,
      participantId: exact.kind === 'independent_record_resolution' ? exact.participant_id : undefined,
      recordId: exact.kind === 'independent_record_resolution' ? exact.record_id : undefined,
      transactionRequestId: original.transaction_request_id, intakeRequestId: original.intake_request_id,
      candidate: original.candidate_id, jobId: original.job_id, revision: view.revision,
      key: `reconciliation-request-${crypto.randomUUID()}`, requestId: withdrawal?.request_id,
    };
    if (!beginNativeCommand(client, agreement, attempt)) return;
    const currentLifetime = lifetime.current; setError('');
    try {
      if (withdrawal) await client.withdrawNativeReconciliationRequest(agreement, withdrawal.request_id, { idempotencyKey: attempt.key, expectedRevision: attempt.revision });
      else await client.requestNativeReconciliation(agreement, exact, { idempotencyKey: attempt.key, expectedRevision: attempt.revision });
      if (currentLifetime === lifetime.current) {
        await onChanged(withdrawal ? 'Never-started reconciliation request withdrawn. Original dispatch history and exposure remain unchanged.' : 'Distinct exact-original reconciliation review request recorded. Separate native review, current evidence and required consent remain necessary.');
        if (currentLifetime === lifetime.current) await read();
      }
      finishNativeCommand(client, agreement, attempt.key, true);
    } catch (caught) {
      finishNativeCommand(client, agreement, attempt.key, false);
      if (currentLifetime === lifetime.current) { setError(errorText(caught)); await read(); }
    }
  };
  if (!available) return null;
  return <section aria-label="Native reconciliation request and historical status">
    <h3>Request separate native observation or record review</h3>
    <Notice>These requests are metadata only. Stop and drain the service before native-reconciliation-request or native-reconciliation-status. A native owner must select the exact original dispatch and retained journal. Provider observation needs its own native read decision. Independent resolution additionally requires an existing exact private participant record, the genuine original signer and current local-node evidence. The browser cannot supply those decisions or evidence.</Notice>
    <p>Every started request stays started, including after interrupted or apparently successful work. A distinct new review/read request may be queued for the same original after a prior request started. It never resets that request, repeats a payment, or skips current native verification. An unresolved browser command must be inspected before another command can be created.</p>
    <label>Original started dispatch request ID<input value={dispatchId} onChange={event => setDispatchId(event.target.value)} disabled={busy || uncertain} maxLength={64} placeholder="64-character original request ID"/></label>
    <label>Separate native request kind<select value={kind} onChange={event => setKind(event.target.value as NativeReconciliationRequest['kind'])} disabled={busy || uncertain}>
      <option value="provider_observation">Provider observation only</option><option value="independent_record_resolution">Independent exact private record resolution review</option>
    </select></label>
    {kind === 'independent_record_resolution' && <>
      <label>Existing record participant ID<input value={participantId} onChange={event => setParticipantId(event.target.value)} disabled={busy || uncertain} maxLength={128}/></label>
      <label>Existing private record ID<input value={recordId} onChange={event => setRecordId(event.target.value)} disabled={busy || uncertain} maxLength={128}/></label>
      <p>The protected engine must find this exact participant-owned record for the original candidate and transaction. No record is created here. A provider report, saved success or browser approval cannot replace fresh independent evidence and original-signer checks.</p>
    </>}
    <p>Paste only the metadata identifiers above. Do not paste keys, raw transactions, private records, provider endpoints or reports. The original operation, journal and transaction identities are derived from the retained dispatch.</p>
    <button className="button secondary" disabled={!canRequestNativeReconciliation(requests, dispatches, request, allowed, busy, uncertain)} onClick={() => void submit()}>Request distinct native review</button>
    <button className="button secondary" disabled={busy} onClick={() => void read()}>Read retained reconciliation metadata</button>
    {error && <p role="alert">{error}</p>}
    {command && <Notice warning>{command.kind}: {command.phase}. Preserve command key {command.key}, dispatch {command.dispatchRequestId ?? 'not supplied'}, request {command.requestId ?? 'not acknowledged'}, kind {command.reconciliationKind ?? 'not supplied'}, participant {command.participantId ?? 'not supplied'}, record {command.recordId ?? 'not supplied'}, candidate {command.candidate}, revision {command.revision}. A read, navigation or historical result never clears an uncertain command.</Notice>}
    {requests?.map(item => <div key={item.request_id}>
      <p>Request {item.request_id}; kind {item.kind}; original dispatch {item.dispatch_request_id}; state {item.state}; historical outcome {item.outcome_status}.</p>
      <p>Original transaction {item.txid}; immutable operation {item.operation_id}; original submission journal {item.submission_journal_identity}.</p>
      {item.kind === 'independent_record_resolution' && <p>Exact private record selector: participant {item.participant_id}; record {item.record_id}. Private record contents remain native.</p>}
      {item.state === 'queued' && <>
        <p>{item.queued_revision === view.revision ? 'Awaiting separate native review.' : 'Stale queue revision; withdraw this never-started request before a new native review.'} Withdrawal does not clear exposure or remove original history.</p>
        <button className="button secondary" disabled={!allowed || busy || uncertain} onClick={() => void submit(item)}>Withdraw never-started request</button>
      </>}
      {item.state === 'attempt_started' && <p>This request is permanently started. Missing status, an empty journal and provider reports never prove non-delivery, independent settlement, zero exposure or permission to replace payment.</p>}
      {item.resolution_commit && <Notice>Historical exact-original independent resolution was applied. Its observation is stale. This does not establish current settlement, global account exposure clearance or permission for another payment. Any new native review still needs current independent evidence and the original signer.</Notice>}
      {item.observations.length > 0 && <details><summary>Retained historical snapshots ({item.observations.length}, maximum 16)</summary>{item.observations.map((snapshot, index) => <div key={index}>
        <p>Snapshot {index + 1}: {reconciliationObservationLabel(snapshot)}.</p>
        <p>Retained submission state: {snapshot.submission.intent?.historical_provider_state ?? 'unknown'}; recorded attempts: {snapshot.submission.attempts.length}.</p>
        {snapshot.report && <>
          <p>Stale historical observation from Unix second {snapshot.report.observed_at_unix_seconds}; previous validity ended at {snapshot.report.valid_until_unix_seconds}. Stored policy: {snapshot.report.policy.required_confirmations} confirmations, expiry observation depth {snapshot.report.policy.expiry_observation_depth}.</p>
          <p>Named policy sources: {snapshot.report.policy.sources.join(', ')}. Retained sources: {snapshot.report.source_ids.join(', ') || 'none'}.</p>
          {snapshot.report.source_tips.map(source => <p key={source.source_id}>Source {source.source_id}: historical tip height {source.tip.height}, hash {source.tip.hash}.</p>)}
          <p>Historical confidence loss: {snapshot.report.confidence_lost ? 'recorded' : 'not recorded'}; historical reorganization: {snapshot.report.reorganization_observed ? 'recorded' : 'not recorded'}.</p>
        </>}
      </div>)}</details>}
    </div>)}
    <p>History is bounded by the shared request quota, 16 snapshots per request and the existing 1 MiB agreement limit. Metadata persistence can fail after native effects. Preserve the exact original journals; history is never evicted to make room.</p>
  </section>;
}
