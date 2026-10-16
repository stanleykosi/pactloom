import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { WholepactClient, type AgreementView, type CapabilitySet, type NativeRequestView } from '@wholepact/sdk';
import { Notice } from './components';
import { errorText } from './App';
import { nativeRequestMetadata, canRequestNativeConstruction } from './native-request-model';
import { nativeCommand, nativeCommandVersion, subscribeNativeCommand, beginNativeCommand, finishNativeCommand } from './native-request-session';

export function NativeConstructionPanel({ view, client, capabilities, permissions, stale, onChanged }: {
  view: AgreementView; client: WholepactClient; capabilities: CapabilitySet | null;
  permissions: string[]; stale: boolean; onChanged: (message: string) => Promise<void>;
}) {
  const [requests, setRequests] = useState<NativeRequestView[] | null>(null);
  const [error, setError] = useState('');
  const agreement = view.agreement.agreement_id;
  const version = useSyncExternalStore(useCallback(listener => subscribeNativeCommand(client, agreement, listener), [client, agreement]), useCallback(() => nativeCommandVersion(client, agreement), [client, agreement]));
  const command = nativeCommand(client, agreement);
  const [inventoryVersion, setInventoryVersion] = useState(-1);
  const busy = command?.phase === 'pending';
  const uncertain = command?.phase === 'uncertain';
  const generation = useRef(0);
  const lifetime = useRef(0);
  useEffect(() => { lifetime.current++; return () => { lifetime.current++; }; }, [client, view.agreement.agreement_id]);
  const available = capabilities?.features.native_construction_requests?.api_access === 'local_http_request_only';
  const allowed = available && permissions.includes('coordinate') && permissions.includes('disclose') && !stale && inventoryVersion === version;
  const read = async () => {
    const current = ++generation.current;
    const readVersion = nativeCommandVersion(client, agreement);
    try {
      const result = nativeRequestMetadata(await client.nativeRequests(agreement), agreement);
      if (current === generation.current && readVersion === nativeCommandVersion(client, agreement)) { setRequests(result); setInventoryVersion(readVersion); setError(''); }
    } catch (caught) { if (current === generation.current) { setRequests(null); setError(errorText(caught)); } }
  };
  useEffect(() => { if (available) void read(); return () => { generation.current++; }; }, [client, agreement, available, view.revision, version]);
  const submit = async (candidate: string) => {
    if (!canRequestNativeConstruction(requests, candidate, allowed, busy, uncertain)) return;
    setError('');
    const currentLifetime = lifetime.current;
    const attempt = { candidate, revision: view.revision, key: `native-request-${crypto.randomUUID()}` };
    if (!beginNativeCommand(client, agreement, { ...attempt, kind: 'enqueue' })) return;
    try {
      await client.requestNativeConstruction(agreement, { candidate_id: candidate }, {
        idempotencyKey: attempt.key, expectedRevision: attempt.revision,
      });
      if (currentLifetime !== lifetime.current) { finishNativeCommand(client, agreement, attempt.key, true); return; }
      await onChanged('Request recorded for separate native review. No private construction or financial action has run from this browser.');
      if (currentLifetime === lifetime.current) await read();
      finishNativeCommand(client, agreement, attempt.key, true);
    } catch (caught) {
      // Any failed response leaves the original key visible. No fresh automatic
      // key or second POST is produced; first inspect retained requests.
      finishNativeCommand(client, agreement, attempt.key, false);
      if (currentLifetime !== lifetime.current) return;
      setError(errorText(caught)); await read();
    }
  };
  const withdraw = async (request: NativeRequestView) => {
    if (busy || !allowed || uncertain || request.state !== 'queued') return;
    setError('');
    const currentLifetime = lifetime.current;
    const attempt = { candidate: request.candidate_id, revision: view.revision, key: `native-withdraw-${crypto.randomUUID()}` };
    if (!beginNativeCommand(client, agreement, { ...attempt, kind: 'withdraw', requestId: request.request_id })) return;
    try {
      await client.withdrawNativeRequest(agreement, request.request_id, { idempotencyKey: attempt.key, expectedRevision: attempt.revision });
      if (currentLifetime !== lifetime.current) { finishNativeCommand(client, agreement, attempt.key, true); return; }
      await onChanged('Never-started native request withdrawn. Retained artifacts and financial exposure are unaffected.');
      if (currentLifetime === lifetime.current) await read();
      finishNativeCommand(client, agreement, attempt.key, true);
    } catch (caught) {
      finishNativeCommand(client, agreement, attempt.key, false);
      if (currentLifetime !== lifetime.current) return;
      setError(errorText(caught)); await read();
    }
  };
  if (!available) return null;
  return <section aria-label="Native construction handoff">
    <h3>Request private preparation in the native host</h3>
    <Notice>No private source material is entered here. A request does not approve construction. Each request is pinned to its queued revision. Further agreement edits or another request can make it stale; withdraw a never-started stale request before preparing a new one. Stop the foreground service with Ctrl+C, open your existing separately protected financial profile with financial-open if needed, then run native-construction-request and review the exact request. The native host asks separately for private configuration and each signer decision. Reconnect afterward to inspect retained metadata.</Notice>
    <button className="button secondary" disabled={busy} onClick={() => void read()}>Read retained requests</button>
    {error && <p role="alert">{error}</p>}
    {command && <Notice warning>The {command.kind} command is {command.phase}. Do not create a replacement request. Preserve this browser command key {command.key}, candidate {command.candidate}, revision {command.revision}{command.requestId ? `, request ${command.requestId}` : ''}. The native operation key is separate and displayed by the native host. Inspect the retained request list or the native host. Absence here does not establish that no work occurred.</Notice>}
    {(view.candidates ?? []).map(candidate => <div key={candidate.candidate_id}>
      <span>{candidate.candidate_id}</span>
      <button className="button secondary" disabled={!canRequestNativeConstruction(requests, candidate.candidate_id, allowed, busy, uncertain)}
        onClick={() => void submit(candidate.candidate_id)}>Request native preparation</button>
    </div>)}
    {requests?.map(request => <p key={request.request_id}>
      Request {request.request_id}: {request.state}. Candidate {request.candidate_id}; original revision {request.original_revision}.
      {request.state === 'queued' && request.queued_revision !== view.revision && <strong> This queued request is stale and cannot start. Withdraw it first; a later request needs a fresh native decision.</strong>}
      {request.state === 'queued' && <button className="button secondary" disabled={!allowed || busy || uncertain} onClick={() => void withdraw(request)}>Withdraw never-started request</button>}
      {request.state === 'attempt_started' ? ' Private work may have occurred. Do not rerun this request; inspect exact retained checkpoints under fresh native review.' : ' Financial outcome and account exposure remain unknown.'}
    </p>)}
  </section>;
}
