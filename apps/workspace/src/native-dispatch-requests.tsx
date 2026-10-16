import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { WholepactClient, nativeSettlementRequestMetadata, type AgreementView, type CapabilitySet, type NativeDispatchRequestView, type NativeSettlementRequestView } from '@wholepact/sdk';
import { Notice } from './components';
import { errorText } from './App';
import { nativeCommand, nativeCommandVersion, subscribeNativeCommand, beginNativeCommand, finishNativeCommand } from './native-request-session';
import { nativeDispatchRequestMetadata, originalDispatchTransaction, canRequestNativeDispatch, validateDispatchOriginals, dispatchAttemptLabel } from './native-dispatch-request-model';

type Inventory = { client: WholepactClient; agreement: string; revision: number; version: number; requests: NativeDispatchRequestView[]; transactions: NativeSettlementRequestView[] };
export function NativeDispatchPanel({ view, client, capabilities, permissions, stale, onChanged }: {
  view: AgreementView; client: WholepactClient; capabilities: CapabilitySet | null; permissions: string[]; stale: boolean; onChanged: (message: string) => Promise<void>;
}) {
  const agreement = view.agreement.agreement_id;
  const version = useSyncExternalStore(useCallback(listener => subscribeNativeCommand(client, agreement, listener), [client, agreement]), useCallback(() => nativeCommandVersion(client, agreement), [client, agreement]));
  const command = nativeCommand(client, agreement);
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [transactionId, setTransactionId] = useState(''); const [error, setError] = useState('');
  const generation = useRef(0); const lifetime = useRef(0);
  useEffect(() => { lifetime.current++; return () => { lifetime.current++; }; }, [client, agreement]);
  const available = capabilities?.features.native_dispatch_requests?.api_access === 'local_http_request_only';
  const currentInventory = inventory?.client === client && inventory.agreement === agreement && inventory.revision === view.revision && inventory.version === version ? inventory : null;
  const requests = currentInventory?.requests ?? null; const transactions = currentInventory?.transactions ?? null;
  const allowed = available && permissions.includes('coordinate') && permissions.includes('disclose') && !stale && currentInventory !== null;
  const busy = command?.phase === 'pending'; const uncertain = command?.phase === 'uncertain';
  const read = async () => {
    const current = ++generation.current; const readVersion = nativeCommandVersion(client, agreement);
    try {
      const [rawRequests, rawTransactions] = await Promise.all([client.nativeDispatchRequests(agreement), client.nativeSettlementRequests(agreement)]);
      const checkedRequests = nativeDispatchRequestMetadata(rawRequests, agreement);
      const checkedTransactions = nativeSettlementRequestMetadata(rawTransactions, agreement);
      validateDispatchOriginals(checkedRequests, checkedTransactions);
      if (current === generation.current && readVersion === nativeCommandVersion(client, agreement)) {
        setInventory({ client, agreement, revision: view.revision, version: readVersion, requests: checkedRequests, transactions: checkedTransactions }); setError('');
      }
    } catch (caught) { if (current === generation.current) { setInventory(null); setError(errorText(caught)); } }
  };
  useEffect(() => { if (available) void read(); return () => { generation.current++; }; }, [client, agreement, available, view.revision, version]);
  const submit = async (withdrawal?: NativeDispatchRequestView) => {
    if (withdrawal ? !allowed || busy || uncertain || withdrawal.state !== 'queued' : !canRequestNativeDispatch(requests, transactions, transactionId, allowed, busy, uncertain)) return;
    const original = originalDispatchTransaction(transactions, withdrawal?.transaction_request_id ?? transactionId);
    if (!original) return;
    const attempt = {
      kind: withdrawal ? 'dispatch_withdraw' as const : 'submission_dispatch' as const,
      transactionRequestId: original.request_id, intakeRequestId: original.intake_request_id,
      candidate: original.candidate_id, jobId: original.job_id, revision: view.revision,
      key: `dispatch-request-${crypto.randomUUID()}`, requestId: withdrawal?.request_id,
    };
    if (!beginNativeCommand(client, agreement, attempt)) return;
    const currentLifetime = lifetime.current; setError('');
    try {
      if (withdrawal) await client.withdrawNativeDispatchRequest(agreement, withdrawal.request_id, { idempotencyKey: attempt.key, expectedRevision: attempt.revision });
      else await client.requestNativeDispatch(agreement, { transaction_request_id: attempt.transactionRequestId }, { idempotencyKey: attempt.key, expectedRevision: attempt.revision });
      if (currentLifetime === lifetime.current) {
        await onChanged(withdrawal ? 'Never-started dispatch request withdrawn. Preserve all original authorizations, operation identities and transaction history.' : 'Exact dispatch request recorded. Native review and fresh explicit decisions are required before any submission attempt.');
        if (currentLifetime === lifetime.current) await read();
      }
      finishNativeCommand(client, agreement, attempt.key, true);
    } catch (caught) {
      finishNativeCommand(client, agreement, attempt.key, false);
      if (currentLifetime === lifetime.current) { setError(errorText(caught)); await read(); }
    }
  };
  if (!available) return null;
  return <section aria-label="Native dispatch request and historical status">
    <h3>Request separate native dispatch review</h3>
    <Notice>These requests contain metadata only. Stop and drain the service before running native-dispatch-request. Native owners must make fresh explicit decisions for the exact retained transaction and named provider. After an attempted request or missing acknowledgement, stop and drain before using native-dispatch-status to inspect local retained history. Status inspection does not observe the chain or perform another submission.</Notice>
    <p>Retained client history is bounded to 16 snapshots and 128 attempts, within the existing 1 MiB agreement record limit. A metadata update may fail after an effect occurred. Missing or failed status updates remain unknown: preserve the original native journal, do not evict history, reset the request or create a replacement.</p>
    <label>Original attempted transaction-checkpoint request ID<input value={transactionId} onChange={event => setTransactionId(event.target.value)} disabled={busy || uncertain} maxLength={64} placeholder="64-character original request ID"/></label>
    <p>The complete original historical transaction observation must already be recorded. Candidate, signatures, transaction and operation identities are derived from that original history. Do not paste transaction bytes, keys, provider details or approvals.</p>
    <button className="button secondary" disabled={!canRequestNativeDispatch(requests, transactions, transactionId, allowed, busy, uncertain)} onClick={() => void submit()}>Request native dispatch review</button>
    <button className="button secondary" disabled={busy} onClick={() => void read()}>Read retained dispatch metadata</button>
    {error && <p role="alert">{error}</p>}
    {command && <Notice warning>{command.kind}: {command.phase}. Preserve browser command key {command.key}, original transaction request {command.transactionRequestId ?? 'not supplied'}, request {command.requestId ?? 'not acknowledged'}, candidate {command.candidate}, original job {command.jobId ?? 'not supplied'}, revision {command.revision}. A metadata read does not clear an uncertain command. Do not create a replacement.</Notice>}
    {requests?.map(item => {
      const latest = item.observations.at(-1); const latestAttempt = latest?.attempts.at(-1);
      return <div key={item.request_id}>
        <p>Request {item.request_id}; original transaction request {item.transaction_request_id}; state {item.state}; outcome {item.outcome_status}.</p>
        <p>Original checkpoint {item.checkpoint_id}; transaction ID {item.txid}; exact-byte digest {item.transaction_digest}; immutable operation {item.operation_id}.</p>
        <p>Original submission journal: {item.submission_journal_identity ?? 'not selected by the native owner yet'}.</p>
        {item.state === 'queued' && <><p>{item.queued_revision === view.revision ? 'Awaiting separate native review.' : 'Stale revision; withdraw this never-started request before requesting a fresh native review.'}</p><p>Withdrawal preserves this request and its operation identity. It does not recall signatures or clear exposure.</p><button className="button secondary" disabled={!allowed || busy || uncertain} onClick={() => void submit(item)}>Withdraw never-started request</button></>}
        {item.state === 'attempt_started' && <>
          <p>Latest historical provider state: {latest?.intent?.historical_provider_state ?? 'no retained provider report'}. This may describe an earlier attempt.</p>
          <p>Latest recorded attempt: {latestAttempt ? `${latestAttempt.number}, ${dispatchAttemptLabel(latestAttempt.outcome)}` : 'none recorded; the durable outcome remains unknown'}.</p>
          <p>Provider acknowledgement, rejection, interruption or an empty journal cannot establish current payment, non-delivery, finality, zero exposure or permission to retry. Preserve the exact original transaction and all journals.</p>
        </>}
        {item.observations.length > 0 && <details><summary>Immutable local historical snapshots ({item.observations.length})</summary>{item.observations.map((snapshot, index) => <div key={index}>
          <p>Snapshot {index + 1}; original journal {snapshot.submission_journal_identity}; provider state {snapshot.intent?.historical_provider_state ?? 'unknown, no retained intent'}.</p>
          {snapshot.descriptor && <p>Historical descriptor: obligation {snapshot.descriptor.obligation_id}; proposal {snapshot.descriptor.proposal_id}; network {snapshot.descriptor.network}; expiry height {snapshot.descriptor.expiry_height}.</p>}
          {snapshot.attempts.length === 0 && <p>No attempt is recorded in this snapshot. Delivery is not disproved.</p>}
          {snapshot.attempts.map(attempt => <p key={attempt.number}>Attempt {attempt.number}; source {attempt.source_id}; started at Unix second {attempt.started_at_unix_seconds}; {dispatchAttemptLabel(attempt.outcome)}.</p>)}
        </div>)}</details>}
      </div>;
    })}
  </section>;
}
