import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { WholepactClient, type AgreementView, type CapabilitySet, type NativeArtifactHandoffRequestView, type NativeSettlementRequestKind, type NativeSettlementRequestView } from '@wholepact/sdk';
import { Notice } from './components';
import { errorText } from './App';
import { nativeCommand, nativeCommandVersion, subscribeNativeCommand, beginNativeCommand, finishNativeCommand } from './native-request-session';
import { nativeArtifactHandoffRequestMetadata } from './native-artifact-handoff-request-model';
import { nativeSettlementRequestMetadata, originalSettlementIntake, canRequestNativeSettlement } from './native-settlement-request-model';

type Inventory = { client: WholepactClient; agreement: string; revision: number; version: number; requests: NativeSettlementRequestView[]; intakes: NativeArtifactHandoffRequestView[] };
export function NativeSettlementPanel({ view, client, capabilities, permissions, stale, onChanged }: {
  view: AgreementView; client: WholepactClient; capabilities: CapabilitySet | null; permissions: string[]; stale: boolean; onChanged: (message: string) => Promise<void>;
}) {
  const agreement = view.agreement.agreement_id;
  const version = useSyncExternalStore(useCallback(listener => subscribeNativeCommand(client, agreement, listener), [client, agreement]), useCallback(() => nativeCommandVersion(client, agreement), [client, agreement]));
  const command = nativeCommand(client, agreement);
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [kind, setKind] = useState<NativeSettlementRequestKind>('signature_reconcile');
  const [intakeId, setIntakeId] = useState(''); const [error, setError] = useState('');
  const generation = useRef(0); const lifetime = useRef(0);
  useEffect(() => { lifetime.current++; return () => { lifetime.current++; }; }, [client, agreement]);
  const available = capabilities?.features.native_settlement_requests?.api_access === 'local_http_request_only';
  const currentInventory = inventory?.client === client && inventory.agreement === agreement && inventory.revision === view.revision && inventory.version === version ? inventory : null;
  const requests = currentInventory?.requests ?? null; const intakes = currentInventory?.intakes ?? null;
  const allowed = available && permissions.includes('coordinate') && permissions.includes('disclose') && !stale && currentInventory !== null;
  const busy = command?.phase === 'pending'; const uncertain = command?.phase === 'uncertain';
  const read = async () => {
    const current = ++generation.current; const readVersion = nativeCommandVersion(client, agreement);
    try {
      const [rawRequests, rawIntakes] = await Promise.all([client.nativeSettlementRequests(agreement), client.nativeArtifactHandoffRequests(agreement)]);
      const checkedRequests = nativeSettlementRequestMetadata(rawRequests, agreement);
      const checkedIntakes = nativeArtifactHandoffRequestMetadata(rawIntakes, agreement);
      if (current === generation.current && readVersion === nativeCommandVersion(client, agreement)) {
        setInventory({ client, agreement, revision: view.revision, version: readVersion, requests: checkedRequests, intakes: checkedIntakes }); setError('');
      }
    } catch (caught) { if (current === generation.current) { setInventory(null); setError(errorText(caught)); } }
  };
  useEffect(() => { if (available) void read(); return () => { generation.current++; }; }, [client, agreement, available, view.revision, version]);
  const submit = async (withdrawal?: NativeSettlementRequestView) => {
    if (withdrawal ? !allowed || busy || uncertain || withdrawal.state !== 'queued' : !canRequestNativeSettlement(requests, intakes, intakeId, kind, allowed, busy, uncertain)) return;
    const intake = originalSettlementIntake(intakes, withdrawal?.intake_request_id ?? intakeId);
    if (!intake) return;
    const attempt = {
      kind: withdrawal ? 'settlement_withdraw' as const : 'settlement_handoff' as const,
      settlementKind: withdrawal?.kind ?? kind, intakeRequestId: intake.request_id,
      candidate: intake.candidate_id, jobId: intake.job_id, revision: view.revision,
      key: `settlement-handoff-${crypto.randomUUID()}`, requestId: withdrawal?.request_id,
    };
    if (!beginNativeCommand(client, agreement, attempt)) return;
    const currentLifetime = lifetime.current; setError('');
    try {
      if (withdrawal) await client.withdrawNativeSettlementRequest(agreement, withdrawal.request_id, { idempotencyKey: attempt.key, expectedRevision: attempt.revision });
      else await client.requestNativeSettlement(agreement, { intake_request_id: attempt.intakeRequestId, kind: attempt.settlementKind }, { idempotencyKey: attempt.key, expectedRevision: attempt.revision });
      if (currentLifetime === lifetime.current) {
        await onChanged(withdrawal ? 'Never-started settlement request withdrawn. Existing signatures and retained transactions remain unaffected.' : 'Exact native settlement request recorded. Separate native owner consent and original-journal checks are still required.');
        if (currentLifetime === lifetime.current) await read();
      }
      finishNativeCommand(client, agreement, attempt.key, true);
    } catch (caught) {
      finishNativeCommand(client, agreement, attempt.key, false);
      if (currentLifetime === lifetime.current) { setError(errorText(caught)); await read(); }
    }
  };
  if (!available) return null;
  return <section aria-label="Native settlement handoff">
    <h3>Inspect original signatures and transaction checkpoints</h3>
    <Notice>These are metadata-only requests. Stop and drain the service before running native-settlement-request. Native owners must separately approve use of the original retained artifacts. After an attempted request or missing acknowledgment, use native-settlement-inspect to revalidate the originals without resetting or extracting again. No current financial completion, chain validity or zero outstanding exposure is established here.</Notice>
    <label>Native workflow<select value={kind} onChange={event => setKind(event.target.value as NativeSettlementRequestKind)} disabled={busy || uncertain}><option value="signature_reconcile">Reconcile original signature result</option><option value="transaction_checkpoint">Create original transaction checkpoint</option></select></label>
    <label>Original started signature-intake request ID<input value={intakeId} onChange={event => setIntakeId(event.target.value)} disabled={busy || uncertain} maxLength={64} placeholder="64-character original request ID"/></label>
    <p>Use the exact started signature-intake request ID. Candidate, job and retention identity are derived from that original request. Do not paste private artifacts, result digests or retention keys.</p>
    {kind === 'transaction_checkpoint' && <p>A matching, complete historical signed observation must already be recorded by native signature reconciliation. This prerequisite does not grant current spending or broadcast authority.</p>}
    <button className="button secondary" disabled={!canRequestNativeSettlement(requests, intakes, intakeId, kind, allowed, busy, uncertain)} onClick={() => void submit()}>Request separate native workflow</button>
    <button className="button secondary" disabled={busy} onClick={() => void read()}>Read retained settlement metadata</button>
    {error && <p role="alert">{error}</p>}
    {command && <Notice warning>{command.kind}: {command.phase}. Preserve browser command key {command.key}, original intake {command.intakeRequestId ?? 'not supplied'}, candidate {command.candidate}, original job {command.jobId ?? 'not supplied'}, revision {command.revision}. Do not create a replacement after an uncertain response.</Notice>}
    {requests?.map(item => <div key={item.request_id}>
      <p>Request {item.request_id}; original intake {item.intake_request_id}; {item.kind}; state {item.state}; outcome {item.outcome_status}.</p>
      {item.state === 'queued' && <><p>{item.queued_revision === view.revision ? 'Awaiting separate native review.' : 'Stale revision; withdraw this never-started request before creating a fresh request.'}</p><button className="button secondary" disabled={!allowed || busy || uncertain} onClick={() => void submit(item)}>Withdraw never-started request</button></>}
      {item.outcome_status === 'attempted_outcome_unknown' && <p>Durable effect is unknown. Signatures or a transaction checkpoint may have been retained. Preserve all original journals and use native-settlement-inspect. Do not reset, repeat extraction or infer no effect.</p>}
      {item.observation?.type === 'signed' && <p>Historical signed result {item.observation.evidence.result_id}; signature completeness observed then: {item.observation.evidence.signatures_complete ? 'complete' : 'incomplete'}. This is historical metadata only.</p>}
      {item.observation?.type === 'transaction' && <p>Historical checkpoint {item.observation.checkpoint_id}; transaction ID {item.observation.txid}. Retention does not establish broadcast, chain validity, confirmation or payment.</p>}
    </div>)}
  </section>;
}
