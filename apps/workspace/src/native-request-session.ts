/** Session-memory only. Remounting a view cannot forget an unresolved command.
 * The key is the authenticated client instance; no credential or browser storage
 * is used. The entry grants no authority and never retries an operation. */
export interface NativeCommand {
  readonly kind: 'owner_inspection' | 'owner_inspection_withdraw' | 'enqueue' | 'withdraw' | 'proof_reconcile' | 'proof_withdraw' | 'proof_execute' | 'proof_execute_withdraw' | 'artifact_handoff' | 'artifact_handoff_withdraw' | 'settlement_handoff' | 'settlement_withdraw' | 'submission_dispatch' | 'dispatch_withdraw' | 'settlement_reconciliation' | 'reconciliation_withdraw';
  readonly jobId?: string;
  readonly intakeRequestId?: string;
  readonly transactionRequestId?: string;
  readonly dispatchRequestId?: string;
  readonly reconciliationKind?: 'provider_observation' | 'independent_record_resolution';
  readonly participantId?: string;
  readonly recordId?: string;
  readonly settlementKind?: 'signature_reconcile' | 'transaction_checkpoint';
  readonly handoffKind?: 'signer_review'|'signature_intake';
  readonly candidate: string;
  readonly revision: number;
  readonly key: string;
  readonly requestId?: string;
  readonly phase: 'pending' | 'uncertain';
}
type Entry = { version: number; command: NativeCommand | null; listeners: Set<() => void> };
const sessions = new WeakMap<object, Map<string, Entry>>();
function entry(client: object, agreement: string): Entry {
  let agreements = sessions.get(client);
  if (!agreements) { agreements = new Map(); sessions.set(client, agreements); }
  let value = agreements.get(agreement);
  if (!value) { value = { version: 0, command: null, listeners: new Set() }; agreements.set(agreement, value); }
  return value;
}
export function nativeCommandVersion(client: object, agreement: string): number {
  return entry(client, agreement).version;
}
export function nativeCommand(client: object, agreement: string): NativeCommand | null {
  return entry(client, agreement).command;
}
export function subscribeNativeCommand(client: object, agreement: string, listener: () => void): () => void {
  const value = entry(client, agreement); value.listeners.add(listener);
  return () => { value.listeners.delete(listener); };
}
export function beginNativeCommand(client: object, agreement: string, command: Omit<NativeCommand, 'phase'>): boolean {
  const value = entry(client, agreement);
  if (value.command !== null) return false;
  value.command = { ...command, phase: 'pending' };
  value.version++;
  for (const listener of value.listeners) listener();
  return true;
}
export function finishNativeCommand(client: object, agreement: string, key: string, confirmed: boolean): void {
  const value = entry(client, agreement);
  if (value.command?.key !== key) return;
  value.command = confirmed ? null : { ...value.command, phase: 'uncertain' };
  value.version++;
  for (const listener of value.listeners) listener();
}

/** Explicit exact retry only; navigation/reads cannot silently clear uncertainty. */
export function retryNativeCommand(client:object, agreement:string, key:string): NativeCommand | null {
  const value = entry(client, agreement);
  if (value.command?.key !== key || value.command.phase !== 'uncertain') return null;
  value.command = { ...value.command, phase:'pending' }; value.version++;
  for (const listener of value.listeners) listener();
  return value.command;
}
