import type { AgreementDraft, AgreementView, ParticipationIntent } from '../../../packages/sdk/src/types.ts';
import { exactTerms, termsSaveFailure } from './terms-revision-model.ts';

/** Session-memory bookkeeping only. It grants no authority and never retries itself. */
export type PlanningScope = 'draft' | `intent:${string}`;
export type PlanningInput = { kind: 'draft'; draft: AgreementDraft; key: string }
  | { kind: 'intent'; intent: ParticipationIntent; revision: number; key: string };
export interface PlanningCommand {
  readonly kind: PlanningInput['kind']; readonly scope: PlanningScope;
  readonly agreementId: string; readonly intentId?: string; readonly revision: number | null;
  readonly encoded: string; readonly key: string; readonly phase: 'pending' | 'uncertain'; readonly retried: boolean;
}
export interface PlanningResolution {
  readonly key: string; readonly kind: PlanningInput['kind']; readonly agreementId: string; readonly intentId?: string;
  readonly journalRevision: number | null; readonly outcome: 'saved' | 'rejected';
}
export interface PlanningSnapshot {
  readonly command: PlanningCommand | null;
  readonly resolution: PlanningResolution | null;
}
type Entry = { snapshot: PlanningSnapshot; listeners: Set<() => void>; dispatching: PlanningCommand | null };
const empty: PlanningSnapshot = Object.freeze({ command: null, resolution: null });
const sessions = new WeakMap<object, Map<PlanningScope, Entry>>();
export const intentScope = (agreementId: string): PlanningScope => `intent:${agreementId}`;
function entry(client: object, scope: PlanningScope): Entry {
  let entries = sessions.get(client);
  if (!entries) { entries = new Map(); sessions.set(client, entries); }
  let value = entries.get(scope);
  if (!value) { value = { snapshot: empty, listeners: new Set(), dispatching: null }; entries.set(scope, value); }
  return value;
}
function update(value: Entry, snapshot: PlanningSnapshot): void {
  value.snapshot = Object.freeze(snapshot);
  for (const listener of value.listeners) listener();
}
export function planningSnapshot(client: object | null, scope: PlanningScope): PlanningSnapshot { return client ? entry(client, scope).snapshot : empty; }
export function subscribePlanning(client: object | null, scope: PlanningScope, listener: () => void): () => void {
  if (!client) return () => {};
  const value = entry(client, scope); value.listeners.add(listener); return () => { value.listeners.delete(listener); };
}
/** Captures exact JSON before dispatch; later caller edits cannot change a retry. */
export function beginPlanningCommand(client: object, input: PlanningInput): PlanningCommand | null {
  const payload = input.kind === 'draft' ? input.draft : input.intent;
  const scope = input.kind === 'draft' ? 'draft' : intentScope(payload.agreement_id);
  const value = entry(client, scope);
  if (value.snapshot.command) return null;
  const command: PlanningCommand = Object.freeze({ kind: input.kind, scope, agreementId: payload.agreement_id,
    ...(input.kind === 'intent' ? { intentId: input.intent.intent_id } : {}), revision: input.kind === 'intent' ? input.revision : null,
    encoded: JSON.stringify(payload), key: input.key, phase: 'pending', retried: false });
  update(value, { command, resolution: null }); return command;
}
export function retryPlanningCommand(client: object, scope: PlanningScope): PlanningCommand | null {
  const value = entry(client, scope), original = value.snapshot.command;
  if (!original || original.phase !== 'uncertain') return null;
  const command: PlanningCommand = Object.freeze({ ...original, phase: 'pending', retried: true });
  update(value, { command, resolution: null }); return command;
}
/** Only the exact currently dispatched attempt can resolve its entry. */
function finish(client: object, command: PlanningCommand, outcome: 'saved' | 'rejected' | 'uncertain'): void {
  const value = entry(client, command.scope);
  if (value.snapshot.command !== command) return;
  value.dispatching = null;
  update(value, outcome === 'uncertain'
    ? { command: Object.freeze({ ...command, phase: 'uncertain' }), resolution: null }
    : { command: null, resolution: Object.freeze({ key: command.key, kind: command.kind, agreementId: command.agreementId,
        ...(command.intentId ? { intentId: command.intentId } : {}), journalRevision: outcome === 'saved' ? (command.revision === null ? 1 : command.revision + 1) : null, outcome }) });
}
/** A stale view/dismiss handler cannot consume a newer completion or a pending request. */
export function currentPlanningResolution(client: object, scope: PlanningScope, resolution: PlanningResolution): boolean {
  const snapshot = entry(client, scope).snapshot;
  return snapshot.command === null && snapshot.resolution === resolution;
}
export function dismissPlanningResolution(client: object, scope: PlanningScope, resolution: PlanningResolution): boolean {
  if (!currentPlanningResolution(client, scope, resolution)) return false;
  update(entry(client, scope), empty); return true;
}
/** A syntactically valid HTTP success is insufficient without the original saved identity/body. */
export function planningAcknowledged(command: PlanningCommand, result: AgreementView): boolean {
  if (!result || result.agreement?.agreement_id !== command.agreementId || !Number.isSafeInteger(result.revision)) return false;
  const original = JSON.parse(command.encoded);
  if (command.kind === 'draft') return result.revision === 1 && exactTerms(result.agreement) === exactTerms(original);
  return result.revision === command.revision! + 1 && Array.isArray(result.intents)
    && result.intents.filter(intent => intent.intent_id === command.intentId).length === 1
    && result.intents.some(intent => intent.intent_id === command.intentId && exactTerms(intent) === exactTerms(original));
}
type PlanningClient = {
  createAgreement(draft: AgreementDraft, options: { idempotencyKey: string }): Promise<AgreementView>;
  recordIntent(id: string, intent: ParticipationIntent, options: { idempotencyKey: string; expectedRevision: number }): Promise<AgreementView>;
};
/** Called only from a deliberate submit/retry handler. Dismissal does not cancel a dispatched write. */
export async function dispatchPlanningCommand(client: PlanningClient, command: PlanningCommand): Promise<void> {
  const value = entry(client, command.scope);
  if (value.snapshot.command !== command || command.phase !== 'pending' || value.dispatching) throw new Error('The original planning request is already running or no longer current.');
  value.dispatching = command;
  try {
    const result = command.kind === 'draft'
      ? await client.createAgreement(JSON.parse(command.encoded) as AgreementDraft, { idempotencyKey: command.key })
      : await client.recordIntent(command.agreementId, JSON.parse(command.encoded) as ParticipationIntent, { idempotencyKey: command.key, expectedRevision: command.revision! });
    if (!planningAcknowledged(command, result)) throw new Error('The original save acknowledgement could not be verified. Inspect or retry only the exact retained request.');
    finish(client, command, 'saved');
  } catch (error) {
    // A later rejection never disproves an earlier possibly committed dispatch.
    const failure = error !== null && typeof error === 'object' ? error as { code?: string; status?: number } : null;
    finish(client, command, termsSaveFailure(failure, command.retried));
    throw error;
  }
}
