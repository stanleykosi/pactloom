import { useSyncExternalStore } from 'react';
import type { WholepactClient } from '@wholepact/sdk';
import { Modal, Notice } from './components';
import { planningSnapshot, subscribePlanning, type PlanningCommand, type PlanningScope, type PlanningResolution } from './planning-command-session';

export function usePlanningCommand(client: WholepactClient | null, scope: PlanningScope) {
  return useSyncExternalStore(listener => subscribePlanning(client, scope, listener), () => planningSnapshot(client, scope), () => planningSnapshot(client, scope));
}
export function RetainedPlanningCommand({ command, error, onClose, onRetry }: { command: PlanningCommand; error: string; onClose: () => void; onRetry: () => void }) {
  const draft = command.kind === 'draft';
  return <Modal title={draft ? 'Original payment draft' : 'Original contribution plan'} onClose={onClose} wide><div className="modal-body">
    <Notice warning title={command.phase === 'pending' ? 'The original save is in progress' : 'The original save outcome is uncertain'}>Closing this window does not cancel a dispatched save. Its exact contents, original revision and retry identity stay in this session. No new request replaces it, and nothing retries automatically.</Notice>
    <p>No payment is authorized or funds reserved. Reloading or disconnecting loses this in-memory reference; inspect the service journal before starting again.</p>
    <dl className="compact-dl"><div><dt>Agreement</dt><dd className="mono wrap">{command.agreementId}</dd></div>{command.intentId && <div><dt>Contribution plan</dt><dd className="mono wrap">{command.intentId}</dd></div>}<div><dt>Original journal revision</dt><dd>{command.revision ?? 'New draft'}</dd></div><div><dt>Retry identity</dt><dd className="mono wrap">{command.key}</dd></div></dl>
    <details className="evidence-details"><summary>Exact original request</summary><pre className="wrap">{JSON.stringify(JSON.parse(command.encoded), null, 2)}</pre></details>
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="modal-actions"><button className="button secondary" onClick={onClose}>Close window</button><button className="button primary" disabled={command.phase !== 'uncertain'} onClick={onRetry}>{command.phase === 'pending' ? 'Saving original request…' : 'Retry exact original request'}</button></div>
  </div></Modal>;
}
export function SavedPlanningCommand({ onClose }: { onClose: () => void }) {
  return <Modal title="Original save confirmed" onClose={onClose}><div className="modal-body"><Notice>The service acknowledged the exact original planning request. Close this window and refresh to inspect the saved record. This is not payment approval.</Notice><button className="button primary" onClick={onClose}>Close window</button></div></Modal>;
}

/** One bounded completion per scope; it never blocks a new deliberate plan. */
export function PlanningSaveNotice({ resolution, onView, onDismiss }: { resolution: PlanningResolution; onView: () => void; onDismiss: () => void }) {
  if (resolution.outcome !== 'saved') return null;
  return <Notice title={resolution.kind === 'draft' ? 'Original draft saved locally' : 'Original contribution plan saved locally'}>
    The service acknowledged the exact original request at journal revision {resolution.journalRevision}. No payment was approved.
    <p className="mono wrap">{resolution.agreementId}{resolution.intentId ? ` · ${resolution.intentId}` : ''}</p>
    <button className="text-button" onClick={onView}>{resolution.kind === 'draft' ? 'View saved draft' : 'Refresh saved contribution plan'}</button>{' '}
    <button className="text-button" onClick={onDismiss}>Dismiss save confirmation</button>
  </Notice>;
}
