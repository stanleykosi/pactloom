import type { AgreementDraft, AgreementView, ProposalPreview, TermsReviewReport } from '../../../packages/sdk/src/types.ts';

/** Comparisons only. The service's Rust validator and lifecycle rules are authoritative. */
export function exactTerms(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(exactTerms).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => `${JSON.stringify(key)}:${exactTerms(entry)}`).join(',')}}`;
  return JSON.stringify(value);
}
export interface TermsDifference { field: string; before: string; after: string; }
const names: Record<string, string> = {
  purpose: 'Purpose', recipients: 'Recipients', funding_policy: 'Funding objective', fee_policy: 'Fee allocation',
  coordination_deadline: 'Coordination deadline (UTC)', confirmation_policy: 'Confirmation policy', extensions: 'Extensions',
};
export function termsDifferences(before: AgreementDraft, after: AgreementDraft): TermsDifference[] {
  return Object.keys(names).flatMap(key => {
    const field = key as keyof AgreementDraft;
    return exactTerms(before[field]) === exactTerms(after[field]) ? [] : [{ field: names[key]!, before: JSON.stringify(before[field], null, 2), after: JSON.stringify(after[field], null, 2) }];
  });
}
export function termsContextChanged(opening: AgreementView, current: AgreementView): boolean {
  return opening.revision !== current.revision || exactTerms(opening.agreement) !== exactTerms(current.agreement) || current.terms_editability?.allowed !== true;
}
export interface TermsReview { readonly before: AgreementDraft; readonly after: AgreementDraft; readonly journalRevision: number; readonly encoded: string; }
export function termsReview(opening: AgreementView, after: AgreementDraft): TermsReview {
  return { before: structuredClone(opening.agreement), after: structuredClone(after), journalRevision: opening.revision, encoded: JSON.stringify(after) };
}
/** A review or acceptance never survives returning to editing, stale context, or dismissal. */
export interface TermsEditorState { review: TermsReview | null; accepted: boolean; }
export const freshTermsEditor = (): TermsEditorState => ({ review: null, accepted: false });
export type TermsEditorAction = { type: 'review'; review: TermsReview } | { type: 'accept'; accepted: boolean } | { type: 'reset' };
export function termsEditorReducer(state: TermsEditorState, action: TermsEditorAction): TermsEditorState {
  if (action.type === 'review') return { review: action.review, accepted: false };
  if (action.type === 'accept') return { ...state, accepted: state.review !== null && action.accepted };
  return freshTermsEditor();
}
export interface TermsRevisionCommand {
  readonly agreementId: string; readonly before: AgreementDraft; readonly encoded: string; readonly revision: number;
  readonly key: string; readonly phase: 'pending' | 'uncertain';
}
type Entry = { command: TermsRevisionCommand | null; listeners: Set<() => void> };
const sessions = new WeakMap<object, Map<string, Entry>>();
function entry(client: object, agreement: string): Entry {
  let agreements = sessions.get(client);
  if (!agreements) { agreements = new Map(); sessions.set(client, agreements); }
  let result = agreements.get(agreement);
  if (!result) { result = { command: null, listeners: new Set() }; agreements.set(agreement, result); }
  return result;
}
function emit(value: Entry): void { for (const listener of value.listeners) listener(); }
/** Memory-only, client- and agreement-scoped. Dismissal never erases an unresolved request. */
export function termsCommand(client: object, agreement: string): TermsRevisionCommand | null { return entry(client, agreement).command; }
export function subscribeTermsCommand(client: object, agreement: string, listener: () => void): () => void {
  const value = entry(client, agreement); value.listeners.add(listener); return () => { value.listeners.delete(listener); };
}
export function beginTermsCommand(client: object, review: TermsReview, key: string): TermsRevisionCommand | null {
  const value = entry(client, review.before.agreement_id);
  if (value.command) return null;
  value.command = { agreementId: review.before.agreement_id, before: structuredClone(review.before), encoded: review.encoded, revision: review.journalRevision, key, phase: 'pending' };
  emit(value); return value.command;
}
export function retryTermsCommand(client: object, agreement: string): TermsRevisionCommand | null {
  const value = entry(client, agreement);
  if (value.command?.phase !== 'uncertain') return null;
  value.command = { ...value.command, phase: 'pending' }; emit(value); return value.command;
}
export function finishTermsCommand(client: object, agreement: string, key: string, outcome: 'saved' | 'rejected' | 'uncertain'): void {
  const value = entry(client, agreement);
  if (value.command?.key !== key) return;
  value.command = outcome === 'uncertain' ? { ...value.command, phase: 'uncertain' } : null;
  emit(value);
}

/** Only recognized definitive pre-commit rejection responses release a first attempt.
 * Server/storage/recovery/unknown errors can occur after commit; a retry stays uncertain. */
export function termsSaveFailure(error: { code?: string; status?: number } | null, retry: boolean): 'rejected' | 'uncertain' {
  const definitive = ['INVALID_TERMS', 'INVALID_AMOUNT', 'UNSUPPORTED_VERSION', 'DUPLICATE_IDENTIFIER', 'CONSERVATION_FAILURE', 'REVISION_CONFLICT', 'PERMISSION_DENIED', 'AUTHENTICATION_REQUIRED', 'NOT_FOUND'];
  return !retry && error && typeof error.status === 'number' && error.status >= 400 && error.status < 500 && definitive.includes(error.code ?? '') ? 'rejected' : 'uncertain';
}
/** Late completion must never refresh or notify a different authenticated session. */
export function sameTermsSession(client: object, generation: number, activeClient: object | null, activeGeneration: number): boolean {
  return client === activeClient && generation === activeGeneration;
}

/** A proposal counter is distinct from the complete agreement terms it froze. */
export function proposalTermsContext(proposal: ProposalPreview, current: AgreementDraft) {
  const frozen = proposal.manifest.agreement;
  const revision = frozen !== null && typeof frozen === 'object' && 'revision' in frozen ? frozen.revision : null;
  const termsRevision = typeof revision === 'number' && Number.isSafeInteger(revision) && revision > 0 ? revision : null;
  const appliesToCurrentTerms = termsRevision !== null && proposal.agreement_id === current.agreement_id && exactTerms(frozen) === exactTerms(current);
  const label = appliesToCurrentTerms ? 'Current agreement terms' : termsRevision !== null && termsRevision < current.revision ? 'Historical agreement terms' : 'Terms do not match current agreement';
  const message = appliesToCurrentTerms
    ? 'This snapshot contains the current agreement terms. Its integrity reports still grant no transaction verification or spending approval.'
    : `This snapshot and its integrity reports do not apply to current terms revision ${current.revision}. No review or approval transfers to the current terms.`;
  return { termsRevision, currentTermsRevision: current.revision, appliesToCurrentTerms, label, message };
}
export function proposalReportAppliesToCurrentTerms(proposal: ProposalPreview, report: TermsReviewReport, current: AgreementDraft): boolean {
  return proposalTermsContext(proposal, current).appliesToCurrentTerms && report.proposal_id === proposal.proposal_id && report.manifest_digest === proposal.manifest_digest;
}
