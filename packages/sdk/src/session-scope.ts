import type { Session } from './types.js';
/** Display-only summary, never a client-side authorization decision. No credentials are retained. */
export function describeAgreementScope(session: Pick<Session, 'agreement_ids' | 'all_agreements' | 'include_owned_agreements' | 'agreement_scope'>): string {
  const expected = session.all_agreements === true ? 'all' : session.include_owned_agreements === true ? 'owned_and_selected' : session.include_owned_agreements === false ? 'selected' : undefined;
  if (session.agreement_scope !== undefined && session.agreement_scope !== expected) return 'Inconsistent agreement scope report. Inspect the native service; no least-privilege claim can be made.';
  if (session.all_agreements === true) return 'All local agreements, including future agreements.';
  const ids = session.agreement_ids.length ? session.agreement_ids.join(', ') : 'none';
  if (session.include_owned_agreements === true) return `All existing and future owned agreements; additional selected IDs: ${ids}.`;
  if (session.include_owned_agreements === false) return `Only these exact selected agreement IDs: ${ids}. Ownership and future creation do not expand this scope.`;
  return `Legacy service did not report explicit ownership scope. Listed IDs: ${ids}. Inspect the native service before relying on least-privilege access.`;
}
