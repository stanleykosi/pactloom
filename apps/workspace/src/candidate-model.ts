import { formatZec, parseZec, type AgreementView, type CandidateRequest, type CandidateReview, type CandidateView, type ParticipationIntent } from '@wholepact/sdk';

export const CANDIDATE_PROFILE = 'ironwood-testnet-nu7-candidate';
export interface ClaimRow {
  intent: ParticipationIntent; selected: boolean; account: string; contribution: string;
  feeShare: string; input: string; returned: string; returnAddress: string;
}
export function selectableIntents(view: AgreementView, now = Date.now()): ParticipationIntent[] {
  const seen = new Set<string>();
  return view.intents.filter(intent => {
    if (seen.has(intent.participant_id) || (view.roster_selected ? intent.status !== 'selected' : intent.status !== 'active')) return false;
    seen.add(intent.participant_id);
    return !intent.conditions.length && (!intent.valid_until || Date.parse(intent.valid_until) > now);
  });
}
export function candidateBlockers(view: AgreementView, supported: boolean, canCoordinate: boolean, stale: boolean, now = Date.now()): string[] {
  const blockers: string[] = [];
  if (stale) blockers.push('Reconnect and refresh the local journal before preparing new claims.');
  if (!supported) blockers.push('This service has not reported support for candidate terms.');
  if (!canCoordinate) blockers.push('This session does not have candidate coordination permission.');
  if (view.cancellation_requested) blockers.push('Cancellation has been requested. New candidate preparation is closed.');
  if (view.agreement.network_profile_id !== CANDIDATE_PROFILE) blockers.push('This draft uses the older terms-only profile. Candidate terms require a new agreement with the Ironwood testnet candidate profile.');
  if (view.agreement.extensions.length) blockers.push('The agreement has extensions that this candidate path cannot verify.');
  if (view.agreement.coordination_deadline && !(Date.parse(view.agreement.coordination_deadline) > now)) blockers.push('The coordination deadline has passed or cannot be read.');
  if (!selectableIntents(view, now).length) blockers.push('Record an eligible intent or repair the selected roster before preparing a candidate.');
  return blockers;
}
export function claimRows(view: AgreementView): ClaimRow[] {
  return selectableIntents(view).map(intent => ({ intent, selected: view.roster_selected === true, account: '', contribution: formatZec(intent.desired_contribution, true), feeShare: '', input: '', returned: '', returnAddress: '' }));
}
/** Presentation adapter only. All allocation, conservation and cap validation remains in Rust. */
export function candidateRequest(view: AgreementView, rows: ClaimRow[], fee: string, expiry: string): CandidateRequest {
  const selected = rows.filter(row => row.selected);
  if (!selected.length) throw new Error('Select at least one participant with an active local intent.');
  if (!/^[1-9]\d*$/.test(expiry) || !Number.isSafeInteger(Number(expiry)) || Number(expiry) > 0xffffffff) throw new Error('Use a positive whole-number expiry height within the supported integer range.');
  for (const row of selected) if (!/^[A-Za-z0-9_.:\-]{1,128}$/.test(row.account.trim())) throw new Error('Use a scoped account label for each selected participant. Do not enter a key.');
  const returns = selected.map(row => ({ row, amount: parseZec(row.returned) })).filter(item => item.amount !== '0');
  for (const { row } of returns) if (!row.returnAddress.trim()) throw new Error('Enter receiving instructions for each nonzero claimed return.');
  return {
    previous_candidate_id: view.candidates?.at(-1)?.candidate_id ?? null,
    manifest: {
      agreement: structuredClone(view.agreement),
      participants: selected.map(row => ({ participant_id: row.intent.participant_id, account_id: row.account.trim(), contribution: parseZec(row.contribution), fee_share: parseZec(row.feeShare), fee_cap: row.intent.fee_cap, maximum_net_debit: row.intent.maximum_net_debit, charges: [] })),
      inputs: selected.map((row, index) => ({ input_id: `claimed-input-${index + 1}`, participant_id: row.intent.participant_id, account_id: row.account.trim(), amount: parseZec(row.input), ownership_evidence_ref: null })),
      outputs: [
        ...view.agreement.recipients.map((recipient, index) => ({ output_id: `recipient-${index + 1}`, address: recipient.address, amount: recipient.amount, allocation: { kind: 'recipient' as const, recipient_id: recipient.recipient_id } })),
        ...returns.map(({ row, amount }, index) => ({ output_id: `claimed-return-${index + 1}`, address: row.returnAddress.trim(), amount, allocation: { kind: 'return' as const, participant_id: row.intent.participant_id, account_id: row.account.trim(), ownership_evidence_ref: null } })),
      ],
      transaction_fee: parseZec(fee), expiry_height: Number(expiry),
    },
  };
}
/** Economic evidence is distinct from a claims review and must bind this exact candidate. */
export function economicReview(candidate: CandidateView): CandidateReview | undefined {
  return [...candidate.reviews].reverse().find(review => review.candidate_id === candidate.candidate_id && review.manifest_digest === candidate.manifest_digest && review.status === 'economic_terms_verified_only' && review.scope === 'local_cryptographic_economic_computation' && review.economic_terms_verified === true && !!review.artifact_digest && !!review.effects_commitment && !!review.review_binding);
}
