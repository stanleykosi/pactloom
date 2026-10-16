import type { NativeAccountInspectionRequestView } from './types.js';
const fail = (): never => { throw new Error('Invalid owner inspection metadata; no current balance, exposure or authority can be inferred.'); };
const object = (v:unknown, keys:string[]): Record<string, any> => {
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== keys.length || Object.keys(v).some(k => !keys.includes(k))) return fail();
  return v as Record<string, any>;
};
const id = (v:unknown) => typeof v === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(v) && v !== '.' && v !== '..';
const hash = (v:unknown) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const count = (v:unknown) => Number.isSafeInteger(v) && Number(v) > 0;
const money = (v:unknown) => typeof v === 'string' && /^(0|[1-9][0-9]{0,15})$/.test(v) && BigInt(v) <= 2100000000000000n;
const request = (v:unknown, agreement:string) => {
  const r = object(v, ['request_id','principal_id','agreement_id','candidate_id','participant_id','manifest_digest']);
  if (!hash(r.request_id) || !hash(r.manifest_digest) || r.agreement_id !== agreement || ![r.principal_id,r.agreement_id,r.candidate_id,r.participant_id].every(id)) fail();
  return r;
};
export function ownerInspectionMetadata(value:unknown, agreement:string): NativeAccountInspectionRequestView[] {
  if (!Array.isArray(value) || value.length > 16) return fail();
  const ids = new Set<string>();
  for (const item of value) {
    const v = object(item, ['schema_version','operation','request','original_revision','queued_revision','attempt_revision','state','result_status','authorization_allowed','result']);
    const r = request(v.request, agreement);
    if (ids.has(r.request_id)) fail(); ids.add(r.request_id);
    if (v.schema_version !== 1 || v.operation !== 'owner_account_inspection' || v.authorization_allowed !== false || !count(v.original_revision) || v.queued_revision !== v.original_revision + 1 || !count(v.queued_revision)) fail();
    if (v.state === 'attempt_started') { if (v.attempt_revision !== v.queued_revision + 1 || !count(v.attempt_revision)) fail(); }
    else if (!['queued','withdrawn'].includes(v.state) || v.attempt_revision !== null || v.result !== null) fail();
    if (v.result === null) { if (v.result_status !== 'unknown_no_committed_result') fail(); continue; }
    if (v.result_status !== 'historical_native_approved_metadata' || v.state !== 'attempt_started') fail();
    const s = object(v.result, ['schema_version','request','account_id','source_principal_id','writer_epoch','recovery_required','inspected_at_ms','provenance','freshness','authorization_allowed','balance','account_pending_exposure','account_settled_debit','account_remaining_budget','authorizations','sponsor_policies','automation_grants']);
    const sr = request(s.request, agreement);
    if (Object.keys(r).some(k => r[k] !== sr[k]) || s.schema_version !== 1 || !id(s.account_id) || !id(s.source_principal_id) || !count(s.writer_epoch) || typeof s.recovery_required !== 'boolean' || !count(s.inspected_at_ms) || s.inspected_at_ms > 8640000000000000 || s.provenance !== 'native_owner_approved_local_signer_journal' || s.freshness !== 'historical_local_snapshot_no_live_witness_or_chain_observation' || s.authorization_allowed !== false || [s.balance,s.account_pending_exposure,s.account_settled_debit,s.account_remaining_budget].some(v => v !== null)) fail();
    for (const [values,limit] of [[s.authorizations,128],[s.sponsor_policies,32],[s.automation_grants,32]] as const) if (!Array.isArray(values) || values.length > limit) fail();
    for (const a of s.authorizations) {
      object(a, ['authorization_id','original_consent_ref','proposal_id','maximum_debit','transaction_expiry_height','result_retained','latest_settlement_record','automation_grant_id']);
      if (!id(a.authorization_id) || !hash(a.original_consent_ref) || !id(a.proposal_id) || !money(a.maximum_debit) || !count(a.transaction_expiry_height) || a.transaction_expiry_height > 4294967295 || typeof a.result_retained !== 'boolean' || ![null,'canonical_consumed','canonical_conflict','reopened'].includes(a.latest_settlement_record) || a.automation_grant_id !== null && !id(a.automation_grant_id)) fail();
    }
    for (const p of s.sponsor_policies) {
      object(p, ['policy_key','version','terms_digest','status','aggregate_budget','expires_at','witness_id','witness_policy_digest']);
      if (!hash(p.policy_key) || !count(p.version) || !hash(p.terms_digest) || !['active','paused','revoked'].includes(p.status) || !money(p.aggregate_budget) || p.expires_at !== null && (typeof p.expires_at !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(p.expires_at)) || !id(p.witness_id) || !hash(p.witness_policy_digest)) fail();
    }
    for (const g of s.automation_grants) {
      object(g, ['grant_id','application_id','revision','terms_digest','status','maximum_payment_debit','maximum_outstanding_debit','expires_at_ms']);
      if (!id(g.grant_id) || !id(g.application_id) || !count(g.revision) || !hash(g.terms_digest) || !['draft','active','paused','revoked','expired'].includes(g.status) || !money(g.maximum_payment_debit) || !money(g.maximum_outstanding_debit) || !count(g.expires_at_ms) || g.expires_at_ms > 8640000000000000) fail();
    }
  }
  return value as NativeAccountInspectionRequestView[];
}
