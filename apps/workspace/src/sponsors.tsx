import { useEffect, useRef, useState, type FormEvent } from 'react';
import { WholepactClient, WholepactError, type AgreementView, type CapabilitySet, type SponsorPolicyView, type SponsorPolicyStateRequest, type SponsorPolicyPreview } from '@wholepact/sdk';
import { Badge, dateTime, Field, human, Modal, Money, Notice } from './components';
import { errorText } from './App';

const newKey = () => `sponsor-${crypto.randomUUID()}`;
const uncertainError = (error: unknown) => error instanceof WholepactError && error.code === 'EXTERNAL_OUTCOME_UNCERTAIN';
export function SponsorPanel({ view, client, capabilities, permissions, stale, onChanged }: { view: AgreementView; client: WholepactClient; capabilities: CapabilitySet | null; permissions: string[]; stale: boolean; onChanged: (message: string) => Promise<void> }) {
  const [policies, setPolicies] = useState<SponsorPolicyView[]>([]); const [error, setError] = useState(''); const [loading, setLoading] = useState(false);
  const [editor, setEditor] = useState<{ generation: number; policy?: SponsorPolicyView } | null>(null); const [selected, setSelected] = useState<SponsorPolicyView | null>(null);
  const editorGeneration = useRef(0); const requestGeneration = useRef(0);
  const supported = capabilities?.features.sponsor_policies?.status === 'supported';
  useEffect(() => {
    if (!supported) return; const current = ++requestGeneration.current; setLoading(true);
    client.sponsorPolicies(view.agreement.agreement_id).then(result => { if (current === requestGeneration.current) { setPolicies(result); setError(''); } }).catch(caught => { if (current === requestGeneration.current) setError(errorText(caught)); }).finally(() => { if (current === requestGeneration.current) setLoading(false); });
    return () => { requestGeneration.current++; };
  }, [client, supported, view.agreement.agreement_id, view.revision]);
  const edit = (policy?: SponsorPolicyView) => setEditor({ generation: ++editorGeneration.current, policy });
  return <section className="panel"><div className="section-heading"><h2>Sponsor policies</h2><Badge>Constraints only</Badge></div><div className="panel-text"><p><a href="#accounts">Open owner-reviewed account audit</a> to inspect separately approved native sponsor metadata. Current account-wide budgets remain unknown here.</p><p>A reusable policy specifies who and what may qualify for a match. Saving it never activates a signer, establishes a verified match or approves future payments.</p>
    {!supported ? <Notice>Non-signing sponsor preparation is not reported as available by this service.</Notice> : <><button className="button secondary" disabled={stale || !permissions.includes('propose')} onClick={() => edit()}>Create sponsor policy</button>{loading && <p>Reading private policies…</p>}{!loading && !policies.length && !error && <p>No sponsor policies are visible to this application.</p>}
      {policies.map(policy => <section className="saved-review" key={policy.policy_id}><strong>{policy.policy_id}</strong><small>Version {policy.current_version} · {human(policy.state)} · spending authority not granted</small><div className="panel-bottom"><button className="text-button" onClick={() => setSelected(policy)}>Inspect policy and preview</button><button className="text-button" disabled={stale || !permissions.includes('propose') || policy.state === 'retired'} onClick={() => edit(policy)}>Revise future constraints</button></div></section>)}</>}
    {error && <p className="form-error" role="alert">{error} Any previous policy list may be stale.</p>}
  </div>
    {editor && <SponsorEditor key={editor.generation} policy={editor.policy} view={view} client={client} stale={stale} onClose={() => setEditor(null)} onSaved={async () => { setEditor(current => current?.generation === editor.generation ? null : current); await onChanged('Sponsor constraints saved. No spending grant, verified match or disclosure consent was created.'); }}/>} 
    {selected && <SponsorReview initial={selected} view={view} client={client} stale={stale} canPropose={permissions.includes('propose')} onClose={() => setSelected(null)} onChanged={onChanged}/>}
  </section>;
}
function SponsorEditor({ policy, view, client, stale, onClose, onSaved }: { policy?: SponsorPolicyView; view: AgreementView; client: WholepactClient; stale: boolean; onClose: () => void; onSaved: () => Promise<void> }) {
  const [snapshot] = useState(() => structuredClone(view)); const [policyId] = useState(() => policy?.policy_id ?? newKey());
  const [source, setSource] = useState(() => JSON.stringify(policy?.versions.at(-1)?.terms ?? {
    schema_version: 1, network_profile_id: snapshot.agreement.network_profile_id, agreement_scope: [snapshot.agreement.agreement_id],
    sponsor: { participant_id: 'choose-sponsor', account_id: 'choose-sponsor-account' }, eligible_contributors: [{ participant_id: 'choose-contributor', account_id: 'choose-contributor-account' }],
    beneficiaries: snapshot.agreement.recipients.map(recipient => ({ recipient_id: recipient.recipient_id, address: recipient.address, maximum_amount: recipient.amount })),
    rate_numerator: 1, rate_denominator: 1, maximum_match: '0', minimum_qualifying_total: '0', fee_cap: '0', maximum_net_debit: '0', aggregate_budget: '0',
    assurance: { kind: 'independently_verified' }, identity_requirements: [], privacy_profile: snapshot.agreement.privacy_profile, expires_at: null,
  }, null, 2));
  const [assurance, setAssurance] = useState(''); const [verifier, setVerifier] = useState(''); const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false); const [uncertain, setUncertain] = useState(false); const [error, setError] = useState('');
  const pending = useRef(false); const attempt = useRef<{ source: string; key: string } | null>(null); const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const changed = snapshot.revision !== view.revision;
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (pending.current || !ack || (!uncertain && (stale || changed))) return;
    pending.current = true; setBusy(true); setError('');
    try {
      if (!uncertain) {
        const terms = JSON.parse(source);
        if (!assurance || terms?.assurance?.kind !== assurance || assurance === 'attested' && (!verifier.trim() || terms.assurance.verifier_identity !== verifier.trim())) throw new Error('Choose the intended assurance explicitly and make the JSON assurance and named verifier match that choice. No assurance fallback is applied.');
        for (const field of ['rate_numerator', 'rate_denominator']) if (!Number.isSafeInteger(terms[field]) || terms[field] < 1) throw new Error('Use positive safe whole numbers for the matching ratio.');
        if (attempt.current?.source !== source) attempt.current = { source, key: newKey() };
      }
      await client.saveSponsorPolicySource(snapshot.agreement.agreement_id, policyId, attempt.current!.source, { idempotencyKey: attempt.current!.key, expectedRevision: snapshot.revision }, policy?.current_version);
      setUncertain(false); if (mounted.current) await onSaved();
    } catch (caught) { setUncertain(previous => previous || uncertainError(caught)); setError(errorText(caught)); }
    finally { pending.current = false; setBusy(false); }
  };
  return <Modal title={policy ? 'Revise sponsor constraints' : 'Create sponsor constraints'} onClose={onClose} wide><form className="modal-body" onSubmit={submit}>
    <Notice warning>Advanced policy editor. Every amount is an exact integer zatoshi string, not a decimal ZEC value. Replace placeholder account labels and zero limits deliberately. Keys and private wallet material never belong here.</Notice>
    {(changed || stale) && <Notice warning>The journal changed or is stale. New edits cannot be saved from this opening revision. An uncertain request can only be retried unchanged.</Notice>}
    <fieldset disabled={busy || uncertain || stale || changed}><legend>Exact future policy constraints</legend><Field label="Policy terms JSON" hint="The original JSON is sent intact so the engine can reject duplicate keys, unknown fields, inconsistent limits and unsupported terms."><textarea spellCheck={false} className="policy-source" rows={24} value={source} onChange={event => setSource(event.target.value)} required/></Field>
      <Field label="Explicit match assurance choice"><select required value={assurance} onChange={event => setAssurance(event.target.value)}><option value="">Choose assurance deliberately</option><option value="independently_verified">Require independently verified matching</option><option value="attested">Trust an explicitly named attestation verifier</option></select></Field>
      {assurance === 'attested' && <Field label="Explicitly trusted verifier identity" hint="Must exactly match assurance.verifier_identity in the JSON. A name is not a verified attestation."><input required maxLength={128} value={verifier} onChange={event => setVerifier(event.target.value)}/></Field>}
      <label className="consent"><input type="checkbox" checked={ack} onChange={event => setAck(event.target.checked)}/><span>I am saving future constraints only. This policy is not a spending grant or data-sharing consent, and its budget does not establish remaining funds.</span></label>
    </fieldset>
    {uncertain && <Notice warning>The exact original policy may already be saved. Its JSON, opening version, journal revision and key remain frozen.<p className="mono wrap">{attempt.current?.key}</p></Notice>}{error && <p role="alert" className="form-error">{error}</p>}
    <div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Close</button><button className="button primary" disabled={busy || !ack || (!uncertain && (changed || stale || !assurance))}>{busy ? 'Checking policy…' : uncertain ? 'Retry exact original policy' : policy ? 'Save new constraint version' : 'Save draft policy'}</button></div>
  </form></Modal>;
}
function SponsorReview({ initial, view, client, stale, canPropose, onClose, onChanged }: { initial: SponsorPolicyView; view: AgreementView; client: WholepactClient; stale: boolean; canPropose: boolean; onClose: () => void; onChanged: (message: string) => Promise<void> }) {
  const [policy, setPolicy] = useState(() => structuredClone(initial)); const [revision, setRevision] = useState(view.revision); const [preview, setPreview] = useState<SponsorPolicyPreview | null>(null);
  const [busy, setBusy] = useState(false); const [uncertain, setUncertain] = useState(false); const [error, setError] = useState('');
  const pending = useRef(false); const attempt = useRef<{ request: SponsorPolicyStateRequest; key: string; revision: number } | null>(null);
  const changed = revision !== view.revision; const candidate = view.candidates?.at(-1);
  const state = async (next: SponsorPolicyStateRequest['state']) => {
    if (pending.current || (!uncertain && (changed || stale || !canPropose))) return; pending.current = true; setBusy(true); setError('');
    if (!uncertain) attempt.current = { request: { policy_id: policy.policy_id, expected_policy_version: policy.current_version, state: next }, key: newKey(), revision };
    try { const original = attempt.current!; const result = await client.setSponsorPolicyState(view.agreement.agreement_id, original.request, { idempotencyKey: original.key, expectedRevision: original.revision }); setPolicy(result.policy); setRevision(result.agreement_revision); setPreview(null); setUncertain(false); await onChanged('Sponsor preparation state updated. Existing released authorizations and budget exposure are unchanged.'); }
    catch (caught) { setUncertain(previous => previous || uncertainError(caught)); setError(errorText(caught)); }
    finally { pending.current = false; setBusy(false); }
  };
  const evaluate = async () => { if (pending.current || !candidate || changed || stale || uncertain) return; pending.current = true; setBusy(true); setError(''); setPreview(null); try { setPreview(await client.previewSponsorPolicy(view.agreement.agreement_id, policy.policy_id, { candidate_id: candidate.candidate_id, expected_policy_version: policy.current_version })); } catch (caught) { setError(errorText(caught)); } finally { pending.current = false; setBusy(false); } };
  return <Modal title="Inspect sponsor policy" onClose={onClose} wide><div className="modal-body review"><Notice warning title="No spending authority granted">Draft means available for nonbinding previews. Pausing or retiring changes future policy use; it never recalls released authorizations or erases budget exposure.</Notice>
    {(changed || stale) && <Notice warning>Journal context changed or is stale. Close and reopen for current policy context. Any displayed preview is historical.</Notice>}
    <h3>{policy.policy_id}</h3><p>Version {policy.current_version} · {human(policy.state)}</p>
    {policy.versions.map(version => <details className="evidence-details" key={version.version}><summary>Immutable policy version {version.version} · {dateTime(version.created_at)}</summary><p className="mono wrap">Digest {version.terms_digest}</p><pre className="wrap">{JSON.stringify(version.terms, null, 2)}</pre></details>)}
    <div className="panel-bottom"><button className="button secondary" disabled={busy || uncertain || changed || stale || policy.state !== 'draft' || !candidate} onClick={evaluate}>Preview latest exact candidate</button><small>{candidate ? `Candidate ${candidate.candidate_id}` : 'A current candidate and explicit selected roster are required.'}</small></div>
    {preview && <><h3>Match remains unverifiable</h3><dl className="review-values"><div><dt>Eligible contribution claims</dt><dd><Money value={preview.formula.evaluation.eligible_total} detail/></dd></div><div><dt>Calculated match</dt><dd><Money value={preview.formula.evaluation.calculated_match} detail/></dd></div><div><dt>Claimed sponsor net debit</dt><dd><Money value={preview.formula.sponsor_net_debit} detail/></dd></div><div><dt>Fees excluded from eligible base</dt><dd><Money value={preview.formula.excluded_transaction_fee} detail/></dd></div><div><dt>Service charges excluded</dt><dd><Money value={preview.formula.excluded_service_charges} detail/></dd></div><div><dt>Aggregate budget ceiling</dt><dd><Money value={preview.budget.aggregate_budget} detail/></dd></div><div><dt>Pending exposure</dt><dd>{preview.budget.pending_authorization_exposure == null ? 'Unknown' : <Money value={preview.budget.pending_authorization_exposure}/>}</dd></div><div><dt>Settled spending</dt><dd>{preview.budget.settled_debit == null ? 'Unknown' : <Money value={preview.budget.settled_debit}/>}</dd></div><div><dt>Remaining spend budget</dt><dd>{preview.budget.remaining_budget == null ? 'Unknown' : <Money value={preview.budget.remaining_budget}/>}</dd></div></dl><p>{preview.budget.reason}</p><p>Assurance requested: {preview.formula.evaluation.assurance.kind === 'attested' ? `Attested by ${preview.formula.evaluation.assurance.verifier_identity}` : 'Independently verified'}. Evidence status: unverifiable. Rounding: {human(preview.formula.rounding)}.</p><ul>{preview.formula.excluded_contributions.map(item => <li key={item.participant_id}>{item.participant_id}: <Money value={item.contribution}/> excluded, {human(item.reason)}</li>)}</ul><ul>{preview.blocking_reasons.map(reason => <li key={reason}>{reason}</li>)}</ul><details className="evidence-details"><summary>Required evidence and exact preview binding</summary><ul>{preview.formula.evaluation.required_evidence.map(item => <li key={item}>{item}</li>)}</ul><p className="mono wrap">Candidate manifest {preview.candidate_manifest_digest}</p><p className="mono wrap">Policy terms {preview.policy_terms_digest}</p></details></>}
    {error && <p className="form-error" role="alert">{error}</p>}{uncertain && <Notice warning>The original state-change may have committed. Retry preserves its exact version and revision.<p className="mono wrap">{attempt.current?.key}</p><button className="button secondary" disabled={busy} onClick={() => state(attempt.current!.request.state)}>Retry exact original state change</button></Notice>}
    <div className="modal-actions"><button className="button secondary" onClick={onClose}>Close</button>{policy.state !== 'retired' && <><button className="button secondary" disabled={busy || uncertain || changed || stale || !canPropose} onClick={() => state(policy.state === 'draft' ? 'paused' : 'draft')}>{policy.state === 'draft' ? 'Pause future previews' : 'Resume draft previews'}</button><button className="button secondary" disabled={busy || uncertain || changed || stale || !canPropose} onClick={() => state('retired')}>Retire future policy use</button></>}</div>
  </div></Modal>;
}
