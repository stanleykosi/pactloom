import { NativeReconciliationPanel } from './native-reconciliation-requests';
import { NativeDispatchPanel } from './native-dispatch-requests';
import { NativeSettlementPanel } from './native-settlement-requests';
import { NativeArtifactHandoffPanel } from './native-artifact-handoff-requests';
import { NativeProofExecutionPanel } from './native-proof-execution-requests';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { WholepactClient, WholepactError, type AgreementView, type CandidateRequest, type CandidateView, type CapabilitySet, type ProposalComparison } from '@wholepact/sdk';
import { Badge, dateTime, Field, human, Icon, Modal, Money, Notice } from './components';
import { candidateBlockers, candidateRequest, claimRows, economicReview, type ClaimRow } from './candidate-model';
import { ComparisonDetails } from './planning';
import { ProofJobSummary } from './recovery';
import { NativeConstructionPanel } from './native-requests';
import { NativeProofReconciliationPanel } from './native-proof-requests';
import { errorText } from './App';

const key = () => `candidate-${crypto.randomUUID()}`;
export function CandidatePanel({ view, client, capabilities, permissions, stale, onChanged }: { view: AgreementView; client: WholepactClient; capabilities: CapabilitySet | null; permissions: string[]; stale: boolean; onChanged: (message: string) => Promise<void> }) {
  const [creating, setCreating] = useState<number | null>(null); const formGeneration = useRef(0);
  const [selected, setSelected] = useState<CandidateView | null>(null); const [comparison, setComparison] = useState<ProposalComparison | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState('');
  const pendingRead = useRef(false); const readGeneration = useRef(0);
  useEffect(() => () => { readGeneration.current++; }, []);
  const supported = capabilities?.features.candidate_terms?.status === 'supported';
  const blockers = candidateBlockers(view, supported, permissions.includes('coordinate'), stale);
  const candidates = view.candidates ?? [];
  const open = async (candidate: CandidateView) => {
    if (pendingRead.current) return;
    pendingRead.current = true; setLoading(candidate.candidate_id); setError('');
    const generation = ++readGeneration.current;
    try {
      const latest = await client.candidate(candidate.candidate_id);
      const previous = latest.proposal.previous_proposal_id;
      const changes = previous ? await client.compareCandidates(previous, latest.candidate_id) : null;
      if (generation === readGeneration.current) { setSelected(latest); setComparison(changes); }
    } catch (caught) { if (generation === readGeneration.current) setError(errorText(caught)); }
    finally { if (generation === readGeneration.current) { pendingRead.current = false; setLoading(null); } }
  };
  return <section className="panel candidate-panel" aria-labelledby="candidate-heading">
    <div className="section-heading"><div><p className="eyebrow">Exact terms, separate evidence</p><h2 id="candidate-heading">Unsigned candidates</h2></div><Badge tone="warning">Not signable</Badge></div>
    <div className="candidate-intro"><p>Freeze selected participants, claimed inputs and returns, fees and expiry into one immutable candidate. The engine checks the claimed accounting. It does not establish wallet funds.</p>
      <div className="candidate-readiness"><Icon name="lock" size={19}/><div><strong>Private local contribution data is missing</strong><p>Wallet note selection, ownership evidence and consented private contribution intake are unavailable through this workspace. Do not paste viewing keys, witnesses, seeds or raw PCZTs here.</p></div></div>
      {blockers.length > 0 && <ul className="candidate-blockers">{blockers.map(reason => <li key={reason}>{reason}</li>)}</ul>}
      <button className="button secondary" disabled={blockers.length > 0} onClick={() => setCreating(++formGeneration.current)}><Icon name="plus" size={16}/>{candidates.length ? 'Prepare another claims candidate' : 'Prepare candidate claims'}</button>
      <small className="candidate-note">Synthetic, non-private development data only. This service stores unencrypted metadata.</small>
    </div>
    {candidates.length > 0 && <div className="candidate-list">{[...candidates].reverse().map((candidate, index) => <article className="candidate-row" key={candidate.candidate_id}>
      <div><div className="candidate-row-title"><strong>Candidate {candidates.length - index}</strong><Badge>{index === 0 ? 'Latest candidate' : 'Earlier candidate'}</Badge></div><small>{dateTime(candidate.proposal.created_at)} · {candidate.reviews.length} saved review{candidate.reviews.length === 1 ? '' : 's'}</small><p>{economicReview(candidate) ? 'Local economic computation recorded. Human approval and chain validation remain absent.' : 'Claimed accounting frozen. Cryptographic economic verification is not established.'}</p><code className="wrap">{candidate.candidate_id}</code></div>
      <button className="button secondary" disabled={!!loading} onClick={() => open(candidate)}>{loading === candidate.candidate_id ? 'Reading…' : 'Inspect candidate'}<Icon name="arrow" size={15}/></button>
    </article>)}</div>}
    <NativeConstructionPanel view={view} client={client} capabilities={capabilities} permissions={permissions} stale={stale} onChanged={onChanged}/>
    <NativeProofReconciliationPanel view={view} client={client} capabilities={capabilities} permissions={permissions} stale={stale} onChanged={onChanged}/>
    <NativeProofExecutionPanel view={view} client={client} capabilities={capabilities} permissions={permissions} stale={stale} onChanged={onChanged}/>
    <NativeArtifactHandoffPanel view={view} client={client} capabilities={capabilities} permissions={permissions} stale={stale} onChanged={onChanged}/>
    <NativeSettlementPanel view={view} client={client} capabilities={capabilities} permissions={permissions} stale={stale} onChanged={onChanged}/>
    <NativeDispatchPanel view={view} client={client} capabilities={capabilities} permissions={permissions} stale={stale} onChanged={onChanged}/>
    <NativeReconciliationPanel view={view} client={client} capabilities={capabilities} permissions={permissions} stale={stale} onChanged={onChanged}/>
    {error && <p className="form-error candidate-error" role="alert">{error} Previously read metadata remains in the journal view.</p>}
    {creating !== null && <CandidateForm key={creating} view={view} client={client} stale={stale} onClose={() => setCreating(null)} onSaved={async () => { setCreating(current => current === creating ? null : current); await onChanged('Unsigned candidate saved. Only claimed accounting was checked; no payment was authorized.'); }}/>}
    {selected && <CandidateReview candidate={selected} comparison={comparison} view={view} client={client} stale={stale} supported={supported} onClose={() => setSelected(null)} onChanged={onChanged}/>}
  </section>;
}
function CandidateForm({ view, client, stale, onClose, onSaved }: { view: AgreementView; client: WholepactClient; stale: boolean; onClose: () => void; onSaved: () => Promise<void> }) {
  const [snapshot] = useState(() => structuredClone(view));
  const [rows, setRows] = useState(() => claimRows(snapshot));
  const [fee, setFee] = useState(''); const [expiry, setExpiry] = useState(''); const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [uncertain, setUncertain] = useState(false);
  const pending = useRef(false); const submitted = useRef<{ request: CandidateRequest; idempotencyKey: string; encoded: string } | null>(null);
  const changed = snapshot.revision !== view.revision;
  const blocked = stale || changed || snapshot.cancellation_requested;
  const edit = (index: number, patch: Partial<ClaimRow>) => setRows(old => old.map((row, i) => i === index ? { ...row, ...patch } : row));
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (pending.current || !ack || (!uncertain && blocked)) return;
    pending.current = true; setBusy(true); setError('');
    try {
      if (!uncertain) {
        const request = candidateRequest(snapshot, rows, fee, expiry); const encoded = JSON.stringify(request);
        if (submitted.current?.encoded !== encoded) submitted.current = { request, encoded, idempotencyKey: key() };
      }
      const attempt = submitted.current!;
      await client.createCandidate(snapshot.agreement.agreement_id, attempt.request, { idempotencyKey: attempt.idempotencyKey, expectedRevision: snapshot.revision });
      await onSaved();
    } catch (caught) { setUncertain(previous => previous || caught instanceof WholepactError && caught.code === 'EXTERNAL_OUTCOME_UNCERTAIN'); setError(errorText(caught)); }
    finally { pending.current = false; setBusy(false); }
  };
  return <Modal title="Prepare unsigned candidate claims" onClose={onClose} wide><form className="agreement-form candidate-form" onSubmit={submit}>
    <Notice title="No wallet material is requested">Enter synthetic accounting claims only. The engine checks exact totals, deterministic fee shares, intent limits and the stored agreement. Account labels and return instructions remain unauthenticated claims.</Notice>
    {changed && <Notice warning title="The journal changed">This form stays bound to revision {snapshot.revision}. Close and reopen before preparing a new candidate. An uncertain request can only be retried unchanged.</Notice>}
    {stale && <Notice warning title="Local information may be stale">Refresh the workspace before preparing new claims. An exact retry keeps the original revision and idempotency key.</Notice>}
    <fieldset disabled={busy || uncertain || blocked}><legend>01 · Select participants and declared accounting</legend><p className="field-guidance">{snapshot.roster_selected ? 'The saved nonbinding roster is selected. Its desired amounts must remain unchanged.' : 'Nothing is selected for you.'} This editor records one claimed input and optional return per selected participant. It never selects wallet notes or computes a balance. Fees must follow the agreement’s allocation policy; Rust validates the result.</p>
      {rows.map((row, index) => <section className="claim-editor" key={row.intent.intent_id}>
        <label className="consent"><input type="checkbox" disabled={snapshot.roster_selected} checked={row.selected} onChange={e => edit(index, { selected: e.target.checked })}/><span>Select {row.intent.participant_id}</span></label>
        <p className="claim-limits">Intent limit <Money value={row.intent.desired_contribution}/> · Fee cap <Money value={row.intent.fee_cap}/> · Maximum debit <Money value={row.intent.maximum_net_debit}/></p>
        {row.selected && <div className="claim-fields"><Field label={`${row.intent.participant_id} · Scoped account label`} hint="A synthetic label, never an account key or proof of ownership."><input required maxLength={128} value={row.account} onChange={e => edit(index, { account: e.target.value })}/></Field><div className="form-grid">
          <Field label={`${row.intent.participant_id} · Contribution (ZEC)`}><input required readOnly={snapshot.roster_selected} inputMode="decimal" value={row.contribution} onChange={e => edit(index, { contribution: e.target.value })}/></Field>
          <Field label={`${row.intent.participant_id} · Fee share (ZEC)`}><input required inputMode="decimal" value={row.feeShare} onChange={e => edit(index, { feeShare: e.target.value })}/></Field>
          <Field label={`${row.intent.participant_id} · Claimed input (ZEC)`} hint="A claim, not funds checked available."><input required inputMode="decimal" value={row.input} onChange={e => edit(index, { input: e.target.value })}/></Field>
          <Field label={`${row.intent.participant_id} · Claimed return (ZEC)`} hint="Enter 0 only if no return is proposed."><input required inputMode="decimal" value={row.returned} onChange={e => edit(index, { returned: e.target.value })}/></Field>
        </div><Field label={`${row.intent.participant_id} · Return receiving instructions`} hint="Not verified as belonging to the participant. Required for a nonzero return."><textarea rows={2} maxLength={2048} value={row.returnAddress} onChange={e => edit(index, { returnAddress: e.target.value })}/></Field></div>}
      </section>)}
    </fieldset>
    <fieldset disabled={busy || uncertain || blocked}><legend>02 · Exact fee and expiry claims</legend><div className="form-grid"><Field label="Exact transaction fee (ZEC)"><input required inputMode="decimal" value={fee} onChange={e => setFee(e.target.value)}/></Field><Field label="Transaction expiry height" hint="A proposed block height. No live chain context has been checked."><input required inputMode="numeric" value={expiry} onChange={e => setExpiry(e.target.value)}/></Field></div>
      <div className="candidate-recipients"><strong>Recipient instructions stay exactly as saved</strong>{snapshot.agreement.recipients.map(recipient => <div key={recipient.recipient_id}><Money value={recipient.amount} detail/><p className="mono wrap">{recipient.address}</p></div>)}</div>
      <p className="field-guidance">{snapshot.candidates?.length ? 'A new immutable candidate will reference the previous one. It does not revoke an earlier authorization or replace a payment.' : 'This will be the agreement’s first immutable candidate.'}</p>
      <label className="consent"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/><span>I understand this saves synthetic claims only. It does not verify actual funds, authorize spending or consent to disclosure.</span></label>
    </fieldset>
    {uncertain && <Notice warning title="The original command may have been recorded">Keep this request unchanged. Retry uses the same key and opening revision; it does not create a replacement. Closing loses this in-memory retry reference, so inspect the journal before preparing another candidate.<p className="mono wrap">{submitted.current?.idempotencyKey}</p></Notice>}
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Close</button><button className="button primary" disabled={busy || !ack || (!uncertain && blocked)}>{busy ? 'Checking and freezing…' : uncertain ? 'Retry exact original request' : 'Freeze candidate claims'}</button></div>
  </form></Modal>;
}
function CandidateReview({ candidate, comparison, view, client, stale, supported, onClose, onChanged }: { candidate: CandidateView; comparison: ProposalComparison | null; view: AgreementView; client: WholepactClient; stale: boolean; supported: boolean; onClose: () => void; onChanged: (message: string) => Promise<void> }) {
  const [snapshot, setSnapshot] = useState(() => structuredClone(candidate)); const [revision, setRevision] = useState(view.revision);
  const [ack, setAck] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [uncertain, setUncertain] = useState(false);
  const pending = useRef(false); const attempt = useRef({ idempotencyKey: key(), expectedRevision: view.revision });
  const changed = view.revision !== revision; const economic = economicReview(snapshot); const manifest = snapshot.proposal.manifest;
  const review = async () => {
    if (pending.current || (!uncertain && (changed || stale || !supported))) return;
    pending.current = true; setBusy(true); setError('');
    try {
      const result = await client.reviewCandidate(snapshot.candidate_id, attempt.current);
      const saved = result.candidates?.find(item => item.candidate_id === snapshot.candidate_id);
      if (!saved || saved.manifest_digest !== snapshot.manifest_digest) throw new Error('The service did not return the same immutable candidate. Close and read the original candidate again.');
      setSnapshot(structuredClone(saved)); setRevision(result.revision); setUncertain(false);
      attempt.current = { idempotencyKey: key(), expectedRevision: result.revision };
      await onChanged('Claims review saved. No cryptographic verification, human approval or chain validation was added.');
    } catch (caught) { setUncertain(previous => previous || caught instanceof WholepactError && caught.code === 'EXTERNAL_OUTCOME_UNCERTAIN'); setError(errorText(caught)); }
    finally { pending.current = false; setBusy(false); }
  };
  return <Modal title="Inspect unsigned candidate" onClose={onClose} wide><div className="modal-body review candidate-review">
    <div className="review-heading"><Badge tone="warning">Not signable</Badge><span className="muted">Immutable candidate · journal read {revision}</span></div>
    {(changed || stale) && <Notice warning title={changed ? 'The journal changed during review' : 'Local information may be stale'}>This view remains bound to the candidate you opened. Close, refresh and reopen for current journal context. Signing and distribution remain disabled.</Notice>}
    <h3>{manifest.agreement.purpose}</h3><p className="mono wrap">{snapshot.candidate_id}</p>
    <div className="assurance-grid" aria-label="Candidate evidence boundaries">
      <Evidence title="Claimed accounting" status="Checked by the engine">Exact claimed totals, allocations and caps were checked when this candidate was frozen. They are not wallet balances.</Evidence>
      <Evidence title="Cryptographic economics" status={economic ? 'Local computation recorded' : 'Not established'}>{economic ? snapshot.proof_jobs?.length ? 'Actual local economics were computed. Inspect the separate protected-job record for checkpoint retention and recovery.' : 'Actual local input and output economics were computed for this manifest. The private artifact was not retained by this transient computation.' : 'No bound local economic computation report is present. A claims review cannot establish actual inputs, ownership or return outputs.'}</Evidence>
      <Evidence title="Human spend approval" status="Not requested">Reading this screen or acknowledging its limits does not grant spending authority.</Evidence>
      <Evidence title="Disclosure consent" status="Not authenticated">A named operator or reviewer roster is not consent. No private artifact can be distributed here.</Evidence>
      <Evidence title="Account associations" status="Not authenticated">Scoped participant and account labels do not authenticate a person’s control of an account.</Evidence>
      <Evidence title="Chain validation" status="Not established">No fresh chain context, spendability, submission or settlement is established. Local proof evidence, if present, is listed separately below.</Evidence>
    </div>
    {comparison && <ComparisonDetails comparison={comparison}/>}
    <ProofJobSummary candidate={snapshot}/>
    <h3>Frozen claimed economics</h3><dl className="review-values"><div><dt>Recipients</dt><dd><Money value={snapshot.accounting.recipient_total} detail/></dd></div><div><dt>Transaction fee</dt><dd><Money value={snapshot.accounting.transaction_fee} detail/></dd></div><div><dt>Claimed inputs</dt><dd><Money value={snapshot.accounting.input_total} detail/></dd></div><div><dt>Claimed outputs, including returns</dt><dd><Money value={snapshot.accounting.output_total} detail/></dd></div><div><dt>Proposed expiry height</dt><dd>{manifest.expiry_height} · chain not checked</dd></div><div><dt>Network profile</dt><dd className="wrap">{manifest.agreement.network_profile_id}</dd></div></dl>
    {manifest.participants.map(participant => <section className="participant-summary" key={participant.participant_id}><h4>{participant.participant_id}</h4><small>Claimed account: <span className="mono wrap">{participant.account_id}</span></small><dl className="review-values"><div><dt>Contribution</dt><dd><Money value={participant.contribution} detail/></dd></div><div><dt>Fee share / cap</dt><dd><Money value={participant.fee_share}/> / <Money value={participant.fee_cap}/></dd></div><div><dt>Claimed net debit</dt><dd><Money value={snapshot.accounting.participant_net_debits[participant.participant_id]} detail/></dd></div><div><dt>Intent maximum net debit</dt><dd><Money value={participant.maximum_net_debit} detail/></dd></div></dl></section>)}
    <h3>Exact receiving instructions</h3>{manifest.outputs.map(output => <div className="recipient-card" key={output.output_id}><div><strong>{output.allocation.kind === 'recipient' ? 'Recipient' : output.allocation.kind === 'return' ? `Claimed return · ${output.allocation.participant_id}` : 'Charge'} · {output.output_id}</strong><Money value={output.amount} detail/></div><p className="mono wrap">{output.address}</p><small>{output.allocation.kind === 'return' ? 'Return ownership is not established by this label.' : 'Address text alone does not authenticate the recipient.'}</small></div>)}
    <details className="evidence-details"><summary>Digests and saved review evidence ({snapshot.reviews.length})</summary><dl className="compact-dl"><div><dt>Manifest digest</dt><dd className="mono wrap">{snapshot.manifest_digest}</dd></div><div><dt>Proposal digest</dt><dd className="mono wrap">{snapshot.proposal_digest}</dd></div><div><dt>Preceding candidate</dt><dd className="mono wrap">{snapshot.proposal.previous_proposal_id ?? 'None'}</dd></div></dl>{snapshot.reviews.length ? [...snapshot.reviews].reverse().map(report => <section className="saved-review" key={report.report_id}><strong>{report.status === 'economic_terms_verified_only' ? 'Local economic computation only' : 'Claims checked only'}</strong><small>{dateTime(report.checked_at)} · {human(report.scope)}</small><dl className="compact-dl"><div><dt>Report</dt><dd className="mono wrap">{report.report_id}</dd></div><div><dt>Artifact digest</dt><dd className="mono wrap">{report.artifact_digest ?? 'No artifact'}</dd></div><div><dt>Transaction-effects commitment</dt><dd className="mono wrap">{report.effects_commitment ?? 'Not established'}</dd></div><div><dt>Review binding</dt><dd className="mono wrap">{report.review_binding ?? 'Not established'}</dd></div><div><dt>Artifact recovery</dt><dd>{report.artifact_persistence === 'no_artifact' ? 'No artifact was constructed.' : 'Not retained. Reconstruction requires a new operation; replay restores this report only.'}</dd></div></dl><ul>{report.blocking_reasons.map(reason => <li key={reason}>{human(reason)}</li>)}</ul></section>) : <p>No separate review report has been recorded.</p>}</details>
    <Notice title="Private contribution intake is unavailable">The workspace can save and recheck claims. It cannot accept wallet notes, viewing keys, witnesses or raw PCZTs. No account setup or wallet secret is needed to inspect this record.</Notice>
    <label className="consent"><input type="checkbox" checked={ack} disabled={changed || stale} onChange={e => setAck(e.target.checked)}/><span>I have read these evidence limits. This is an in-memory acknowledgment, not spend approval or disclosure consent.</span></label>
    <div className="blocked-action"><Icon name="lock"/><div><strong>Authorization and private export remain unavailable</strong><p>Neither a claims review nor local economic computation supplies human consent, authenticated disclosure approval or chain validation.</p></div></div>
    {uncertain && <Notice warning title="Review outcome is uncertain">Retry checks the same operation with the same candidate, key and revision. Inspect the journal before starting another review.<p className="mono wrap">{attempt.current.idempotencyKey}</p></Notice>}
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="modal-actions candidate-actions"><button className="button secondary" onClick={onClose}>Close candidate</button><button className="button secondary" disabled={busy || (!uncertain && (changed || stale || !supported))} onClick={review}>{busy ? 'Checking claims…' : uncertain ? 'Retry original claims review' : 'Recheck claims only'}</button><button className="button primary" disabled>Authorize · unavailable</button><button className="button secondary" disabled>Private export · unavailable</button></div>
  </div></Modal>;
}
function Evidence({ title, status, children }: { title: string; status: string; children: React.ReactNode }) { return <div className="evidence-axis"><span>{title}</span><strong>{status}</strong><p>{children}</p></div>; }
