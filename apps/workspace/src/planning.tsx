import { useEffect, useRef, useState } from 'react';
import { WholepactClient, WholepactError, sumZatoshis, type AgreementView, type ProposalComparison, type ProposalPreview, type RosterSelectionRequest } from '@wholepact/sdk';
import { Badge, dateTime, Empty, Modal, Money, Notice } from './components';
import { errorText } from './App';
import { proposalTermsContext, proposalReportAppliesToCurrentTerms } from './terms-revision-model';

const key = () => `planning-${crypto.randomUUID()}`;
const unresolved = (error: unknown) => error instanceof WholepactError && error.code === 'EXTERNAL_OUTCOME_UNCERTAIN';

export function RosterPanel({ view, client, canCoordinate, stale, onChanged }: { view: AgreementView; client: WholepactClient; canCoordinate: boolean; stale: boolean; onChanged: (message: string) => Promise<void> }) {
  const [open, setOpen] = useState<number | null>(null); const opening = useRef(0);
  const selected = view.intents.filter(intent => intent.status === 'selected');
  const waiting = view.intents.filter(intent => intent.status === 'waitlisted');
  return <section className="panel"><div className="section-heading"><h2>Participant selection</h2><Badge>{view.roster_selected ? 'Nonbinding roster saved' : 'No roster saved'}</Badge></div><div className="panel-text">
    <p>Select an exact funding roster from recorded intent. Unselected eligible participants wait without any payment or reservation.</p>
    {view.roster_selected && <><p>{selected.length} selected · {waiting.length} waitlisted</p><p>Selected intent total: <Money value={sumZatoshis(selected.map(intent => intent.desired_contribution))}/></p></>}
    <button className="button secondary" disabled={stale || !canCoordinate || view.cancellation_requested} onClick={() => setOpen(++opening.current)}>{view.roster_selected ? 'Review or change roster' : 'Select a roster'}</button>
    {!canCoordinate && <small>Coordination permission is required.</small>}
  </div>{open !== null && <RosterForm key={open} view={view} client={client} stale={stale} onClose={() => setOpen(null)} onSaved={async () => { setOpen(current => current === open ? null : current); await onChanged('Nonbinding roster recorded. Selected amounts were not increased and no funds were reserved.'); }}/>}</section>;
}
function RosterForm({ view, client, stale, onClose, onSaved }: { view: AgreementView; client: WholepactClient; stale: boolean; onClose: () => void; onSaved: () => Promise<void> }) {
  const [snapshot] = useState(() => structuredClone(view));
  const eligible = snapshot.intents.filter(intent => ['active', 'selected', 'waitlisted'].includes(intent.status));
  const [selected, setSelected] = useState<string[]>(() => eligible.filter(intent => intent.status === 'selected').map(intent => intent.intent_id));
  const [busy, setBusy] = useState(false); const [uncertain, setUncertain] = useState(false); const [error, setError] = useState('');
  const pending = useRef(false); const attempt = useRef<{ request: RosterSelectionRequest; revision: number; key: string } | null>(null);
  const changed = snapshot.revision !== view.revision; const blocked = changed || stale || snapshot.cancellation_requested;
  const submit = async () => {
    if (pending.current || (!uncertain && blocked)) return;
    pending.current = true; setBusy(true); setError('');
    if (!uncertain) attempt.current = { request: { selected_intent_ids: [...selected] }, revision: snapshot.revision, key: key() };
    try { const original = attempt.current!; await client.selectRoster(snapshot.agreement.agreement_id, original.request, { idempotencyKey: original.key, expectedRevision: original.revision }); setUncertain(false); await onSaved(); }
    catch (caught) { setUncertain(previous => previous || unresolved(caught)); setError(errorText(caught)); }
    finally { pending.current = false; setBusy(false); }
  };
  return <Modal title="Select nonbinding participants" onClose={onClose}><div className="modal-body">
    <Notice>Desired contributions must fund the exact target. A reduced or changed contribution requires a new intent from that participant. This roster does not establish available funds or approval.</Notice>
    {(changed || stale) && <Notice warning>Journal context changed or is stale. Close and refresh before a new selection. An interrupted command can be retried unchanged.</Notice>}
    <fieldset disabled={busy || uncertain || blocked}><legend>Explicit participant selection</legend>{eligible.length ? eligible.map(intent => <label className="consent" key={intent.intent_id}><input type="checkbox" checked={selected.includes(intent.intent_id)} onChange={event => setSelected(current => event.target.checked ? [...current, intent.intent_id] : current.filter(id => id !== intent.intent_id))}/><span>{intent.participant_id} · <Money value={intent.desired_contribution}/><small>{intent.conditions.length ? 'Conditions require evaluation; the engine may refuse selection.' : 'Nonbinding intent'}{intent.valid_until ? ` · valid until ${dateTime(intent.valid_until)}` : ''}</small></span></label>) : <Empty title="No eligible intent">Record intent before selecting a roster.</Empty>}</fieldset>
    <p>Selected total: <Money value={sumZatoshis(eligible.filter(intent => selected.includes(intent.intent_id)).map(intent => intent.desired_contribution))}/> · Target: <Money value={snapshot.agreement.funding_policy.target}/></p>
    {uncertain && <Notice warning title="The selection may already be saved">Only retry the original request with its original revision and key. Closing loses this in-memory retry reference.<p className="mono wrap">{attempt.current?.key}</p></Notice>}
    {error && <p role="alert" className="form-error">{error}</p>}<div className="modal-actions"><button className="button secondary" onClick={onClose}>Close</button><button className="button primary" disabled={busy || (!uncertain && (blocked || !selected.length))} onClick={submit}>{busy ? 'Checking roster…' : uncertain ? 'Retry exact original request' : 'Save nonbinding roster'}</button></div>
  </div></Modal>;
}

export function ProposalPanel({ view, client, canCoordinate, stale, onChanged }: { view: AgreementView; client: WholepactClient; canCoordinate: boolean; stale: boolean; onChanged: (message: string) => Promise<void> }) {
  const [selected, setSelected] = useState<ProposalPreview | null>(null); const [comparison, setComparison] = useState<ProposalComparison | null>(null);
  const [busy, setBusy] = useState(false); const [uncertain, setUncertain] = useState(false); const [error, setError] = useState('');
  const pending = useRef(false); const generation = useRef(0); const attempt = useRef<{ key: string; revision: number } | null>(null);
  useEffect(() => () => { generation.current++; }, []);
  const proposals = view.proposals ?? [];
  const freeze = async () => {
    if (pending.current || (!uncertain && (stale || !canCoordinate || view.cancellation_requested))) return;
    pending.current = true; setBusy(true); setError('');
    if (!uncertain) attempt.current = { key: key(), revision: view.revision };
    try { await client.createProposal(view.agreement.agreement_id, { idempotencyKey: attempt.current!.key, expectedRevision: attempt.current!.revision }); setUncertain(false); await onChanged('Immutable terms snapshot saved. This is not a transaction or spending approval.'); }
    catch (caught) { setUncertain(previous => previous || unresolved(caught)); setError(errorText(caught)); }
    finally { pending.current = false; setBusy(false); }
  };
  const inspect = async (proposal: ProposalPreview, older?: ProposalPreview) => {
    if (pending.current) return; pending.current = true; setBusy(true); setError(''); const current = ++generation.current;
    try {
      const result = await client.proposal(proposal.proposal_id);
      const diff = older ? await client.compareProposals(older.proposal_id, proposal.proposal_id) : null;
      if (current === generation.current) { setSelected(result); setComparison(diff); }
    } catch (caught) { if (current === generation.current) setError(errorText(caught)); }
    finally { if (current === generation.current) { pending.current = false; setBusy(false); } }
  };
  return <section className="panel"><div className="section-heading"><h2>Immutable proposal snapshots</h2><span className="muted">{proposals.length} local snapshots</span></div>
    {proposals.length ? proposals.map((proposal, index) => { const terms = proposalTermsContext(proposal, view.agreement); return <div className="proposal-row" key={proposal.proposal_id}><div><strong>Proposal revision {proposal.revision}</strong><small>Snapshot terms revision {terms.termsRevision ?? 'not established'} · Current terms revision {terms.currentTermsRevision}</small><small>{terms.label}{!terms.appliesToCurrentTerms && ' · Snapshot and reports do not apply to current terms'}</small><small className="mono wrap">{proposal.proposal_id}</small><small>{dateTime(proposal.created_at)}</small><button className="text-button" disabled={busy || uncertain} onClick={() => inspect(proposal, index ? proposals[index - 1] : undefined)}>Inspect terms{index ? ' and changes' : ''}</button></div><Badge tone="warning">Not signable</Badge></div>; }) : <p className="panel-text">No immutable terms snapshot yet. A snapshot preserves the agreement and intent claims, without constructing a transaction.</p>}
    <div className="panel-bottom"><button className="button secondary" disabled={busy || (!uncertain && (stale || !canCoordinate || view.cancellation_requested))} onClick={freeze}>{uncertain ? 'Retry exact original snapshot' : 'Freeze a terms snapshot'}</button><small>New or changed terms require renewed review.</small></div>
    {uncertain && <Notice warning>The original snapshot request may have committed. Retrying preserves its exact revision and key.<p className="mono wrap">{attempt.current?.key}</p></Notice>}
    {error && <p className="form-error panel-text" role="alert">{error}</p>}
    {selected && <ProposalReview proposal={selected} comparison={comparison} view={view} client={client} stale={stale} onClose={() => setSelected(null)} onChanged={onChanged}/>}
  </section>;
}
function ProposalReview({ proposal, comparison, view, client, stale, onClose, onChanged }: { proposal: ProposalPreview; comparison: ProposalComparison | null; view: AgreementView; client: WholepactClient; stale: boolean; onClose: () => void; onChanged: (message: string) => Promise<void> }) {
  const [revision, setRevision] = useState(view.revision); const [busy, setBusy] = useState(false); const [uncertain, setUncertain] = useState(false); const [error, setError] = useState('');
  const pending = useRef(false); const attempt = useRef({ key: key(), revision: view.revision });
  const changed = revision !== view.revision;
  const terms = proposalTermsContext(proposal, view.agreement);
  const review = async () => {
    if (pending.current || (!uncertain && (changed || stale || !terms.appliesToCurrentTerms))) return; pending.current = true; setBusy(true); setError('');
    try { const result = await client.reviewProposal(proposal.proposal_id, { idempotencyKey: attempt.current.key, expectedRevision: attempt.current.revision }); setRevision(result.revision); setUncertain(false); attempt.current = { key: key(), revision: result.revision }; await onChanged('Terms integrity report saved. Transaction verification and spending approval remain unavailable.'); }
    catch (caught) { setUncertain(previous => previous || unresolved(caught)); setError(errorText(caught)); }
    finally { pending.current = false; setBusy(false); }
  };
  const reports = view.verification_reports?.filter(report => report.proposal_id === proposal.proposal_id) ?? [];
  return <Modal title="Inspect immutable terms snapshot" onClose={onClose} wide><div className="modal-body review">
    <Notice warning title="Nonbinding terms only">These terms have no transaction artifact or transaction-effects commitment. An integrity report cannot authorize them.</Notice>
    <Notice warning={!terms.appliesToCurrentTerms} title={terms.label}>{terms.message}</Notice>
    {(changed || stale) && <Notice warning>Newer or stale journal context prevents a new review. This display still shows the snapshot you opened.</Notice>}
    <dl className="compact-dl"><div><dt>Proposal revision</dt><dd>{proposal.revision}</dd></div><div><dt>Snapshot terms revision</dt><dd>{terms.termsRevision ?? 'Not established'}</dd></div><div><dt>Current agreement terms revision</dt><dd>{terms.currentTermsRevision}</dd></div><div><dt>Current journal revision</dt><dd>{view.revision}</dd></div><div><dt>Proposal</dt><dd className="mono wrap">{proposal.proposal_id}</dd></div><div><dt>Manifest digest</dt><dd className="mono wrap">{proposal.manifest_digest}</dd></div><div><dt>Previous proposal</dt><dd className="mono wrap">{proposal.previous_proposal_id ?? 'None'}</dd></div></dl>
    {comparison && <ComparisonDetails comparison={comparison}/>}
    <details className="evidence-details"><summary>Exact frozen terms</summary><pre className="wrap">{JSON.stringify(proposal.manifest, null, 2)}</pre></details>
    <h3>Saved integrity reports</h3>{reports.length ? reports.map(report => <section className="saved-review" key={report.report_id}><strong>Transaction verification unsupported</strong><small>Bound snapshot terms revision {terms.termsRevision ?? 'not established'} · Current terms revision {terms.currentTermsRevision}</small>{!proposalReportAppliesToCurrentTerms(proposal, report, view.agreement) && <Notice warning>This saved report does not apply to current agreement terms. It remains attached to its original immutable snapshot and transfers no approval.</Notice>}<small>{dateTime(report.checked_at)}</small><p>{report.review_summary.message}</p><ul>{report.blocking_errors.map((error, index) => <li key={index}>{error.message} ({error.code})</li>)}</ul></section>) : <p>No integrity report saved for this snapshot.</p>}
    {uncertain && <Notice warning>Retry only this original review request.<p className="mono wrap">{attempt.current.key}</p></Notice>}{error && <p role="alert" className="form-error">{error}</p>}
    <div className="modal-actions"><button className="button secondary" onClick={onClose}>Close</button><button className="button primary" disabled={busy || (!uncertain && (changed || stale || !terms.appliesToCurrentTerms))} onClick={review}>{busy ? 'Checking integrity…' : uncertain ? 'Retry exact original review' : !terms.appliesToCurrentTerms ? 'Historical terms review unavailable' : 'Record terms integrity report'}</button></div>
  </div></Modal>;
}
export function ComparisonDetails({ comparison }: { comparison: ProposalComparison }) {
  return <section className="comparison-panel"><h3>Changes from preceding revision</h3><Notice warning={comparison.material_change}>{comparison.message}</Notice>{comparison.changes.length ? comparison.changes.map(change => <details className="evidence-details" key={change.field}><summary>{change.field}</summary><div className="two-column"><div><strong>Earlier</strong><pre className="wrap">{JSON.stringify(change.older, null, 2)}</pre></div><div><strong>Current</strong><pre className="wrap">{JSON.stringify(change.newer, null, 2)}</pre></div></div></details>) : <p>No material differences were reported by the engine for these snapshots.</p>}<small>Scope: {comparison.scope}. This comparison grants no authorization and does not revoke earlier signatures.</small></section>;
}
