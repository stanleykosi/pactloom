import { useEffect, useReducer, useRef, useState, useSyncExternalStore, type FormEvent } from 'react';
import { formatZec, parseZec, sumZatoshis, WholepactClient, WholepactError, type AgreementDraft, type AgreementView } from '@wholepact/sdk';
import { Badge, Field, Modal, Money, Notice } from './components';
import { errorText } from './App';
import { beginTermsCommand, finishTermsCommand, retryTermsCommand, subscribeTermsCommand, termsCommand, termsContextChanged, termsDifferences, termsReview, termsSaveFailure, freshTermsEditor, termsEditorReducer, type TermsRevisionCommand } from './terms-revision-model';

export function useTermsCommand(client: WholepactClient, agreement: string) {
  return useSyncExternalStore(listener => subscribeTermsCommand(client, agreement, listener), () => termsCommand(client, agreement));
}
export function TermsHistory({ view }: { view: AgreementView }) {
  return <section className="panel"><div className="section-heading"><h2>Terms revision history</h2><Badge>Current terms revision {view.agreement.revision}</Badge></div><div className="panel-text"><p>Journal revision {view.revision} includes all recorded activity. Terms revisions are separate immutable snapshots.</p>{!view.terms_history?.length ? <p>No earlier terms snapshots reported.</p> : view.terms_history.map(draft => <details className="evidence-details" key={draft.revision}><summary>Terms revision {draft.revision} · {draft.purpose}</summary><p>Exact funding objective: <Money value={draft.funding_policy.target} detail/></p>{draft.recipients.map(recipient => <div className="recipient-card" key={recipient.recipient_id}><strong>{recipient.recipient_id}</strong><Money value={recipient.amount} detail/><p className="mono wrap">{recipient.address}</p><small>{recipient.instruction_provenance}</small><small>{recipient.memo ?? 'No reference'}</small></div>)}<pre className="terms-exact">{JSON.stringify(draft, null, 2)}</pre></details>)}</div></section>;
}
function Changes({ before, after }: { before: AgreementDraft; after: AgreementDraft }) {
  const differences = termsDifferences(before, after);
  return <section aria-label="Exact before and after terms"><h3>Review exact changes</h3><p>Terms revision {before.revision} → {after.revision}. Amounts below are exact integer zatoshis; 100,000,000 zatoshis = 1 ZEC.</p>{differences.map(item => <div className="terms-change" key={item.field}><h4>{item.field}</h4><div className="form-grid"><div><strong>Before</strong><pre className="terms-exact">{item.before}</pre></div><div><strong>After</strong><pre className="terms-exact">{item.after}</pre></div></div></div>)}</section>;
}
export function ReviseAgreement({ client, agreement: current, stale, canPropose, onClose, onChanged }: { client: WholepactClient; agreement: AgreementView; stale: boolean; canPropose: boolean; onClose: () => void; onChanged: () => Promise<void> }) {
  const [opening] = useState(() => structuredClone(current));
  const draft = opening.agreement;
  const command = useTermsCommand(client, draft.agreement_id);
  const [purpose, setPurpose] = useState(draft.purpose);
  const [recipients, setRecipients] = useState(() => draft.recipients.map(recipient => ({ ...recipient, amountText: formatZec(recipient.amount, true) })));
  const [feeMode, setFeeMode] = useState(draft.fee_policy.kind);
  const [feeSponsor, setFeeSponsor] = useState(draft.fee_policy.kind === 'sponsor' ? draft.fee_policy.participant_id : '');
  const [sponsorAmount, setSponsorAmount] = useState(draft.fee_policy.kind === 'sponsor' ? formatZec(draft.fee_policy.amount, true) : '');
  const [deadline, setDeadline] = useState(draft.coordination_deadline ?? '');
  const [confirmations, setConfirmations] = useState(String(draft.confirmation_policy.required_confirmations));
  const [{ review, accepted: ack }, reviewAction] = useReducer(termsEditorReducer, undefined, freshTermsEditor);
  const [validating, setValidating] = useState(false); const [error, setError] = useState('');
  const generation = useRef(0); const mounted = useRef(true); const validation = useRef<AbortController | null>(null);
  const latest = useRef({ current, stale, canPropose }); latest.current = { current, stale, canPropose };
  const changed = termsContextChanged(opening, current);
  const blocked = changed || stale || !canPropose || current.terms_editability?.allowed !== true;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current++; validation.current?.abort(); }; }, []);
  useEffect(() => { if (blocked) { generation.current++; validation.current?.abort(); setValidating(false); reviewAction({ type: 'reset' }); } }, [blocked]);
  const editRecipient = (index: number, patch: Partial<typeof recipients[number]>) => setRecipients(items => items.map((item, i) => i === index ? { ...item, ...patch } : item));
  const prepareReview = async (event: FormEvent) => {
    event.preventDefault(); if (validating || blocked || command) return;
    const attempt = ++generation.current; const abort = new AbortController(); validation.current = abort;
    setValidating(true); reviewAction({ type: 'reset' }); setError('');
    try {
      if (!/^[1-9]\d*$/.test(confirmations) || !Number.isSafeInteger(Number(confirmations))) throw new Error('Use a positive whole-number confirmation policy.');
      const revisedRecipients = recipients.map(({ amountText, ...recipient }) => ({ ...recipient, amount: parseZec(amountText) }));
      const after: AgreementDraft = { ...structuredClone(draft), revision: draft.revision + 1, purpose, recipients: revisedRecipients,
        funding_policy: { kind: 'exact', target: sumZatoshis(revisedRecipients.map(recipient => recipient.amount)) },
        fee_policy: feeMode === 'pro_rata' ? { kind: 'pro_rata' } : { kind: 'sponsor', participant_id: feeSponsor, amount: parseZec(sponsorAmount) },
        coordination_deadline: deadline || null, confirmation_policy: { required_confirmations: Number(confirmations) } };
      if (!termsDifferences(draft, after).length) throw new Error('Change at least one editable term before reviewing a new revision.');
      await client.validateAgreement(after, abort.signal);
      if (!mounted.current || attempt !== generation.current || latest.current.stale || !latest.current.canPropose || termsContextChanged(opening, latest.current.current) || termsCommand(client, draft.agreement_id)) return;
      reviewAction({ type: 'review', review: termsReview(opening, after) });
    } catch (caught) { if (mounted.current && attempt === generation.current && !abort.signal.aborted) setError(errorText(caught)); }
    finally { if (mounted.current && attempt === generation.current) setValidating(false); }
  };
  const save = async (retry: boolean) => {
    if (retry ? command?.phase !== 'uncertain' : !review || !ack || blocked || command) return;
    if (!retry && (latest.current.stale || !latest.current.canPropose || termsContextChanged(opening, latest.current.current))) return;
    const original: TermsRevisionCommand | null = retry ? retryTermsCommand(client, draft.agreement_id) : beginTermsCommand(client, review!, `terms-${crypto.randomUUID()}`);
    if (!original) return;
    setError('');
    try {
      await client.reviseAgreement(original.agreementId, JSON.parse(original.encoded) as AgreementDraft, { idempotencyKey: original.key, expectedRevision: original.revision });
      finishTermsCommand(client, original.agreementId, original.key, 'saved');
      if (mounted.current) onClose();
      await onChanged();
    } catch (caught) {
      // A later deterministic rejection cannot disprove a previously uncertain dispatch.
      finishTermsCommand(client, original.agreementId, original.key, termsSaveFailure(caught instanceof WholepactError ? caught : null, retry));
      if (mounted.current) { setError(errorText(caught)); reviewAction({ type: 'reset' }); }
    }
  };
  const retainedAfter = command ? JSON.parse(command.encoded) as AgreementDraft : null;
  return <Modal title="Revise unsigned agreement terms" onClose={onClose} wide><div className="modal-body">
    <Notice>Save one new local terms revision after reviewing exact changes. Previous terms remain immutable. This does not authorize payment, verify recipient ownership or share the agreement.</Notice>
    <p>Opening terms revision {draft.revision} · journal revision {opening.revision}</p>
    {command ? <><Notice warning title={command.phase === 'pending' ? 'The original save is in progress' : 'The original save outcome is uncertain'}>The exact original body, journal revision and idempotency key stay in session memory even if you dismiss or reopen this editor. A new revision is blocked until this request is resolved. Reloading or disconnecting loses this in-memory reference; inspect the service journal before trying anything new.<p className="mono wrap">{command.key} · journal revision {command.revision}</p></Notice><Changes before={command.before} after={retainedAfter!}/><div className="modal-actions"><button className="button secondary" onClick={onClose}>Close editor</button><button className="button primary" disabled={command.phase === 'pending'} onClick={() => void save(true)}>{command.phase === 'pending' ? 'Saving original revision…' : 'Retry exact original revision'}</button></div></> : <>
      {blocked && <Notice warning title="New terms revision unavailable">{changed ? 'The journal or terms changed after this editor opened. Close and reopen with current context.' : stale ? 'Local information is stale. Refresh before editing.' : !canPropose ? 'This session does not have propose permission.' : current.terms_editability?.reason ?? 'The service has not reported editing eligibility.'}</Notice>}
      {review ? <><Changes before={review.before} after={review.after}/><p>Network, organizer, agreement identity, obligation, schema and privacy profile remain bound to the original agreement. The service rechecks editing eligibility and journal revision when saving.</p><label className="consent"><input type="checkbox" checked={ack} disabled={blocked} onChange={event => reviewAction({ type: 'accept', accepted: event.target.checked })}/><span>I reviewed these exact before and after values and accept this new unsigned terms revision. No payment or disclosure is authorized.</span></label><div className="modal-actions"><button className="button secondary" onClick={() => { reviewAction({ type: 'reset' }); }}>Back to editing</button><button className="button primary" disabled={!ack || blocked} onClick={() => void save(false)}>Save terms revision {review.after.revision}</button></div></> : <form onSubmit={prepareReview}>
      <fieldset disabled={validating || blocked}><legend>Editable unsigned terms</legend><Field label="Purpose"><input autoFocus required maxLength={500} value={purpose} onChange={event => setPurpose(event.target.value)}/></Field>
      {recipients.map((recipient, index) => <section className="claim-editor" key={recipient.recipient_id}><h3>Recipient {index + 1}</h3><small className="mono wrap">{recipient.recipient_id}</small><Field label={`Recipient ${index + 1} amount (ZEC)`}><input required inputMode="decimal" value={recipient.amountText} onChange={event => editRecipient(index, { amountText: event.target.value })}/></Field><Field label={`Recipient ${index + 1} receiving instructions`} hint="Address text is unverified. Check it through a trusted independent channel."><textarea required maxLength={2048} value={recipient.address} onChange={event => editRecipient(index, { address: event.target.value })}/></Field><Field label={`Recipient ${index + 1} instruction provenance`}><input required maxLength={500} value={recipient.instruction_provenance} onChange={event => editRecipient(index, { instruction_provenance: event.target.value })}/></Field><Field label={`Recipient ${index + 1} reference (optional)`}><input maxLength={512} value={recipient.memo ?? ''} onChange={event => editRecipient(index, { memo: event.target.value || null })}/></Field>{recipients.length > 1 && <button type="button" className="text-button danger" onClick={() => setRecipients(items => items.filter((_, i) => i !== index))}>Remove recipient {index + 1}</button>}</section>)}
      <button type="button" className="button secondary" disabled={recipients.length >= 64} onClick={() => setRecipients(items => [...items, { recipient_id: `recipient-${crypto.randomUUID()}`, address: '', amount: parseZec('0'), amountText: '', memo: null, instruction_provenance: '' }])}>Add recipient</button>
      <Field label="Fee allocation"><select value={feeMode} onChange={event => setFeeMode(event.target.value as typeof feeMode)}><option value="pro_rata">Proportional to contribution</option><option value="sponsor">Explicit fee sponsor amount</option></select></Field>{feeMode === 'sponsor' && <div className="form-grid"><Field label="Fee sponsor participant identifier"><input required maxLength={128} value={feeSponsor} onChange={event => setFeeSponsor(event.target.value)}/></Field><Field label="Sponsored fee amount (ZEC)"><input required inputMode="decimal" value={sponsorAmount} onChange={event => setSponsorAmount(event.target.value)}/></Field></div>}
      <Field label="Coordination deadline (UTC, optional)" hint="Use an exact ISO 8601 timestamp, such as 2026-11-01T12:00:00Z. This is not transaction expiry."><input value={deadline} onChange={event => setDeadline(event.target.value)}/></Field><Field label="Confirmation policy"><input required type="number" min="1" max="1000" value={confirmations} onChange={event => setConfirmations(event.target.value)}/></Field>
      <p>Fixed identity: {draft.organizer_identity}. Network: {draft.network_profile_id}. Privacy: {draft.privacy_profile.mode}. Extensions are preserved unchanged.</p></fieldset><div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={validating || blocked}>{validating ? 'Validating terms…' : 'Review exact changes'}</button></div></form>}
    </>}{error && <p className="form-error" role="alert">{error}</p>}
  </div></Modal>;
}
