import { useEffect, useRef, useState } from 'react';
import { WholepactClient, type CapabilitySet, type ProtectedInvitationView, type ProtectedTransportSummary } from '@wholepact/sdk';
import { Badge, dateTime, human, Modal, Notice } from './components';
import { errorText } from './App';

/** Invitation review never creates an agreement, enrollment, disclosure or spending grant. */
export function InvitationsPanel({ client, capabilities }: { client: WholepactClient; capabilities: CapabilitySet | null }) {
  const [items, setItems] = useState<ProtectedTransportSummary[]>([]); const [review, setReview] = useState<ProtectedInvitationView | null>(null);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [loaded, setLoaded] = useState(false);
  const generation = useRef(0); const pending = useRef(false);
  useEffect(() => () => { generation.current++; }, []);
  const configured = capabilities?.features.protected_transport_runtime?.api_access === 'local_http';
  const read = async (handle?: string) => {
    if (pending.current) return; pending.current = true; setBusy(true); setError(''); const current = ++generation.current;
    try {
      if (handle) { const item = await client.invitation(handle); if (current === generation.current) setReview(item); }
      else { const result = await client.invitations(); if (current === generation.current) { setItems(result); setLoaded(true); } }
    } catch (caught) { if (current === generation.current) setError(errorText(caught)); }
    finally { if (current === generation.current) { pending.current = false; setBusy(false); } }
  };
  const invitation = review?.invitation;
  return <section className="panel"><div className="section-heading"><h2>Received private invitations</h2><Badge>Read-only</Badge></div><div className="panel-text">
    <p>Review an invitation retained by your protected native runtime, even before an agreement exists locally. Receiving or reading it does not join the agreement or prove anyone’s identity.</p>
    {configured ? <><button className="button secondary" disabled={busy} onClick={() => read()}>{busy ? 'Reading protected inbox…' : 'Read received invitations'}</button>{loaded && !items.length && <p>No received invitation is visible to this local application.</p>}{items.map(item => <section className="saved-review" key={item.handle}><strong className="mono wrap">{item.agreement_id}</strong><small>{item.currently_valid && !item.historical ? 'Current invitation metadata' : 'Historical or expired invitation metadata'}</small><button className="text-button" disabled={busy} onClick={() => read(item.handle)}>Review invitation text and provenance</button></section>)}</> : <Notice>No protected invitation inbox is configured. Native key enrollment and local file selection are separate setup steps; this page accepts no private key, file path or ciphertext.</Notice>}
    {error && <p className="form-error" role="alert">{error} Previously displayed invitations may be stale or access may have changed.</p>}
  </div>{review && invitation && <Modal title="Review received invitation" onClose={() => setReview(null)} wide><div className="modal-body review">
    <Notice warning>This is selected invitation text from a pinned transport peer. Human identity, wallet control and recipient ownership remain unverified. No participant enrollment or spending authority was created.</Notice>
    {(!review.summary.currently_valid || review.summary.historical) && <Notice warning>This invitation is historical or expired. It cannot establish a current offer or renew access.</Notice>}
    <h3>{invitation.purpose}</h3><dl className="review-values"><div><dt>Offered roles</dt><dd>{invitation.offered_roles.map(human).join(', ')}</dd></div><div><dt>Invited participant label</dt><dd>{invitation.invited_participant_id}</dd></div><div><dt>Recipient summary</dt><dd>{invitation.recipient_summary}</dd></div><div><dt>Fee summary</dt><dd>{invitation.fee_summary}</dd></div><div><dt>Visibility summary</dt><dd>{invitation.visibility_summary}</dd></div><div><dt>Coordination deadline</dt><dd>{dateTime(invitation.coordination_deadline)}</dd></div><div><dt>Issued</dt><dd>{dateTime(review.issued_at)}</dd></div><div><dt>Invitation expiry</dt><dd>{dateTime(review.expires_at)}</dd></div></dl>
    <details className="evidence-details"><summary>Exact local provenance</summary><dl className="compact-dl"><div><dt>Agreement terms digest</dt><dd className="mono wrap">{invitation.agreement_manifest_digest}</dd></div><div><dt>Artifact fingerprint</dt><dd className="mono wrap">{review.summary.artifact_fingerprint}</dd></div><div><dt>Pinned sender key fingerprint</dt><dd className="mono wrap">{review.sender_key_fingerprint}</dd></div><div><dt>Local recipient key fingerprint</dt><dd className="mono wrap">{review.recipient_key_fingerprint}</dd></div><div><dt>Message identity</dt><dd className="mono wrap">{review.original_message_id}</dd></div><div><dt>Local retention identity</dt><dd className="mono wrap">{review.local_retention_id}</dd></div><div><dt>Transport labels</dt><dd>{review.sender_id} → {review.recipient_id}</dd></div></dl></details>
    <p>Any participation intent requires a separate deliberately scoped workflow. These summaries do not replace exact immutable terms or a verified payment review.</p><div className="modal-actions"><button className="button secondary" onClick={() => setReview(null)}>Close read-only review</button></div>
  </div></Modal>}</section>;
}
