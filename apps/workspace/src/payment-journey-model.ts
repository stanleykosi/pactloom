import type { AgreementView, CapabilitySet } from '@wholepact/sdk';

/** Presentation only. These helpers never establish payment or signing authority. */
export function draftAvailability(capabilities: CapabilitySet | null, permissions: string[], stale: boolean): { allowed: boolean; reason: string } {
  if (stale) return { allowed: false, reason: 'Refresh the local service before starting a new payment plan.' };
  if (!permissions.includes('propose')) return { allowed: false, reason: 'This session can’t create drafts. A new permission needs separate local approval.' };
  const feature = capabilities?.features.local_agreements;
  if (feature?.status !== 'supported' || !feature.operations?.includes('create') || (feature.api_access !== undefined && feature.api_access !== 'local_http')) return { allowed: false, reason: 'This service has not reported support for creating local drafts.' };
  return { allowed: true, reason: 'Save a local draft. Nothing is sent and no payment is approved.' };
}

export function invitationAvailability(capabilities: CapabilitySet | null, stale: boolean): { readable: boolean; label: string } {
  if (stale) return { readable: false, label: 'Local information needs refreshing' };
  const feature = capabilities?.features.protected_transport_runtime;
  const readable = (feature?.status === 'supported' || feature?.status === 'experimental') && feature.api_access === 'local_http';
  return { readable, label: readable ? 'Protected messages can be inspected' : 'Protected invitation setup required' };
}

export type PaymentNextAction = { title: string; description: string; action: 'review' | 'status'; label: string };
export function paymentNextAction(view: AgreementView, stale: boolean): PaymentNextAction {
  const status = (title: string, description: string): PaymentNextAction => ({ title, description, action: 'status', label: 'Inspect payment status' });
  if (stale) return status('Refresh before continuing', 'These are the last-read records. Reconnect to your local service before making changes; a cached stage is not current payment evidence.');
  if (view.cancellation_requested || ['cancel_requested', 'cancellation_requested', 'closed'].includes(view.progress)) return status('Keep checking any shared approvals', 'Closing a plan or requesting cancellation cannot recall a shared signature. Do not make a replacement payment until outstanding approvals are reconciled.');
  if (['submission_unknown', 'reorganized', 'conflicted_observed', 'backend_rejected'].includes(view.chain_observation)) return status('Resolve the original payment’s status', 'The chain result needs careful inspection. A rejection or changed observation does not prove that no payment can occur. Do not start a replacement automatically.');
  if (view.authorization_exposure !== 'not_authorized') return status('Check what may still spend', view.authorization_exposure === 'unknown' ? 'Your signer’s complete approval history has not been established here. You can inspect and plan, but don’t assume there are no outstanding approvals.' : 'The service reports authorization history for this payment. Inspect its actual exposure and chain observations before considering another payment.');
  if (view.chain_observation !== 'not_submitted') return status('Inspect the reported chain result', 'Read the observation source, synchronization and confirmation policy. The progress of this plan alone does not prove payment.');
  if (['declined', 'obsolete', 'validation_failed', 'requires_revision'].includes(view.progress)) return { title: 'Review the terms before going further', description: 'The recorded plan needs attention. A material change needs a fresh review; it never carries an earlier approval forward.', action: 'review', label: 'Check recipients & amounts' };
  if (['preparing_proposal', 'awaiting_authorization', 'ready_for_submission', 'submission_attempted', 'observing_settlement'].includes(view.progress)) return status('Inspect the recorded stage', 'This is the service’s reported coordination stage, not permission to sign or send. Native verification and current chain evidence remain separate requirements.');
  return { title: 'Start with the exact payment plan', description: 'Check every recipient and amount through a trusted channel, then invite contributors and collect their plans. A contribution plan does not reserve or spend funds.', action: 'review', label: 'Check recipients & amounts' };
}
