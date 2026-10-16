import type { ParticipantRecordStatus, ParticipantRecordSummary } from '@wholepact/sdk';
/** Null means unavailable, never a known empty account/exposure journal. */
export function visibleRecordSummaries(status: ParticipantRecordStatus | null): ParticipantRecordSummary[] | null {
  return status?.status === 'available' && status.account_exposure === 'unknown_not_established_by_records' && Array.isArray(status.records) ? status.records : null;
}
export function observedSettlementCount(records: ParticipantRecordSummary[]): number {
  return records.filter(record => record.confidence === 'confirmation_policy_met' && !record.recovery_required).length;
}
