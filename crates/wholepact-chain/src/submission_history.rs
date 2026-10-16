//! Atomic v2 obligation bindings and bounded attempt history.
use super::*;
use crate::{SubmissionAttempt, SubmissionAttemptOutcome, SubmissionDescriptor, SubmissionPlan};

fn read_plan(connection: &Connection, id: &str) -> Result<Option<SubmissionPlan>, ChainError> {
    let mut stmt = connection
        .prepare("SELECT obligation,descriptor FROM submission_bindings WHERE operation=?1")
        .map_err(|_| ChainError::JournalFailure)?;
    let mut rows = stmt.query([id]).map_err(|_| ChainError::JournalFailure)?;
    let Some(row) = rows.next().map_err(|_| ChainError::JournalFailure)? else {
        return Ok(None);
    };
    let text = row
        .get_ref(1)
        .and_then(|v| v.as_str().map_err(Into::into))
        .map_err(|_| ChainError::JournalFailure)?;
    if text.len() > 4096 {
        return Err(ChainError::ResourceLimit);
    }
    let descriptor: SubmissionDescriptor =
        serde_json::from_str(text).map_err(|_| ChainError::JournalFailure)?;
    let obligation: &str = row
        .get_ref(0)
        .and_then(|v| v.as_str().map_err(Into::into))
        .map_err(|_| ChainError::JournalFailure)?;
    let (intent, _) = read_record(connection, id)?.ok_or(ChainError::JournalFailure)?;
    let plan = SubmissionPlan::new(
        &descriptor.obligation_id,
        &descriptor.proposal_id,
        id,
        intent.exact_bytes(),
    )?;
    if descriptor != plan.descriptor || obligation != descriptor.obligation_id {
        return Err(ChainError::JournalFailure);
    }
    Ok(Some(plan))
}
fn decode_attempt(row: &rusqlite::Row<'_>) -> Result<SubmissionAttempt, ChainError> {
    let text = row
        .get_ref(3)
        .and_then(|v| v.as_str().map_err(Into::into))
        .map_err(|_| ChainError::JournalFailure)?;
    if text.len() > 1024 {
        return Err(ChainError::ResourceLimit);
    }
    let attempt = SubmissionAttempt {
        number: row.get(0).map_err(|_| ChainError::JournalFailure)?,
        source_id: row.get(1).map_err(|_| ChainError::JournalFailure)?,
        started_at_unix_seconds: row.get(2).map_err(|_| ChainError::JournalFailure)?,
        outcome: serde_json::from_str(text).map_err(|_| ChainError::JournalFailure)?,
    };
    if !(1..=128).contains(&attempt.number)
        || !crate::reconciliation::valid_source_id(&attempt.source_id)
        || attempt.started_at_unix_seconds > i64::MAX as u64
    {
        return Err(ChainError::JournalFailure);
    }
    if matches!(
        attempt.outcome,
        SubmissionAttemptOutcome::Rejected { code: 0 }
    ) {
        return Err(ChainError::JournalFailure);
    }
    Ok(attempt)
}
fn read_attempts(connection: &Connection, id: &str) -> Result<Vec<SubmissionAttempt>, ChainError> {
    let mut stmt = connection.prepare("SELECT number,source,started,outcome FROM submission_attempts WHERE operation=?1 ORDER BY number").map_err(|_| ChainError::JournalFailure)?;
    let mut rows = stmt.query([id]).map_err(|_| ChainError::JournalFailure)?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().map_err(|_| ChainError::JournalFailure)? {
        if result.len() >= 128 {
            return Err(ChainError::ResourceLimit);
        }
        let attempt = decode_attempt(row)?;
        if attempt.number as usize != result.len() + 1 {
            return Err(ChainError::JournalFailure);
        }
        result.push(attempt);
    }
    Ok(result)
}
impl EncryptedSubmissionJournal {
    pub(crate) fn validate_dispatch_history(&self) -> Result<(), ChainError> {
        let mut stmt = self
            .connection
            .prepare("SELECT operation FROM submission_bindings")
            .map_err(|_| ChainError::JournalFailure)?;
        let mut rows = stmt.query([]).map_err(|_| ChainError::JournalFailure)?;
        while let Some(row) = rows.next().map_err(|_| ChainError::JournalFailure)? {
            let id: String = row.get(0).map_err(|_| ChainError::JournalFailure)?;
            read_plan(&self.connection, &id)?.ok_or(ChainError::JournalFailure)?;
            read_attempts(&self.connection, &id)?;
        }
        Ok(())
    }
    pub(crate) fn bind_submission_plan(&mut self, plan: &SubmissionPlan) -> Result<(), ChainError> {
        self.verify_identity()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ChainError::JournalFailure)?;
        if let Some(old) = read_plan(&tx, &plan.descriptor.operation_id)? {
            if old.descriptor != plan.descriptor
                || old.intent.exact_bytes() != plan.intent.exact_bytes()
            {
                return Err(ChainError::IdempotencyConflict);
            }
            tx.commit().map_err(|_| ChainError::JournalFailure)?;
            return Ok(());
        }
        let occupied: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM submission_bindings WHERE obligation=?1)",
                [&plan.descriptor.obligation_id],
                |r| r.get(0),
            )
            .map_err(|_| ChainError::JournalFailure)?;
        if occupied {
            return Err(ChainError::ObligationConflict);
        }
        if let Some((old, _)) = read_record(&tx, &plan.descriptor.operation_id)? {
            if old.exact_bytes() != plan.intent.exact_bytes() {
                return Err(ChainError::IdempotencyConflict);
            }
        } else {
            let (count, size): (i64, i64) = tx
                .query_row(
                    "SELECT count(*),coalesce(sum(length(bytes)),0) FROM submission_intents",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| ChainError::JournalFailure)?;
            if count >= MAX_RECORDS
                || size + plan.intent.exact_bytes().len() as i64 > MAX_TOTAL_BYTES
            {
                return Err(ChainError::ResourceLimit);
            }
            tx.execute(
                "INSERT INTO submission_intents(operation,bytes,digest,state) VALUES(?1,?2,?3,0)",
                params![
                    plan.descriptor.operation_id,
                    plan.intent.exact_bytes(),
                    plan.intent.bytes_sha256()
                ],
            )
            .map_err(|_| ChainError::JournalFailure)?;
        }
        let descriptor =
            serde_json::to_string(&plan.descriptor).map_err(|_| ChainError::JournalFailure)?;
        if descriptor.len() > 4096 {
            return Err(ChainError::ResourceLimit);
        }
        tx.execute(
            "INSERT INTO submission_bindings(operation,obligation,descriptor) VALUES(?1,?2,?3)",
            params![
                plan.descriptor.operation_id,
                plan.descriptor.obligation_id,
                descriptor
            ],
        )
        .map_err(|_| ChainError::JournalFailure)?;
        tx.commit().map_err(|_| ChainError::JournalFailure)
    }
    pub(crate) fn recover_submission_plan(
        &self,
        id: &str,
    ) -> Result<Option<SubmissionPlan>, ChainError> {
        validate_operation_id(id)?;
        read_plan(&self.connection, id)
    }
    pub fn retained_submission_descriptor(
        &self,
        id: &str,
    ) -> Result<Option<SubmissionDescriptor>, ChainError> {
        self.recover_submission_plan(id)
            .map(|p| p.map(|p| p.descriptor))
    }
    pub fn submission_attempts(&self, id: &str) -> Result<Vec<SubmissionAttempt>, ChainError> {
        validate_operation_id(id)?;
        read_attempts(&self.connection, id)
    }
    pub(crate) fn begin_submission_attempt(
        &mut self,
        plan: &SubmissionPlan,
        source: &str,
        now: u64,
    ) -> Result<SubmissionAttempt, ChainError> {
        if !crate::reconciliation::valid_source_id(source) || now > i64::MAX as u64 {
            return Err(ChainError::InvalidConfiguration);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ChainError::JournalFailure)?;
        let old =
            read_plan(&tx, &plan.descriptor.operation_id)?.ok_or(ChainError::JournalFailure)?;
        if old.descriptor != plan.descriptor
            || old.intent.exact_bytes() != plan.intent.exact_bytes()
        {
            return Err(ChainError::IdempotencyConflict);
        }
        let history = read_attempts(&tx, &plan.descriptor.operation_id)?;
        if history.len() >= 128 {
            return Err(ChainError::ResourceLimit);
        }
        if history
            .last()
            .is_some_and(|a| a.started_at_unix_seconds > now)
        {
            return Err(ChainError::StaleChain);
        }
        let attempt = SubmissionAttempt {
            number: history.len() as u32 + 1,
            source_id: source.into(),
            started_at_unix_seconds: now,
            outcome: SubmissionAttemptOutcome::Unknown,
        };
        tx.execute("INSERT INTO submission_attempts(operation,number,source,started,outcome) VALUES(?1,?2,?3,?4,?5)", params![plan.descriptor.operation_id, attempt.number, source, now, serde_json::to_string(&attempt.outcome).map_err(|_| ChainError::JournalFailure)?]).map_err(|_| ChainError::JournalFailure)?;
        tx.commit().map_err(|_| ChainError::JournalFailure)?;
        Ok(attempt)
    }
    pub(crate) fn finish_submission_attempt(
        &mut self,
        id: &str,
        attempt: &SubmissionAttempt,
    ) -> Result<SubmissionState, ChainError> {
        if matches!(
            attempt.outcome,
            SubmissionAttemptOutcome::Rejected { code: 0 }
        ) {
            return Err(ChainError::MalformedEvidence);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ChainError::JournalFailure)?;
        let history = read_attempts(&tx, id)?;
        let old = history
            .iter()
            .find(|a| a.number == attempt.number)
            .ok_or(ChainError::JournalFailure)?;
        if old.source_id != attempt.source_id
            || old.started_at_unix_seconds != attempt.started_at_unix_seconds
        {
            return Err(ChainError::IdempotencyConflict);
        }
        if old.outcome != SubmissionAttemptOutcome::Unknown && old.outcome != attempt.outcome {
            return Err(ChainError::IdempotencyConflict);
        }
        let (_, previous) = read_record(&tx, id)?.ok_or(ChainError::JournalFailure)?;
        let state = match (previous, &attempt.outcome) {
            (SubmissionState::BackendAcknowledged, _)
            | (_, SubmissionAttemptOutcome::Acknowledged) => SubmissionState::BackendAcknowledged,
            (SubmissionState::BackendRejected, _)
            | (_, SubmissionAttemptOutcome::Rejected { .. }) => SubmissionState::BackendRejected,
            _ => SubmissionState::SubmissionUnknown,
        };
        let state_code = match state {
            SubmissionState::SubmissionUnknown => 0,
            SubmissionState::BackendAcknowledged => 1,
            SubmissionState::BackendRejected => 2,
        };
        tx.execute(
            "UPDATE submission_attempts SET outcome=?3 WHERE operation=?1 AND number=?2",
            params![
                id,
                attempt.number,
                serde_json::to_string(&attempt.outcome).map_err(|_| ChainError::JournalFailure)?
            ],
        )
        .map_err(|_| ChainError::JournalFailure)?;
        tx.execute(
            "UPDATE submission_intents SET state=?2 WHERE operation=?1",
            params![id, state_code],
        )
        .map_err(|_| ChainError::JournalFailure)?;
        tx.commit().map_err(|_| ChainError::JournalFailure)?;
        Ok(state)
    }
}
