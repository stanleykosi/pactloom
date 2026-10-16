//! Positive local draft lineage. Absence of local candidates is never evidence
//! that an obligation has no exposure. This check grants metadata editing only.
use super::*;
impl Store {
    pub fn agreement_has_local_draft_history(
        &self,
        id: &str,
        revision: u64,
        owner: &str,
        obligation: &str,
    ) -> Result<bool> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        is_local_draft(&c, id, revision, owner, obligation)
    }
}

pub(super) fn is_local_draft(
    c: &Connection,
    id: &str,
    revision: u64,
    owner: &str,
    obligation: &str,
) -> Result<bool> {
    // The bounded engine permits at most 64 terms versions, 64 previews, and
    // 128 local reviews. Unknown activity and incomplete history fail closed.
    if revision == 0 || revision > 256 {
        return Ok(false);
    }
    let exposed: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_exposures WHERE obligation_id=?1) OR EXISTS(SELECT 1 FROM effect_intents WHERE resource_id=?2)",
        params![obligation, id], |r| r.get(0),
    )?;
    if exposed {
        return Ok(false);
    }
    let mut query = c.prepare(
        "SELECT e.aggregate_revision,e.kind,o.principal_id,o.kind,o.resource_id,o.status FROM events e LEFT JOIN operations o ON o.operation_id=e.operation_id WHERE e.aggregate_type='agreement' AND e.aggregate_id=?1 ORDER BY e.sequence LIMIT 257",
    )?;
    let mut rows = query.query([id])?;
    let mut expected = 1u64;
    while let Some(row) = rows.next()? {
        let actual: u64 = row.get(0)?;
        let kind: String = row.get(1)?;
        let principal: Option<String> = row.get(2)?;
        let operation_kind: Option<String> = row.get(3)?;
        let resource: Option<String> = row.get(4)?;
        let status: Option<String> = row.get(5)?;
        let allowed = if expected == 1 {
            kind == "agreement.created"
        } else {
            matches!(
                kind.as_str(),
                "agreement_terms_revised"
                    | "terms_preview_created"
                    | "review_blocked_by_unqualified_protocol"
            )
        };
        if actual != expected
            || !allowed
            || principal.as_deref() != Some(owner)
            || operation_kind.as_deref() != Some(kind.as_str())
            || resource.as_deref() != Some(id)
            || status.as_deref() != Some("succeeded")
        {
            return Ok(false);
        }
        expected += 1;
    }
    Ok(expected == revision + 1)
}
