//! Read-only inspection of verified restored coordination history. This never
//! creates a live Store, returns raw connections/rows, or establishes freshness.
use super::*;
use serde::Deserialize;

const QUARANTINE_SCHEMA: &str = "CREATE TABLE wholepact_bundle_quarantine(singleton INTEGER PRIMARY KEY CHECK(singleton=1), bundle_digest TEXT NOT NULL, component_id TEXT NOT NULL, original_application_id INTEGER NOT NULL, original_schema_version INTEGER NOT NULL, recovery_required INTEGER NOT NULL CHECK(recovery_required=1));";
const MAX_HISTORY_PAGE: usize = 100;

/// Local identity of one authenticated, pinned read snapshot. Possession is not
/// authorization. A trusted runtime explicitly enrolls this exact handle; labels
/// or a serializable archive digest cannot substitute for this binding.
#[derive(Clone)]
pub struct HistoryBinding(Arc<()>);
impl PartialEq for HistoryBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for HistoryBinding {}
impl std::fmt::Debug for HistoryBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HistoryBinding([opaque])")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryAction {
    AgreementSummary,
    AgreementEvents,
}
pub struct HistoryScope<'a> {
    pub source: &'a HistoryBinding,
    pub principal_id: &'a str,
    pub profile_id: &'a str,
    pub component_id: &'a str,
    pub bundle_digest: &'a str,
    pub agreement_id: &'a str,
    pub action: HistoryAction,
}
pub trait HistoryLease {
    /// The provider must fence concurrent consent revocation for the entire
    /// read and result handoff. A preflight boolean/recheck alone is insufficient.
    fn check_current(&self) -> Result<()>;
}
pub trait HistoryAuthority {
    /// Must authenticate the principal and exact enrolled source, profile,
    /// component, action, and agreement. Ordinary backup/admin or live agreement
    /// read grants are not implicitly historical-read consent.
    fn acquire<'a>(&'a self, scope: &HistoryScope<'_>) -> Result<Box<dyn HistoryLease + 'a>>;
}
pub struct HistoryOpenRequest<'a> {
    pub archive: &'a Path,
    pub archive_key: &'a DatabaseKey,
    pub component_id: &'a str,
    pub restored_component: &'a Path,
    pub restored_key: &'a DatabaseKey,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalObservation {
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HistoricalAgreement {
    pub agreement_id: String,
    pub revision: u64,
    pub purpose: String,
    /// A recorded workflow label, never evidence of current settlement.
    pub recorded_progress: String,
    pub cancellation_requested: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub authorization_exposure: HistoricalObservation,
    pub chain_observation: HistoricalObservation,
    pub recovery_required: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HistoricalAgreementEvent {
    pub sequence: u64,
    pub agreement_revision: u64,
    pub occurred_at_ms: i64,
    /// Event payloads, operation results and arbitrary kind labels are omitted.
    pub change: HistoricalChange,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalChange {
    Created,
    RecordedChange,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HistoricalEventPage {
    pub agreement_id: String,
    pub events: Vec<HistoricalAgreementEvent>,
    /// Local cursor only; sequence gaps disclose no private event content.
    pub next_after_sequence: u64,
    pub recovery_required: bool,
    pub authorization_exposure: HistoricalObservation,
    pub chain_observation: HistoricalObservation,
}

/// No connection accessor, mutable Store conversion, generic SQL, raw JSON,
/// full-envelope export, or protected-participant-record endpoint exists.
/// The read transaction pins the exact component snapshot verified at open.
pub struct QuarantinedCoordinationHistory {
    connection: crate::read_snapshot::ReadOnlySnapshot,
    binding: HistoryBinding,
    profile_id: String,
    component_id: String,
    bundle_digest: String,
}
impl QuarantinedCoordinationHistory {
    /// Authenticates only. No history is returned until the trusted runtime has
    /// enrolled `binding()` and supplies a held exact-agreement read lease.
    /// The template must come from the compiled coordination journal adapter.
    /// The caller must keep both source file sets quiescent under the owning
    /// recovery/profile locks during open. SQLite reads private encrypted copies;
    /// the complete original file trees, including sidecars, remain unchanged.
    pub fn open(
        request: HistoryOpenRequest<'_>,
        template: &'static JournalTemplate,
    ) -> Result<Self> {
        identifier(request.component_id)?;
        if template.kind != JournalKind::CoordinationAuthority {
            return Err(BundleError::Unsupported);
        }
        bounded_file(request.archive)?;
        bounded_file(request.restored_component)?;
        let archive = crate::open_encrypted_read_only(request.archive, request.archive_key)?;
        archive.execute_batch("BEGIN DEFERRED;")?;
        let manifest = validate_archive(&archive)?;
        let component = manifest
            .components
            .iter()
            .find(|c| c.id == request.component_id)
            .ok_or(BundleError::Invalid)?;
        validate_component_template(component, template)?;
        let connection =
            crate::open_encrypted_read_only(request.restored_component, request.restored_key)?;
        connection.execute_batch("BEGIN DEFERRED;")?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != QUARANTINE_APPLICATION_ID || version != component.schema_version {
            return Err(BundleError::Integrity);
        }
        let reference = Connection::open_in_memory()?;
        reference.execute_batch(template.create_sql)?;
        reference.execute_batch(QUARANTINE_SCHEMA)?;
        if schema(&connection)? != schema(&reference)? {
            return Err(BundleError::Integrity);
        }
        let marker: (String,String,i64,i64,i64) = connection.query_row(
            "SELECT bundle_digest,component_id,original_application_id,original_schema_version,recovery_required FROM wholepact_bundle_quarantine WHERE singleton=1", [],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        if marker
            != (
                manifest.digest.clone(),
                component.id.clone(),
                component.application_id,
                component.schema_version,
                1,
            )
        {
            return Err(BundleError::Integrity);
        }
        integrity(&connection)?;
        verify_restored_rows(&connection, component)?;
        Ok(Self {
            connection,
            binding: HistoryBinding(Arc::new(())),
            profile_id: manifest.profile_id,
            component_id: component.id.clone(),
            bundle_digest: manifest.digest,
        })
    }
    pub fn binding(&self) -> HistoryBinding {
        self.binding.clone()
    }
    fn lease<'a>(
        &self,
        principal: &str,
        id: &str,
        action: HistoryAction,
        authority: &'a dyn HistoryAuthority,
    ) -> Result<Box<dyn HistoryLease + 'a>> {
        identifier(principal)?;
        identifier(id)?;
        if self.connection.is_autocommit() {
            return Err(BundleError::Integrity);
        }
        let scope = HistoryScope {
            source: &self.binding,
            principal_id: principal,
            profile_id: &self.profile_id,
            component_id: &self.component_id,
            bundle_digest: &self.bundle_digest,
            agreement_id: id,
            action,
        };
        let lease = authority.acquire(&scope)?;
        lease.check_current()?;
        Ok(lease)
    }
    pub fn agreement(
        &self,
        principal: &str,
        id: &str,
        authority: &dyn HistoryAuthority,
    ) -> Result<Option<HistoricalAgreement>> {
        let lease = self.lease(principal, id, HistoryAction::AgreementSummary, authority)?;
        let raw: Option<(i64,String,i64,i64)> = self.connection.query_row(
            "SELECT revision,payload,created_at_ms,updated_at_ms FROM records WHERE aggregate_type='agreement' AND id=?1", [id],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let result = raw
            .map(|(revision, payload, created, updated)| {
                if payload.len() > MAX_CELL {
                    return Err(BundleError::Limit);
                }
                let parsed: PublicEnvelopeProjection =
                    serde_json::from_str(&payload).map_err(|_| BundleError::Integrity)?;
                if parsed.view.agreement.agreement_id != id
                    || parsed.view.agreement.purpose.len() > 4096
                    || parsed.view.progress.len() > 128
                {
                    return Err(BundleError::Integrity);
                }
                Ok(HistoricalAgreement {
                    agreement_id: id.into(),
                    revision: u64::try_from(revision).map_err(|_| BundleError::Integrity)?,
                    purpose: parsed.view.agreement.purpose,
                    recorded_progress: parsed.view.progress,
                    cancellation_requested: parsed.view.cancellation_requested,
                    created_at_ms: created,
                    updated_at_ms: updated,
                    authorization_exposure: HistoricalObservation::Unknown,
                    chain_observation: HistoricalObservation::Unknown,
                    recovery_required: true,
                })
            })
            .transpose()?;
        lease.check_current()?;
        Ok(result)
    }
    pub fn events(
        &self,
        principal: &str,
        id: &str,
        after_sequence: u64,
        limit: usize,
        authority: &dyn HistoryAuthority,
    ) -> Result<HistoricalEventPage> {
        if limit == 0 || limit > MAX_HISTORY_PAGE || after_sequence > i64::MAX as u64 {
            return Err(BundleError::Limit);
        }
        let lease = self.lease(principal, id, HistoryAction::AgreementEvents, authority)?;
        let mut statement = self.connection.prepare("SELECT sequence,aggregate_revision,occurred_at_ms,kind FROM events WHERE aggregate_type='agreement' AND aggregate_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3")?;
        let mut rows = statement.query(params![id, after_sequence as i64, limit as i64])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            let sequence: i64 = row.get(0)?;
            let revision: i64 = row.get(1)?;
            let kind: String = row.get(3)?;
            events.push(HistoricalAgreementEvent {
                sequence: u64::try_from(sequence).map_err(|_| BundleError::Integrity)?,
                agreement_revision: u64::try_from(revision).map_err(|_| BundleError::Integrity)?,
                occurred_at_ms: row.get(2)?,
                change: if kind == "agreement.created" {
                    HistoricalChange::Created
                } else {
                    HistoricalChange::RecordedChange
                },
            });
        }
        let next = events.last().map_or(after_sequence, |e| e.sequence);
        lease.check_current()?;
        Ok(HistoricalEventPage {
            agreement_id: id.into(),
            events,
            next_after_sequence: next,
            recovery_required: true,
            authorization_exposure: HistoricalObservation::Unknown,
            chain_observation: HistoricalObservation::Unknown,
        })
    }
}
// Deserialize an explicit allowlist. Unknown fields are ignored, never forwarded.
// In particular owner IDs, participant records, sponsor policies, key grants,
// intent owners and checkpoint receipts are not part of these DTOs.
#[derive(Deserialize)]
struct PublicEnvelopeProjection {
    view: PublicViewProjection,
}
#[derive(Deserialize)]
struct PublicViewProjection {
    agreement: PublicAgreementProjection,
    progress: String,
    cancellation_requested: bool,
}
#[derive(Deserialize)]
struct PublicAgreementProjection {
    agreement_id: String,
    purpose: String,
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
