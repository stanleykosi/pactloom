//! Typed historical coordination inventory and generation-local safety fences.
//! Authentication is not freshness. Nothing in an inventory authorizes signing,
//! delivery, submission, or reuse of a restored permission.
use crate::{
    authority::ReleaseIntent,
    automation::{AutomaticAuthorizationRecord, StoredAutomationAccount, StoredAutomationGrant},
    *,
};
use std::collections::BTreeSet;
mod layers;
pub use layers::{
    coordination_layered_successor_template, coordination_layered_successor_template_for_schema,
    stage_layered_coordination_successor, verify_archived_generation_obligation_fences,
};
use wholepact_storage_security::bundle::{
    JournalKind,
    recovery::{RecoveryCell, RecoveryProvenance, RecoveryTable, VerifiedRecoveryComponent},
};

/// Constructed only by validating an authenticated complete Store component.
/// Agreement envelopes additionally require the engine's semantic validator.
/// This type deliberately has no Deserialize implementation.
pub struct StoreRecoveryInventory {
    provenance: RecoveryProvenance,
    accounts: BTreeSet<String>,
    obligations: BTreeSet<String>,
    agreements: Vec<StoredRecord>,
    historical_agreements: Vec<StoredRecord>,
    releases: Vec<ReleaseIntent>,
    effects: Vec<EffectIntent>,
    construction_claims: Vec<(
        String,
        crate::manual_enrollment::ManualRosterConstructionClaimV2,
    )>,
    construction_checkpoints: Vec<(
        String,
        crate::manual_enrollment::ManualRosterConstructionCheckpointV2,
    )>,
    construction_claims_v3: Vec<(
        String,
        crate::manual_enrollment::ManualRosterConstructionClaimV3,
    )>,
    construction_checkpoints_v3: Vec<(
        String,
        crate::manual_enrollment::ManualRosterConstructionCheckpointV3,
    )>,
}
impl StoreRecoveryInventory {
    pub fn construction_claims(
        &self,
    ) -> &[(
        String,
        crate::manual_enrollment::ManualRosterConstructionClaimV2,
    )] {
        &self.construction_claims
    }
    pub fn construction_checkpoints(
        &self,
    ) -> &[(
        String,
        crate::manual_enrollment::ManualRosterConstructionCheckpointV2,
    )] {
        &self.construction_checkpoints
    }
    pub fn construction_claims_v3(
        &self,
    ) -> &[(
        String,
        crate::manual_enrollment::ManualRosterConstructionClaimV3,
    )] {
        &self.construction_claims_v3
    }
    pub fn construction_checkpoints_v3(
        &self,
    ) -> &[(
        String,
        crate::manual_enrollment::ManualRosterConstructionCheckpointV3,
    )] {
        &self.construction_checkpoints_v3
    }
    pub fn provenance(&self) -> &RecoveryProvenance {
        &self.provenance
    }
    pub fn accounts(&self) -> &BTreeSet<String> {
        &self.accounts
    }
    pub fn obligations(&self) -> &BTreeSet<String> {
        &self.obligations
    }
    pub fn agreements(&self) -> &[StoredRecord] {
        &self.agreements
    }
    /// Every retained operation and idempotency result, including old revisions.
    pub fn historical_agreements(&self) -> &[StoredRecord] {
        &self.historical_agreements
    }
    pub fn releases(&self) -> &[ReleaseIntent] {
        &self.releases
    }
    pub fn effects(&self) -> &[EffectIntent] {
        &self.effects
    }

    pub fn inspect(source: &VerifiedRecoveryComponent) -> Result<Self> {
        Self::inspect_parts(source.provenance(), source.tables())
    }

    /// Trusted complete-inventory validation of authenticated inherited history.
    /// This is not a disclosure facade or permission to use historical authority.
    pub fn inspect_successor(
        source: &wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
    ) -> Result<Self> {
        Self::inspect_parts(source.provenance(), source.tables())
    }

    fn inspect_parts(provenance: &RecoveryProvenance, tables: &[RecoveryTable]) -> Result<Self> {
        if provenance.kind != JournalKind::CoordinationAuthority
            || provenance.application_id != 0
            || !(1..=SCHEMA_VERSION).contains(&provenance.schema_version)
        {
            return Err(StoreError::RecoveryRequired);
        }
        let mut expected: BTreeSet<&str> = [
            "records",
            "operations",
            "idempotency",
            "events",
            "authority_accounts",
            "authority_exposures",
            "authority_reservations",
            "authority_events",
            "effect_intents",
            "store_recovery",
            "sqlite_sequence",
        ]
        .into_iter()
        .collect();
        if provenance.schema_version == 1 {
            expected.remove("store_recovery");
        }
        if tables.len() != expected.len()
            || tables.iter().map(|t| t.name()).collect::<BTreeSet<_>>() != expected
        {
            return Err(StoreError::RecoveryRequired);
        }
        Self::inspect_rows(
            provenance,
            tables.iter().flat_map(|table| {
                table
                    .rows()
                    .iter()
                    .map(move |row| (table.name(), row.cells()))
            }),
            false,
        )
    }

    fn inspect_rows<'a>(
        provenance: &RecoveryProvenance,
        rows: impl IntoIterator<Item = (&'a str, &'a [RecoveryCell])>,
        recovered: bool,
    ) -> Result<Self> {
        let supports_v3 = construction_v3_supported_by_provenance(provenance)?;
        let supports_v4 = construction_v4_supported_by_provenance(provenance)?;
        let supports_v5 = construction_v5_supported_by_provenance(provenance)?;
        let mut inventory = Self {
            provenance: provenance.clone(),
            accounts: BTreeSet::new(),
            obligations: BTreeSet::new(),
            agreements: Vec::new(),
            historical_agreements: Vec::new(),
            releases: Vec::new(),
            effects: Vec::new(),
            construction_claims: Vec::new(),
            construction_checkpoints: Vec::new(),
            construction_claims_v3: Vec::new(),
            construction_checkpoints_v3: Vec::new(),
        };
        let mut manual_enrollments = Vec::new();
        let mut manual_actions = Vec::new();
        let mut manual_exclusions = Vec::new();
        let mut manual_permanent_stops = Vec::new();
        let mut manual_continuations = Vec::new();
        let mut manual_initials_v2 = Vec::new();
        let mut manual_continuations_v3 = Vec::new();
        let mut manual_additions_v3 = Vec::new();
        let mut manual_continuations_v4 = Vec::new();
        for (table, cells) in rows {
            match table {
                "records" => {
                    let kind = text(cells, 0)?;
                    if !supports_v3 && is_construction_v3_kind(kind) {
                        return Err(StoreError::RecoveryRequired);
                    }
                    let record = stored(cells, 1)?;
                    if !supports_v5 && is_construction_v5_claim(kind, &record.payload) {
                        return Err(StoreError::RecoveryRequired);
                    }
                    if !supports_v4 && is_construction_v4_claim(kind, &record.payload) {
                        return Err(StoreError::RecoveryRequired);
                    }
                    if recovered && kind == "settlement_generation_identity" {
                        validate_generation_identity_record(&record)?;
                    } else {
                        inventory.validate_aggregate(kind, &record)?;
                    }
                    use crate::manual_enrollment::{
                        ADDITIONAL_PUBLICATION_V3, CONTINUATION, CONTINUATION_V3, CONTINUATION_V4,
                        ENROLLMENT, EXCLUSION, INITIAL_PUBLICATION_V2, SCOPE, PERMANENT_STOP_V1,
                    };
                    match kind {
                        ENROLLMENT => manual_enrollments
                            .push((record.id.clone(), strict_value(record.payload.clone())?)),
                        SCOPE => manual_actions
                            .push((record.id.clone(), strict_value(record.payload.clone())?)),
                        PERMANENT_STOP_V1 => manual_permanent_stops
                            .push((record.id.clone(), strict_value(record.payload.clone())?)),
                        EXCLUSION => manual_exclusions
                            .push((record.id.clone(), strict_value(record.payload.clone())?)),
                        CONTINUATION => manual_continuations
                            .push((record.id.clone(), strict_value(record.payload.clone())?)),
                        INITIAL_PUBLICATION_V2 => manual_initials_v2
                            .push((record.id.clone(), strict_value(record.payload.clone())?)),
                        CONTINUATION_V3 => manual_continuations_v3
                            .push((record.id.clone(), strict_value(record.payload.clone())?)),
                        ADDITIONAL_PUBLICATION_V3 => manual_additions_v3
                            .push((record.id.clone(), strict_value(record.payload.clone())?)),
                        CONTINUATION_V4 => manual_continuations_v4
                            .push((record.id.clone(), strict_value(record.payload.clone())?)),
                        _ => (),
                    }
                    if kind == crate::manual_enrollment::construction_claim_v2::CONSTRUCTION_CLAIM_V2 {
                        inventory.construction_claims.push((record.id.clone(), strict_value(record.payload.clone())?));
                    } else if kind == crate::manual_enrollment::construction_claim_v2::CONSTRUCTION_CHECKPOINT_V2 {
                        inventory.construction_checkpoints.push((record.id.clone(), strict_value(record.payload.clone())?));
                    }
                    if kind == crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3 {
                        inventory.construction_claims_v3.push((record.id.clone(), strict_value(record.payload.clone())?));
                    } else if kind == crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3 {
                        inventory.construction_checkpoints_v3.push((record.id.clone(), strict_value(record.payload.clone())?));
                    }
                    if kind == "agreement" {
                        inventory.agreements.push(record);
                    }
                }
                "authority_accounts" => {
                    let account = text(cells, 0)?;
                    validate_id(account)?;
                    integer(cells, 1)?;
                    boolean(cells, 2)?;
                    inventory.accounts.insert(account.into());
                }
                "authority_exposures" => {
                    let release: ReleaseIntent = serde_json::from_str(text(cells, 8)?)?;
                    crate::authority::validate_intent(&release)?;
                    if release.authorization_id != text(cells, 0)?
                        || release.account_id != text(cells, 1)?
                        || release.obligation_id != text(cells, 2)?
                        || release.proposal_id != text(cells, 3)?
                        || request_digest(&serde_json::to_value(&release)?)? != text(cells, 4)?
                        || release.maximum_debit != text(cells, 5)?
                        || !boolean(cells, 7)?
                        || !matches!(
                            text(cells, 6)?,
                            "authorized_locally"
                                | "released"
                                | "outstanding_uncertain"
                                | "expired_observed"
                                | "conflicted_observed"
                                | "consumed"
                        )
                    {
                        return Err(StoreError::RecoveryRequired);
                    }
                    integer(cells, 9)?;
                    integer(cells, 10)?;
                    inventory.accounts.insert(release.account_id.clone());
                    inventory.obligations.insert(release.obligation_id.clone());
                    inventory.releases.push(release);
                }
                "authority_reservations" => {
                    for index in 0..3 {
                        validate_id(text(cells, index)?)?;
                    }
                    inventory.accounts.insert(text(cells, 0)?.into());
                }
                "operations" | "idempotency" => {
                    let index = if table == "operations" { 5 } else { 3 };
                    let result_value: Value = serde_json::from_str(text(cells, index)?)?;
                    let result: MutationResult = strict_value(result_value)?;
                    // The supported native engine records only agreement mutations.
                    // A generic embedding's unknown aggregate is not recoverable here.
                    inventory.validate_aggregate("agreement", &result.record)?;
                    if table == "operations"
                        && (result.operation_id != text(cells, 0)?
                            || result.record.id != text(cells, 3)?
                            || text(cells, 4)? != "succeeded")
                    {
                        return Err(StoreError::RecoveryRequired);
                    }
                    inventory.historical_agreements.push(result.record);
                }
                "effect_intents" => {
                    let effect = EffectIntent {
                        operation_id: text(cells, 0)?.into(),
                        kind: text(cells, 1)?.into(),
                        resource_id: text(cells, 2)?.into(),
                        payload_digest: text(cells, 3)?.into(),
                        protected_payload_ref: text(cells, 4)?.into(),
                        status: text(cells, 5)?.into(),
                        created_at_ms: integer(cells, 6)?,
                        updated_at_ms: integer(cells, 7)?,
                    };
                    for value in [
                        &effect.operation_id,
                        &effect.kind,
                        &effect.resource_id,
                        &effect.protected_payload_ref,
                    ] {
                        validate_id(value)?;
                    }
                    digest(&effect.payload_digest)?;
                    if effect.status != "outcome_unknown" {
                        return Err(StoreError::RecoveryRequired);
                    }
                    inventory.effects.push(effect);
                }
                "events" => {
                    let kind = text(cells, 1)?;
                    if matches!(kind, crate::manual_enrollment::PERMANENT_STOP_V1 | crate::manual_enrollment::construction_claim_v2::CONSTRUCTION_CLAIM_V2 | crate::manual_enrollment::construction_claim_v2::CONSTRUCTION_CHECKPOINT_V2 | crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3 | crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3) { return Err(StoreError::RecoveryRequired); }
                    if kind != "agreement" {
                        let record = StoredRecord {
                            id: text(cells, 2)?.into(),
                            revision: integer(cells, 3)? as u64,
                            payload: serde_json::from_str(text(cells, 5)?)?,
                            created_at_ms: integer(cells, 7)?,
                            updated_at_ms: integer(cells, 7)?,
                        };
                        inventory.validate_aggregate(kind, &record)?;
                    } else {
                        let payload: Value = serde_json::from_str(text(cells, 5)?)?;
                        if !payload.is_object()
                            || payload
                                .as_object()
                                .is_some_and(|v| v.keys().any(|k| k != "id" && k != "revision"))
                        {
                            return Err(StoreError::RecoveryRequired);
                        }
                    }
                }
                "authority_events" | "store_recovery" | "sqlite_sequence" => (),
                _ => return Err(StoreError::RecoveryRequired),
            }
        }
        crate::manual_enrollment::validate_audit_set(
            &manual_enrollments,
            &manual_actions,
            &manual_exclusions,
            &manual_continuations,
            &manual_initials_v2,
            &manual_continuations_v3,
            crate::manual_enrollment::RosterAuditRows {
                additions: &manual_additions_v3,
                continuations: &manual_continuations_v4,
            },
        )?;
        crate::manual_enrollment::validate_permanent_stop_set(
            &manual_permanent_stops, &manual_additions_v3, &manual_exclusions,
        )?;
        crate::manual_enrollment::construction_claim_v2::validate_construction_set(
            &inventory.construction_claims,
            &inventory.construction_checkpoints,
        )?;
        crate::manual_enrollment::construction_claim_v2::validate_construction_roster_history(
            &inventory.construction_claims,
            &manual_additions_v3,
            &manual_continuations_v4,
        )?;
        crate::manual_enrollment::construction_claim_v3::validate_construction_set(
            &inventory.construction_claims_v3,
            &inventory.construction_checkpoints_v3,
        )?;
        crate::manual_enrollment::construction_claim_v3::validate_construction_roster_history(
            &inventory.construction_claims_v3,
            &manual_additions_v3,
            &manual_continuations_v4,
        )?;
        crate::manual_enrollment::construction_claim_union::validate_union(
            &inventory.construction_claims,
            &inventory.construction_claims_v3,
        )?;
        for release in &inventory.releases {
            if !inventory.accounts.contains(&release.account_id) {
                return Err(StoreError::RecoveryRequired);
            }
        }
        Ok(inventory)
    }

    fn validate_aggregate(&mut self, kind: &str, record: &StoredRecord) -> Result<()> {
        validate_id(&record.id)?;
        if record.created_at_ms < 0 || record.updated_at_ms < 0 {
            return Err(StoreError::RecoveryRequired);
        }
        match kind {
            "agreement" => {
                if record
                    .payload
                    .pointer("/view/agreement/agreement_id")
                    .and_then(Value::as_str)
                    != Some(record.id.as_str())
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            "automation_account" | "automation_policy_history" => {
                let value: StoredAutomationAccount = strict_value(record.payload.clone())?;
                value
                    .policy
                    .validate()
                    .map_err(|_| StoreError::RecoveryRequired)?;
                if record.id.as_str()
                    != if kind == "automation_account" {
                        value.policy.account_id.as_str()
                    } else {
                        value.policy.policy_id.as_str()
                    }
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            "automation_grant" => {
                let value: StoredAutomationGrant = strict_value(record.payload.clone())?;
                if value.terms.grant_id != record.id {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            "automation_authorization" => {
                let value: AutomaticAuthorizationRecord = strict_value(record.payload.clone())?;
                if value.request.authorization_id != record.id {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            "automation_clock" => {
                let _: u64 = strict_value(record.payload.clone())?;
                self.accounts.insert(record.id.clone());
            }
            crate::manual_enrollment::ENROLLMENT
            | crate::manual_enrollment::SCOPE
            | crate::manual_enrollment::EXCLUSION
            | crate::manual_enrollment::PERMANENT_STOP_V1
            | crate::manual_enrollment::CONTINUATION
            | crate::manual_enrollment::INITIAL_PUBLICATION_V2
            | crate::manual_enrollment::CONTINUATION_V3
            | crate::manual_enrollment::ADDITIONAL_PUBLICATION_V3
            | crate::manual_enrollment::CONTINUATION_V4 => {
                self.accounts
                    .extend(crate::manual_enrollment::validate_recovery_record(
                        kind, record,
                    )?);
            }
            crate::manual_enrollment::construction_claim_v2::CONSTRUCTION_CLAIM_V2
            | crate::manual_enrollment::construction_claim_v2::CONSTRUCTION_CHECKPOINT_V2 => {
                crate::manual_enrollment::construction_claim_v2::validate_construction_record(
                    kind, record,
                )?;
            }
            crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3
            | crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3 => {
                crate::manual_enrollment::construction_claim_v3::validate_construction_record(
                    kind, record,
                )?;
            }
            "settlement_identity" => {
                let value: String = strict_value(record.payload.clone())?;
                digest(&value)?;
                if record.id != "local" {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            "settlement_applied" => {
                let value: String = strict_value(record.payload.clone())?;
                validate_id(&value)?;
                self.obligations.insert(value);
            }
            "settlement_consumed" => {
                #[derive(Serialize, Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Consumed {
                    release: ReleaseIntent,
                    evidence_id: String,
                    provenance: Value,
                }
                let value: Consumed = strict_value(record.payload.clone())?;
                crate::authority::validate_intent(&value.release)?;
                validate_id(&value.evidence_id)?;
                if request_digest(&serde_json::json!([
                    value.evidence_id,
                    value.release.authorization_id
                ]))? != record.id
                    || !value.provenance.is_object()
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            _ => return Err(StoreError::RecoveryRequired),
        }
        collect_identity(&record.payload, "account_id", &mut self.accounts)?;
        collect_identity(&record.payload, "obligation_id", &mut self.obligations)?;
        Ok(())
    }
}

fn validate_generation_identity_record(record: &StoredRecord) -> Result<()> {
    if record.id != "local"
        || record.revision != 0
        || record.created_at_ms < 0
        || record.updated_at_ms < 0
    {
        return Err(StoreError::RecoveryRequired);
    }
    let identity: String = strict_value(record.payload.clone())?;
    digest(&identity)
}

fn collect_identity(value: &Value, key: &str, output: &mut BTreeSet<String>) -> Result<()> {
    match value {
        Value::Object(values) => {
            for (name, value) in values {
                if name == key {
                    let id = value.as_str().ok_or(StoreError::RecoveryRequired)?;
                    validate_id(id)?;
                    output.insert(id.into());
                }
                collect_identity(value, key, output)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_identity(value, key, output)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn stored(cells: &[RecoveryCell], offset: usize) -> Result<StoredRecord> {
    Ok(StoredRecord {
        id: text(cells, offset)?.into(),
        revision: integer(cells, offset + 1)? as u64,
        payload: serde_json::from_str(text(cells, offset + 2)?)?,
        created_at_ms: integer(cells, offset + 3)?,
        updated_at_ms: integer(cells, offset + 4)?,
    })
}
fn text(cells: &[RecoveryCell], index: usize) -> Result<&str> {
    match cells.get(index) {
        Some(RecoveryCell::Text(value)) => Ok(value),
        _ => Err(StoreError::RecoveryRequired),
    }
}
fn integer(cells: &[RecoveryCell], index: usize) -> Result<i64> {
    match cells.get(index) {
        Some(RecoveryCell::Integer(value)) if *value >= 0 => Ok(*value),
        _ => Err(StoreError::RecoveryRequired),
    }
}
fn boolean(cells: &[RecoveryCell], index: usize) -> Result<bool> {
    match integer(cells, index)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreError::RecoveryRequired),
    }
}
fn digest(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(StoreError::RecoveryRequired)
    }
}

use wholepact_storage_security::bundle::recovery::generation::{
    GenerationBinding, RECOVERED_GENERATION_APPLICATION_ID, RecoveredGenerationConnection,
    RecoveredGenerationSnapshot,
};
use wholepact_storage_security::bundle::{BundleError, JournalTemplate};

static LEGACY_SUCCESSOR_TEMPLATE_V2: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 2,
    create_sql: concat!(
        include_str!("schema.sql"),
        "\n",
        include_str!("migration-v2.sql"),
        "\n",
        include_str!("recovery-schema.sql")
    ),
};
// Recovered versions 2 and 3 are immutable historical formats. Version 4
// reserves the first single-generation format that may contain V3 construction.
static LEGACY_SUCCESSOR_TEMPLATE_V4: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 4,
    create_sql: concat!(
        include_str!("schema.sql"),
        "\n",
        include_str!("migration-v2.sql"),
        "\n",
        include_str!("recovery-schema.sql")
    ),
};
static LEGACY_SUCCESSOR_TEMPLATE_V6: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 6,
    create_sql: concat!(
        include_str!("schema.sql"),
        "\n",
        include_str!("migration-v2.sql"),
        "\n",
        include_str!("recovery-schema.sql")
    ),
};
static SUCCESSOR_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 8,
    create_sql: concat!(
        include_str!("schema.sql"),
        "\n",
        include_str!("migration-v2.sql"),
        "\n",
        include_str!("recovery-schema.sql")
    ),
};
pub fn coordination_successor_template_for_schema(
    version: i64,
) -> std::result::Result<&'static JournalTemplate, BundleError> {
    match version {
        2 => Ok(&LEGACY_SUCCESSOR_TEMPLATE_V2),
        4 => Ok(&LEGACY_SUCCESSOR_TEMPLATE_V4),
        6 => Ok(&LEGACY_SUCCESSOR_TEMPLATE_V6),
        8 => Ok(&SUCCESSOR_TEMPLATE),
        _ => Err(BundleError::Unsupported),
    }
}
fn recovered_templates() -> [&'static JournalTemplate; 8] {
    [
        &LEGACY_SUCCESSOR_TEMPLATE_V2,
        layers::legacy_layered_template(),
        &LEGACY_SUCCESSOR_TEMPLATE_V4,
        layers::legacy_layered_template_v5(),
        &LEGACY_SUCCESSOR_TEMPLATE_V6,
        layers::legacy_layered_template_v7(),
        coordination_successor_template(),
        coordination_layered_successor_template(),
    ]
}
fn is_construction_v3_kind(kind: &str) -> bool {
    matches!(
        kind,
        crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3
            | crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3
    )
}
// Exact encoding support, independent of physical SQL layout. Unknown markers
// are never treated as future supersets of a known encoding.
pub(crate) fn construction_encoding_support(
    application: i64,
    version: i64,
) -> Result<(bool, bool, bool)> {
    match (application, version) {
        (0, 1 | 2) | (RECOVERED_GENERATION_APPLICATION_ID, 2 | 3) => {
            Ok((false, false, false))
        }
        (0, 3) | (RECOVERED_GENERATION_APPLICATION_ID, 4 | 5) => {
            Ok((true, false, false))
        }
        (0, 4) | (RECOVERED_GENERATION_APPLICATION_ID, 6 | 7) => {
            Ok((true, true, false))
        }
        (0, 5) | (RECOVERED_GENERATION_APPLICATION_ID, 8 | 9) => {
            Ok((true, true, true))
        }
        _ => Err(StoreError::RecoveryRequired),
    }
}
fn construction_encoding_supported_by_provenance(
    provenance: &RecoveryProvenance,
) -> Result<(bool, bool, bool)> {
    if provenance.kind != JournalKind::CoordinationAuthority {
        return Err(StoreError::RecoveryRequired);
    }
    construction_encoding_support(provenance.application_id, provenance.schema_version)
}
fn construction_v3_supported_by_provenance(provenance: &RecoveryProvenance) -> Result<bool> {
    Ok(construction_encoding_supported_by_provenance(provenance)?.0)
}
pub(crate) fn is_construction_v4_claim(kind: &str, payload: &Value) -> bool {
    kind == crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3
        && (payload.get("version").and_then(Value::as_u64) == Some(4)
            || payload.get("reentry_lineages").is_some())
}
pub(crate) fn is_construction_v5_claim(kind: &str, payload: &Value) -> bool {
    kind == crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3
        && (payload.get("version").and_then(Value::as_u64) == Some(5)
            || payload.get("historical_provenance").is_some())
}
fn construction_v4_supported_by_provenance(provenance: &RecoveryProvenance) -> Result<bool> {
    Ok(construction_encoding_supported_by_provenance(provenance)?.1)
}
fn construction_v5_supported_by_provenance(provenance: &RecoveryProvenance) -> Result<bool> {
    Ok(construction_encoding_supported_by_provenance(provenance)?.2)
}
fn require_construction_support(
    destination: (bool, bool, bool),
    source: (bool, bool, bool),
) -> Result<()> {
    if (!destination.0 && source.0)
        || (!destination.1 && source.1)
        || (!destination.2 && source.2)
    {
        Err(StoreError::RecoveryRequired)
    } else {
        Ok(())
    }
}
pub fn coordination_successor_template() -> &'static JournalTemplate {
    &SUCCESSOR_TEMPLATE
}

/// Immutable, source-preserving inspection of a generation Store. This is an
/// integrity proof only: it cannot be consumed as Store or authorize a runtime.
/// All original-row, monetary-counter, recovery-flag and fence checks are the
/// same checks used by the dedicated runtime opener, without a writable handle.
pub struct RecoveredStoreSnapshot {
    snapshot: RecoveredGenerationSnapshot,
}
impl RecoveredStoreSnapshot {
    pub fn open(
        path: &Path,
        key: &wholepact_storage_security::DatabaseKey,
        binding: &GenerationBinding,
        expected: &RecoveryProvenance,
    ) -> Result<Self> {
        for template in recovered_templates() {
            if let Ok(snapshot) = wholepact_storage_security::bundle::recovery::generation::open_recovered_generation_snapshot(
                path, key, binding, expected, template,
            ) { return Self::validate(snapshot); }
        }
        Err(StoreError::RecoveryRequired)
    }

    /// The host must authenticate the entire archive and exact origin mapping
    /// before calling. The original path is inert authenticated evidence; it is
    /// not accessed, rewritten, or accepted by any runtime constructor.
    pub fn open_archived(
        path: &Path,
        original_path: &Path,
        key: &wholepact_storage_security::DatabaseKey,
        binding: &GenerationBinding,
        expected: &RecoveryProvenance,
    ) -> Result<Self> {
        for template in recovered_templates() {
            if let Ok(snapshot) = wholepact_storage_security::bundle::recovery::generation::open_archived_generation_snapshot(
                path, original_path, key, binding, expected, template,
            ) { return Self::validate(snapshot); }
        }
        Err(StoreError::RecoveryRequired)
    }

    fn validate(snapshot: RecoveredGenerationSnapshot) -> Result<Self> {
        snapshot
            .check_source_unchanged()
            .map_err(|_| StoreError::RecoveryRequired)?;
        validate_generation(
            snapshot.connection(),
            snapshot.provenance(),
            snapshot.generation(),
        )?;
        snapshot
            .check_source_unchanged()
            .map_err(|_| StoreError::RecoveryRequired)?;
        Ok(Self { snapshot })
    }

    /// Source-race guard under the owning profile's quiescence. The retained
    /// private snapshot never becomes a live Store or a financial permission.
    pub fn check_source_unchanged(&self) -> Result<()> {
        self.snapshot
            .check_source_unchanged()
            .map_err(|_| StoreError::RecoveryRequired)
    }

    /// Exact captured generation destination, without opening the original
    /// database through SQLite or creating a missing settlement identity.
    pub fn current_store_destination_identity(&self) -> Result<String> {
        self.check_source_unchanged()?;
        let result = layers::current_identity(self.snapshot.connection(), self.generation());
        self.check_source_unchanged()?;
        result
    }

    /// One unfenced current agreement from the authenticated captured generation.
    /// The Engine still validates its full envelope and exact selected Access.
    /// This is read correlation only, never restored approval or authority.
    pub fn current_agreement_record(&self, agreement_id: &str) -> Result<StoredRecord> {
        self.check_source_unchanged()?;
        validate_id(agreement_id)?;
        let c = self.snapshot.connection();
        let result = (|| {
            if !crate::backup::read_recovery_state(c)?.recovery_required {
                return Err(StoreError::RecoveryRequired);
            }
            // Preserve both exclusions used by ManualStoreTarget; a current
            // generation does not make inherited agreements current targets.
            let fenced: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM store_generation_fences WHERE (kind='agreement' AND identity=?1) OR (kind='record' AND identity=?2))",
                params![agreement_id, format!("agreement:{agreement_id}")],
                |row| row.get(0),
            )?;
            if fenced {
                return Err(StoreError::RecoveryRequired);
            }
            layers::current_identity(c, self.generation())?;
            crate::read_record(c, "agreement", agreement_id)?.ok_or(StoreError::RecoveryRequired)
        })();
        self.check_source_unchanged()?;
        result
    }

    /// Complete bounded immutable construction/audit integrity, then exact
    /// historical principal/key selection. No private witness or live token.
    pub fn manual_roster_construction_evidence_v2(
        &self,
        principal: &str,
        key: &str,
    ) -> Result<
        Option<(
            crate::manual_enrollment::ManualRosterConstructionClaimV2,
            Option<crate::manual_enrollment::ManualRosterConstructionCheckpointV2>,
        )>,
    > {
        self.check_source_unchanged()?;
        let result = (|| {
            let (claims, checkpoints) =
                crate::manual_enrollment::construction_claim_v2::read_construction_rows(
                    self.snapshot.connection(),
                )?;
            Ok(claims
                .into_iter()
                .find(|(_, claim)| claim.principal_id == principal && claim.construction_key == key)
                .map(|(id, claim)| {
                    let receipt = checkpoints
                        .into_iter()
                        .find(|(claim_id, _)| claim_id == &id)
                        .map(|(_, receipt)| receipt);
                    (claim, receipt)
                }))
        })();
        self.check_source_unchanged()?;
        result
    }

    pub fn manual_roster_construction_evidence_v3(
        &self,
        principal: &str,
        key: &str,
    ) -> Result<
        Option<(
            crate::manual_enrollment::ManualRosterConstructionClaimV3,
            Option<crate::manual_enrollment::ManualRosterConstructionCheckpointV3>,
        )>,
    > {
        self.check_source_unchanged()?;
        let result =
            read_snapshot_construction_evidence_v3(self.snapshot.connection(), principal, key);
        self.check_source_unchanged()?;
        result
    }

    /// Historical complete manual audit rows from this authenticated immutable
    /// snapshot. Every enrollment remains bound to its original retained Store
    /// generation; projection never restores scope or current signer authority.
    pub fn manual_audit_projection(
        &self,
    ) -> Result<crate::manual_enrollment::ManualAuditProjection> {
        project_manual_snapshot(self.snapshot.connection(), self.generation())
    }

    /// Source-preserving archived counterpart. The owning archive source and
    /// all original rows/layers are authenticated before projecting any audit.
    pub fn archived_manual_audit_projection(
        source: &wholepact_storage_security::generation_archive::ArchivedGenerationSource,
    ) -> Result<crate::manual_enrollment::ManualAuditProjection> {
        layers::validate_archived_source(source)?;
        project_manual_snapshot(
            source.snapshot().connection(),
            source.snapshot().generation(),
        )
    }

    pub fn layer_depth(&self) -> Result<usize> {
        layers::generation_depth(self.snapshot.connection())
    }

    pub fn validate_archived_source(
        source: &wholepact_storage_security::generation_archive::ArchivedGenerationSource,
    ) -> Result<()> {
        layers::validate_archived_source(source)
    }

    pub fn generation(&self) -> &GenerationBinding {
        self.snapshot.generation()
    }
    pub fn provenance(&self) -> &RecoveryProvenance {
        self.snapshot.provenance()
    }

    /// Match the exact historical publication manifest's continuity batch and
    /// every inherited witness-only restriction. Saved evidence is not current
    /// financial confidence or an admission to publish another generation.
    pub fn verify_recovery_obligation_fences(&self, obligations: &BTreeSet<String>) -> Result<()> {
        verify_obligation_fences(self.snapshot.connection(), self.generation(), obligations)
    }
}

// Private row projection shared only by the immutable reader and pure tests.
// The caller's sealed snapshot authenticates source shape; this additional
// encoding restriction prevents legacy history from being reported as absence.
fn read_snapshot_construction_evidence_v3(
    c: &Connection,
    principal: &str,
    key: &str,
) -> Result<
    Option<(
        crate::manual_enrollment::ManualRosterConstructionClaimV3,
        Option<crate::manual_enrollment::ManualRosterConstructionCheckpointV3>,
    )>,
> {
    crate::backup::require_construction_v3_encoding(c)?;
    let (claims, checkpoints) =
        crate::manual_enrollment::construction_claim_v3::read_construction_rows(c)?;
    Ok(claims
        .into_iter()
        .find(|(_, claim)| claim.principal_id == principal && claim.construction_key == key)
        .map(|(id, claim)| {
            let receipt = checkpoints
                .into_iter()
                .find(|(claim_id, _)| claim_id == &id)
                .map(|(_, receipt)| receipt);
            (claim, receipt)
        }))
}

pub(crate) fn project_manual_snapshot(
    c: &Connection,
    generation: &GenerationBinding,
) -> Result<crate::manual_enrollment::ManualAuditProjection> {
    let destination = layers::current_identity(c, generation)?;
    let projection = crate::manual_enrollment::project_snapshot(c, generation, &destination)?;
    for audit in projection.enrollments() {
        let host = &audit.terms().host;
        let binding = GenerationBinding::new(&host.generation_id, &host.inventory_digest)
            .map_err(|_| StoreError::RecoveryRequired)?;
        if (!layers::is_layered(c)? && &binding != generation)
            || layers::current_identity(c, &binding)? != host.store_destination_identity
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(projection)
}

/// Build only an inert, separately encrypted generation. The host must validate
/// the engine's semantic inventory, all other journals, current signer leases,
/// native approval and its committed generation manifest before opening it.
/// Source files and source rows are never rewritten. Replays verify the exact
/// previously staged destination; they never pick replacement identities.
pub fn stage_coordination_successor(
    source: &VerifiedRecoveryComponent,
    binding: &GenerationBinding,
    destination: &Path,
    key: &wholepact_storage_security::DatabaseKey,
) -> Result<()> {
    let inventory = StoreRecoveryInventory::inspect(source)?;
    wholepact_storage_security::bundle::recovery::generation::initialize_coordination_generation(
        source,
        crate::bundle::coordination_template_for_schema(source.provenance().schema_version)
            .map_err(|_| StoreError::RecoveryRequired)?,
        coordination_successor_template(),
        binding,
        destination,
        key,
        |connection| {
            initialize_successor(connection, source, &inventory).map_err(|_| BundleError::Integrity)
        },
    )
    .map_err(|_| StoreError::RecoveryRequired)?;
    // Validate the persisted result on initial construction and exact retry.
    let connection =
        wholepact_storage_security::bundle::recovery::generation::open_recovered_generation(
            destination,
            key,
            binding,
            source.provenance(),
            coordination_successor_template(),
        )
        .map_err(|_| StoreError::RecoveryRequired)?;
    validate_generation(connection.connection(), source.provenance(), binding)?;
    Ok(())
}

fn initialize_successor(
    c: &Connection,
    source: &VerifiedRecoveryComponent,
    inventory: &StoreRecoveryInventory,
) -> Result<()> {
    if source.provenance().schema_version == 1 {
        c.execute_batch(include_str!("migration-v2.sql"))?;
    }
    c.execute_batch(include_str!("recovery-schema.sql"))?;
    for table in source.tables() {
        for (ordinal, row) in table.rows().iter().enumerate() {
            let values: Vec<Value> = row
                .cells()
                .iter()
                .map(|cell| match cell {
                    RecoveryCell::Null => Ok(Value::Null),
                    RecoveryCell::Integer(value) => Ok(serde_json::json!(value)),
                    RecoveryCell::Text(value) => Ok(Value::String(value.clone())),
                    _ => Err(StoreError::RecoveryRequired),
                })
                .collect::<Result<_>>()?;
            c.execute(
                "INSERT INTO store_generation_original_rows VALUES(?1,?2,?3)",
                params![
                    table.name(),
                    ordinal as i64,
                    serde_json::to_string(&values)?
                ],
            )?;
        }
    }
    for record in &inventory.agreements {
        fence(c, "agreement", &record.id, "historical_only")?;
    }
    for table in source.tables() {
        for row in table.rows() {
            match table.name() {
                "records" => fence(
                    c,
                    "record",
                    &format!("{}:{}", text(row.cells(), 0)?, text(row.cells(), 1)?),
                    "historical_only",
                )?,
                "operations" => fence(c, "operation", text(row.cells(), 0)?, "historical_result")?,
                "idempotency" => fence(
                    c,
                    "idempotency",
                    &replay_identity(text(row.cells(), 0)?, text(row.cells(), 1)?)?,
                    "historical_result",
                )?,
                "effect_intents" => fence(
                    c,
                    "effect",
                    text(row.cells(), 0)?,
                    "external_outcome_unknown",
                )?,
                _ => (),
            }
        }
    }
    for account in &inventory.accounts {
        fence(c, "account", account, "old_history_not_current_authority")?;
    }
    for obligation in &inventory.obligations {
        fence(
            c,
            "obligation",
            obligation,
            "historical_resolution_not_current",
        )?;
    }
    // Consumed remains charged exactly once. Expired/conflicted observations are
    // historical and cannot free budget. Every input is separately fenced even
    // if multiple historical authorizations reuse it and the old reservation PK
    // cannot represent all alternatives at once.
    for release in &inventory.releases {
        for input in &release.input_ids {
            fence(
                c,
                "input",
                &request_digest(&serde_json::json!([release.account_id, input]))?,
                "historical_input_exposure",
            )?;
            c.execute("INSERT OR IGNORE INTO authority_reservations(account_id,input_id,authorization_id) VALUES(?1,?2,?3)", params![release.account_id,input,release.authorization_id])?;
        }
        c.execute("UPDATE authority_exposures SET state=CASE WHEN state='consumed' THEN 'consumed' ELSE 'outstanding_uncertain' END,updated_at_ms=?2 WHERE authorization_id=?1", params![release.authorization_id, now_ms()])?;
        c.execute("INSERT INTO authority_events(authorization_id,kind,evidence_ref,occurred_at_ms) VALUES(?1,'host_generation_conservative_reopening',?2,?3)", params![release.authorization_id, source.provenance().component_digest, now_ms()])?;
    }
    c.execute("UPDATE authority_accounts SET recovery_required=1", [])?;
    c.execute("UPDATE store_recovery SET recovery_required=1,restored_at_ms=?1,source_snapshot_digest=?2 WHERE singleton=1", params![now_ms(), source.provenance().component_digest])?;
    c.execute("INSERT INTO records(aggregate_type,id,revision,payload,created_at_ms,updated_at_ms) VALUES('settlement_generation_identity','local',0,json_quote(lower(hex(randomblob(32)))),?1,?1)", [now_ms()])?;
    Ok(())
}
fn fence(c: &Connection, kind: &str, identity: &str, detail: &str) -> Result<()> {
    c.execute(
        "INSERT OR IGNORE INTO store_generation_fences VALUES(?1,?2,?3)",
        params![kind, identity, detail],
    )?;
    Ok(())
}
fn replay_identity(principal: &str, key: &str) -> Result<String> {
    request_digest(&serde_json::json!([principal, key]))
}

fn validate_generation(
    c: &Connection,
    provenance: &RecoveryProvenance,
    binding: &GenerationBinding,
) -> Result<()> {
    let source_support = construction_encoding_supported_by_provenance(provenance)?;
    let template = layers::generation_template(c)?;
    let support = construction_encoding_support(template.application_id, template.schema_version)?;
    require_construction_support(support, source_support)?;
    crate::backup::validate_construction_encoding(c, support.0, support.1, support.2)?;
    if layers::is_layered(c)? {
        layers::validate_layered(c, provenance, binding)?;
        project_manual_snapshot(c, binding)?;
        return Ok(());
    }
    let state = crate::backup::read_recovery_state(c)?;
    if !state.recovery_required
        || state.source_snapshot_digest.as_deref() != Some(&provenance.component_digest)
    {
        return Err(StoreError::RecoveryRequired);
    }
    layers::current_identity(c, binding)?;
    validate_continuity_batches(c, std::slice::from_ref(binding))?;
    validate_originals(c, provenance)?;
    project_manual_snapshot(c, binding)?;
    Ok(())
}
fn validate_originals(c: &Connection, provenance: &RecoveryProvenance) -> Result<()> {
    let supports_v3 = construction_v3_supported_by_provenance(provenance)?;
    let supports_v4 = construction_v4_supported_by_provenance(provenance)?;
    let supports_v5 = construction_v5_supported_by_provenance(provenance)?;
    let count: usize = c.query_row(
        "SELECT count(*) FROM store_generation_original_rows",
        [],
        |r| r.get(0),
    )?;
    if count != provenance.rows {
        return Err(StoreError::RecoveryRequired);
    }
    let mut q = c.prepare(
        "SELECT table_name,payload FROM store_generation_original_rows ORDER BY table_name,ordinal",
    )?;
    for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (table, encoded) = row?;
        let cells: Vec<Value> = serde_json::from_str(&encoded)?;
        if table == "records"
            && cells
                .first()
                .and_then(Value::as_str)
                .is_some_and(is_construction_v3_kind)
            && !supports_v3
        {
            return Err(StoreError::RecoveryRequired);
        }
        verify_original_row(c, &table, &cells)?;
        let s = |i: usize| -> Result<&str> {
            cells
                .get(i)
                .and_then(Value::as_str)
                .ok_or(StoreError::RecoveryRequired)
        };
        let required = match table.as_str() {
            "records" => {
                let current: Option<(u64,String,i64,i64)> = c.query_row("SELECT revision,payload,created_at_ms,updated_at_ms FROM records WHERE aggregate_type=?1 AND id=?2", params![s(0)?,s(1)?], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
                let current = current.ok_or(StoreError::RecoveryRequired)?;
                if cells.get(2).and_then(Value::as_u64) != Some(current.0)
                    || s(3)? != current.1
                    || cells.get(4).and_then(Value::as_i64) != Some(current.2)
                    || cells.get(5).and_then(Value::as_i64) != Some(current.3)
                {
                    return Err(StoreError::RecoveryRequired);
                }
                let payload: Value = serde_json::from_str(s(3)?)?;
                if !supports_v5 && is_construction_v5_claim(s(0)?, &payload) {
                    return Err(StoreError::RecoveryRequired);
                }
                if !supports_v4 && is_construction_v4_claim(s(0)?, &payload) {
                    return Err(StoreError::RecoveryRequired);
                }
                let mut obligations = BTreeSet::new();
                collect_identity(&payload, "obligation_id", &mut obligations)?;
                if s(0)? == "settlement_applied" {
                    obligations.insert(serde_json::from_value(payload.clone())?);
                }
                for obligation in obligations {
                    require_fence(c, "obligation", &obligation)?;
                }
                Some(("record", format!("{}:{}", s(0)?, s(1)?)))
            }
            "operations" => Some(("operation", s(0)?.to_owned())),
            "idempotency" => Some(("idempotency", replay_identity(s(0)?, s(1)?)?)),
            "effect_intents" => Some(("effect", s(0)?.to_owned())),
            "authority_exposures" => {
                let (payload, state): (String, String) = c.query_row(
                    "SELECT payload,state FROM authority_exposures WHERE authorization_id=?1",
                    [s(0)?],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if payload != s(8)?
                    || (s(6)? == "consumed" && state != "consumed")
                    || (s(6)? != "consumed" && state != "outstanding_uncertain")
                {
                    return Err(StoreError::RecoveryRequired);
                }
                Some(("obligation", s(2)?.to_owned()))
            }
            "authority_accounts" => {
                let fenced: bool = c.query_row(
                    "SELECT recovery_required FROM authority_accounts WHERE account_id=?1",
                    [s(0)?],
                    |r| r.get(0),
                )?;
                if !fenced {
                    return Err(StoreError::RecoveryRequired);
                }
                Some(("account", s(0)?.to_owned()))
            }
            "authority_reservations"
            | "authority_events"
            | "events"
            | "store_recovery"
            | "sqlite_sequence" => None,
            _ => return Err(StoreError::RecoveryRequired),
        };
        if let Some((kind, id)) = required {
            require_fence(c, kind, &id)?;
        }
    }
    Ok(())
}

fn validate_continuity_batches(c: &Connection, bindings: &[GenerationBinding]) -> Result<()> {
    let bad: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM store_generation_fences WHERE kind NOT IN('agreement','record','operation','idempotency','effect','account','obligation','input','continuity_batch'))", [], |r| r.get(0))?;
    if bad {
        return Err(StoreError::RecoveryRequired);
    }
    let mut batches = c.prepare("SELECT identity,detail FROM store_generation_fences WHERE kind='continuity_batch' ORDER BY identity")?;
    for row in batches.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (identity, detail) = row?;
        let obligations: BTreeSet<String> = serde_json::from_str(&detail)?;
        if serde_json::to_string(&obligations)? != detail
            || obligations.len() > 100_000
            || bindings
                .iter()
                .map(|binding| {
                    request_digest(&serde_json::json!([
                        binding.generation_id(),
                        binding.inventory_digest(),
                        obligations
                    ]))
                })
                .collect::<Result<Vec<_>>>()?
                .iter()
                .filter(|digest| **digest == identity)
                .count()
                != 1
        {
            return Err(StoreError::RecoveryRequired);
        }
        for obligation in &obligations {
            validate_id(obligation)?;
            require_fence(c, "obligation", obligation)?;
        }
    }
    Ok(())
}

// All original cells remain exact except the explicitly conservative overlay
// columns. In particular, writer epochs, monetary counters, retry snapshots,
// reservations and AUTOINCREMENT high-water marks cannot silently disappear.
fn verify_original_row(c: &Connection, table: &str, original: &[Value]) -> Result<()> {
    let (columns, keys, allowed): (&str, &[usize], &[usize]) = match table {
        "records" => (
            "aggregate_type,id,revision,payload,created_at_ms,updated_at_ms",
            &[0, 1],
            &[],
        ),
        "operations" => (
            "operation_id,principal_id,kind,resource_id,status,result,created_at_ms,updated_at_ms",
            &[0],
            &[],
        ),
        "idempotency" => (
            "principal_id,idempotency_key,request_digest,result",
            &[0, 1],
            &[],
        ),
        "events" => (
            "sequence,aggregate_type,aggregate_id,aggregate_revision,kind,payload,operation_id,occurred_at_ms",
            &[0],
            &[],
        ),
        "authority_accounts" => ("account_id,writer_epoch,recovery_required", &[0], &[2]),
        "authority_exposures" => (
            "authorization_id,account_id,obligation_id,proposal_id,request_digest,maximum_debit,state,release_intent,payload,created_at_ms,updated_at_ms",
            &[0],
            &[6, 10],
        ),
        "authority_reservations" => ("account_id,input_id,authorization_id", &[0, 1], &[]),
        "authority_events" => (
            "sequence,authorization_id,kind,evidence_ref,occurred_at_ms",
            &[0],
            &[],
        ),
        "effect_intents" => (
            "operation_id,kind,resource_id,payload_digest,protected_payload_ref,status,created_at_ms,updated_at_ms",
            &[0],
            &[],
        ),
        "store_recovery" => (
            "singleton,recovery_required,restored_at_ms,source_snapshot_digest",
            &[0],
            &[1, 2, 3],
        ),
        "sqlite_sequence" => ("name,seq", &[0], &[1]),
        _ => return Err(StoreError::RecoveryRequired),
    };
    let names: Vec<_> = columns.split(',').collect();
    if names.len() != original.len() {
        return Err(StoreError::RecoveryRequired);
    }
    let parameters: Vec<rusqlite::types::Value> = keys
        .iter()
        .map(|index| match &original[*index] {
            Value::String(value) => Ok(rusqlite::types::Value::Text(value.clone())),
            Value::Number(value) => value
                .as_i64()
                .map(rusqlite::types::Value::Integer)
                .ok_or(StoreError::RecoveryRequired),
            _ => Err(StoreError::RecoveryRequired),
        })
        .collect::<Result<_>>()?;
    let predicate = keys
        .iter()
        .enumerate()
        .map(|(parameter, index)| format!("{}=?{}", names[*index], parameter + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    let current: Vec<Value> = c.query_row(
        &format!("SELECT {columns} FROM {table} WHERE {predicate}"),
        rusqlite::params_from_iter(parameters),
        |row| {
            (0..names.len())
                .map(|index| match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => Ok(Value::Null),
                    rusqlite::types::ValueRef::Integer(value) => Ok(serde_json::json!(value)),
                    rusqlite::types::ValueRef::Text(value) => String::from_utf8(value.to_vec())
                        .map(Value::String)
                        .map_err(|_| rusqlite::Error::InvalidQuery),
                    _ => Err(rusqlite::Error::InvalidQuery),
                })
                .collect::<rusqlite::Result<_>>()
        },
    )?;
    for (index, (old, new)) in original.iter().zip(&current).enumerate() {
        if !allowed.contains(&index) && old != new {
            return Err(StoreError::RecoveryRequired);
        }
    }
    if table == "sqlite_sequence" {
        let old = original[1].as_i64().ok_or(StoreError::RecoveryRequired)?;
        let new = current[1].as_i64().ok_or(StoreError::RecoveryRequired)?;
        if new < old {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(())
}
fn require_fence(c: &Connection, kind: &str, id: &str) -> Result<()> {
    if !c.query_row(
        "SELECT EXISTS(SELECT 1 FROM store_generation_fences WHERE kind=?1 AND identity=?2)",
        params![kind, id],
        |r| r.get::<_, bool>(0),
    )? {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}

fn verify_obligation_fences(
    connection: &Connection,
    binding: &GenerationBinding,
    obligations: &BTreeSet<String>,
) -> Result<()> {
    if obligations.len() > 100_000 {
        return Err(StoreError::RecoveryRequired);
    }
    for obligation in obligations {
        validate_id(obligation)?;
    }
    let batch = request_digest(&serde_json::json!([
        binding.generation_id(),
        binding.inventory_digest(),
        obligations
    ]))?;
    let expected = serde_json::to_string(obligations)?;
    let detail: Option<String> = connection.query_row(
        "SELECT detail FROM store_generation_fences WHERE kind='continuity_batch' AND identity=?1",
        [batch], |r| r.get(0),
    ).optional()?;
    if detail.as_deref() != Some(expected.as_str()) {
        return Err(StoreError::RecoveryRequired);
    }
    for obligation in obligations {
        require_fence(connection, "obligation", obligation)?;
    }
    Ok(())
}

impl Store {
    pub fn reconstruct_recovered_generation(
        source: &VerifiedRecoveryComponent,
        path: &Path,
        key: &wholepact_storage_security::DatabaseKey,
        binding: &GenerationBinding,
    ) -> Result<()> {
        stage_coordination_successor(source, binding, path, key)
    }
    pub fn open_recovered_generation(
        path: &Path,
        key: &wholepact_storage_security::DatabaseKey,
        binding: &GenerationBinding,
        expected: &RecoveryProvenance,
    ) -> Result<Self> {
        // Probe on a source-preserving encrypted snapshot before selecting the
        // dedicated writable generation opener. Ordinary schemas are never tried.
        let snapshot = RecoveredStoreSnapshot::open(path, key, binding, expected)?;
        let template = layers::generation_template(snapshot.snapshot.connection())?;
        drop(snapshot);
        let connection =
            wholepact_storage_security::bundle::recovery::generation::open_recovered_generation(
                path, key, binding, expected, template,
            )
            .map_err(|_| StoreError::RecoveryRequired)?;
        Self::from_recovered_generation(connection)
    }
    /// Only the native committed-generation opener may compose this constructor
    /// into a live host. The specialized connection authenticates exact encrypted
    /// provenance/schema/path; it is never convertible to an ordinary Store.
    pub fn from_recovered_generation(connection: RecoveredGenerationConnection) -> Result<Self> {
        // Retain the sealed authenticated generation connection's identity at
        // this constructor boundary, before consuming that owner.
        let original_database = connection
            .database_identity()
            .map_err(|_| StoreError::RecoveryRequired)?;
        validate_generation(
            connection.connection(),
            connection.provenance(),
            connection.generation(),
        )?;
        let binding = connection.generation().clone();
        let connection = connection.into_connection();
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        original_database
            .check_current(&connection)
            .map_err(|_| StoreError::RecoveryRequired)?;
        Ok(Self {
            connection: Mutex::new(connection),
            protection: StorageProtection::Encrypted,
            original_database: Some(original_database),
            recovered_generation: true,
            recovered_binding: Some(binding),
        })
    }
    pub(crate) fn current_recovered_settlement_identity(&self, c: &Connection) -> Result<String> {
        layers::current_identity(
            c,
            self.recovered_binding
                .as_ref()
                .ok_or(StoreError::RecoveryRequired)?,
        )
    }
    /// Restriction-only union with every obligation in the current signer's
    /// conservative witness history. The native host calls this before its final
    /// publication marker. This never clears a fence or activates authority.
    /// The exact open-generation binding is mandatory, and retries are append-only.
    pub fn add_recovery_obligation_fences(
        &self,
        binding: &GenerationBinding,
        obligations: &BTreeSet<String>,
    ) -> Result<()> {
        if self.recovered_binding.as_ref() != Some(binding) || obligations.len() > 100_000 {
            return Err(StoreError::RecoveryRequired);
        }
        for obligation in obligations {
            validate_id(obligation)?;
        }
        let detail = serde_json::to_string(obligations)?;
        let batch = request_digest(&serde_json::json!([
            binding.generation_id(),
            binding.inventory_digest(),
            obligations
        ]))?;
        let mut connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx.query_row("SELECT detail FROM store_generation_fences WHERE kind='continuity_batch' AND identity=?1",[&batch],|r|r.get(0)).optional()?;
        if existing.as_ref().is_some_and(|old| old != &detail) {
            return Err(StoreError::IdempotencyConflict);
        }
        for obligation in obligations {
            fence(
                &tx,
                "obligation",
                obligation,
                "signer_witness_history_not_current_resolution",
            )?;
        }
        fence(&tx, "continuity_batch", &batch, &detail)?;
        tx.commit()?;
        Ok(())
    }
    /// Read-only committed-manifest check. Unlike the monotone construction
    /// helper, this must reject a missing exact continuity batch or fence.
    pub fn verify_recovery_obligation_fences(
        &self,
        binding: &GenerationBinding,
        obligations: &BTreeSet<String>,
    ) -> Result<()> {
        if self.recovered_binding.as_ref() != Some(binding) {
            return Err(StoreError::RecoveryRequired);
        }
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        verify_obligation_fences(&connection, binding, obligations)
    }
    /// Admission for NEW operations only. Historical provenance stays fenced.
    pub fn runtime_recovery_required(&self) -> Result<bool> {
        Ok(self.recovery_state()?.recovery_required && !self.recovered_generation)
    }
    pub fn recovery_record_is_historical(&self, aggregate_type: &str, id: &str) -> Result<bool> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        self.generation_fenced(&c, "record", &format!("{aggregate_type}:{id}"))
    }
    pub(crate) fn generation_fenced(&self, c: &Connection, kind: &str, id: &str) -> Result<bool> {
        if !self.recovered_generation {
            return Ok(false);
        }
        Ok(c.query_row(
            "SELECT EXISTS(SELECT 1 FROM store_generation_fences WHERE kind=?1 AND identity=?2)",
            params![kind, id],
            |r| r.get(0),
        )?)
    }
    pub(crate) fn require_current_replay(
        &self,
        c: &Connection,
        context: &CommandContext,
    ) -> Result<()> {
        if self.generation_fenced(
            c,
            "idempotency",
            &replay_identity(&context.principal_id, &context.idempotency_key)?,
        )? {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub(crate) fn require_current_record_write(
        &self,
        c: &Connection,
        kind: &str,
        id: &str,
        payload: &Value,
    ) -> Result<()> {
        if self.generation_fenced(c, "record", &format!("{kind}:{id}"))? {
            return Err(StoreError::RecoveryRequired);
        }
        if self.recovered_generation {
            let mut obligations = BTreeSet::new();
            collect_identity(payload, "obligation_id", &mut obligations)?;
            for obligation in obligations {
                if self.generation_fenced(c, "obligation", &obligation)? {
                    return Err(StoreError::RecoveryRequired);
                }
            }
        }
        Ok(())
    }
}

fn strict_value<T: serde::de::DeserializeOwned + Serialize>(value: Value) -> Result<T> {
    let decoded: T = serde_json::from_value(value.clone())?;
    if serde_json::to_value(&decoded)? != value {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic private raw fixture only. Production cannot set these fields;
    // it must authenticate the separately encrypted generation connection.
    fn raw_fixture() -> (Store, GenerationBinding, BTreeSet<String>) {
        let mut store = Store::in_memory().unwrap();
        let binding = GenerationBinding::new(&"a".repeat(64), &"b".repeat(64)).unwrap();
        store.recovered_generation = true;
        store.recovered_binding = Some(binding.clone());
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(include_str!("recovery-schema.sql"))
            .unwrap();
        (
            store,
            binding,
            BTreeSet::from(["witness-only-one".into(), "witness-only-two".into()]),
        )
    }
    #[test]
    fn recovery_obligation_fences_require_exact_batch_and_every_restriction() {
        let (store, binding, obligations) = raw_fixture();
        assert!(
            store
                .verify_recovery_obligation_fences(&binding, &obligations)
                .is_err()
        );
        store
            .add_recovery_obligation_fences(&binding, &obligations)
            .unwrap();
        store
            .verify_recovery_obligation_fences(&binding, &obligations)
            .unwrap();
        let subset = BTreeSet::from(["witness-only-one".into()]);
        assert!(
            store
                .verify_recovery_obligation_fences(&binding, &subset)
                .is_err()
        );
        {
            let c = store.connection.lock().unwrap();
            assert!(c.execute("DELETE FROM store_generation_fences WHERE kind='obligation' AND identity='witness-only-one'",[]).is_err());
            // Bypass a trigger only to model corruption. The public dedicated
            // opener also rejects the altered compiled schema independently.
            c.execute_batch("DROP TRIGGER store_generation_fences_no_delete; DELETE FROM store_generation_fences WHERE kind='obligation' AND identity='witness-only-one';").unwrap();
        }
        assert!(
            store
                .verify_recovery_obligation_fences(&binding, &obligations)
                .is_err()
        );
    }
    #[test]
    fn recovery_obligation_fences_reject_missing_authenticated_batch() {
        let (store, binding, obligations) = raw_fixture();
        store
            .add_recovery_obligation_fences(&binding, &obligations)
            .unwrap();
        store.connection.lock().unwrap().execute_batch("DROP TRIGGER store_generation_fences_no_delete; DELETE FROM store_generation_fences WHERE kind='continuity_batch';").unwrap();
        assert!(
            store
                .settlement_obligation_requires_recovery("witness-only-one")
                .unwrap()
        );
        assert!(
            store
                .verify_recovery_obligation_fences(&binding, &obligations)
                .is_err()
        );
    }
    #[test]
    fn recovery_original_rows_reject_counter_and_retry_corruption() {
        let (store, _, _) = raw_fixture();
        let c = store.connection.lock().unwrap();
        c.execute(
            "INSERT INTO authority_accounts VALUES('synthetic-account',7,1)",
            [],
        )
        .unwrap();
        let original = vec![
            serde_json::json!("synthetic-account"),
            serde_json::json!(7),
            serde_json::json!(0),
        ];
        verify_original_row(&c, "authority_accounts", &original).unwrap();
        c.execute("UPDATE authority_accounts SET writer_epoch=6", [])
            .unwrap();
        assert!(verify_original_row(&c, "authority_accounts", &original).is_err());
        c.execute(
            "INSERT INTO sqlite_sequence(name,seq) VALUES('authority_events',100)",
            [],
        )
        .unwrap();
        let sequence = vec![serde_json::json!("authority_events"), serde_json::json!(99)];
        verify_original_row(&c, "sqlite_sequence", &sequence).unwrap();
        c.execute(
            "UPDATE sqlite_sequence SET seq=98 WHERE name='authority_events'",
            [],
        )
        .unwrap();
        assert!(verify_original_row(&c, "sqlite_sequence", &sequence).is_err());
        c.execute(
            "INSERT INTO idempotency VALUES('synthetic-owner','old-key','old-digest','old-result')",
            [],
        )
        .unwrap();
        let replay = vec![
            serde_json::json!("synthetic-owner"),
            serde_json::json!("old-key"),
            serde_json::json!("old-digest"),
            serde_json::json!("old-result"),
        ];
        verify_original_row(&c, "idempotency", &replay).unwrap();
        c.execute("UPDATE idempotency SET result='different-result'", [])
            .unwrap();
        assert!(verify_original_row(&c, "idempotency", &replay).is_err());
    }
}

#[cfg(test)]
mod historical_provenance_v5_encoding_tests;
