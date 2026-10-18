//! Bounded recursive Store lineage. Historical layers preserve their own binding;
//! no saved resolution, grant, identity or continuity record becomes authority.
use super::*;
use wholepact_storage_security::{
    bundle::recovery::generation::{
        coordination_owner_rows_commitment, initialize_coordination_generation_from_archive,
    },
    generation_archive::ArchivedGenerationSource,
};

const MAX_GENERATIONS: usize = 16;
const MAX_LAYER_ROWS: usize = 100_000;
const MAX_LAYER_BYTES: usize = 64 * 1024 * 1024;
const MAX_ROW_BYTES: usize = 4 * 1024 * 1024;
static LEGACY_LAYERED_TEMPLATE_V3: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 3,
    create_sql: concat!(
        include_str!("../schema.sql"),
        "\n",
        include_str!("../migration-v2.sql"),
        "\n",
        include_str!("../recovery-schema.sql"),
        "\n",
        include_str!("../recovery-schema-v2.sql")
    ),
};
static LEGACY_LAYERED_TEMPLATE_V5: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 5,
    create_sql: concat!(
        include_str!("../schema.sql"),
        "\n",
        include_str!("../migration-v2.sql"),
        "\n",
        include_str!("../recovery-schema.sql"),
        "\n",
        include_str!("../recovery-schema-v2.sql")
    ),
};
static LEGACY_LAYERED_TEMPLATE_V7: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 7,
    create_sql: concat!(
        include_str!("../schema.sql"),
        "\n",
        include_str!("../migration-v2.sql"),
        "\n",
        include_str!("../recovery-schema.sql"),
        "\n",
        include_str!("../recovery-schema-v2.sql")
    ),
};
static LAYERED_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 9,
    create_sql: concat!(
        include_str!("../schema.sql"),
        "\n",
        include_str!("../migration-v2.sql"),
        "\n",
        include_str!("../recovery-schema.sql"),
        "\n",
        include_str!("../recovery-schema-v2.sql")
    ),
};
pub(super) fn legacy_layered_template_v7() -> &'static JournalTemplate {
    &LEGACY_LAYERED_TEMPLATE_V7
}
pub(super) fn legacy_layered_template_v5() -> &'static JournalTemplate {
    &LEGACY_LAYERED_TEMPLATE_V5
}
pub(super) fn legacy_layered_template() -> &'static JournalTemplate {
    &LEGACY_LAYERED_TEMPLATE_V3
}
pub fn coordination_layered_successor_template_for_schema(
    version: i64,
) -> std::result::Result<&'static JournalTemplate, BundleError> {
    match version {
        3 => Ok(&LEGACY_LAYERED_TEMPLATE_V3),
        5 => Ok(&LEGACY_LAYERED_TEMPLATE_V5),
        7 => Ok(&LEGACY_LAYERED_TEMPLATE_V7),
        9 => Ok(&LAYERED_TEMPLATE),
        _ => Err(BundleError::Unsupported),
    }
}
pub fn coordination_layered_successor_template() -> &'static JournalTemplate {
    &LAYERED_TEMPLATE
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Layer {
    version: u16,
    ordinal: usize,
    parent_generation_id: String,
    parent_inventory_digest: String,
    parent_provenance: RecoveryProvenance,
    parent_schema_version: i64,
    parent_destination_identity: String,
    destination_identity: String,
    generation_id: String,
    inventory_digest: String,
    source_provenance: RecoveryProvenance,
    previous_layer_digest: Option<String>,
    tables: Vec<(String, usize)>,
    rows: usize,
    bytes: usize,
}
impl Layer {
    fn parent_binding(&self) -> Result<GenerationBinding> {
        GenerationBinding::new(&self.parent_generation_id, &self.parent_inventory_digest)
            .map_err(|_| StoreError::RecoveryRequired)
    }
    fn binding(&self) -> Result<GenerationBinding> {
        GenerationBinding::new(&self.generation_id, &self.inventory_digest)
            .map_err(|_| StoreError::RecoveryRequired)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalRow {
    rowid: i64,
    cells: Vec<Value>,
}
struct CapturedRow {
    table: &'static str,
    ordinal: usize,
    payload: String,
    row: HistoricalRow,
}
struct Table {
    name: &'static str,
    columns: &'static str,
}
const BASE: &[Table] = &[
    Table {
        name: "records",
        columns: "aggregate_type,id,revision,payload,created_at_ms,updated_at_ms",
    },
    Table {
        name: "operations",
        columns: "operation_id,principal_id,kind,resource_id,status,result,created_at_ms,updated_at_ms",
    },
    Table {
        name: "idempotency",
        columns: "principal_id,idempotency_key,request_digest,result",
    },
    Table {
        name: "events",
        columns: "sequence,aggregate_type,aggregate_id,aggregate_revision,kind,payload,operation_id,occurred_at_ms",
    },
    Table {
        name: "authority_accounts",
        columns: "account_id,writer_epoch,recovery_required",
    },
    Table {
        name: "authority_exposures",
        columns: "authorization_id,account_id,obligation_id,proposal_id,request_digest,maximum_debit,state,release_intent,payload,created_at_ms,updated_at_ms",
    },
    Table {
        name: "authority_reservations",
        columns: "account_id,input_id,authorization_id",
    },
    Table {
        name: "authority_events",
        columns: "sequence,authorization_id,kind,evidence_ref,occurred_at_ms",
    },
    Table {
        name: "effect_intents",
        columns: "operation_id,kind,resource_id,payload_digest,protected_payload_ref,status,created_at_ms,updated_at_ms",
    },
    Table {
        name: "store_recovery",
        columns: "singleton,recovery_required,restored_at_ms,source_snapshot_digest",
    },
    Table {
        name: "sqlite_sequence",
        columns: "name,seq",
    },
];
const ORIGINALS: Table = Table {
    name: "store_generation_original_rows",
    columns: "table_name,ordinal,payload",
};
const FENCES: Table = Table {
    name: "store_generation_fences",
    columns: "kind,identity,detail",
};
const IDENTITIES: Table = Table {
    name: "store_generation_identities",
    columns: "generation_id,inventory_digest,destination_identity",
};
const LAYERS: Table = Table {
    name: "store_generation_layers",
    columns: "ordinal,payload,digest",
};
const LAYER_ROWS: Table = Table {
    name: "store_generation_layer_rows",
    columns: "layer,table_name,ordinal,payload",
};
fn snapshot_tables(layered: bool) -> Vec<&'static Table> {
    let mut tables: Vec<_> = BASE.iter().chain([&ORIGINALS, &FENCES]).collect();
    if layered {
        tables.push(&IDENTITIES);
    }
    tables.sort_by_key(|table| table.name);
    tables
}
fn table(name: &str) -> Result<&'static Table> {
    BASE.iter()
        .chain([&ORIGINALS, &FENCES, &IDENTITIES, &LAYERS, &LAYER_ROWS])
        .find(|table| table.name == name)
        .ok_or(StoreError::RecoveryRequired)
}
pub(super) fn is_layered(c: &Connection) -> Result<bool> {
    Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='store_generation_layers')", [], |r|r.get(0))?)
}
pub(super) fn generation_template(c: &Connection) -> Result<&'static JournalTemplate> {
    let application: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != RECOVERED_GENERATION_APPLICATION_ID {
        return Err(StoreError::RecoveryRequired);
    }
    if is_layered(c)? {
        coordination_layered_successor_template_for_schema(version)
    } else {
        coordination_successor_template_for_schema(version)
    }
    .map_err(|_| StoreError::RecoveryRequired)
}
pub(super) fn generation_depth(c: &Connection) -> Result<usize> {
    if !is_layered(c)? {
        return Ok(1);
    }
    let count: usize = c.query_row("SELECT count(*) FROM store_generation_layers", [], |r| {
        r.get(0)
    })?;
    if count == 0 || count >= MAX_GENERATIONS {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(count + 1)
}
fn read_rows(c: &Connection, table: &'static Table, predicate: &str) -> Result<Vec<HistoricalRow>> {
    let mut statement = c.prepare(&format!(
        "SELECT rowid,{} FROM {} {} ORDER BY rowid",
        table.columns, table.name, predicate
    ))?;
    let count = table.columns.split(',').count();
    let mut query = statement.query([])?;
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = query.next()? {
        let mut cells = Vec::with_capacity(count);
        for index in 0..count {
            cells.push(match row.get_ref(index + 1)? {
                rusqlite::types::ValueRef::Null => Value::Null,
                rusqlite::types::ValueRef::Integer(value) => serde_json::json!(value),
                rusqlite::types::ValueRef::Text(value) if value.len() <= MAX_ROW_BYTES => {
                    Value::String(
                        std::str::from_utf8(value)
                            .map_err(|_| StoreError::RecoveryRequired)?
                            .into(),
                    )
                }
                _ => return Err(StoreError::RecoveryRequired),
            });
        }
        let historical = HistoricalRow {
            rowid: row.get(0)?,
            cells,
        };
        validate_snapshot_row_without_private_input_projections(table.name, &historical.cells)?;
        let size = serde_json::to_vec(&historical)?.len();
        bytes = bytes
            .checked_add(size)
            .ok_or(StoreError::ResourceExhausted)?;
        if size > MAX_ROW_BYTES || bytes > MAX_LAYER_BYTES || rows.len() >= MAX_LAYER_ROWS {
            return Err(StoreError::ResourceExhausted);
        }
        rows.push(historical);
    }
    Ok(rows)
}

fn validate_snapshot_row_without_private_input_projections(
    table: &str,
    cells: &[Value],
) -> Result<()> {
    if table == ORIGINALS.name {
        // A snapshot retains original-row wrappers one level deep. Their third
        // cell encodes the base SQL cells; scanning the wrapper alone would
        // miss private projections or workspace markers in its JSON text. Layers
        // themselves are not recursive snapshots and are deliberately not
        // traversed here.
        let original_table = cells
            .first()
            .and_then(Value::as_str)
            .ok_or(StoreError::RecoveryRequired)?;
        if !BASE.iter().any(|base| base.name == original_table) {
            return Err(StoreError::RecoveryRequired);
        }
        let encoded = cells
            .get(2)
            .and_then(Value::as_str)
            .ok_or(StoreError::RecoveryRequired)?;
        original_cells_without_private_input_projections(original_table, encoded)?;
    } else {
        validate_no_private_input_projection_values(table, cells)?;
    }
    Ok(())
}

type CapturedSnapshot = (Vec<CapturedRow>, Vec<(String, usize)>, usize);

fn capture(c: &Connection) -> Result<CapturedSnapshot> {
    let mut captured = Vec::new();
    let mut counts = Vec::new();
    let mut bytes = 0usize;
    for table in snapshot_tables(is_layered(c)?) {
        let rows = read_rows(c, table, "")?;
        counts.push((table.name.into(), rows.len()));
        for (ordinal, row) in rows.into_iter().enumerate() {
            let payload = serde_json::to_string(&row)?;
            bytes = bytes
                .checked_add(payload.len())
                .ok_or(StoreError::ResourceExhausted)?;
            if bytes > MAX_LAYER_BYTES || captured.len() >= MAX_LAYER_ROWS {
                return Err(StoreError::ResourceExhausted);
            }
            captured.push(CapturedRow {
                table: table.name,
                ordinal,
                payload,
                row,
            });
        }
    }
    Ok((captured, counts, bytes))
}
fn layer_digest(header: &Layer, rows: &[CapturedRow]) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"wholepact:store-generation-layer:v2\0");
    hash.update(serde_json::to_vec(header)?);
    for row in rows {
        hash.update(serde_json::to_vec(&(row.table, row.ordinal, &row.payload))?);
    }
    Ok(hex::encode(hash.finalize()))
}
fn insert_row(c: &Connection, table: &Table, row: &HistoricalRow) -> Result<()> {
    let count = table.columns.split(',').count();
    if row.cells.len() != count {
        return Err(StoreError::RecoveryRequired);
    }
    let mut values = vec![rusqlite::types::Value::Integer(row.rowid)];
    for cell in &row.cells {
        values.push(match cell {
            Value::Null => rusqlite::types::Value::Null,
            Value::String(value) => rusqlite::types::Value::Text(value.clone()),
            Value::Number(value) => {
                rusqlite::types::Value::Integer(value.as_i64().ok_or(StoreError::RecoveryRequired)?)
            }
            _ => return Err(StoreError::RecoveryRequired),
        });
    }
    c.execute(
        &format!(
            "INSERT INTO {} (rowid,{}) VALUES ({})",
            table.name,
            table.columns,
            vec!["?"; count + 1].join(",")
        ),
        rusqlite::params_from_iter(values),
    )?;
    Ok(())
}

impl StoreRecoveryInventory {
    /// Complete current parent semantics, after its complete archived generation
    /// and every original binding/overlay have passed owner validation.
    pub fn inspect_archived_generation(source: &ArchivedGenerationSource) -> Result<Self> {
        validate_archived_source(source)?;
        inventory(source.snapshot().connection(), source.source_provenance())
    }
}
fn inventory(c: &Connection, provenance: &RecoveryProvenance) -> Result<StoreRecoveryInventory> {
    let mut rows = Vec::new();
    for table in BASE {
        for row in read_rows(c, table, "")? {
            let cells = row
                .cells
                .into_iter()
                .map(|cell| match cell {
                    Value::Null => Ok(RecoveryCell::Null),
                    Value::String(value) => Ok(RecoveryCell::Text(value)),
                    Value::Number(value) => Ok(RecoveryCell::Integer(
                        value.as_i64().ok_or(StoreError::RecoveryRequired)?,
                    )),
                    _ => Err(StoreError::RecoveryRequired),
                })
                .collect::<Result<Vec<_>>>()?;
            rows.push((table.name, cells));
        }
    }
    StoreRecoveryInventory::inspect_rows(
        provenance,
        rows.iter().map(|(name, cells)| (*name, cells.as_slice())),
        true,
    )
}
pub fn verify_archived_generation_obligation_fences(
    source: &ArchivedGenerationSource,
    obligations: &BTreeSet<String>,
) -> Result<()> {
    validate_archived_source(source)?;
    verify_obligation_fences(
        source.snapshot().connection(),
        source.snapshot().generation(),
        obligations,
    )
}
pub(super) fn validate_archived_source(source: &ArchivedGenerationSource) -> Result<()> {
    let parent = source.snapshot();
    validate_generation(
        parent.connection(),
        parent.provenance(),
        parent.generation(),
    )?;
    let template = generation_template(parent.connection())?;
    let provenance = source.source_provenance();
    let (digest, rows) = coordination_owner_rows_commitment(parent.connection(), template)
        .map_err(|_| StoreError::RecoveryRequired)?;
    if provenance.kind != JournalKind::CoordinationAuthority
        || provenance.application_id != RECOVERED_GENERATION_APPLICATION_ID
        || provenance.schema_version != template.schema_version
        || provenance.rows != rows
        || provenance.component_digest != digest
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}

pub fn stage_layered_coordination_successor(
    source: &ArchivedGenerationSource,
    binding: &GenerationBinding,
    destination: &Path,
    key: &wholepact_storage_security::DatabaseKey,
) -> Result<()> {
    validate_archived_source(source)?;
    let parent = source.snapshot();
    let depth = generation_depth(parent.connection())?;
    if depth >= MAX_GENERATIONS {
        return Err(StoreError::ResourceExhausted);
    }
    let inventory = inventory(parent.connection(), source.source_provenance())?;
    let (rows, counts, bytes) = capture(parent.connection())?;
    let previous = if depth > 1 {
        Some(parent.connection().query_row(
            "SELECT digest FROM store_generation_layers WHERE ordinal=?1",
            [(depth - 1) as i64],
            |r| r.get::<_, String>(0),
        )?)
    } else {
        None
    };
    let header = Layer {
        version: 2,
        ordinal: depth,
        parent_generation_id: parent.generation().generation_id().into(),
        parent_inventory_digest: parent.generation().inventory_digest().into(),
        parent_provenance: parent.provenance().clone(),
        parent_schema_version: generation_template(parent.connection())?.schema_version,
        parent_destination_identity: current_identity(parent.connection(), parent.generation())?,
        destination_identity: parent.connection().query_row(
            "SELECT lower(hex(randomblob(32)))",
            [],
            |row| row.get(0),
        )?,
        generation_id: binding.generation_id().into(),
        inventory_digest: binding.inventory_digest().into(),
        source_provenance: source.source_provenance().clone(),
        previous_layer_digest: previous,
        tables: counts,
        rows: rows.len(),
        bytes,
    };
    let old_rows: usize = if depth > 1 {
        parent.connection().query_row(
            "SELECT count(*) FROM store_generation_layer_rows",
            [],
            |r| r.get(0),
        )?
    } else {
        0
    };
    let old_bytes: usize = if depth > 1 {
        parent.connection().query_row("SELECT coalesce(sum(length(CAST(payload AS BLOB))),0) FROM store_generation_layer_rows",[],|r|r.get(0))?
    } else {
        0
    };
    if old_rows
        .checked_add(rows.len())
        .is_none_or(|value| value > MAX_LAYER_ROWS)
        || old_bytes
            .checked_add(bytes)
            .is_none_or(|value| value > MAX_LAYER_BYTES)
    {
        return Err(StoreError::ResourceExhausted);
    }
    if retained_bindings(parent.connection(), parent.generation())?
        .iter()
        .any(|old| old.generation_id() == binding.generation_id())
    {
        return Err(StoreError::RecoveryRequired);
    }
    initialize_coordination_generation_from_archive(
        source,
        generation_template(parent.connection())?,
        coordination_layered_successor_template(),
        binding,
        destination,
        key,
        |c| initialize_layer(c, &header, &rows, &inventory).map_err(|_| BundleError::Integrity),
    )
    .map_err(|_| StoreError::RecoveryRequired)?;
    let snapshot =
        RecoveredStoreSnapshot::open(destination, key, binding, source.source_provenance())?;
    if snapshot.layer_depth()? != depth + 1 {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}
fn initialize_layer(
    c: &Connection,
    header: &Layer,
    rows: &[CapturedRow],
    inventory: &StoreRecoveryInventory,
) -> Result<()> {
    if header.ordinal == 1 {
        c.execute_batch(include_str!("../recovery-schema-v2.sql"))?;
        c.execute(
            "INSERT INTO store_generation_identities VALUES(?1,?2,?3)",
            params![
                header.parent_generation_id,
                header.parent_inventory_digest,
                header.parent_destination_identity
            ],
        )?;
    }
    let encoded = serde_json::to_string(header)?;
    let digest = layer_digest(header, rows)?;
    c.execute(
        "INSERT INTO store_generation_layers VALUES(?1,?2,?3)",
        params![header.ordinal as i64, encoded, digest],
    )?;
    for row in rows {
        c.execute(
            "INSERT INTO store_generation_layer_rows VALUES(?1,?2,?3,?4)",
            params![
                header.ordinal as i64,
                row.table,
                row.ordinal as i64,
                row.payload
            ],
        )?;
    }
    for row in rows
        .iter()
        .filter(|row| BASE.iter().any(|table| table.name == row.table))
    {
        add_row_restrictions(c, row.table, &row.row.cells)?;
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
    for release in &inventory.releases {
        for input in &release.input_ids {
            fence(
                c,
                "input",
                &request_digest(&serde_json::json!([release.account_id, input]))?,
                "historical_input_exposure",
            )?;
            c.execute(
                "INSERT OR IGNORE INTO authority_reservations VALUES(?1,?2,?3)",
                params![release.account_id, input, release.authorization_id],
            )?;
        }
        c.execute("UPDATE authority_exposures SET state=CASE WHEN state='consumed' THEN 'consumed' ELSE 'outstanding_uncertain' END,updated_at_ms=?2 WHERE authorization_id=?1",params![release.authorization_id,now_ms()])?;
        c.execute("INSERT INTO authority_events(authorization_id,kind,evidence_ref,occurred_at_ms) VALUES(?1,'host_layer_conservative_reopening',?2,?3)",params![release.authorization_id,header.source_provenance.component_digest,now_ms()])?;
    }
    c.execute("UPDATE authority_accounts SET recovery_required=1", [])?;
    c.execute("UPDATE store_recovery SET recovery_required=1,restored_at_ms=?1,source_snapshot_digest=?2 WHERE singleton=1",params![now_ms(),header.source_provenance.component_digest])?;
    c.execute(
        "INSERT INTO store_generation_identities VALUES(?1,?2,?3)",
        params![
            header.generation_id,
            header.inventory_digest,
            header.destination_identity
        ],
    )?;
    // Storage installs the authenticated final marker only after this callback
    // returns. Validate the additive destination semantics against our compiled
    // target; do not treat its staging/parent marker as runtime admission.
    validate_layered_for_template(
        c,
        &header.source_provenance,
        &header.binding()?,
        coordination_layered_successor_template(),
    )
}

pub(super) fn current_identity(c: &Connection, binding: &GenerationBinding) -> Result<String> {
    let identity = if is_layered(c)? {
        c.query_row("SELECT destination_identity FROM store_generation_identities WHERE generation_id=?1 AND inventory_digest=?2",params![binding.generation_id(),binding.inventory_digest()],|r|r.get::<_,String>(0))?
    } else {
        let encoded:String = c.query_row("SELECT payload FROM records WHERE aggregate_type='settlement_generation_identity' AND id='local' AND revision=0",[],|r|r.get(0))?;
        serde_json::from_str::<String>(&encoded)?
    };
    digest(&identity)?;
    Ok(identity)
}
fn load_headers(c: &Connection) -> Result<Vec<(Layer, String)>> {
    let mut statement =
        c.prepare("SELECT ordinal,payload,digest FROM store_generation_layers ORDER BY ordinal")?;
    let mut query = statement.query([])?;
    let mut headers = Vec::new();
    while let Some(row) = query.next()? {
        if headers.len() >= MAX_GENERATIONS - 1 {
            return Err(StoreError::ResourceExhausted);
        }
        let ordinal: usize = row.get(0)?;
        let encoded: String = row.get(1)?;
        if encoded.len() > MAX_ROW_BYTES {
            return Err(StoreError::ResourceExhausted);
        }
        let header: Layer = serde_json::from_str(&encoded)?;
        let checksum: String = row.get(2)?;
        digest(&checksum)?;
        if ordinal != headers.len() + 1
            || header.ordinal != ordinal
            || serde_json::to_string(&header)? != encoded
        {
            return Err(StoreError::RecoveryRequired);
        }
        headers.push((header, checksum));
    }
    if headers.is_empty() {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(headers)
}
fn retained_bindings(
    c: &Connection,
    current: &GenerationBinding,
) -> Result<Vec<GenerationBinding>> {
    if !is_layered(c)? {
        return Ok(vec![current.clone()]);
    }
    let headers = load_headers(c)?;
    let mut bindings = vec![headers[0].0.parent_binding()?];
    for (header, _) in headers {
        bindings.push(header.binding()?);
    }
    Ok(bindings)
}
fn load_layer_rows(c: &Connection, header: &Layer) -> Result<Vec<CapturedRow>> {
    let mut statement=c.prepare("SELECT table_name,ordinal,payload FROM store_generation_layer_rows WHERE layer=?1 ORDER BY table_name,ordinal")?;
    let mut query = statement.query([header.ordinal as i64])?;
    let expected = snapshot_tables(header.ordinal > 1);
    let mut counts = expected
        .iter()
        .map(|table| (table.name.to_string(), 0usize))
        .collect::<Vec<_>>();
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    let mut rowids = BTreeSet::new();
    while let Some(record) = query.next()? {
        let name: String = record.get(0)?;
        let ordinal: usize = record.get(1)?;
        let payload: String = record.get(2)?;
        if payload.len() > MAX_ROW_BYTES {
            return Err(StoreError::ResourceExhausted);
        }
        let table = expected
            .iter()
            .find(|table| table.name == name)
            .ok_or(StoreError::RecoveryRequired)?;
        let count = &mut counts
            .iter_mut()
            .find(|(name, _)| name == table.name)
            .ok_or(StoreError::RecoveryRequired)?
            .1;
        if ordinal != *count {
            return Err(StoreError::RecoveryRequired);
        }
        *count += 1;
        crate::backup::validate_no_private_input_projections_json(&payload)?;
        let row: HistoricalRow = serde_json::from_str(&payload)?;
        validate_snapshot_row_without_private_input_projections(table.name, &row.cells)?;
        if row.cells.len() != table.columns.split(',').count()
            || serde_json::to_string(&row)? != payload
            || !rowids.insert((table.name, row.rowid))
        {
            return Err(StoreError::RecoveryRequired);
        }
        bytes = bytes
            .checked_add(payload.len())
            .ok_or(StoreError::ResourceExhausted)?;
        if bytes > MAX_LAYER_BYTES || rows.len() >= MAX_LAYER_ROWS {
            return Err(StoreError::ResourceExhausted);
        }
        rows.push(CapturedRow {
            table: table.name,
            ordinal,
            payload,
            row,
        });
    }
    if counts != header.tables || rows.len() != header.rows || bytes != header.bytes {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(rows)
}
fn restrictions(table: &str, cells: &[Value]) -> Result<Vec<(&'static str, String)>> {
    let text = |index: usize| {
        cells
            .get(index)
            .and_then(Value::as_str)
            .ok_or(StoreError::RecoveryRequired)
    };
    let mut result = Vec::new();
    match table {
        "records" => {
            let kind = text(0)?;
            let id = text(1)?;
            result.push(("record", format!("{kind}:{id}")));
            if kind == "agreement" {
                result.push(("agreement", id.into()));
            }
            let payload: Value = serde_json::from_str(text(3)?)?;
            let mut accounts = BTreeSet::new();
            let mut obligations = BTreeSet::new();
            collect_identity(&payload, "account_id", &mut accounts)?;
            collect_identity(&payload, "obligation_id", &mut obligations)?;
            if matches!(
                kind,
                crate::manual_enrollment::ENROLLMENT
                    | crate::manual_enrollment::SCOPE
                    | crate::manual_enrollment::EXCLUSION
                    | crate::manual_enrollment::PERMANENT_STOP_V1
                    | crate::manual_enrollment::CONTINUATION
                    | crate::manual_enrollment::INITIAL_PUBLICATION_V2
                    | crate::manual_enrollment::CONTINUATION_V3
                    | crate::manual_enrollment::ADDITIONAL_PUBLICATION_V3
                    | crate::manual_enrollment::CONTINUATION_V4
            ) {
                let record = StoredRecord {
                    id: id.into(),
                    revision: cells
                        .get(2)
                        .and_then(Value::as_u64)
                        .ok_or(StoreError::RecoveryRequired)?,
                    payload: payload.clone(),
                    created_at_ms: cells
                        .get(4)
                        .and_then(Value::as_i64)
                        .ok_or(StoreError::RecoveryRequired)?,
                    updated_at_ms: cells
                        .get(5)
                        .and_then(Value::as_i64)
                        .ok_or(StoreError::RecoveryRequired)?,
                };
                accounts.extend(crate::manual_enrollment::validate_recovery_record(
                    kind, &record,
                )?);
            }
            if kind == crate::manual_enrollment::PERMANENT_STOP_V1 {
                let audit: crate::manual_enrollment::ManualPermanentStopPublicationV1 =
                    strict_value(payload.clone())?;
                result.push(("operation", audit.exclusion.operation_id));
            }
            if kind == crate::manual_enrollment::CONTINUATION {
                let audit: crate::manual_enrollment::ManualEnrollmentContinuationAudit =
                    strict_value(payload.clone())?;
                result.push(("operation", audit.operation_id));
                result.push(("idempotency", audit.request_identity_digest));
            }
            if kind == crate::manual_enrollment::INITIAL_PUBLICATION_V2 {
                let audit: crate::manual_enrollment::ManualEnrollmentInitialPublicationV2 =
                    strict_value(payload.clone())?;
                result.push(("operation", audit.terms().operation_id.clone()));
                result.push(("operation", audit.operation_id));
                result.push(("idempotency", audit.request_identity_digest));
            }
            if kind == crate::manual_enrollment::CONTINUATION_V3 {
                let audit: crate::manual_enrollment::ManualEnrollmentContinuationAuditV3 =
                    strict_value(payload.clone())?;
                result.push(("operation", audit.operation_id));
                result.push(("idempotency", audit.request_identity_digest));
            }
            if kind == crate::manual_enrollment::ADDITIONAL_PUBLICATION_V3 {
                let audit: crate::manual_enrollment::ManualEnrollmentAdditionalPublicationV3 =
                    strict_value(payload.clone())?;
                result.push(("operation", audit.terms().operation_id.clone()));
                result.push(("operation", audit.operation_id));
                result.push(("idempotency", audit.request_identity_digest));
            }
            if kind == crate::manual_enrollment::CONTINUATION_V4 {
                let audit: crate::manual_enrollment::ManualEnrollmentContinuationAuditV4 =
                    strict_value(payload.clone())?;
                result.push(("operation", audit.operation_id));
                result.push(("idempotency", audit.request_identity_digest));
            }
            if kind == "automation_clock" {
                accounts.insert(id.into());
            }
            if kind == "settlement_applied" {
                obligations.insert(serde_json::from_value(payload)?);
            }
            result.extend(accounts.into_iter().map(|id| ("account", id)));
            result.extend(obligations.into_iter().map(|id| ("obligation", id)));
        }
        "operations" => result.push(("operation", text(0)?.into())),
        "idempotency" => result.push(("idempotency", replay_identity(text(0)?, text(1)?)?)),
        "effect_intents" => result.push(("effect", text(0)?.into())),
        "authority_accounts" => result.push(("account", text(0)?.into())),
        "authority_exposures" => {
            let release: ReleaseIntent = serde_json::from_str(text(8)?)?;
            crate::authority::validate_intent(&release)?;
            result.push(("account", release.account_id.clone()));
            result.push(("obligation", release.obligation_id.clone()));
            for input in &release.input_ids {
                result.push((
                    "input",
                    request_digest(&serde_json::json!([release.account_id, input]))?,
                ));
            }
        }
        "authority_reservations" => {
            result.push(("account", text(0)?.into()));
            result.push((
                "input",
                request_digest(&serde_json::json!([text(0)?, text(1)?]))?,
            ));
        }
        "events" | "authority_events" | "store_recovery" | "sqlite_sequence" => (),
        _ => return Err(StoreError::RecoveryRequired),
    }
    Ok(result)
}
fn add_row_restrictions(c: &Connection, table: &str, cells: &[Value]) -> Result<()> {
    for (kind, id) in restrictions(table, cells)? {
        fence(c, kind, &id, "inherited_layer_restriction")?;
    }
    Ok(())
}
fn verify_captured_row(c: &Connection, captured: &CapturedRow) -> Result<()> {
    let descriptor = table(captured.table)?;
    let current = read_rows(
        c,
        descriptor,
        &format!("WHERE rowid={}", captured.row.rowid),
    )?;
    if current.len() != 1 {
        return Err(StoreError::RecoveryRequired);
    }
    let current = &current[0].cells;
    let old = &captured.row.cells;
    let allowed: &[usize] = match captured.table {
        "authority_accounts" => &[2],
        "authority_exposures" => &[6, 10],
        "store_recovery" => &[1, 2, 3],
        "sqlite_sequence" => &[1],
        _ => &[],
    };
    if current.len() != old.len()
        || current
            .iter()
            .zip(old)
            .enumerate()
            .any(|(index, (a, b))| !allowed.contains(&index) && a != b)
    {
        return Err(StoreError::RecoveryRequired);
    }
    match captured.table {
        "authority_accounts" if current[2] != serde_json::json!(1) => {
            return Err(StoreError::RecoveryRequired);
        }
        "authority_exposures" => {
            let state = if old[6].as_str() == Some("consumed") {
                "consumed"
            } else {
                "outstanding_uncertain"
            };
            if current[6].as_str() != Some(state) {
                return Err(StoreError::RecoveryRequired);
            }
        }
        "sqlite_sequence"
            if current[1].as_i64().ok_or(StoreError::RecoveryRequired)?
                < old[1].as_i64().ok_or(StoreError::RecoveryRequired)? =>
        {
            return Err(StoreError::RecoveryRequired);
        }
        _ => (),
    }
    if BASE.iter().any(|table| table.name == captured.table) {
        for (kind, id) in restrictions(captured.table, old)? {
            require_fence(c, kind, &id)?;
        }
    }
    Ok(())
}

// Rebuild only an inert in-memory checksum view. It is never opened as a Store,
// contains no new marker and cannot produce any verified source capability.
// Previous layer payloads are retained once, selected by their original prefix.
fn verify_parent_commitment(c: &Connection, header: &Layer, rows: &[CapturedRow]) -> Result<()> {
    let template = if header.ordinal == 1 {
        coordination_successor_template_for_schema(header.parent_schema_version)
    } else {
        coordination_layered_successor_template_for_schema(header.parent_schema_version)
    }
    .map_err(|_| StoreError::RecoveryRequired)?;
    let support = construction_encoding_support(template.application_id, template.schema_version)?;
    require_construction_support(
        support,
        construction_encoding_supported_by_provenance(&header.parent_provenance)?,
    )?;
    let scratch = Connection::open_in_memory()?;
    scratch.execute_batch(
        "PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=OFF;",
    )?;
    scratch.execute_batch(template.create_sql)?;
    let triggers = {
        let mut query = scratch
            .prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")?;
        let collected = query
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        collected
    };
    for (name, _) in &triggers {
        scratch.execute_batch(&format!("DROP TRIGGER {name}"))?;
    }
    let mut tables = snapshot_tables(header.ordinal > 1);
    if header.ordinal > 1 {
        tables.extend([&LAYERS, &LAYER_ROWS]);
    }
    for table in &tables {
        scratch.execute(&format!("DELETE FROM {}", table.name), [])?;
    }
    for row in rows.iter().filter(|row| row.table != "sqlite_sequence") {
        insert_row(&scratch, table(row.table)?, &row.row)?;
    }
    if header.ordinal > 1 {
        for row in read_rows(c, &LAYERS, &format!("WHERE ordinal<{}", header.ordinal))? {
            insert_row(&scratch, &LAYERS, &row)?;
        }
        for row in read_rows(c, &LAYER_ROWS, &format!("WHERE layer<{}", header.ordinal))? {
            insert_row(&scratch, &LAYER_ROWS, &row)?;
        }
    }
    scratch.execute("DELETE FROM sqlite_sequence", [])?;
    for row in rows.iter().filter(|row| row.table == "sqlite_sequence") {
        insert_row(&scratch, table(row.table)?, &row.row)?;
    }
    for (_, sql) in triggers {
        scratch.execute_batch(&sql)?;
    }
    scratch.pragma_update(None, "application_id", template.application_id)?;
    scratch.pragma_update(None, "user_version", template.schema_version)?;
    crate::backup::validate_construction_encoding(&scratch, support.0, support.1, support.2)?;
    let (checksum, count) = coordination_owner_rows_commitment(&scratch, template)
        .map_err(|_| StoreError::RecoveryRequired)?;
    let state = crate::backup::read_recovery_state(&scratch)?;
    if !state.recovery_required
        || state.source_snapshot_digest.as_deref()
            != Some(&header.parent_provenance.component_digest)
    {
        return Err(StoreError::RecoveryRequired);
    }
    validate_continuity_batches(
        &scratch,
        &retained_bindings(&scratch, &header.parent_binding()?)?,
    )?;
    if checksum != header.source_provenance.component_digest
        || count != header.source_provenance.rows
        || current_identity(&scratch, &header.parent_binding()?)?
            != header.parent_destination_identity
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}

pub(super) fn validate_layered(
    c: &Connection,
    provenance: &RecoveryProvenance,
    binding: &GenerationBinding,
) -> Result<()> {
    // Runtime readers must always authenticate the actual exact version/form.
    let template = generation_template(c)?;
    validate_layered_for_template(c, provenance, binding, template)
}

// Private construction-time semantic check. Only the initializer's compiled
// target or the runtime selector above may supply this template. This does not
// create an opener, snapshot, marker, writer or financial admission capability.
fn validate_layered_for_template(
    c: &Connection,
    provenance: &RecoveryProvenance,
    binding: &GenerationBinding,
    template: &'static JournalTemplate,
) -> Result<()> {
    if template.kind != JournalKind::CoordinationAuthority
        || template.application_id != RECOVERED_GENERATION_APPLICATION_ID
        || !matches!(template.schema_version, 3 | 5 | 7 | 9)
    {
        return Err(StoreError::RecoveryRequired);
    }
    let support = construction_encoding_support(template.application_id, template.schema_version)?;
    require_construction_support(
        support,
        construction_encoding_supported_by_provenance(provenance)?,
    )?;
    crate::backup::validate_construction_encoding(c, support.0, support.1, support.2)?;
    let state = crate::backup::read_recovery_state(c)?;
    if !state.recovery_required
        || state.source_snapshot_digest.as_deref() != Some(&provenance.component_digest)
    {
        return Err(StoreError::RecoveryRequired);
    }
    let headers = load_headers(c)?;
    for (header, _) in &headers {
        require_construction_support(
            support,
            construction_encoding_support(
                RECOVERED_GENERATION_APPLICATION_ID,
                header.parent_schema_version,
            )?,
        )?;
    }
    let last = &headers.last().ok_or(StoreError::RecoveryRequired)?.0;
    if last.binding()? != *binding || last.source_provenance != *provenance {
        return Err(StoreError::RecoveryRequired);
    }
    let mut identities = BTreeSet::new();
    let mut bindings = Vec::new();
    let root = &headers[0].0;
    let root_binding = root.parent_binding()?;
    bindings.push(root_binding.clone());
    if !identities.insert(root_binding.generation_id().to_string()) {
        return Err(StoreError::RecoveryRequired);
    }
    let mut previous: Option<&(Layer, String)> = None;
    let mut count = 0usize;
    let mut bytes = 0usize;
    for pair in &headers {
        let (header, checksum) = pair;
        if header.version != 2
            || header.ordinal >= MAX_GENERATIONS
            || header.source_provenance.kind != JournalKind::CoordinationAuthority
            || header.source_provenance.application_id != RECOVERED_GENERATION_APPLICATION_ID
            || header.source_provenance.schema_version != header.parent_schema_version
            || !identities.insert(header.generation_id.clone())
        {
            return Err(StoreError::RecoveryRequired);
        }
        header.parent_binding()?;
        bindings.push(header.binding()?);
        digest(&header.source_provenance.component_digest)?;
        digest(&header.source_provenance.bundle_digest)?;
        digest(&header.parent_destination_identity)?;
        digest(&header.destination_identity)?;
        if current_identity(c, &header.binding()?)? != header.destination_identity {
            return Err(StoreError::RecoveryRequired);
        }
        match previous {
            Some((old, old_digest))
                if header.parent_binding()? == old.binding()?
                    && header.parent_provenance == old.source_provenance
                    && header.previous_layer_digest.as_ref() == Some(old_digest)
                    && require_construction_support(
                        construction_encoding_support(
                            RECOVERED_GENERATION_APPLICATION_ID,
                            header.parent_schema_version,
                        )?,
                        construction_encoding_support(
                            RECOVERED_GENERATION_APPLICATION_ID,
                            old.parent_schema_version,
                        )?,
                    )
                    .is_ok() => {}
            None if header.previous_layer_digest.is_none() => (),
            _ => return Err(StoreError::RecoveryRequired),
        }
        if current_identity(c, &header.parent_binding()?)? != header.parent_destination_identity {
            return Err(StoreError::RecoveryRequired);
        }
        let rows = load_layer_rows(c, header)?;
        if layer_digest(header, &rows)? != *checksum {
            return Err(StoreError::RecoveryRequired);
        }
        count = count
            .checked_add(rows.len())
            .ok_or(StoreError::ResourceExhausted)?;
        bytes = bytes
            .checked_add(header.bytes)
            .ok_or(StoreError::ResourceExhausted)?;
        if count > MAX_LAYER_ROWS || bytes > MAX_LAYER_BYTES {
            return Err(StoreError::ResourceExhausted);
        }
        verify_parent_commitment(c, header, &rows)?;
        for row in &rows {
            verify_captured_row(c, row)?;
        }
        previous = Some(pair);
    }
    let actual: usize = c.query_row(
        "SELECT count(*) FROM store_generation_layer_rows",
        [],
        |r| r.get(0),
    )?;
    let identity_count: usize = c.query_row(
        "SELECT count(*) FROM store_generation_identities",
        [],
        |r| r.get(0),
    )?;
    if actual != count || identity_count != bindings.len() {
        return Err(StoreError::RecoveryRequired);
    }
    let mut destination_ids = BTreeSet::new();
    for historical in &bindings {
        if !destination_ids.insert(current_identity(c, historical)?) {
            return Err(StoreError::RecoveryRequired);
        }
    }
    let original:String=c.query_row("SELECT payload FROM records WHERE aggregate_type='settlement_generation_identity' AND id='local'",[],|r|r.get(0))?;
    if serde_json::from_str::<String>(&original)? != root.parent_destination_identity {
        return Err(StoreError::RecoveryRequired);
    }
    validate_originals(c, &root.parent_provenance)?;
    validate_continuity_batches(c, &bindings)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod private_input_projection_tests;
