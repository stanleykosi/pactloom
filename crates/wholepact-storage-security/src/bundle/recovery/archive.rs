//! Private row capture for sealed ordinary archive sources. This produces no
//! restored-source capability and cannot authorize a mutable journal.
use super::*;
use zeroize::{Zeroize, Zeroizing};

struct PrivateRow(Row);
impl Drop for PrivateRow {
    fn drop(&mut self) {
        for cell in &mut self.0.cells {
            match cell {
                Cell::Text(value) => value.zeroize(),
                Cell::Blob(value) => value.zeroize(),
                _ => {}
            }
        }
    }
}
impl PrivateRow {
    fn into_recovery(mut self) -> RecoveryRow {
        RecoveryRow {
            rowid: self.0.rowid,
            cells: self
                .0
                .cells
                .drain(..)
                .map(|cell| match cell {
                    Cell::Null => RecoveryCell::Null,
                    Cell::Integer(value) => RecoveryCell::Integer(value),
                    Cell::Real(value) => RecoveryCell::RealBits(value),
                    Cell::Text(value) => RecoveryCell::Text(value),
                    Cell::Blob(value) => RecoveryCell::Blob(value),
                })
                .collect(),
        }
    }
}

struct BoundedEncoding {
    bytes: Zeroizing<Vec<u8>>,
    remaining: usize,
}
impl std::io::Write for BoundedEncoding {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.len() > self.remaining {
            return Err(std::io::Error::other(
                "private archive row exceeds its bound",
            ));
        }
        self.remaining -= input.len();
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode_private(row: &Row, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = BoundedEncoding {
        bytes: Zeroizing::new(Vec::new()),
        remaining: maximum,
    };
    serde_json::to_writer(&mut output, row).map_err(|_| BundleError::Limit)?;
    Ok(output.bytes)
}

pub(crate) fn inspect_ordinary(
    connection: &Connection,
    template: &JournalTemplate,
) -> Result<(String, usize, Vec<RecoveryTable>)> {
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let schema = schema(connection)?;
    if application != template.application_id
        || version != template.schema_version
        || schema != template_schema(template)?
    {
        return Err(BundleError::Unsupported);
    }
    integrity(connection)?;
    let mut digest = Sha256::new();
    digest.update(b"wholepact.bundle.component.v1\0");
    digest.update(encode(&schema)?);
    let mut total_rows = 0usize;
    let mut total_bytes = 0usize;
    let mut tables = Vec::new();
    for object in schema.iter().filter(|object| object.kind == "table") {
        let mut table = table_manifest(connection, &object.name)?;
        let columns = table
            .columns
            .iter()
            .map(|column| quote(column))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let mut query = connection.prepare(&format!(
            "SELECT {}{} FROM {}",
            if table.rowid { "rowid," } else { "" },
            columns,
            quote(&table.name)?
        ))?;
        let mut rows = query.query([])?;
        let mut encoded = Vec::new();
        while let Some(row) = rows.next()? {
            total_rows = total_rows.checked_add(1).ok_or(BundleError::Limit)?;
            if total_rows > MAX_ROWS {
                return Err(BundleError::Limit);
            }
            let mut private = PrivateRow(Row {
                rowid: if table.rowid { Some(row.get(0)?) } else { None },
                cells: Vec::with_capacity(table.columns.len()),
            });
            for index in 0..table.columns.len() {
                private
                    .0
                    .cells
                    .push(match row.get_ref(index + usize::from(table.rowid))? {
                        ValueRef::Null => Cell::Null,
                        ValueRef::Integer(value) => Cell::Integer(value),
                        ValueRef::Real(value) if value.is_finite() => Cell::Real(value.to_bits()),
                        ValueRef::Real(_) => return Err(BundleError::Unsupported),
                        ValueRef::Text(value) => {
                            if value.len() > MAX_CELL {
                                return Err(BundleError::Limit);
                            }
                            Cell::Text(
                                std::str::from_utf8(value)
                                    .map_err(|_| BundleError::Integrity)?
                                    .into(),
                            )
                        }
                        ValueRef::Blob(value) => {
                            if value.len() > MAX_CELL {
                                return Err(BundleError::Limit);
                            }
                            Cell::Blob(value.to_vec())
                        }
                    });
            }
            let bytes = encode_private(&private.0, MAX_COMPONENT_BYTES - total_bytes)?;
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or(BundleError::Limit)?;
            if total_bytes > MAX_COMPONENT_BYTES {
                return Err(BundleError::Limit);
            }
            encoded.push(bytes);
        }
        encoded.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        table.rows = encoded.len();
        digest.update(encode(&table)?);
        let mut recovered = Vec::with_capacity(encoded.len());
        for bytes in encoded {
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes.as_slice());
            let row =
                PrivateRow(serde_json::from_slice(&bytes).map_err(|_| BundleError::Integrity)?);
            validate_row(&row.0, &table)?;
            recovered.push(row.into_recovery());
        }
        tables.push(RecoveryTable {
            name: table.name,
            columns: table.columns,
            rows: recovered,
            has_rowid: table.rowid,
        });
    }
    Ok((hex_digest(digest), total_rows, tables))
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEMPLATE: JournalTemplate = JournalTemplate {
        kind: JournalKind::ProofWitness,
        application_id: 1234,
        schema_version: 1,
        create_sql: "CREATE TABLE artifacts(id TEXT PRIMARY KEY, secret BLOB, value REAL);",
    };
    fn source() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(TEMPLATE.create_sql).unwrap();
        connection
            .pragma_update(None, "application_id", TEMPLATE.application_id)
            .unwrap();
        connection
            .pragma_update(None, "user_version", TEMPLATE.schema_version)
            .unwrap();
        connection
    }
    #[test]
    fn sealed_ordinary_rows_commit_hidden_rowids_and_exact_compiled_schema() {
        let first = source();
        first
            .execute(
                "INSERT INTO artifacts(rowid,id,secret,value) VALUES(7,'synthetic',?1,1.0)",
                [b"synthetic-private-archive-fixture".as_slice()],
            )
            .unwrap();
        let (digest, count, tables) = inspect_ordinary(&first, &TEMPLATE).unwrap();
        assert_eq!(count, 1);
        assert_eq!(tables[0].rows()[0].rowid(), Some(7));
        assert_eq!(inspect_ordinary(&first, &TEMPLATE).unwrap().0, digest);
        first.execute("UPDATE artifacts SET rowid=8", []).unwrap();
        assert_ne!(inspect_ordinary(&first, &TEMPLATE).unwrap().0, digest);
        first
            .execute_batch("CREATE TABLE omitted_private_rows(secret BLOB);")
            .unwrap();
        assert!(inspect_ordinary(&first, &TEMPLATE).is_err());
    }
    #[test]
    fn oversized_or_wrong_application_ordinary_sources_fail_closed() {
        let connection = source();
        connection
            .execute(
                "INSERT INTO artifacts(id,secret) VALUES('synthetic',zeroblob(?1))",
                [MAX_CELL + 1],
            )
            .unwrap();
        assert!(matches!(
            inspect_ordinary(&connection, &TEMPLATE),
            Err(BundleError::Limit)
        ));
        connection.execute("DELETE FROM artifacts", []).unwrap();
        connection
            .pragma_update(None, "application_id", TEMPLATE.application_id + 1)
            .unwrap();
        assert!(matches!(
            inspect_ordinary(&connection, &TEMPLATE),
            Err(BundleError::Unsupported)
        ));
    }
}
