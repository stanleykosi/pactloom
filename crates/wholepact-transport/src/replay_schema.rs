// Canonical immutable schema bytes shared by independent protected owners.
pub(crate) const INBOX_SCHEMAS: [(&str, i64); 2] = [
    (include_str!("inbox_schema_v2.sql"), 2),
    (include_str!("inbox_schema_v3.sql"), 3),
];
