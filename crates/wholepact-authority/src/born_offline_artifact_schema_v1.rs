//! Exact maintained transport tables, embedded only by native schema7 installation.
pub(crate) const INBOX_SCHEMA: &str =
    include_str!("../../wholepact-transport/src/inbox_schema_v3.sql");
pub(crate) const OUTBOX_SCHEMA: &str =
    include_str!("../../wholepact-transport/src/outbox_schema_v1.sql");
