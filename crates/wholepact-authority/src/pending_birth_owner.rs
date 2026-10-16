//! Specific native worker composition. No public approval or raw policy factory.
use crate::native_witness_owner::NativeEnrollmentDecision;
use crate::{AuthorityJournal, Result};
pub(crate) fn commit_native(decision: NativeEnrollmentDecision) -> Result<()> {
    let mut reserved = crate::witness_locator::reserve_birth(decision)?;
    // Factory authenticates exact completed journal and durably records locator
    // completion before returning. This is no writer session or spending permit.
    let _journal = AuthorityJournal::create_pending_birth(&mut reserved)?;
    Ok(())
}
