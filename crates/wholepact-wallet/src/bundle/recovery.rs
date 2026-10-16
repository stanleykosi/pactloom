//! Reconstruct a separate wallet-scan successor from authenticated historical
//! rows. Reconstruction alone grants no synchronization or viewing-key authority.

use std::path::Path;
use wholepact_storage_security::{
    DatabaseKey,
    bundle::{BundleError, recovery::VerifiedRecoveryComponent},
};

/// Copy the complete authenticated wallet-scan inventory into a separately keyed
/// successor using only this executable's pinned maintained-library schema.
///
/// The profile recovery controller must hold its whole-profile recovery lease,
/// choose the deterministic successor path and independent key, and keep that
/// key private until final profile activation. This does not establish writer
/// freshness, activate the profile, grant sync/key-use authority, or modify the
/// quarantined source. An existing successor is accepted only if every schema
/// object and typed row still exactly matches the authenticated reconstruction.
pub fn reconstruct_wallet_scan_successor(
    source: &VerifiedRecoveryComponent,
    path: impl AsRef<Path>,
    key: &DatabaseKey,
) -> Result<(), BundleError> {
    wholepact_storage_security::bundle::recovery::wallet::reconstruct_wallet_scan_successor(
        source,
        trusted_template_for_recovery_component(source)?,
        path,
        key,
    )
}

/// Retain complete authenticated original rows in an independently keyed,
/// generation-bound evidence file. This never activates a restored journal,
/// reruns work, renews consent, or establishes current settlement.
pub fn reconstruct_wallet_scan_successor_evidence(
    source: &wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent,
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
) -> Result<(), wholepact_storage_security::bundle::BundleError> {
    wholepact_storage_security::bundle::recovery::evidence::reconstruct_wallet_scan_evidence(
        source,
        trusted_template_for_recovery_component(source)?,
        path,
        key,
        binding,
    )
}

/// Authenticate immutable evidence under this journal's compiled schema.
/// Private artifact access remains subject to the caller's native disclosure
/// boundary. Returned historical rows cannot be converted into a live journal.
pub fn open_wallet_scan_successor_evidence(
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
) -> Result<
    wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
    wholepact_storage_security::bundle::BundleError,
> {
    let path = path.as_ref();
    let selected =
        wholepact_storage_security::bundle::recovery::wallet_templates::for_evidence_file(
            path,
            key,
            super::trusted_wallet_templates()?,
        )?;
    wholepact_storage_security::bundle::recovery::evidence::open_wallet_scan_evidence(
        path, key, binding, expected, selected,
    )
}

/// Select from the entire authenticated component schema and table descriptors.
/// This preserves any malformed, pending or completed import-record bytes as
/// history; it neither decodes those records nor grants import/reopen authority.
pub fn trusted_template_for_recovery_component(
    source: &VerifiedRecoveryComponent,
) -> Result<&'static wholepact_storage_security::bundle::JournalTemplate, BundleError> {
    wholepact_storage_security::bundle::recovery::wallet_templates::for_recovery_component(
        source,
        super::trusted_wallet_templates()?,
    )
}

/// Select the fixed template from the authenticated archive, then revalidate
/// BOTH archive and quarantined source through the existing sealed reader. The
/// caller must retain its recovery locks and source quiescence throughout.
pub fn open_verified_wallet_scan_component(
    request: wholepact_storage_security::bundle::history::HistoryOpenRequest<'_>,
) -> Result<VerifiedRecoveryComponent, BundleError> {
    let template = super::trusted_template_for_bundle_component(
        request.archive,
        request.archive_key,
        request.component_id,
    )?;
    VerifiedRecoveryComponent::open(request, template)
}

/// Read ordinary wallet history from a verified capsule, retaining its sealed
/// lineage. The archived original path is never opened or used for selection.
pub fn inspect_archived_wallet_scan_history(
    source: &wholepact_storage_security::generation_archive::ArchivedJournal<'_>,
    key: &DatabaseKey,
) -> Result<
    wholepact_storage_security::generation_archive::ArchivedOrdinarySource,
    wholepact_storage_security::generation_archive::ArchiveError,
> {
    source.inspect_wallet_ordinary_with_templates(key, super::trusted_wallet_templates()?)
}

/// Authenticate archived immutable wallet evidence against its sealed original
/// destination after full schema selection. No caller kind/version hint chooses
/// the schema; existing evidence validation rechecks marker, descriptors and rows.
pub fn open_archived_wallet_scan_successor_evidence(
    source: &wholepact_storage_security::generation_archive::ArchivedJournal<'_>,
    key: &DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
) -> Result<
    wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
    wholepact_storage_security::generation_archive::ArchiveError,
> {
    source.open_wallet_evidence_with_templates(
        key,
        binding,
        expected,
        super::trusted_wallet_templates()?,
    )
}
