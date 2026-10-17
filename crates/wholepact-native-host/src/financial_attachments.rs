//! Private actual-owner native attachment boundary. The parent module keeps
//! registry mutation private. Inert records, paths and review digests cannot
//! construct approval: every create/open and durable pending/commit effect here
//! is admitted by the existing exact foreground PublicationApproval.
use super::*;
use crate::financial_profile::RecordableImportKind;
use crate::{
    financial_profile::{ConstructionWallet, FinancialProfile},
    terminal::PublicationApproval,
};
use wholepact_core::manual_construction::ManualConstructionAttachmentBinding;

pub(crate) struct PreparedAttachment<'a> {
    host: &'a Directory,
    secrets: &'a Secrets,
    primary: &'a FinancialProfile,
    request: PendingAttachment,
    original_primary_origin: String,
    expected_registry_digest: String,
    review_digest: String,
    detail: String,
}
/// Actual just-created empty profile, unavailable from reopen, retry or JSON.
/// A crash loses this process-local import provenance; reopening does not revive it.
pub(crate) struct FreshFinancialProfile(FinancialProfile);
impl FreshFinancialProfile {
    pub(crate) fn profile(&self) -> &FinancialProfile {
        &self.0
    }
    pub(crate) fn into_profile(self) -> FinancialProfile {
        self.0
    }
}
/// Exact newly-created V2 roster import owner; never issued by ordinary open.
pub(crate) struct FreshRosterFinancialProfileV2(FinancialProfile);
impl FreshRosterFinancialProfileV2 {
    pub(crate) fn profile(&self) -> &FinancialProfile {
        &self.0
    }
    pub(crate) fn into_profile(self) -> FinancialProfile {
        self.0
    }
}
fn registry_digest(registry: &Registry) -> Result<String> {
    match registry {
        Registry::V1(inventory) => digest("wholepact:native-financial-registry:v1", inventory),
        Registry::V2(inventory) => inventory.current_digest(),
    }
}
fn v2_from(
    registry: Registry,
    original_primary_origin: &str,
    secrets: &Secrets,
) -> Result<InventoryV2> {
    match registry {
        Registry::V1(registry) => {
            if registry.entries.len() != 1
                || registry.entries[0].role != AttachmentRole::PrimaryFinancial
                || registry.entries[0].account.is_some()
            {
                return Err(Error::RecoveryFinancialUnsupported);
            }
            Ok(InventoryV2 {
                version: 2,
                owner: secrets.profile(),
                original_primary: OriginalPrimary {
                    registry,
                    journal_origin_digest: original_primary_origin.into(),
                },
                extensions: Vec::new(),
            })
        }
        Registry::V2(inventory) => {
            if inventory.original_primary.journal_origin_digest != original_primary_origin {
                return Err(Error::Authentication);
            }
            Ok(inventory)
        }
    }
}
fn target_check(
    host: &Directory,
    primary: &FinancialProfile,
    request: &PendingAttachment,
) -> Result<()> {
    request.validate()?;
    host.external_destination(&request.directory)?;
    primary.directory.external_destination(&request.directory)?;
    let host_root = host.path("profile.vault")?;
    if host_root
        .parent()
        .ok_or(Error::Invalid)?
        .starts_with(&request.directory)
        || primary.current_directory()?.starts_with(&request.directory)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
impl<'a> PreparedAttachment<'a> {
    /// Values describe the exact proposed operation; they supply no authority.
    /// The original primary and registry are independently read from held owners.
    pub(crate) fn prepare(
        host: &'a Directory,
        secrets: &'a Secrets,
        primary: &'a FinancialProfile,
        operation_digest: &str,
        account_id: &str,
        path: &Path,
        mode: AttachmentOpenMode,
    ) -> Result<Self> {
        let request = PendingAttachment {
            operation_digest: operation_digest.into(),
            account_id: account_id.into(),
            directory: path.to_owned(),
            mode,
        };
        target_check(host, primary, &request)?;
        let original_primary_origin =
            primary.manual_original_primary_origin_digest(host, secrets)?;
        let registry = load(host, secrets)?;
        let expected_registry_digest = registry_digest(&registry)?;
        let mut preview = v2_from(registry, &original_primary_origin, secrets)?;
        let existing = preview.pending(&request)?;
        if existing.is_some() {
            // An interrupted creation is never absence-as-empty initialization.
            // Retained pending entries can only retry opening existing storage.
            if !request.directory.try_exists()? {
                return Err(Error::Invalid);
            }
        } else {
            match request.mode {
                AttachmentOpenMode::Create if request.directory.try_exists()? => {
                    return Err(Error::Invalid);
                }
                AttachmentOpenMode::Open if !request.directory.try_exists()? => {
                    return Err(Error::Invalid);
                }
                _ => (),
            }
        }
        let review_digest = digest(
            "wholepact:native-financial-attachment-review:v2",
            &(
                secrets.profile(),
                host.manual_target_identity_digest()?,
                &original_primary_origin,
                &expected_registry_digest,
                &request,
                existing.as_ref().map(|(_, id)| id),
            ),
        )?;
        if existing.is_none() {
            // Check every logical and byte capacity bound before asking for native
            // approval or writing even a pending record.
            preview.append(
                Extension::Pending {
                    request: request.clone(),
                },
                &review_digest,
                secrets,
            )?;
        }
        let detail = format!(
            "Attach exact independently encrypted participant journals to this host.\nProfile: {}\nAccount: {}\nDirectory: {}\nOperation: {}\nAction: {}\nOriginal primary journal origin: {}\nCurrent registry: {}\nExact native review: {}\nThe complete backup will permanently require this dependency, including after a failed create/open. Missing or partial storage is never initialized on retry. This does not establish account/FVK ownership, authorize financial use, sign, prove, submit, or clear any historical exposure.",
            secrets.profile(),
            account_id,
            path.display(),
            operation_digest,
            if existing.is_some() {
                "Reopen the exact already retained dependency"
            } else {
                match mode {
                    AttachmentOpenMode::Create => {
                        "Create new storage after retaining the pending dependency"
                    }
                    AttachmentOpenMode::Open => {
                        "Open existing storage after retaining the pending dependency"
                    }
                }
            },
            original_primary_origin,
            expected_registry_digest,
            review_digest,
        );
        Ok(Self {
            host,
            secrets,
            primary,
            request,
            original_primary_origin,
            expected_registry_digest,
            review_digest,
            detail,
        })
    }
    pub(crate) fn review_digest(&self) -> &str {
        &self.review_digest
    }
    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
    fn check_current(&self) -> Result<InventoryV2> {
        target_check(self.host, self.primary, &self.request)?;
        if self
            .primary
            .manual_original_primary_origin_digest(self.host, self.secrets)?
            != self.original_primary_origin
        {
            return Err(Error::Authentication);
        }
        let registry = load(self.host, self.secrets)?;
        if registry_digest(&registry)? != self.expected_registry_digest {
            return Err(Error::Authentication);
        }
        v2_from(registry, &self.original_primary_origin, self.secrets)
    }
    pub(crate) fn open_fresh(
        self,
        approval: PublicationApproval,
        password: &[u8],
    ) -> Result<FreshFinancialProfile> {
        // This additional restriction is checked again by open's exact registry
        // predecessor validation under the native effect. Pending retries never
        // qualify, including an earlier incomplete Create for the same path.
        let inventory = self.check_current()?;
        if self.request.mode != AttachmentOpenMode::Create
            || inventory.pending(&self.request)?.is_some()
            || self.request.directory.try_exists()?
        {
            return Err(Error::Permission);
        }
        self.open_layout(approval, password, RecordableImportKind::V1)
            .map(FreshFinancialProfile)
    }
    pub(crate) fn open_fresh_roster_v2(
        self,
        approval: PublicationApproval,
        password: &[u8],
    ) -> Result<FreshRosterFinancialProfileV2> {
        let inventory = self.check_current()?;
        if self.request.mode != AttachmentOpenMode::Create
            || inventory.pending(&self.request)?.is_some()
            || self.request.directory.try_exists()?
        {
            return Err(Error::Permission);
        }
        self.open_layout(approval, password, RecordableImportKind::RosterV2)
            .map(FreshRosterFinancialProfileV2)
    }
    pub(crate) fn open_fresh_roster_exact_input_v1(
        self,
        approval: PublicationApproval,
        password: &[u8],
    ) -> Result<FreshRosterFinancialProfileV2> {
        let inventory = self.check_current()?;
        if self.request.mode != AttachmentOpenMode::Create
            || inventory.pending(&self.request)?.is_some()
            || self.request.directory.try_exists()?
        {
            return Err(Error::Permission);
        }
        self.open_layout(approval, password, RecordableImportKind::RosterExactInputV1)
            .map(FreshRosterFinancialProfileV2)
    }
    /// One native decision admits the fixed bounded local attachment effect.
    /// There is no caller effect callback, trait authority or approved boolean.
    /// The decision is consumed even on error; all durable partial output stays.
    pub(crate) fn open(
        self,
        approval: PublicationApproval,
        password: &[u8],
    ) -> Result<FinancialProfile> {
        self.open_layout(approval, password, RecordableImportKind::None)
    }
    fn open_layout(
        self,
        approval: PublicationApproval,
        password: &[u8],
        recorded_import: RecordableImportKind,
    ) -> Result<FinancialProfile> {
        approval.commit(
            &self.review_digest,
            || self.check_current(),
            |mut inventory| {
                let existing = inventory.pending(&self.request)?;
                let pending_digest = if let Some((_, id)) = &existing {
                    id.clone()
                } else {
                    inventory.append(
                        Extension::Pending {
                            request: self.request.clone(),
                        },
                        &self.review_digest,
                        self.secrets,
                    )?;
                    // This write precedes every target create/open, and is never
                    // rolled back or removed after failure or uncertain completion.
                    write_v2(self.host, self.secrets, &inventory)?;
                    inventory.latest_digest()?
                };
                let profile = if existing.is_none()
                    && self.request.mode == AttachmentOpenMode::Create
                {
                    if recorded_import != RecordableImportKind::None {
                        match recorded_import {
                            RecordableImportKind::V1 => FinancialProfile::create_recordable_import(
                                &self.request.directory,
                                &self.secrets.profile(),
                                password,
                            )?,
                            RecordableImportKind::RosterV2 => {
                                FinancialProfile::create_recordable_roster_import_v2(
                                    &self.request.directory,
                                    &self.secrets.profile(),
                                    password,
                                )?
                            }
                            RecordableImportKind::RosterExactInputV1 => {
                                FinancialProfile::create_recordable_roster_exact_input_v1(
                                    &self.request.directory,
                                    &self.secrets.profile(),
                                    password,
                                )?
                            }
                            RecordableImportKind::None => return Err(Error::Permission),
                        }
                    } else {
                        FinancialProfile::create(
                            &self.request.directory,
                            &self.secrets.profile(),
                            password,
                        )?
                    }
                } else {
                    // Reopen/retry can never reissue the original import owner.
                    if recorded_import != RecordableImportKind::None {
                        return Err(Error::Permission);
                    }
                    FinancialProfile::open(
                        &self.request.directory,
                        &self.secrets.profile(),
                        password,
                    )?
                };
                let actual = profile.manual_attachment_descriptor(
                    &self.secrets.profile(),
                    &self.request.account_id,
                )?;
                // Reauthenticate the persisted predecessor and retained original
                // primary after journal constructors. No stale clone may overwrite
                // an intervening pending/committed registry or changed source tree.
                if self
                    .primary
                    .manual_original_primary_origin_digest(self.host, self.secrets)?
                    != self.original_primary_origin
                {
                    return Err(Error::Authentication);
                }
                match load(self.host, self.secrets)? {
                    Registry::V2(current) if current == inventory => (),
                    _ => return Err(Error::Authentication),
                }
                if let Some(expected) = inventory.committed(&pending_digest) {
                    // Exact retry/reopen is read-only and cannot rebind a replacement.
                    if expected != &actual {
                        return Err(Error::Authentication);
                    }
                    return Ok(profile);
                }
                inventory.append(
                    Extension::Committed {
                        pending_extension_digest: pending_digest,
                        actual,
                    },
                    &self.review_digest,
                    self.secrets,
                )?;
                write_v2(self.host, self.secrets, &inventory)?;
                // A post-commit error leaves its committed extension retained.
                profile.check_retained_owner(&self.secrets.profile())?;
                match load(self.host, self.secrets)? {
                    Registry::V2(current) if current == inventory => Ok(profile),
                    _ => Err(Error::Authentication),
                }
            },
        )
    }
}
fn binding_for_actual(
    host: &Directory,
    secrets: &Secrets,
    primary: &FinancialProfile,
    actual: ManualParticipantAttachment,
) -> Result<ManualConstructionAttachmentBinding> {
    let original_primary_journal_origin_digest =
        primary.manual_original_primary_origin_digest(host, secrets)?;
    let inventory = match load(host, secrets)? {
        Registry::V2(value) => value,
        _ => return Err(Error::RecoveryFinancialUnsupported),
    };
    let (record, _) = inventory
        .extensions
        .iter()
        .find_map(|record| match &record.extension {
            Extension::Pending { request }
                if request.account_id == actual.account_id
                    && request.directory == Path::new(&actual.canonical_directory) =>
            {
                Some((record, request))
            }
            _ => None,
        })
        .ok_or(Error::Authentication)?;
    if inventory.committed(&record.digest()?) != Some(&actual) {
        return Err(Error::Authentication);
    }
    let result = ManualConstructionAttachmentBinding {
        version: 1,
        original_primary_journal_origin_digest,
        predecessor_registry_digest: inventory.predecessor_digest()?.into(),
        current_registry_digest: inventory.current_digest()?,
        latest_extension_digest: inventory.latest_digest()?,
        selected: actual,
    };
    result.validate().map_err(|_| Error::Invalid)?;
    Ok(result)
}
pub(crate) fn binding_for_profile(
    host: &Directory,
    secrets: &Secrets,
    primary: &FinancialProfile,
    profile: &FinancialProfile,
    account_id: &str,
) -> Result<ManualConstructionAttachmentBinding> {
    binding_for_actual(
        host,
        secrets,
        primary,
        profile.manual_attachment_descriptor(&secrets.profile(), account_id)?,
    )
}
pub(crate) fn binding_for_wallet(
    host: &Directory,
    secrets: &Secrets,
    primary: &FinancialProfile,
    wallet: &ConstructionWallet,
    account_id: &str,
) -> Result<ManualConstructionAttachmentBinding> {
    binding_for_actual(
        host,
        secrets,
        primary,
        wallet.manual_attachment_descriptor(&secrets.profile(), account_id)?,
    )
}

#[cfg(test)]
#[path = "financial_attachments/tests.rs"]
mod tests;

/// Retained-stage provenance ONLY. A later independently approved attachment
/// may append to the registry, but the exact original prefix and selected held
/// wallet descriptor must still exist. This does not renew selection or import.
pub(crate) fn require_retained_wallet_binding(
    host: &Directory,
    secrets: &Secrets,
    primary: &FinancialProfile,
    wallet: &ConstructionWallet,
    expected: &ManualConstructionAttachmentBinding,
) -> Result<()> {
    expected.validate().map_err(|_| Error::Invalid)?;
    let actual =
        wallet.manual_attachment_descriptor(&secrets.profile(), &expected.selected.account_id)?;
    if actual != expected.selected
        || primary.manual_original_primary_origin_digest(host, secrets)?
            != expected.original_primary_journal_origin_digest
    {
        return Err(Error::Authentication);
    }
    let inventory = match load(host, secrets)? {
        Registry::V2(value) => value,
        _ => return Err(Error::RecoveryFinancialUnsupported),
    };
    require_retained_registry_prefix(&inventory, secrets, expected, &actual)
}
/// Same original-prefix check through a borrowed original provenance owner;
/// performs no reentrant access to the mutable maintained wallet database.
pub(crate) fn require_retained_wallet_provenance_binding(
    host: &Directory,
    secrets: &Secrets,
    primary: &FinancialProfile,
    wallet: &crate::financial_profile::ConstructionWalletProvenance<'_>,
    expected: &ManualConstructionAttachmentBinding,
) -> Result<()> {
    expected.validate().map_err(|_| Error::Invalid)?;
    let actual =
        wallet.manual_attachment_descriptor(&secrets.profile(), &expected.selected.account_id)?;
    if actual != expected.selected
        || primary.manual_original_primary_origin_digest(host, secrets)?
            != expected.original_primary_journal_origin_digest
    {
        return Err(Error::Authentication);
    }
    let inventory = match load(host, secrets)? {
        Registry::V2(value) => value,
        _ => return Err(Error::RecoveryFinancialUnsupported),
    };
    require_retained_registry_prefix(&inventory, secrets, expected, &actual)
}
fn require_retained_registry_prefix(
    inventory: &InventoryV2,
    secrets: &Secrets,
    expected: &ManualConstructionAttachmentBinding,
    actual: &ManualParticipantAttachment,
) -> Result<()> {
    // Validate the COMPLETE authenticated current append-only chain first.
    inventory.validate(secrets)?;
    if actual != &expected.selected
        || inventory.original_primary.journal_origin_digest
            != expected.original_primary_journal_origin_digest
    {
        return Err(Error::Authentication);
    }
    let length = inventory
        .extensions
        .iter()
        .enumerate()
        .find_map(|(index, record)| {
            (record.digest().ok().as_deref() == Some(expected.latest_extension_digest.as_str()))
                .then_some(index + 1)
        })
        .ok_or(Error::Authentication)?;
    let mut prefix = inventory.clone();
    prefix.extensions.truncate(length);
    prefix.validate(secrets)?;
    if prefix.current_digest()? != expected.current_registry_digest
        || prefix.predecessor_digest()? != expected.predecessor_registry_digest
    {
        return Err(Error::Authentication);
    }
    let pending = prefix
        .extensions
        .iter()
        .find(|record| {
            matches!(&record.extension,
                Extension::Pending { request }
                    if request.account_id == actual.account_id
                        && request.directory == Path::new(&actual.canonical_directory)
            )
        })
        .ok_or(Error::Authentication)?;
    if prefix.committed(&pending.digest()?) != Some(actual)
        || inventory.committed(&pending.digest()?) != Some(actual)
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// Read-only validation for a purpose-distinct post-return reopened owner. It
/// validates the whole current registry and exact original committed prefix;
/// this cannot append a dependency, renew import, or grant construction.
pub(crate) fn require_born_post_return_wallet_binding_v1(
    host: &Directory,
    secrets: &Secrets,
    primary: &FinancialProfile,
    wallet: &crate::financial_profile::born_post_return_v1::BornPostReturnWalletProvenanceV1,
    expected: &ManualConstructionAttachmentBinding,
) -> Result<()> {
    expected.validate().map_err(|_| Error::Invalid)?;
    let actual = wallet.descriptor(&secrets.profile(), &expected.selected.account_id)?;
    if actual != expected.selected
        || primary.manual_original_primary_origin_digest(host, secrets)?
            != expected.original_primary_journal_origin_digest
    { return Err(Error::Authentication); }
    let inventory = match load(host, secrets)? {
        Registry::V2(value) => value,
        _ => return Err(Error::RecoveryFinancialUnsupported),
    };
    require_retained_registry_prefix(&inventory, secrets, expected, &actual)
}
