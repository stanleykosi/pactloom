//! Explicit quarantined historical read; no mutable Store or private-record escape.
use crate::{
    authority::{Fence, Held},
    files::Directory,
    now,
    terminal::Terminal,
    vault::{Secrets, JOURNALS},
    Error, Result,
};
use std::{path::Path, sync::Arc};
use wholepact_storage_security::bundle::{self, BundleError};
use wholepact_store::history::*;
struct Consent {
    source: HistoryBinding,
    profile: String,
    digest: String,
    agreement: String,
    terminal: Terminal,
    fence: Arc<Fence>,
}
struct Lease(Held);
impl HistoryLease for Lease {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        self.0.check().map_err(|_| BundleError::Permission)
    }
}
impl HistoryAuthority for Consent {
    fn acquire<'a>(
        &'a self,
        s: &HistoryScope<'_>,
    ) -> std::result::Result<Box<dyn HistoryLease + 'a>, BundleError> {
        if s.source != &self.source
            || s.principal_id != "native-history-reader"
            || s.profile_id != self.profile
            || s.component_id != "coordination"
            || s.bundle_digest != self.digest
            || s.agreement_id != self.agreement
        {
            return Err(BundleError::Permission);
        }
        let expires = now()
            .map_err(|_| BundleError::Permission)?
            .saturating_add(120);
        let held = self
            .fence
            .acquire(expires)
            .map_err(|_| BundleError::Permission)?;
        self.terminal.confirm(&format!("Read quarantined historical metadata. This cannot establish current chain state, account exposure, wallet ownership or writer authority.\nProfile: {}\nPrincipal: {}\nComponent: {}\nAuthenticated bundle digest: {}\nAgreement: {}\nAction: {:?}\nExpires Unix: {expires}",s.profile_id,s.principal_id,s.component_id,s.bundle_digest,s.agreement_id,s.action)).map_err(|_|BundleError::Permission)?;
        held.check().map_err(|_| BundleError::Permission)?;
        Ok(Box::new(Lease(held)))
    }
}
pub(crate) fn read(terminal: Terminal, profile: &Path, backup: &Path) -> Result<()> {
    let dir = Directory::open(profile)?;
    dir.inventory()?;
    if !profile.join("restored.quarantine").exists() {
        return Err(Error::Invalid);
    }
    let p = terminal.secret("Restored profile passphrase: ")?;
    let secrets = Secrets::open(&dir.read("profile.vault", 1024)?, p.as_bytes())?;
    drop(p);
    let original = Directory::open(backup)?;
    let p = terminal.secret("Original backup recovery passphrase: ")?;
    let (original_secrets, backup_key) =
        Secrets::open_recovery(&original.read("recovery.wp", 1024)?, p.as_bytes())?;
    drop(p);
    if secrets.profile() != original_secrets.profile() {
        return Err(Error::Authentication);
    }
    let archive = original.path("bundle.sqlite")?;
    let manifest = bundle::inspect(&archive, &backup_key)?;
    let history = open_quarantined_history(HistoryOpenRequest {
        archive: &archive,
        archive_key: &backup_key,
        component_id: "coordination",
        restored_component: &dir.path(JOURNALS[0])?,
        restored_key: &secrets.key(0)?,
    })?;
    let agreement = terminal.ask("Exact historical agreement ID: ")?.to_string();
    crate::id(&agreement)?;
    let gate = Consent {
        source: history.binding(),
        profile: secrets.profile(),
        digest: manifest.digest,
        agreement: agreement.clone(),
        terminal: terminal.clone(),
        fence: Arc::new(Fence::default()),
    };
    let handoff = gate.fence.acquire(now()?.saturating_add(300))?;
    terminal.json(&history.agreement("native-history-reader", &agreement, &gate)?)?;
    let events = history.events("native-history-reader", &agreement, 0, 100, &gate)?;
    handoff.check()?;
    terminal.json(&events)?;
    terminal.message("Historical read only. New authorization, mutable journal recovery and private participant-record history remain unavailable.\n")
}
