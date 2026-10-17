//! Key-free foreground retirement and genuine fresh named-payment entry.
//! Old owners are revoked and drained, never extended or transferred.
use super::*;
use std::os::unix::fs::PermissionsExt;
use crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::{
    ConsumedBornNamedSourceV1, DormantConsumedBornNamedSourceV1,
};

struct Drain {
    thread: JoinHandle<()>,
    receive: mpsc::Receiver<Result<DormantConsumedBornNamedSourceV1>>,
}
#[derive(Default)]
pub(super) struct State {
    dormant: Option<DormantConsumedBornNamedSourceV1>,
    drain: Option<Drain>,
    pub(super) source: Option<ConsumedBornNamedSourceV1>,
}
pub(super) struct OpenedNamed {
    source: ConsumedBornNamedSourceV1,
    endpoint: CompletionOpened,
}
impl State {
    pub(super) fn draining(&self) -> bool {
        self.drain.is_some()
    }
    pub(super) fn clear(&mut self) -> Option<JoinHandle<()>> {
        self.dormant = None;
        // The parent moves any decrypted source into its off-GUI retired
        // bundle after immediately revoking admission. Never drop it here.
        self.drain.take().map(|drain| drain.thread)
    }
    pub(super) fn poll(&mut self) -> Result<()> {
        if self
            .drain
            .as_ref()
            .is_some_and(|drain| drain.thread.is_finished())
        {
            let drain = self.drain.take().ok_or(Error::Locked)?;
            drain.thread.join().map_err(|_| Error::Uncertain)?;
            let dormant = drain.receive.try_recv().map_err(|_| Error::Uncertain)??;
            self.dormant = Some(dormant);
        }
        Ok(())
    }
}
pub(super) fn open(
    dormant: DormantConsumedBornNamedSourceV1,
    path: &Path,
    password: &[u8],
    owner: &PendingAccountNativeAuthority,
) -> Result<OpenedNamed> {
    let source = dormant.unlock(path, password, owner)?;
    let temporary = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let ipc = LocalIpc::bind(crate::files::PrivateDirectory::open(temporary.path())?)?;
    owner.publish_pending_endpoint(ipc.socket_path())?;
    source.check(owner)?;
    Ok(OpenedNamed {
        source,
        endpoint: CompletionOpened {
            source: None,
            revocation: ipc.revocation(),
            ipc: Arc::new(Mutex::new(ipc)),
            _temporary: temporary,
            queued: None,
        },
    })
}
impl BornManualRosterUiV2 {
    pub(in crate::native_ui) fn has_dormant_named(&self) -> bool {
        self.named_reentry.dormant.is_some()
    }
    pub(in crate::native_ui) fn begin_named(
        &mut self,
        entry: PendingBirthEntry,
        path: &Path,
        password: &str,
    ) -> Result<()> {
        if self.is_active() {
            return Err(Error::Locked);
        }
        // Consume the actual key-free slot before native entry, KDF, endpoint
        // publication or credential selection. Errors cannot recycle the token.
        let dormant = self
            .named_reentry
            .dormant
            .take()
            .ok_or(Error::ReviewMismatch)?;
        if !path.is_absolute() || path != dormant.path() || !(12..=1024).contains(&password.len()) {
            return Err(Error::ReviewMismatch);
        }
        let owner = Arc::new(PendingAccountNativeAuthority::enter_consumed_born_named(
            entry, &dormant,
        )?);
        self.job = Some(Job::start(
            Work::OpenNamed(
                Box::new(dormant),
                path.to_path_buf(),
                Zeroizing::new(password.into()),
            ),
            owner.clone(),
        )?);
        self.owner = Some(owner);
        self.message = "Fresh exact named-payment unlock. Original consumed construction and all financial deadlines remain unchanged. Existing original-owner credential contact and same-Host pairing require separate native reviews.";
        Ok(())
    }
    pub(super) fn park_named(&mut self) -> Result<()> {
        if self.job.is_some()
            || self.review.is_some()
            || self.named_controls.active()
            || self.named_reentry.draining()
        {
            return Err(Error::Locked);
        }
        let actual = self.named_continuation.take().ok_or(Error::Locked)?;
        // Close native/key admission before any potentially blocking drain.
        self.revoke_foreground_now();
        self.retire_foreground();
        let cleanup = std::mem::take(&mut self.cleanup);
        let (send, receive) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("wholepact-born-named-key-free-drain".into())
            .spawn(move || {
                let result = (|| {
                    for thread in cleanup {
                        thread.join().map_err(|_| Error::Uncertain)?;
                    }
                    // This consumes and drops signer/client/session owners BEFORE
                    // the backend demands unique vault/journal ownership.
                    actual.into_dormant()
                })();
                let _ = send.send(result);
            })?;
        self.named_reentry.drain = Some(Drain { thread, receive });
        self.message = "Original native owner revoked. Waiting for exact admitted work to drain before retaining only a key-free, unchanged-source reentry token. No new financial authority was created.";
        Ok(())
    }
    pub(super) fn accept_named_reentry_open(&mut self, opened: OpenedNamed) -> Result<()> {
        if self.completion_opened.is_some()
            || self.named_continuation.is_some()
            || self.named_reentry.source.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        self.completion_opened = Some(opened.endpoint);
        self.named_reentry.source = Some(opened.source);
        self.message = "Exact consumed source reopened with a new native owner. Select only the original owner credentials; the old general writer transport remains permanently fenced.";
        Ok(())
    }
    // Shared finite event path: production button and synthetic controller both
    // stage the same existing original-owner review, never issue an approval.
    pub(super) fn prepare_named_original_owner_contact(&mut self, epoch: u64) -> Result<()> {
        self.owner(epoch)?;
        if self.job.is_some() || self.review.is_some() || self.named_controls.active() {
            return Err(Error::Locked);
        }
        let source = self.named_reentry.source.take().ok_or(Error::Locked)?;
        let setup = Zeroizing::new(self.witness_setup.to_string());
        self.witness_setup.zeroize();
        self.start(Work::PrepareNamedWitness(Box::new(source), setup), epoch)
    }
    pub(super) fn named_reentry_ui(&mut self, ui: &mut egui::Ui, epoch: u64) -> Result<()> {
        self.owner(epoch)?;
        ui.label("Existing original-owner credential-selection JSON. No writer acquisition, session renewal, replacement transaction or reset of retained evidence is available.");
        ui.add(egui::TextEdit::multiline(&mut *self.witness_setup).char_limit(16 * 1024));
        if ui
            .button("Review original-owner contact for exact named payment")
            .clicked_by(egui::PointerButton::Primary)
        {
            self.prepare_named_original_owner_contact(epoch)?;
        }
        Ok(())
    }
}

// A pure classifier, not an issuer. The actual private owner carries its purpose;
// caller data or a longer timestamp cannot select this route.
#[derive(Clone, Copy)]
enum WorkClass {
    ExactNamedSource,
    ExactHostPair,
    Ordinary,
}
fn classify(work: &Work) -> WorkClass {
    match work {
        Work::OpenNamed(..)
        | Work::PrepareNamedWitness(..)
        | Work::ApproveNamedWitness(..)
        | Work::Named(..) => WorkClass::ExactNamedSource,
        Work::CommitCompletion(_, Step::Pair(_), _) => WorkClass::ExactHostPair,
        // Every unrelated current or future work variant fails closed for the
        // longer named owner, including writer acquisition and construction.
        _ => WorkClass::Ordinary,
    }
}
fn permits(purpose: super::super::authority::PendingEntryPurpose, class: WorkClass) -> bool {
    use super::super::authority::PendingEntryPurpose;
    matches!(
        (purpose, class),
        (
            PendingEntryPurpose::ConsumedBornNamed,
            WorkClass::ExactNamedSource | WorkClass::ExactHostPair
        ) | (
            PendingEntryPurpose::Ordinary,
            WorkClass::Ordinary | WorkClass::ExactHostPair
        )
    )
}
pub(super) fn require_work_purpose(
    work: &Work,
    owner: &PendingAccountNativeAuthority,
) -> Result<()> {
    if permits(owner.entry_purpose(), classify(work)) {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

#[cfg(test)]
mod purpose_tests {
    use super::super::super::authority::PendingEntryPurpose;
    use super::*;
    #[test]
    fn consumed_named_entry_cannot_route_ordinary_pending_birth_or_writer_work() {
        // Data-only routing. No native owner, account, decision or worker runs.
        assert!(!permits(
            PendingEntryPurpose::ConsumedBornNamed,
            WorkClass::Ordinary
        ));
        let generic_open = Work::Open(
            PathBuf::from("/inert-not-opened"),
            Zeroizing::new(String::new()),
        );
        assert!(!permits(
            PendingEntryPurpose::ConsumedBornNamed,
            classify(&generic_open)
        ));
        assert!(permits(
            PendingEntryPurpose::Ordinary,
            classify(&generic_open)
        ));
    }
    #[test]
    fn consumed_named_entry_allowlist_is_not_a_generic_lifetime_extension() {
        assert!(permits(
            PendingEntryPurpose::ConsumedBornNamed,
            WorkClass::ExactNamedSource
        ));
        assert!(permits(
            PendingEntryPurpose::ConsumedBornNamed,
            WorkClass::ExactHostPair
        ));
        assert!(!permits(
            PendingEntryPurpose::Ordinary,
            WorkClass::ExactNamedSource
        ));
    }
}
