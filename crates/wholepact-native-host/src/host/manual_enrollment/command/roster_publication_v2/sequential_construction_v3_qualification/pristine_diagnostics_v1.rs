//! One closed setup failure, not progress, authority or a cleanup verdict.
//! Enabled only by the pristine setup selector. All retained labels come from
//! the existing source-pinned diagnostic enums; raw PTY bytes are never copied.
use super::safe_diagnostics_v1::{self as diagnostic, Boundary, Outcome};
use std::cell::Cell;

thread_local! {
    static SOURCE_BOUNDARY: Cell<Option<Boundary>> = const { Cell::new(None) };
}

pub(super) struct SourceGuard;
impl Drop for SourceGuard {
    fn drop(&mut self) { SOURCE_BOUNDARY.with(|slot| slot.set(None)); }
}
pub(super) fn begin_source() -> SourceGuard {
    SOURCE_BOUNDARY.with(|slot| slot.set(Some(Boundary::PrivateWorkspaceBootstrap)));
    SourceGuard
}
pub(super) fn source_progress(boundary: Boundary, outcome: Outcome) {
    if matches!(outcome, Outcome::Begin) {
        SOURCE_BOUNDARY.with(|slot| { if slot.get().is_some() { slot.set(Some(boundary)); } });
    }
}
pub(super) fn source_authority_error(error: &wholepact_authority::AuthorityError) {
    if let Some(boundary) = SOURCE_BOUNDARY.with(Cell::get) {
        diagnostic::emit(boundary, diagnostic::authority_error(error));
    }
}
pub(super) fn source_host_error(error: &crate::Error) {
    if let Some(boundary) = SOURCE_BOUNDARY.with(Cell::get) {
        diagnostic::emit(boundary, diagnostic::host_error(error));
    }
}

/// The outer custody harness has only these finite I/O stages. This is a
/// fallback when no actual nested source observation was already retained.
pub(super) fn emit_outer_failure(boundary: Boundary) {
    let label = match boundary {
        Boundary::PristineSetupRoot => "PristineSetupRoot",
        Boundary::PristineOriginalCutoff => "PristineOriginalCutoff",
        Boundary::PristinePredecessorProcess => "PristinePredecessorProcess",
        Boundary::PristineCustodyValidation => "PristineCustodyValidation",
        Boundary::PristineCustodyHandoff => "PristineCustodyHandoff",
        Boundary::PristineOriginalAudit => "PristineOriginalAudit",
        _ => return,
    };
    use std::io::Write;
    let _ = writeln!(std::io::stdout().lock(),
        "CI_UI_SETUP_FAILURE boundary={label} outcome=HostStorage");
}

#[derive(Clone, Copy)]
pub(super) struct Failure {
    pub(super) boundary: &'static str,
    pub(super) outcome: &'static str,
}

#[derive(Default)]
pub(super) struct Capture { first: Option<Failure> }
impl Capture {
    // Reserved even before the first observation. This small fixed allowance
    // cannot be evicted by later private transcript/diagnostic growth.
    pub(super) const RESERVED: usize = 256;
    pub(super) fn first(&self) -> Option<Failure> { self.first }
    pub(super) fn observe(&mut self, line: &[u8]) {
        if self.first.is_some() { return; }
        let Some((boundary, outcome)) = diagnostic::pristine_terminal_pair(line) else { return; };
        self.first = Some(Failure { boundary, outcome });
        // Write the original finite boundary before descendant cleanup can
        // stall/fail. This observation is explicitly NOT a success/custody claim.
        use std::io::Write;
        let _ = writeln!(std::io::stdout().lock(),
            "\nCI_UI_SETUP_FAILURE boundary={boundary} outcome={outcome}");
    }
}

#[test]
fn first_nested_failure_survives_outer_and_cleanup_failure() {
    // Fabricated bytes only. Avoid output side effects by using the same parser
    // and assigning the inert first record directly, then observing later rows.
    let (boundary, outcome) = diagnostic::pristine_terminal_pair(
        b"[JOINED_DIAGNOSTIC BirthEnroll AuthorityAuthentication]").unwrap();
    let mut capture = Capture { first: Some(Failure { boundary, outcome }) };
    capture.observe(b"[JOINED_DIAGNOSTIC BirthEnroll HostReceipt]");
    capture.observe(b"[JOINED_DIAGNOSTIC PrivateWorkspaceBootstrap HostStorage]");
    assert_eq!(capture.first().unwrap().boundary, "BirthEnroll");
    assert_eq!(capture.first().unwrap().outcome, "AuthorityAuthentication");
    assert!(boundary.len() + outcome.len() + 48 <= Capture::RESERVED);
}

#[test]
fn pristine_failure_accepts_only_complete_closed_terminal_pairs() {
    for line in [
        &b"[JOINED_DIAGNOSTIC BirthEnroll Begin]"[..],
        &b"[JOINED_DIAGNOSTIC BirthEnroll Complete]"[..],
        &b"[JOINED_DIAGNOSTIC BirthEnroll AuthorityInputEmpty]"[..],
        &b"[JOINED_DIAGNOSTIC BirthEnroll AuthorityInputWithinBound]"[..],
        &b"[JOINED_DIAGNOSTIC BirthEnroll AuthorityInputOverBound]"[..],
        &b"[JOINED_DIAGNOSTIC BirthEnroll unknown]"[..],
        &b"[JOINED_DIAGNOSTIC unknown AuthorityStorage]"[..],
        &b"prefix [JOINED_DIAGNOSTIC BirthEnroll AuthorityStorage]"[..],
        &b"[JOINED_DIAGNOSTIC BirthEnroll AuthorityStorage] private"[..],
        &b"[JOINED_DIAGNOSTIC BirthEnroll AuthorityStorage extra]"[..],
    ] { assert!(diagnostic::pristine_terminal_pair(line).is_none()); }
}
