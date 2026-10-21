//! Full-financial CI observation only. No inputs, grants, setters or commands.
//! Compiled exclusively for the separate wholepact_financial_ci runtime image.
use std::cell::RefCell;
use eframe::egui;
use serde_json::{json, Value};
#[cfg(wholepact_financial_external_ci)]
#[path = "financial_ci_v3_export.rs"]
mod v3_export;
#[cfg(wholepact_financial_external_ci)]
pub(super) use v3_export::export_v3_admission;

#[derive(Default)]
struct Frame {
    facts: Option<Value>,
    widgets: Vec<Value>,
    owner: Option<&'static str>,
    failed: bool,
    last_emitted: u64,
    last_emit_at: Option<std::time::Instant>,
    last_protected: Option<(bool,bool)>,
}
thread_local! { static FRAME: RefCell<Frame> = RefCell::new(Frame::default()); }
const TAGS: &[&str] = &["ActivateArm", "ActivateFinal", "ActivateRead", "AdmitFinal", "ArmContinue", "ArmSigner", "ArmV3Admit", "ArmWitness", "Begin", "BeginContinue", "BeginHostLine", "BeginV3", "Close", "CompletedPairAction", "Configure", "ConfigureFinancialSetup", "ConfigureV3", "ConfigureV3Owner", "ConfirmV3", "ContinueConfirm", "ContinueSelectorPath", "EnterPassword", "EntryConfirm", "Field:AccountId", "Field:ContinueSelectorPath", "Field:Endpoint", "Field:FinancialSelection", "Field:HostCommands", "Field:HostProfile", "Field:HostWorkspace", "Field:InitialReadSelection", "Field:MaterialRoot", "Field:NetworkProfile", "Field:OwnerCertificate", "Field:OwnerCertificateDerHex", "Field:OwnerConfiguration", "Field:PinnedServerCertificate", "Field:ResultSelectorPath", "Field:SelectedJournal", "Field:ServerCertificate", "Field:ServerName", "Field:ServerPrivateKey", "Field:SourceIdentity", "Field:SourceRoot", "Field:StorageKey", "Field:TrustedClientRoot", "Field:TrustedServerRoot", "Field:V3Selection", "Field:WalletConfiguration", "Field:WitnessId", "Field:WriterCertificate", "Field:WriterConfiguration", "Field:WriterPrivateKey", "FinalV3Admit", "FinalV3AdmitRead", "FinalV3Audit", "FinalV3Enrollment", "FinalV3Manifest", "FinalV3Pair", "FinalV3PrepareRead", "FinalV3Receive", "FinalV3Redisclose", "FinalV3RedisclosureRead", "HostEditor", "HostOutput", "HostSubmit", "NormalFinish", "ParkFinancial", "PasswordSubmit", "PasswordV3", "PrepareCompletedPair", "PrepareHistory", "PrepareSetup", "Read", "ReadConfirm", "ResultSelectorPath", "ResumeFinancial", "RetireSigning", "ReturnExact", "ReturnRead", "ReviewAcknowledgement", "ReviewBody", "ReviewV3Admit", "ReviewV3AdmitRead", "ReviewV3Audit", "ReviewV3Enrollment", "ReviewV3Manifest", "ReviewV3Pair", "ReviewV3PrepareRead", "ReviewV3Receive", "ReviewV3Redisclose", "ReviewV3RedisclosureRead", "SaveContinuationSelector", "SaveResultSelector", "ScrollRegion", "SelectFinancialSetup", "SelectNextV3", "SelectV3Owner", "ServeHistory", "Setup", "SetupHistory", "ShowContinuationSelector", "SignExact", "SignRead", "SignerReviewAcknowledgement", "SignerReviewBody", "SourcePassword", "WalletObserve", "WalletPrepare", "WitnessReviewAcknowledgement", "WitnessReviewBody", "WriterAction"];

pub(super) fn begin(ctx: &egui::Context, phase: &'static str, subphase: &'static str,
    owner: Option<&'static str>, focused: bool, secret: bool, host: bool) {
    FRAME.with(|cell| {
        let mut f = cell.borrow_mut();
        f.widgets.clear(); f.failed = false; f.owner = owner;
        f.facts = Some(json!({"phase":phase,"subphase":subphase,"owner":owner,
            "view_generation":ctx.cumulative_frame_nr()+1,"focused":focused,
            "secret_input":secret,"host_input":host,
            "pixels_per_point":ctx.pixels_per_point(),"viewport":[1280,800]}));
    });
}
pub(super) fn owner() -> Option<&'static str> { FRAME.with(|f| f.borrow().owner) }
pub(super) fn response(ui: &egui::Ui, response: &egui::Response, tag: &'static str,
    owner: Option<&'static str>) {
    rect(ui, response.rect, response.enabled(), tag, owner);
}
pub(super) fn rect(ui: &egui::Ui, actual: egui::Rect, enabled: bool,
    tag: &'static str, owner: Option<&'static str>) {
    if !ui.is_visible() || ui.is_sizing_pass() { return; }
    let scale = ui.ctx().pixels_per_point();
    let bounds = egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1280.0/scale,800.0/scale));
    let r = actual.intersect(ui.clip_rect()).intersect(bounds);
    if !r.is_positive() { return; }
    FRAME.with(|cell| {
        let mut f = cell.borrow_mut();
        if f.facts.is_none() { return; }
        if !TAGS.contains(&tag) || !matches!(owner, None|Some("Signer1")|Some("Signer2"))
            || f.widgets.len() >= 128 || ![r.min.x,r.min.y,r.max.x,r.max.y].iter().all(|v|v.is_finite())
            || f.widgets.iter().any(|w| w["tag"] == tag && w["owner"] == json!(owner)) {
            f.failed = true; return;
        }
        f.widgets.push(json!({"tag":tag,"owner":owner,"rect":[r.min.x,r.min.y,r.max.x,r.max.y],
            "enabled":enabled && ui.is_enabled()}));
    });
}
/// Called only after real layout. Source/Host editor-entry intents conservatively
/// mark this same frame protected before the native tail can open the editor.
pub(super) fn finish(ctx: &egui::Context, visible: bool, secret: bool, host: bool) -> std::io::Result<()> {
    FRAME.with(|cell| {
        let mut f = cell.borrow_mut();
        let Some(mut facts) = f.facts.take() else { return Err(error()); };
        if !visible || ctx.will_discard() { f.widgets.clear(); return Ok(()); }
        let generation = ctx.cumulative_frame_nr()+1;
        if generation <= f.last_emitted { f.widgets.clear(); return Ok(()); }
        let scale = ctx.pixels_per_point();
        let size = ctx.content_rect().size()*scale;
        if f.failed || !scale.is_finite() || !(0.5..=4.0).contains(&scale)
            || (size.x-1280.0).abs()>1.0 || (size.y-800.0).abs()>1.0 { return Err(error()); }
        facts["secret_input"] = json!(secret || facts["secret_input"] == true);
        facts["host_input"] = json!(host || facts["host_input"] == true);
        let protected = (facts["secret_input"] == true, facts["host_input"] == true);
        // Bound the fixed 1800-second profile below its record budget. A new
        // protected-input boundary is never throttled behind an old safe frame.
        if f.last_protected == Some(protected)
            && f.last_emit_at.is_some_and(|t| t.elapsed() < std::time::Duration::from_millis(100)) {
            f.widgets.clear(); return Ok(());
        }
        facts["widgets"] = Value::Array(std::mem::take(&mut f.widgets));
        wholepact_financial_coordinator_origin::financial_ci_snapshot(facts)?;
        f.last_emitted = generation;
        f.last_emit_at = Some(std::time::Instant::now());
        f.last_protected = Some(protected);
        Ok(())
    })
}
fn error() -> std::io::Error { std::io::Error::new(std::io::ErrorKind::InvalidData,"financial CI snapshot rejected") }
