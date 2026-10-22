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
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    host_text: Option<zeroize::Zeroizing<String>>,
}
thread_local! { static FRAME: RefCell<Frame> = RefCell::new(Frame::default()); }
const TAGS: &[&str] = &["ActivateArm", "ActivateFinal", "ActivateRead", "AdmitFinal", "ArmContinue", "ArmSigner", "ArmV3Admit", "ArmWitness", "Begin", "BeginContinue", "BeginHostLine", "BeginV3", "Close", "CompletedPairAction", "Configure", "ConfigureFinancialSetup", "ConfigureV3", "ConfigureV3Owner", "ConfirmV3", "ContinueConfirm", "ContinueSelectorPath", "EnterPassword", "EntryConfirm", "Field:AccountId", "Field:ContinueSelectorPath", "Field:Endpoint", "Field:FinancialSelection", "Field:HostCommands", "Field:HostProfile", "Field:HostWorkspace", "Field:InitialReadSelection", "Field:MaterialRoot", "Field:NetworkProfile", "Field:OwnerCertificate", "Field:OwnerCertificateDerHex", "Field:OwnerConfiguration", "Field:PinnedServerCertificate", "Field:ResultSelectorPath", "Field:SelectedJournal", "Field:ServerCertificate", "Field:ServerName", "Field:ServerPrivateKey", "Field:SourceIdentity", "Field:SourceRoot", "Field:StorageKey", "Field:TrustedClientRoot", "Field:TrustedServerRoot", "Field:V3Selection", "Field:WalletConfiguration", "Field:WitnessId", "Field:WriterCertificate", "Field:WriterConfiguration", "Field:WriterPrivateKey", "FinalV3Admit", "FinalV3AdmitRead", "FinalV3Audit", "FinalV3Enrollment", "FinalV3Manifest", "FinalV3Pair", "FinalV3PrepareRead", "FinalV3Receive", "FinalV3Redisclose", "FinalV3RedisclosureRead", "HostEditor", "HostOutput", "HostSubmit", "NormalFinish", "ParkFinancial", "PasswordSubmit", "PasswordV3", "PrepareCompletedPair", "PrepareHistory", "PrepareSetup", "Read", "ReadConfirm", "ResultSelectorPath", "ResumeFinancial", "RetireSigning", "ReturnExact", "ReturnRead", "ReviewAcknowledgement", "ReviewBody", "ReviewV3Admit", "ReviewV3AdmitRead", "ReviewV3Audit", "ReviewV3Enrollment", "ReviewV3Manifest", "ReviewV3Pair", "ReviewV3PrepareRead", "ReviewV3Receive", "ReviewV3Redisclose", "ReviewV3RedisclosureRead", "SaveContinuationSelector", "SaveResultSelector", "ScrollRegion", "SelectFinancialSetup", "SelectNextV3", "SelectV3Owner", "ServeHistory", "Setup", "SetupHistory", "ShowContinuationSelector", "SignExact", "SignRead", "SignerReviewAcknowledgement", "SignerReviewBody", "SourcePassword", "WalletObserve", "WalletPrepare", "WitnessReviewAcknowledgement", "WitnessReviewBody", "WriterAction"];

pub(super) fn begin(ctx: &egui::Context, phase: &'static str, subphase: &'static str,
    owner: Option<&'static str>, focused: bool, secret: bool, host: bool) {
    FRAME.with(|cell| {
        let mut f = cell.borrow_mut();
        f.widgets.clear(); f.failed = false; f.owner = owner;
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        { f.host_text = None; }
        f.facts = Some(json!({"phase":phase,"subphase":subphase,"owner":owner,
            "view_generation":ctx.cumulative_frame_nr()+1,"focused":focused,
            "secret_input":secret,"host_input":host,
            "pixels_per_point":ctx.pixels_per_point(),"viewport":[1280,800]}));
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        { f.facts.as_mut().unwrap()["host_view_id"] = Value::Null; }
    });
}
/// Closed content-free context of the actual Host layout; never a readiness grant.
pub(super) fn host_observation(revision: u64, nonws_end: u64, context_valid: bool,
    entry: &'static str, editor: Option<(u64, u64)>, view: Option<crate::host_output_view::HostOutputView>) {
    FRAME.with(|cell| {
        let mut f = cell.borrow_mut();
        if let Some(facts) = &mut f.facts {
            facts["host_observation"] = json!({"revision":revision,"nonws_end":nonws_end,
                "context_valid":context_valid,"entry":entry,
                "editor":editor.map(|(ordinal,revision)| json!({"ordinal":ordinal,"revision":revision})),
                "view":view.as_ref().map(|v| json!({"rect":[v.rect.min.x,v.rect.min.y,v.rect.max.x,v.rect.max.y],
                    "nonws":v.nonws,"rows":v.rows}))});
        }
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        { f.host_text = view.map(|v| v.text); }
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
    finish_impl(ctx, visible, secret, host,
        #[cfg(wholepact_financial_rendered_host_semantic_ci)] wholepact_financial_coordinator_origin::financial_ci_snapshot,
        #[cfg(wholepact_financial_rendered_host_semantic_ci)] wholepact_financial_coordinator_origin::financial_ci_clear_host_view)
}
// Private observer sinks allow pure final-pass tests without touching actor
// custody or creating evidence files. No input or authority operation is a sink.
fn finish_impl(ctx: &egui::Context, visible: bool, secret: bool, host: bool,
    #[cfg(wholepact_financial_rendered_host_semantic_ci)] mut emit: impl FnMut(Value, Option<zeroize::Zeroizing<String>>) -> std::io::Result<()>,
    #[cfg(wholepact_financial_rendered_host_semantic_ci)] mut clear: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    FRAME.with(|cell| {
        let mut f = cell.borrow_mut();
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        let mut host_text = f.host_text.take();
        let Some(mut facts) = f.facts.take() else {
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            clear()?;
            return Err(error());
        };
        if !visible || ctx.will_discard() {
            f.widgets.clear();
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            clear()?;
            return Ok(());
        }
        let generation = ctx.cumulative_frame_nr()+1;
        if generation <= f.last_emitted {
            f.widgets.clear();
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            clear()?;
            return Ok(());
        }
        let scale = ctx.pixels_per_point();
        let size = ctx.content_rect().size()*scale;
        if f.failed || !scale.is_finite() || !(0.5..=4.0).contains(&scale)
            || (size.x-1280.0).abs()>1.0 || (size.y-800.0).abs()>1.0 {
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            clear()?;
            return Err(error());
        }
        facts["secret_input"] = json!(secret || facts["secret_input"] == true);
        facts["host_input"] = json!(host || facts["host_input"] == true);
        let protected = (facts["secret_input"] == true, facts["host_input"] == true);
        if protected.0 || protected.1 { facts["host_observation"]["view"] = Value::Null; }
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if protected.0 || protected.1 || facts["focused"] != true
            || facts["host_observation"]["entry"] != "Idle"
            || facts["host_observation"]["context_valid"] != true
            || facts["host_observation"]["view"].is_null() {
            facts["host_observation"]["view"] = Value::Null;
            host_text = None;
            clear()?;
        }
        // Bound the fixed 1800-second profile below its record budget. A new
        // protected-input boundary is never throttled behind an old safe frame.
        if f.last_protected == Some(protected)
            && f.last_emit_at.is_some_and(|t| t.elapsed() < std::time::Duration::from_millis(100)) {
            f.widgets.clear(); return Ok(());
        }
        facts["widgets"] = Value::Array(std::mem::take(&mut f.widgets));
        #[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
        wholepact_financial_coordinator_origin::financial_ci_snapshot(facts)?;
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        emit(facts, host_text)?;
        f.last_emitted = generation;
        f.last_emit_at = Some(std::time::Instant::now());
        f.last_protected = Some(protected);
        Ok(())
    })
}
fn error() -> std::io::Error { std::io::Error::new(std::io::ErrorKind::InvalidData,"financial CI snapshot rejected") }

#[cfg(all(test, wholepact_financial_rendered_host_semantic_ci))]
mod tests {
    use super::*;
    #[derive(Clone, Copy, Debug)] enum Mode { Visible, Hidden, Sizing, Discarded, Unfocused, Secret, HostIntent, Editing, Writing, Closed, Invalid }
    fn run(ctx: &egui::Context, mode: Mode) -> (Vec<(Value,bool)>, usize) {
        let mut emitted=Vec::new(); let mut clears=0;
        let mut raw=egui::RawInput::default();
        raw.screen_rect=Some(egui::Rect::from_min_size(egui::Pos2::ZERO,egui::vec2(1280.0,800.0)));
        let _=ctx.run_ui(raw, |parent| {
            let builder=match mode {Mode::Hidden=>egui::UiBuilder::new().invisible(),Mode::Sizing=>egui::UiBuilder::new().sizing_pass(),_=>egui::UiBuilder::new()};
            let mut ui=parent.new_child(builder);
            begin(ctx,"Selecting","None",None,!matches!(mode,Mode::Unfocused),false,false);
            let (origin,galley,_)=egui::Label::new(egui::RichText::new("prompt: ").monospace()).selectable(false).layout_in_ui(&mut ui);
            let origin=crate::host_output_view::paint_origin(origin,ctx.pixels_per_point());
            ui.painter().galley(origin,galley.clone(),ui.visuals().text_color());
            // Stage an actual galley even in suppression cases to test wiping.
            let view=crate::host_output_view::visible_tail(&galley,origin,ui.clip_rect(),ctx.pixels_per_point(),7);
            let entry=match mode {Mode::Editing=>"Editing",Mode::Writing=>"Writing",Mode::Closed=>"Closed",_=>"Idle"};
            host_observation(1,7,!matches!(mode,Mode::Invalid),entry,None,view);
            rect(&ui,ui.clip_rect(),true,"HostOutput",None);
            if matches!(mode,Mode::Discarded) && ctx.current_pass_index()==0 {ctx.request_discard("synthetic observer suppression");}
            // Keep the follow-on pass hidden: this case tests only the discarded
            // pass, not a subsequent legitimate repaint within the same frame.
            let visible=ui.is_visible()&&ui.is_enabled()&&!ui.is_sizing_pass()
                && !(matches!(mode,Mode::Discarded)&&ctx.current_pass_index()>0);
            finish_impl(ctx,visible,matches!(mode,Mode::Secret),matches!(mode,Mode::HostIntent|Mode::Editing|Mode::Writing),
                |facts,text|{emitted.push((facts,text.is_some()));Ok(())},
                ||{clears+=1;Ok(())}).unwrap();
            FRAME.with(|f|assert!(f.borrow().host_text.is_none()));
        });
        (emitted,clears)
    }
    #[test] fn final_pass_suppresses_and_drops_all_ineligible_text() {
        for mode in [Mode::Hidden,Mode::Sizing,Mode::Discarded,Mode::Unfocused,Mode::Secret,Mode::HostIntent,Mode::Editing,Mode::Writing,Mode::Closed,Mode::Invalid] {
            FRAME.with(|f|*f.borrow_mut()=Frame::default());
            let (emitted,clears)=run(&egui::Context::default(),mode);
            assert!(clears>0);
            assert!(emitted.iter().all(|(facts,text)|!text&&facts["host_view_id"].is_null()&&facts["host_observation"]["view"].is_null()),"{mode:?}");
            if matches!(mode,Mode::Hidden|Mode::Sizing|Mode::Discarded){assert!(emitted.is_empty());}
        }
    }
    #[test] fn throttle_never_emits_semantic_text_or_delays_protected_boundary() {
        FRAME.with(|f|*f.borrow_mut()=Frame::default());let ctx=egui::Context::default();
        let (first,clears)=run(&ctx,Mode::Visible);assert_eq!(first.len(),1);assert!(first[0].1);assert_eq!(clears,0);
        let (throttled,_)=run(&ctx,Mode::Visible);assert!(throttled.is_empty());
        let (protected,clears)=run(&ctx,Mode::HostIntent);assert_eq!(protected.len(),1);assert!(!protected[0].1);assert!(clears>0);
        let (returned,_)=run(&ctx,Mode::Visible);assert_eq!(returned.len(),1);assert!(returned[0].1);
    }
}
