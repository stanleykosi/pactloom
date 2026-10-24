//! Headless REAL egui layout, with data-only public presentation input.
//! No Window/native owner/ticket/Final, clock permission, IPC, or effect is
//! constructed. The dry Arm result is ONLY widget/tail reachability.
use super::*;
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::PermissionsExt;

thread_local! { static GEOMETRY: RefCell<Value> = RefCell::new(json!({})); }
fn rect(r: egui::Rect) -> Value { json!([r.min.x, r.min.y, r.max.x, r.max.y]) }
pub(super) fn record_review_geometry<R>(o: &egui::scroll_area::ScrollAreaOutput<R>) {
    GEOMETRY.with(|g| { let mut g=g.borrow_mut();
        g["inner_rect"]=rect(o.inner_rect); g["content_height"]=json!(o.content_size.y);
        g["viewport_height"]=json!(o.inner_rect.height()); g["offset_y"]=json!(o.state.offset.y);
    });
}
pub(super) fn record_outer_geometry<R>(o: &egui::scroll_area::ScrollAreaOutput<R>) {
    GEOMETRY.with(|g| { let mut g=g.borrow_mut();
        g["outer_rect"]=rect(o.inner_rect); g["outer_content_height"]=json!(o.content_size.y);
        g["outer_viewport_height"]=json!(o.inner_rect.height()); g["outer_offset_y"]=json!(o.state.offset.y);
    });
}
pub(super) fn record_end_geometry(r: egui::Rect, visible: bool) {
    GEOMETRY.with(|g| { let mut g=g.borrow_mut(); g["end_label_rect"]=rect(r); g["end_label_visible"]=json!(visible); });
}

// Exact effective prelude of Window::draw for the observed first-seven S1
// state, with S2 not opened. Source audit pins each literal and branch premise.
// Not a native-state fixture: all authority-bearing fields are absent.
fn header(ui: &mut egui::Ui) {
    ui.heading("Wholepact coordinator · Original Signer source");
    ui.label("Original Pair completed only after actual StatusProof. Later Read/receive/admission/audit remain separately unapproved.");
    ui.label("Signer 1 V3: actual account/journal open observed; later V3 work unapproved");
    ui.label("Fresh enrollment: actual committed result retained; no later permission.");
    ui.label("Fresh manifest: actual committed result retained; no later permission.");
    ui.label("RedisclosureRead: actual bound result retained; no later permission.");
    ui.label("Redisclose: actual bound result retained; no later permission.");
    ui.label("PrepareRead: actual bound result retained; no later permission.");
    ui.label("Receive: actual bound result retained; no later permission.");
    ui.label("Original Pair: actual authenticated StatusProof retained; later actions remain unapproved.");
    ui.label("Signer 2 V3: initial V3 source not selected");
    for role in [Role::Signer1, Role::Signer2] {
        ui.label(format!("{}: {} · {}", role_name(role), progress_text(Progress::NotStarted), effect_text(ContinueEffect::None)));
    }
    for role in [Role::Signer1, Role::Signer2] {
        ui.label(format!("{} admission: Signer {} · Witness {}", role_name(role), admission_effect_text(AdmissionEffect::None), admission_effect_text(AdmissionEffect::None)));
    }
    let _ = ui.button("Cancel and dispose sources");
    // Actual phase gate excludes Host rendering at V3AdmitReview.
    assert!(!host_phase_allows_input(Phase::V3AdmitReview));
}

fn keys(v: &Value, expected: &[&str]) {
    let o=v.as_object().expect("closed test command object");
    assert_eq!(o.len(),expected.len(),"closed test command fields");
    assert!(expected.iter().all(|k|o.contains_key(*k)),"closed test command names");
}
fn coordinate(v: &Value, max: i64) -> f32 {
    let n=v.as_i64().expect("integer pointer coordinate"); assert!((0..max).contains(&n)); n as f32
}

// Test-only finite failure observation. The original panic payload is never
// inspected or emitted; the previous hook is restored outside the unwind.
static CHECKPOINT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
const CHECKPOINTS: [&str; 13] = ["Metadata", "ReadDto", "ParseDto", "ValidateDto",
    "FormatReview", "CreateContext", "ReadCommand", "ParseCommand", "RunFrame",
    "ReadSnapshot", "EncodeFrame", "WriteFrame", "Stop"];
fn checkpoint(n: u8) {
    CHECKPOINT.store(n, std::sync::atomic::Ordering::Relaxed);
}
fn panic_source(file: &str) -> &'static str {
    if file.ends_with("/egui_layout_tests.rs") { "Harness" }
    else if file.ends_with("/financial_ci.rs") { "Observer" }
    else if file.ends_with("/financial_source_ui.rs") { "SourceUi" }
    else if file.contains("/egui-0.36.2/src/context") { "EguiContext" }
    else if file.contains("/egui-0.36.2/") && file.ends_with("/ui.rs") { "EguiUi" }
    else if file.contains("/egui-0.36.2/") && file.ends_with("/scroll_area.rs") { "EguiScrollArea" }
    else if file.contains("/epaint-0.36.2/src/text/") { "EpaintText" }
    else { "Other" }
}
#[test]
#[ignore = "requires fixed diagnostic runner public DTO and finite input protocol"]
fn actual_admit_review_layout_protocol() {
    checkpoint(0);
    let previous=std::panic::take_hook();
    std::panic::set_hook(Box::new(|info| {
        let stage=CHECKPOINTS[usize::from(CHECKPOINT.load(std::sync::atomic::Ordering::Relaxed))];
        let (source,line,column)=info.location().map(|l|
            (panic_source(l.file()),l.line().min(1_000_000),l.column().min(1_000_000)))
            .unwrap_or(("Other",0,0));
        // All text is from the closed enums above. No panic message/path/DTO.
        let _=writeln!(std::io::stderr(),
            "EGUI_LAYOUT_FAILURE_V1 {{\"checkpoint\":\"{stage}\",\"source\":\"{source}\",\"line\":{line},\"column\":{column}}}");
    }));
    let result=std::panic::catch_unwind(layout_protocol_inner);
    std::panic::set_hook(previous);
    if let Err(payload)=result { std::panic::resume_unwind(payload); }
}
fn layout_protocol_inner() {
    let path=std::env::var_os("WHOLEPACT_CI_EGUI_ADMIT_FIXTURE").expect("fixed fixture path required");
    let path=std::path::PathBuf::from(path);
    let metadata=std::fs::symlink_metadata(&path).expect("test DTO metadata");
    assert!(metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600);
    assert!(metadata.len()>0 && metadata.len()<=60*1024,"bounded public DTO");
    checkpoint(1);
    let bytes=std::fs::read(&path).expect("test DTO read");
    checkpoint(2);
    let p: SignerV3AdmitPresentationV1=serde_json::from_slice(&bytes).expect("strict public Admit DTO");
    checkpoint(3);
    assert!(p.validate().is_ok(),"complete validated material-derived Admit DTO");
    assert_eq!(p.actor.signer_role,Role::Signer1);
    checkpoint(4);
    let no_ready: Option<SignerV3AdmitReadyV1> = None;
    let text=serde_json::to_string_pretty(&json!({"exact_admission":p,"authenticated_ready":no_ready})).expect("exact UI formatter");
    assert!(text.len()<=128*1024,"bounded exact UI text, never truncated");
    checkpoint(5);
    let ctx=egui::Context::default();
    let (mut read_to_end,mut acknowledged,mut arm_clicked)=(false,false,false);
    let mut last_tail=None; let mut elapsed_ms=0u64; let mut wheel_started=false; let mut position=egui::pos2(0.0,0.0);
    let input=std::io::stdin(); let mut input=input.lock();
    for seq in 1..=4096u64 {
        checkpoint(6);
        let mut line=Vec::new();
        let n=input.by_ref().take(4097).read_until(b'\n',&mut line).expect("bounded command read");
        assert!(n>0&&n<=4096&&line.last()==Some(&b'\n'),"bounded complete command");
        checkpoint(7);
        let command:Value=serde_json::from_slice(&line).expect("closed command JSON");
        if command["kind"]=="Stop" { checkpoint(12); keys(&command,&["kind"]); println!("EGUI_LAYOUT_DONE_V1 {{\"frames\":{},\"arm_clicked\":{}}}",seq-1,arm_clicked); return; }
        keys(&command,&["kind","dt_ms","event"]); assert_eq!(command["kind"],"Frame");
        let dt=command["dt_ms"].as_u64().expect("integer frame interval"); assert!((1..=1000).contains(&dt));
        elapsed_ms=elapsed_ms.checked_add(dt).expect("finite frame time");
        let mut raw=egui::RawInput::default(); raw.focused=true;
        raw.screen_rect=Some(egui::Rect::from_min_size(egui::Pos2::ZERO,egui::vec2(1280.0,800.0)));
        raw.time=Some(elapsed_ms as f64/1000.0); raw.predicted_dt=dt as f32/1000.0;
        let event=&command["event"];
        if !event.is_null() {
            match event["kind"].as_str().expect("closed event kind") {
                "Move"=>{keys(event,&["kind","x","y"]);position=egui::pos2(coordinate(&event["x"],1280),coordinate(&event["y"],800));raw.events.push(egui::Event::PointerMoved(position));},
                "Wheel"=>{keys(event,&["kind","delta_y"]);let d=event["delta_y"].as_i64().expect("fixed wheel delta");assert!(d==120||d== -120);raw.events.push(egui::Event::MouseWheel{unit:egui::MouseWheelUnit::Point,delta:egui::vec2(0.0,d as f32),phase:if wheel_started {egui::TouchPhase::Move} else {egui::TouchPhase::Start},modifiers:egui::Modifiers::default()});wheel_started=true;},
                "Button"=>{keys(event,&["kind","pressed"]);raw.events.push(egui::Event::PointerButton{pos:position,button:egui::PointerButton::Primary,pressed:event["pressed"].as_bool().expect("button bool"),modifiers:egui::Modifiers::default()});},
                _=>panic!("closed event kind"),
            }
        }
        let mut arm_enabled=false;
        checkpoint(8);
        let mut frame_output=ctx.run_ui(raw, |parent| {
            let frame=ctx.cumulative_frame_nr(); let visible=parent.is_enabled()&&parent.is_visible()&&!parent.is_sizing_pass();
            crate::financial_ci::begin(&ctx,"V3AdmitReview","None",Some("Signer1"),true,false,false);
            crate::financial_ci::host_observation(0,0,true,"Idle",None,None);
            let mut painted_to_end=read_to_end; let mut ack_in_pass=acknowledged; let mut clicked=false;
            egui::CentralPanel::default().show(parent,|ui| {
                ci_panel!(ui,|ui:&mut egui::Ui| {
                    header(ui);
                    if review_display(ui,&text,visible&&!ctx.will_discard()){painted_to_end=true;}
                    ci_response!(ui,ui.checkbox(&mut ack_in_pass,"Arm this exact admission request to obtain one authenticated READY on the retained original owner connection. No local publication or final remote send yet."),"ReviewAcknowledgement",Some(Role::Signer1));
                    arm_enabled=read_to_end&&acknowledged&&frame>0;
                    clicked=ci_response!(ui,ui.add_enabled(arm_enabled,egui::Button::new("Arm exact V3 admission")),"ArmV3Admit",Some(Role::Signer1)).clicked_by(egui::PointerButton::Primary);
                });
            });
            let eligible=tail_eligible(frame,last_tail,visible,ctx.will_discard());
            (read_to_end,acknowledged)=review_progress_after_pass((read_to_end,acknowledged),(painted_to_end,ack_in_pass),eligible,true);
            if eligible {last_tail=Some(frame); if clicked {assert!(v3_admission_tail_eligible(Phase::V3AdmitReview,Phase::V3AdmitReview,read_to_end,acknowledged,true,false,frame>0));arm_clicked=true;}}
        });
        // Headless layout has no GPU backend. epaint 0.36.2 requires explicit
        // disposal of unapplied texture deltas; retain all layout/font work.
        frame_output.textures_delta.clear();
        drop(frame_output);
        checkpoint(9);
        let snapshot=crate::financial_ci::take_layout_test_snapshot();
        let geometry=GEOMETRY.with(|g|g.borrow().clone());
        checkpoint(10);
        let out=json!({"seq":seq,"elapsed_ms":elapsed_ms,"snapshot":snapshot,"geometry":geometry,
            "state":{"read_to_end":read_to_end,"acknowledged":acknowledged,"arm_enabled":arm_enabled,"arm_clicked":arm_clicked}});
        let encoded=serde_json::to_string(&out).expect("finite frame output"); assert!(encoded.len()<=16*1024);
        checkpoint(11);
        println!("EGUI_LAYOUT_FRAME_V1 {encoded}"); std::io::stdout().flush().expect("test frame flush");
    }
    panic!("bounded layout frame budget exhausted");
}
