//! Actual pinned-egui scheduling regression, not a retirement-authority fixture.
//! No Window, native ticket, driver command, process, or event-loop input is made.

use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const POLL: Duration = Duration::from_millis(20);

fn take_requests(requests: &Mutex<Vec<egui::RequestRepaintInfo>>) -> Vec<egui::RequestRepaintInfo> {
    std::mem::take(&mut *requests.lock().unwrap())
}

fn quiet_pass(ctx: &egui::Context, predicted_dt: f32, in_pass_poll: bool) -> Duration {
    let raw = egui::RawInput {
        // An explicit advancing clock also makes the zero-prediction case honest.
        time: Some((ctx.cumulative_frame_nr() + 1) as f64 / 60.0),
        predicted_dt,
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(320.0, 200.0),
        )),
        ..Default::default()
    };
    let mut output = ctx.run_ui(raw, |ui| {
        let ctx = ui.ctx().clone();
        if in_pass_poll {
            ctx.request_repaint_after(POLL);
        }
        // The closure ends here, like a quiet early-return draw. No animation
        // or input event supplies an accidental successor repaint.
    });
    // Headless tests do not upload textures. Clear before any assertion/drop.
    output.textures_delta.clear();
    assert_eq!(output.platform_output.num_completed_passes, 1);
    output.viewport_output[&egui::ViewportId::ROOT].repaint_delay
}

fn assert_current_request(
    ctx: &egui::Context,
    requests: &[egui::RequestRepaintInfo],
    pass_before: u64,
    delay: Duration,
) {
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].viewport_id, egui::ViewportId::ROOT);
    assert_eq!(requests[0].delay, delay);
    assert_eq!(requests[0].current_cumulative_pass_nr, pass_before);
    // eframe 0.36.2 accepts the same pass or its immediate successor, not +2.
    assert_eq!(ctx.cumulative_pass_nr(), pass_before + 1);
}

#[test]
fn quiet_retirement_poll_requires_in_pass_repaint() {
    // Cover both an exact-duration control and the production-default frame
    // prediction. egui subtracts predicted_dt from a delayed repaint request.
    for predicted_dt in [0.0_f32, 1.0_f32 / 60.0] {
        let ctx = egui::Context::default();
        let requests = Arc::new(Mutex::new(Vec::new()));
        ctx.set_request_repaint_callback({
            let requests = Arc::clone(&requests);
            move |info| requests.lock().unwrap().push(info)
        });

        // Exhaust initial repaint state under quiet, stable input. The bound
        // is only fixture setup; quietness is asserted rather than assumed.
        for warm in 0..8 {
            let before = ctx.cumulative_pass_nr();
            let delay = quiet_pass(&ctx, predicted_dt, false);
            let initial = take_requests(&requests);
            for request in &initial {
                assert_eq!(request.viewport_id, egui::ViewportId::ROOT);
                // Initial widget bookkeeping can request again at end_pass,
                // after egui has incremented the completed-pass counter.
                assert!(request.current_cumulative_pass_nr == before
                    || request.current_cumulative_pass_nr == before + 1);
            }
            if warm == 7 {
                assert_eq!(delay, Duration::MAX);
                assert!(initial.is_empty());
            }
        }
        let expected = POLL.saturating_sub(Duration::from_secs_f32(predicted_dt));

        // Prior ordinary draw scheduled the timer that starts this next frame.
        let seed_pass = ctx.cumulative_pass_nr();
        assert_eq!(quiet_pass(&ctx, predicted_dt, true), expected);
        let serviced_seed = take_requests(&requests);
        assert_current_request(&ctx, &serviced_seed, seed_pass, expected);

        // Old order: eframe invokes raw_input_hook before Context::run_ui.
        // Its equal delayed request is coalesced against the serviced timer.
        ctx.request_repaint_after(POLL);
        assert!(take_requests(&requests).is_empty());
        assert_eq!(quiet_pass(&ctx, predicted_dt, false), Duration::MAX);
        assert!(take_requests(&requests).is_empty());
        assert_eq!(
            ctx.cumulative_pass_nr(),
            serviced_seed[0].current_cumulative_pass_nr + 2,
        );
        // There is no successor callback. An old queued seed would also be
        // stale under eframe's same-pass / +1 acceptance relation.

        // Start the fixed control with another genuine in-pass timer.
        let fixed_seed = ctx.cumulative_pass_nr();
        assert_eq!(quiet_pass(&ctx, predicted_dt, true), expected);
        assert_current_request(&ctx, &take_requests(&requests), fixed_seed, expected);
        for _ in 0..4 {
            ctx.request_repaint_after(POLL); // unchanged raw-input hook
            assert!(take_requests(&requests).is_empty());
            let before = ctx.cumulative_pass_nr();
            assert_eq!(quiet_pass(&ctx, predicted_dt, true), expected);
            assert_current_request(&ctx, &take_requests(&requests), before, expected);
        }
    }
}

#[test]
fn draw_poll_request_precedes_every_early_return() {
    // Bind the actual-library contrast to the real App's placement. The
    // separate byte-restoration audit proves no native guard was edited.
    let source = include_str!("../financial_source_ui.rs");
    let draw = source
        .split_once("    fn draw(&mut self, ui: &mut egui::Ui) {")
        .unwrap().1
        .split_once("    fn apply_intent(")
        .unwrap().0;
    let operations: Vec<_> = draw.lines().map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect();
    let request = "ctx.request_repaint_after(Duration::from_millis(20));";
    assert_eq!(operations[0], "let ctx = ui.ctx().clone();");
    assert_eq!(operations[1], request);
    assert_eq!(draw.matches(request).count(), 1);
    assert!(draw.find(request).unwrap() < draw.find("self.interrupt(").unwrap());
    assert!(draw.find(request).unwrap() < draw.find("return;").unwrap());

    let raw_hook = source.split_once("impl eframe::App for Window {")
        .unwrap().1.split_once("    fn ui(").unwrap().0;
    assert_eq!(raw_hook.matches(request).count(), 1);
    assert!(raw_hook.trim_end().ends_with(
        "self.check_current();\n        ctx.request_repaint_after(Duration::from_millis(20));\n    }"
    ));
}
