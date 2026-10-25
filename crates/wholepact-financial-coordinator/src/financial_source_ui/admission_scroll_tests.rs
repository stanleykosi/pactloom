//! Pinned-egui pane identity regression, not an admission-authority fixture.
//! Only ordinary display text and real egui wheel events are supplied. No
//! Window, native ticket, consent setter, or scroll-position setter is used.

use super::review_display_tagged;
use eframe::egui;

const TAGS: [&str; 2] = ["SignerReviewBody", "WitnessReviewBody"];

// Exact pre-fix rendering/completion operations, without the CI-only observer.
// The repaired branch below instead calls the actual production helper.
fn legacy_review_display(ui: &mut egui::Ui, display: &str, eligible: bool) -> bool {
    let mut end_visible = false;
    egui::ScrollArea::vertical()
        .max_height(390.0)
        .show(ui, |ui| {
            ui.monospace(display);
            let end = ui.label("End of the complete authenticated review");
            end_visible = eligible && ui.is_rect_visible(end.rect);
        });
    end_visible
}

struct Painted {
    ids: [egui::Id; 2],
    rects: [egui::Rect; 2],
    complete: [bool; 2],
    offsets: [f32; 2],
    left_offset_before_right: f32,
}

fn paint(
    ctx: &egui::Context,
    legacy: bool,
    displays: [&str; 2],
    events: Vec<egui::Event>,
    eligible: bool,
) -> Painted {
    let raw = egui::RawInput {
        time: Some((ctx.cumulative_frame_nr() + 1) as f64 / 60.0),
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(1280.0, 800.0),
        )),
        events,
        ..Default::default()
    };
    let mut painted = None;
    let mut output = ctx.run_ui(raw, |parent| {
        egui::CentralPanel::default().show(parent, |ui| {
            ui.columns(2, |columns| {
                let mut ids = [egui::Id::new("not painted"); 2];
                let mut rects = [egui::Rect::NOTHING; 2];
                let mut complete = [false; 2];
                let mut left_offset_before_right = 0.0;
                for i in 0..2 {
                    // ScrollArea wraps its default/explicit salt in IdSalt
                    // before make_persistent_id; hashing the bare str differs.
                    ids[i] = columns[i].make_persistent_id(egui::IdSalt::new(if legacy {
                        "scroll_area"
                    } else {
                        TAGS[i]
                    }));
                    complete[i] = if legacy {
                        legacy_review_display(&mut columns[i], displays[i], eligible)
                    } else {
                        review_display_tagged(&mut columns[i], displays[i], eligible, TAGS[i])
                    };
                    // The wheel targets the actual allocated visible pane,
                    // not a guessed rectangle or a programmatic scroll offset.
                    rects[i] = columns[i].min_rect().intersect(columns[i].clip_rect());
                    if i == 0 {
                        left_offset_before_right = egui::scroll_area::State::load(ctx, ids[0])
                            .expect("left ScrollArea stored its state before right begins")
                            .offset.y;
                    }
                }
                painted = Some((ids, rects, complete, left_offset_before_right));
            });
        });
    });
    output.textures_delta.clear();
    assert_eq!(output.platform_output.num_completed_passes, 1);
    let (ids, rects, complete, left_offset_before_right) =
        painted.expect("both real panes were painted");
    let offsets = ids.map(|id| {
        egui::scroll_area::State::load(ctx, id)
            .expect("actual ScrollArea persisted its state")
            .offset.y
    });
    Painted { ids, rects, complete, offsets, left_offset_before_right }
}

fn wheel(point: egui::Pos2) -> Vec<egui::Event> {
    vec![
        egui::Event::PointerMoved(point),
        egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: egui::vec2(0.0, -240.0),
            phase: egui::TouchPhase::Move,
            modifiers: egui::Modifiers::NONE,
        },
    ]
}

#[test]
fn paired_review_scroll_areas_keep_independent_native_state() {
    let long = "A complete ordinary review row.\n".repeat(180);
    let short = "First ordinary row.\nSecond ordinary row.\nThird ordinary row.";
    for legacy in [true, false] {
        let ctx = egui::Context::default();
        for _ in 0..8 {
            let _ = paint(&ctx, legacy, [&long, short], vec![], true);
        }
        let mut view = paint(&ctx, legacy, [&long, short], vec![], true);
        assert_eq!(view.ids[0] == view.ids[1], legacy);
        assert_eq!(view.offsets, [0.0, 0.0]);
        assert_eq!(view.complete, [false, true]);
        assert!(view.rects.iter().all(|rect| rect.is_positive()));
        let point = view.rects[0].center();
        assert!(!view.rects[1].contains(point));

        view = paint(&ctx, legacy, [&long, short], wheel(point), true);
        // The real wheel reached the left pane in BOTH branches. Only the old
        // branch loses that progress when the right pane subsequently renders.
        assert!(view.left_offset_before_right > 0.0);
        assert_eq!(view.offsets[0] == 0.0, legacy);
        for _ in 0..8 {
            view = paint(&ctx, legacy, [&long, short], vec![], true);
        }
        assert_eq!(view.offsets[1], 0.0);
        if legacy {
            // The short right pane overwrites the very same persistent state
            // after clamping its loaded left offset to its own zero maximum.
            assert_eq!(view.offsets[0], 0.0);
        } else {
            assert!(view.offsets[0] > 0.0);
        }

        let mut left_completed = view.complete[0];
        for _ in 0..40 {
            view = paint(&ctx, legacy, [&long, short], wheel(point), true);
            left_completed |= view.complete[0];
            view = paint(&ctx, legacy, [&long, short], vec![], true);
            left_completed |= view.complete[0];
            assert_eq!(view.offsets[1], 0.0);
            if legacy {
                assert_eq!(view.offsets[0], 0.0);
            }
        }
        // Completion comes only from the helper painting its actual end marker
        // in view. This moderate wheel sequence cannot retain left progress in
        // the aliased baseline; no claim about arbitrary gestures is needed.
        assert_eq!(left_completed, !legacy);
    }
}

#[test]
fn review_completion_requires_eligible_visible_end() {
    let short = "Ordinary public review text.";
    let long = "Ordinary public review row.\n".repeat(180);
    for eligible in [false, true] {
        let ctx = egui::Context::default();
        let view = paint(&ctx, false, [short, &long], vec![], eligible);
        assert_eq!(view.complete, [eligible, false]);
        assert_eq!(view.offsets, [0.0, 0.0]);
    }
}

#[test]
fn paired_review_ids_and_completion_are_bound_to_production() {
    let source = include_str!("../financial_source_ui.rs");
    let helper = source.split("fn review_display_tagged(").nth(1).unwrap()
        .split("fn index(").next().unwrap();
    assert_eq!(helper.matches(".id_salt(_ci_tag)").count(), 1);
    assert!(helper.contains(".max_height(390.0)"));
    assert!(helper.contains("ui.monospace(display);"));
    assert!(helper.contains("let end = ui.label(\"End of the complete authenticated review\");"));
    assert!(helper.contains("end_visible = eligible && ui.is_rect_visible(end.rect);"));
    assert!(helper.contains("_ci_scroll.inner_rect, ui.is_enabled(), _ci_tag"));
    let admission = source.split("    fn draw_admission(").nth(1).unwrap()
        .split("    fn admit_rendezvous(").next().unwrap();
    assert!(admission.contains("ui.columns(2, |columns| {"));
    assert!(admission.contains("review_display_tagged(&mut columns[0], &full, visible, \"SignerReviewBody\")"));
    assert!(admission.contains("review_display_tagged(&mut columns[1], &witness_display(p), visible, \"WitnessReviewBody\")"));
    assert!(source.contains("self.draw_admission(ui, visible && !ctx.will_discard(), later_frame, &mut paired_in_pass);"));
    assert!(source.contains("self.paired = paired_progress_after_pass(\n            self.paired,\n            paired_in_pass,\n            eligible,\n            self.phase == painted_phase,\n        );"));
}
