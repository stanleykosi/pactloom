//! Finite synthetic navigation of the actual disabled public V3 controls.
//! No scroll-state assignment, input replacement, native decision, or worker
//! entry is exposed. The same populated Window is drawn and genuinely clicked.
use super::{AuthorityError, Result, Window, egui, fixture_input};

const DOWNWARD_STEPS: usize = 16;
const MAX_WHEEL_STEPS: usize = 3 * DOWNWARD_STEPS;
const MAX_SETTLE_FRAMES: usize = 128;
const WHEEL_POINTS: f32 = 10_000.0;

fn viewport() -> egui::Rect {
    egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1800.0, 20000.0))
}

fn wheel_position() -> egui::Pos2 {
    // This is the outer selection ScrollArea's right gutter at mid-height,
    // below the bounded receipt panel and outside its default-width TextEdits.
    // selection_ui has no nested ScrollArea. The renderer regression checks
    // that wheel input actually moves this parent rather than editing text.
    egui::pos2(1700.0, 10000.0)
}

fn visible_position(output: &egui::FullOutput, label: &str) -> Option<egui::Pos2> {
    output.shapes.iter().find_map(|clipped| {
        let position = super::text_position(&clipped.shape, label)?;
        (clipped.clip_rect.contains(position) && viewport().contains(position)).then_some(position)
    })
}

fn find_control(
    context: &egui::Context,
    label: &str,
    frame: &mut impl FnMut(Vec<egui::Event>) -> egui::FullOutput,
) -> Result<egui::Pos2> {
    frame(vec![]);
    for step in 0..=MAX_WHEEL_STEPS {
        // Wheel smoothing belongs to egui. Let actual empty frames settle it,
        // with a strict frame count, before choosing a stable click location.
        for _ in 0..MAX_SETTLE_FRAMES {
            if !context.input(|input| input.is_scrolling()) {
                break;
            }
            frame(vec![]);
        }
        if context.input(|input| input.is_scrolling()) {
            return Err(AuthorityError::Permission);
        }
        // ScrollArea applies an offset at the end of a frame. Paint the final
        // settled layout before inspecting the exact clipped control label.
        let output = frame(vec![]);
        if let Some(position) = visible_position(&output, label) {
            return Ok(position);
        }
        if step == MAX_WHEEL_STEPS {
            break;
        }
        // Search below the starting position first. A finite upward sweep then
        // backtracks that range and also covers controls above the start. No
        // assumption about a prior review's retained scroll offset is needed.
        let direction = if step < DOWNWARD_STEPS { -1.0 } else { 1.0 };
        frame(vec![
            egui::Event::PointerMoved(wheel_position()),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, direction * WHEEL_POINTS),
                phase: egui::TouchPhase::Move,
                modifiers: egui::Modifiers::NONE,
            },
        ]);
    }
    Err(AuthorityError::Permission)
}

pub(super) fn require_refusal(
    window: &mut Window,
    context: &egui::Context,
    label: &str,
) -> Result<()> {
    if crate::COMMON_CONTEXT_V3_ACTIVATION_QUALIFIED {
        return Err(AuthorityError::Conflict);
    }
    {
        let mut frame =
            |events| context.run_ui(fixture_input(events, true), |ui| window.draw(ui));
        let position = find_control(context, label, &mut frame)?;
        let event = |pressed| egui::Event::PointerButton {
            pos: position,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        frame(vec![egui::Event::PointerMoved(position), event(true)]);
        frame(vec![event(false)]);
    }
    // Exactly the original negative assertion, after an actual visible click.
    if window.job.is_some() || window.pending.is_some() || !window.can_select() {
        return Err(AuthorityError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    const PLAN: &str = "Authenticate signed V3 non-signing construction plan for review";
    const HANDOFF: &str = "Authenticate original-owner handoff admission for exact review";

    fn context() -> egui::Context {
        let context = egui::Context::default();
        super::super::configure_style(&context);
        context
    }

    fn render(context: &egui::Context, window: &mut Window) -> egui::FullOutput {
        context.run_ui(fixture_input(vec![], true), |ui| window.draw(ui))
    }

    #[test]
    fn wheel_navigation_reaches_actual_disabled_controls_without_mutating_form() {
        assert!(!crate::COMMON_CONTEXT_V3_ACTIVATION_QUALIFIED);
        let context = context();
        let mut window = Window::new();
        // Inert, valid JSON, deliberately tall. It is not a signed plan and
        // grants no authority. Actual signed-plan coverage is the native test.
        let original = serde_json::to_string_pretty(&serde_json::json!({
            "synthetic_renderer_rows": vec!["inert fixture row"; 2800]
        }))
        .unwrap();
        assert!(original.len() < crate::MAX_FRAME_BYTES);
        window.input.signed_manual_roster_construction_v3_json = Zeroizing::new(original.clone());
        window.input.signed_construction_transport_preauthorization_json =
            Zeroizing::new(original.clone());
        let initial = render(&context, &mut window);
        assert!(visible_position(&initial, PLAN).is_none());
        let editor_clip = initial
            .shapes
            .iter()
            .find_map(|clipped| {
                if let egui::epaint::Shape::Text(text) = &clipped.shape {
                    if text.galley.text() == original {
                        let text_bounds = text.galley.rect.translate(text.pos.to_vec2());
                        assert!(!text_bounds.contains(wheel_position()));
                        return Some(clipped.clip_rect);
                    }
                }
                None
            })
            .expect("actual populated multiline editor is painted");
        // TextEdit clips to its own inner rectangle, not the parent viewport.
        // The wheel is outside that editor. Reaching the initially hidden
        // control below it proves the outer selection area actually moved.
        assert!(!editor_clip.contains(wheel_position()));
        require_refusal(&mut window, &context, PLAN).unwrap();
        assert_eq!(
            &*window.input.signed_manual_roster_construction_v3_json,
            &original
        );
        assert!(window.job.is_none() && window.pending.is_none() && window.can_select());
        require_refusal(&mut window, &context, HANDOFF).unwrap();
        assert_eq!(
            &*window.input.signed_manual_roster_construction_v3_json,
            &original
        );
        // The earlier control is now above the retained scroll position. This
        // exercises the real upward fallback, not a scroll-state reset.
        require_refusal(&mut window, &context, PLAN).unwrap();
        assert_eq!(
            &*window.input.signed_construction_transport_preauthorization_json,
            &original
        );
        assert!(window.job.is_none() && window.pending.is_none() && window.can_select());
        assert_eq!(context.input(|input| input.viewport_rect()), viewport());
    }

    #[test]
    fn retained_receipt_scroll_is_independent_of_actual_selection_navigation() {
        let context = context();
        let mut window = Window::new();
        let original = serde_json::to_string_pretty(&serde_json::json!({
            "synthetic_renderer_rows": vec!["inert fixture row"; 2800]
        }))
        .unwrap();
        let receipt = serde_json::to_string_pretty(&serde_json::json!({
            "synthetic_display_only": vec!["not an authenticated receipt"; 128]
        }))
        .unwrap();
        // A private data-only display/clock fixture, never a completed ledger
        // row, native decision, namespace owner, or authenticated receipt.
        // This same clock remains in the Window throughout navigation.
        window.last_archive_receipt = Some((
            super::super::ReviewClock::start(None).unwrap(),
            Zeroizing::new(receipt.clone()),
        ));
        window.input.signed_manual_roster_construction_v3_json = Zeroizing::new(original.clone());
        let initial = render(&context, &mut window);
        let receipt_position = |output: &egui::FullOutput| {
            output
                .shapes
                .iter()
                .find_map(|shape| super::super::text_position(&shape.shape, &receipt))
                .expect("retained receipt text remains painted")
        };
        let before = receipt_position(&initial);
        assert!(visible_position(&initial, PLAN).is_none());
        require_refusal(&mut window, &context, PLAN).unwrap();
        let after = render(&context, &mut window);
        assert!(visible_position(&after, PLAN).is_some());
        assert_eq!(receipt_position(&after), before);
        let (original_clock, retained_display) = window.last_archive_receipt.as_ref().unwrap();
        original_clock.check().unwrap();
        assert_eq!(retained_display.as_str(), receipt);
        assert_eq!(window.input.signed_manual_roster_construction_v3_json.as_str(), original);
        assert!(window.job.is_none() && window.pending.is_none() && window.can_select());
    }

    #[test]
    fn same_parent_scroll_areas_use_distinct_stable_production_ids() {
        fn ids(explicit: bool) -> (egui::Id, egui::Id) {
            let context = context();
            let mut ids = None;
            context.run_ui(fixture_input(vec![], true), |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    let receipt = egui::ScrollArea::vertical().max_height(160.0);
                    let receipt = if explicit {
                        receipt.id_salt(super::super::COMPLETED_RECEIPT_SCROLL_ID)
                    } else {
                        receipt
                    };
                    let receipt = receipt.show(ui, |ui| ui.label("inert prior display"));
                    let selection = egui::ScrollArea::vertical();
                    let selection = if explicit {
                        selection.id_salt(super::super::OPERATION_SELECTION_SCROLL_ID)
                    } else {
                        selection
                    };
                    let selection = selection.show(ui, |ui| ui.label("inert current form"));
                    ids = Some((receipt.id, selection.id));
                });
            });
            ids.unwrap()
        }
        // The old defaults alias even for distinct same-parent controls.
        let legacy = ids(false);
        assert_eq!(legacy.0, legacy.1);
        let actual = ids(true);
        assert_ne!(actual.0, actual.1);
        assert_eq!(actual, ids(true));
    }

    #[test]
    fn missing_exact_control_stops_after_finite_wheel_events() {
        let context = context();
        let mut window = Window::new();
        let mut frames = 0;
        let mut wheels = 0;
        let result = find_control(&context, "not the exact public control", &mut |events| {
            frames += 1;
            wheels += events
                .iter()
                .filter(|event| matches!(event, egui::Event::MouseWheel { .. }))
                .count();
            context.run_ui(fixture_input(events, true), |ui| window.draw(ui))
        });
        assert!(matches!(result, Err(AuthorityError::Permission)));
        assert_eq!(wheels, MAX_WHEEL_STEPS);
        assert!(frames <= 1 + (MAX_WHEEL_STEPS + 1) * (MAX_SETTLE_FRAMES + 2));
        assert!(window.job.is_none() && window.pending.is_none() && window.can_select());
    }

    #[test]
    fn exact_label_requires_visible_clip_and_viewport() {
        let context = context();
        let mut window = Window::new();
        let output = render(&context, &mut window);
        assert!(visible_position(&output, PLAN).is_some());
        assert!(visible_position(&output, "Authenticate signed V3").is_none());
        let point = visible_position(&output, PLAN).unwrap();
        assert!(viewport().contains(point));
        assert!(viewport().contains(wheel_position()));
        let mut clipped = output;
        for shape in &mut clipped.shapes {
            shape.clip_rect = egui::Rect::NOTHING;
        }
        assert!(visible_position(&clipped, PLAN).is_none());
    }
}
