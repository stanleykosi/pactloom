//! Real egui editing and production text-routing predicates only. These tests
//! construct no Window, retained metadata, native ticket, command, or file.

use super::{
    HostEntry, Phase, scrub_unrequested_payloads, selector_events_bounded,
    selector_export_input_allowed, selector_export_phase, selector_path_valid,
};
use eframe::egui;

const EXPORT_PHASES: [Phase; 5] = [
    Phase::SetupNeeded, Phase::Selecting, Phase::SignCommitted,
    Phase::SignedRetired, Phase::ReturnCompleted,
];
const DESTINATIONS: [&str; 4] = [
    "/tmp/signer1-continue-selector.json", "/tmp/signer2-continue-selector.json",
    "/tmp/signer1-result-selector.json", "/tmp/signer2-result-selector.json",
];

#[derive(Clone, Copy)]
struct RouteFacts {
    phase: Phase,
    focused: bool,
    revoked: bool,
    host: HostEntry,
    has_selector: bool,
}
impl RouteFacts {
    fn eligible(phase: Phase) -> Self {
        Self { phase, focused: true, revoked: false, host: HostEntry::Idle, has_selector: true }
    }
    fn allows_export_input(self) -> bool {
        selector_export_input_allowed(
            self.phase, self.focused, self.revoked, self.host, self.has_selector,
        )
    }
}

fn payload_count(events: &[egui::Event]) -> usize {
    events.iter().filter(|event| matches!(event,
        egui::Event::Text(_) | egui::Event::Paste(_) | egui::Event::Ime(_)
    )).count()
}

#[derive(Default)]
struct PassObservation {
    focused: bool,
    changed: bool,
    before_scrub: (usize, usize),
    after_scrub: (usize, usize),
}

struct Editor {
    ctx: egui::Context,
    text: String,
    frame: u64,
}
impl Editor {
    fn id() -> egui::Id { egui::Id::new("selector-export-regression") }
    fn focused() -> Self {
        let mut editor = Self { ctx: egui::Context::default(), text: String::new(), frame: 0 };
        editor.pass(Vec::new(), true, None);
        let established = editor.pass(Vec::new(), false, None);
        assert!(established.focused);
        assert!(!established.changed && editor.text.is_empty());
        assert!(editor.ctx.memory(|memory| memory.owns_ime_events(Self::id())));
        editor
    }
    fn pass(&mut self, events: Vec<egui::Event>, request_focus: bool, cleanup: Option<Phase>) -> PassObservation {
        self.frame += 1;
        let mut raw = egui::RawInput {
            time: Some(self.frame as f64 / 60.0),
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(640.0, 240.0))),
            events,
            ..Default::default()
        };
        raw.viewports.get_mut(&egui::ViewportId::ROOT).unwrap().focused = Some(true);
        let ctx = self.ctx.clone();
        let mut observed = PassObservation::default();
        let mut output = ctx.run_ui(raw, |ui| {
            let response = ui.add(egui::TextEdit::singleline(&mut self.text).id(Self::id()));
            if request_focus { response.request_focus(); }
            observed.focused = response.has_focus();
            observed.changed |= response.changed();
            observed.before_scrub = ctx.input(|input|
                (payload_count(&input.events), payload_count(&input.raw.events)));
            if cleanup.is_some_and(selector_export_phase) {
                ctx.input_mut(|input| {
                    scrub_unrequested_payloads(&mut input.events);
                    scrub_unrequested_payloads(&mut input.raw.events);
                });
            }
            observed.after_scrub = ctx.input(|input|
                (payload_count(&input.events), payload_count(&input.raw.events)));
        });
        // No headless test uploads textures. Clear before assertions or drop.
        output.textures_delta.clear();
        assert_eq!(output.platform_output.num_completed_passes, 1);
        observed
    }
}

fn edit_export_batch(facts: RouteFacts, mut events: Vec<egui::Event>, old_scrub: bool)
    -> (String, PassObservation, bool)
{
    let mut editor = Editor::focused();
    // Only routing/bounds are exercised here. Production native revocation on
    // malformed input and protected-owner precedence are source-bound below.
    let forwarded = !old_scrub && facts.allows_export_input() && selector_events_bounded(&events);
    if !forwarded { scrub_unrequested_payloads(&mut events); }
    // Keep the fixture editor focused even for a false routing focus fact:
    // denial must come from the production gate, not accidental egui blur.
    let observed = editor.pass(events, false, Some(facts.phase));
    assert!(observed.focused);
    assert_eq!(observed.after_scrub, (0, 0));
    (editor.text, observed, forwarded)
}

fn payloads(value: &str) -> [egui::Event; 3] {
    [egui::Event::Text(value.into()), egui::Event::Paste(value.into()),
        egui::Event::Ime(egui::ImeEvent::Commit(value.into()))]
}

#[test]
fn export_payloads_reach_focused_textedit_only_after_native_gate() {
    for phase in EXPORT_PHASES {
        for path in DESTINATIONS {
            for event in payloads(path) {
                let facts = RouteFacts::eligible(phase);
                let (old, observed, forwarded) = edit_export_batch(facts, vec![event.clone()], true);
                assert!(!forwarded && old.is_empty() && !observed.changed);
                assert!(!selector_path_valid(&old));

                let (fixed, observed, forwarded) = edit_export_batch(facts, vec![event], false);
                assert!(forwarded && observed.changed);
                assert_eq!(fixed, path);
                assert!(selector_path_valid(&fixed));
                assert!(observed.before_scrub.0 > 0 && observed.before_scrub.1 > 0);
            }
        }
    }
}

#[test]
fn export_input_gate_denies_wrong_phase_focus_revocation_host_and_missing_selector() {
    let valid = RouteFacts::eligible(Phase::SetupNeeded);
    let mut denied = vec![
        RouteFacts { focused: false, ..valid }, RouteFacts { revoked: true, ..valid },
        RouteFacts { host: HostEntry::Editing(1), ..valid },
        RouteFacts { host: HostEntry::Writing(1), ..valid },
        RouteFacts { has_selector: false, ..valid },
    ];
    for phase in [Phase::Reading, Phase::HistoryRetiring, Phase::RetirementBlocked,
        Phase::SigningRetiring, Phase::NormalClosing, Phase::Password, Phase::V3Password,
        Phase::Revoked, Phase::Finished] {
        assert!(!selector_export_phase(phase));
        denied.push(RouteFacts { phase, ..valid });
    }
    // Configuring has its own existing ordinary-selector route; it is not an
    // export phase, rather than a newly forbidden general text-input phase.
    assert!(!selector_export_phase(Phase::Configuring));
    for facts in denied {
        assert!(!facts.allows_export_input());
        let (text, observed, forwarded) = edit_export_batch(facts,
            vec![egui::Event::Text(DESTINATIONS[0].into())], false);
        assert!(!forwarded && text.is_empty() && !observed.changed);
    }
    // Closed is not an editing/writing owner, matching the unchanged Save gate.
    for phase in EXPORT_PHASES {
        assert!(RouteFacts::eligible(phase).allows_export_input());
        assert!(RouteFacts { host: HostEntry::Closed, ..RouteFacts::eligible(phase) }
            .allows_export_input());
    }
}

#[test]
fn export_payload_bounds_prevent_normalization_and_preserve_path_limit() {
    let facts = RouteFacts::eligible(Phase::SetupNeeded);
    for value in ["/tmp/line\npath", "/tmp/line\rpath", "/tmp/nul\0path"] {
        let mut cases = payloads(value).to_vec();
        cases.push(egui::Event::Ime(egui::ImeEvent::Preedit {
            text: value.into(), active_range_chars: None,
        }));
        for event in cases {
            assert!(!selector_events_bounded(std::slice::from_ref(&event)));
            let (text, observed, forwarded) = edit_export_batch(facts, vec![event], false);
            assert!(!forwarded && text.is_empty() && !observed.changed);
        }
    }
    for events in [vec![egui::Event::Text("x".repeat(32769))],
        vec![egui::Event::Text("x".repeat(20000)), egui::Event::Paste("y".repeat(20000))]] {
        assert!(!selector_events_bounded(&events));
        let (text, observed, forwarded) = edit_export_batch(facts, events, false);
        assert!(!forwarded && text.is_empty() && !observed.changed);
    }
    // Batch acceptance does not widen the independent final destination limit.
    for (length, valid) in [(4096, true), (4097, false)] {
        let path = format!("/{}", "x".repeat(length - 1));
        let events = vec![egui::Event::Text(path.clone())];
        assert!(selector_events_bounded(&events));
        let (text, observed, forwarded) = edit_export_batch(facts, events, false);
        assert!(forwarded && observed.changed);
        assert_eq!(text, path);
        assert_eq!(selector_path_valid(&text), valid);
    }
    assert!(!selector_path_valid(""));
    assert!(!selector_path_valid("relative-selector.json"));
}

#[test]
fn export_routing_is_bound_to_native_fields_and_postpass_scrub() {
    let source = include_str!("../financial_source_ui.rs");
    let hook = source.split_once("impl eframe::App for Window {").unwrap().1
        .split_once("    fn ui(").unwrap().0;
    let host = hook.find("if let Some(input) = &mut self.host_input").unwrap();
    let password = hook.find("else if let Some(input) = &mut self.password").unwrap();
    let export = hook.find("selector_export_input_allowed(").unwrap();
    let bounds = hook.find("if !selector_events_bounded(&raw.events)").unwrap();
    assert!(hook.find("self.interrupt(raw_facts(raw), ctx);").unwrap() < host);
    assert!(host < password && password < export && export < bounds);
    assert!(hook.contains("selector_export_input_allowed(\n                self.phase,\n                self.focused_last,\n                self.native.is_revoked(),\n                self.host_entry,\n                self.retained_continue.iter().any(Option::is_some)\n                    || self.result_selectors.iter().any(Option::is_some),\n            )"));
    let branch = &hook[bounds..];
    assert!(branch.find("self.revoke(").unwrap()
        < branch.find("scrub_unrequested_payloads(&mut raw.events);").unwrap());

    let draw = source.split_once("    fn draw(&mut self, ui: &mut egui::Ui) {").unwrap().1
        .split_once("    fn apply_intent(").unwrap().0;
    assert!(draw.contains("if matches!(self.phase, Phase::SetupNeeded | Phase::Selecting | Phase::SignCommitted | Phase::SignedRetired | Phase::ReturnCompleted) {"));
    assert!(draw.contains("TextEdit::singleline(&mut continuation_paths_in_pass[i])"));
    assert!(draw.contains("TextEdit::singleline(&mut result_paths_in_pass[i])"));
    assert!(draw.contains(") || selector_export_phase(painted_phase) {\n            ctx.input_mut(|input| {\n                scrub_unrequested_payloads(&mut input.events);\n                scrub_unrequested_payloads(&mut input.raw.events);\n            });"));
    assert!(draw.contains("if eligible && self.phase == painted_phase {\n            if continuation_paths_in_pass.iter().chain(result_paths_in_pass.iter()).all(|p| p.len() <= 4096 && !p.contains('\\0'))"));

    // Complete full-flow public TextEdit inventory: two export fields, four
    // already-routed JSON/config fields, one ordinary-selector field factory,
    // and one explicitly noninteractive continuation metadata display.
    assert_eq!(source.matches("egui::TextEdit::").count(), 8);
    assert_eq!(source.matches("egui::TextEdit::multiline(&mut text).interactive(false)").count(), 1);
}
