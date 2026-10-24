#!/usr/bin/env python3
"""Source binding only. Real egui compilation/execution is a separate gate."""
import argparse,hashlib,json,pathlib,re
PINS = {'crates/wholepact-financial-coordinator/src/financial_source_ui.rs': 'e7eab264c493c758e8723576fb476b1373204502d35d125113ede6d537dbdc96', 'crates/wholepact-financial-coordinator/src/financial_ci.rs': 'e182c4622284d2cade734a216d72d1d4613407205222780d40768101b6d5ee2a', 'crates/wholepact-financial-coordinator/Cargo.toml': '3f3a40630ce8f008052d776d7a649c63dca8bac1bd5e9b450945dd563b52a4da', 'scripts/ci-financial-weston-module.c': '598439c725869c977e827baa4c3f535cdf472150dce278d9b03482046ebf44b1', 'scripts/ci-financial-container.py': '2b5769a8ecbcac522232c4af97ba718c42a64b9dda690ea66ddc59cd5bf2603f', 'Cargo.lock': '72be33ff3e072216414cad1cc66b1f5363bdcea1c5ec29c087e09103fc815c29'}
UI = 'crates/wholepact-financial-coordinator/src/financial_source_ui.rs'
CI = 'crates/wholepact-financial-coordinator/src/financial_ci.rs'
TEST = 'crates/wholepact-financial-coordinator/src/financial_source_ui/egui_layout_tests.rs'
BLOCKS = [('            #[cfg(test)]\n            egui_layout_tests::record_outer_geometry(&output);\n', ''), ('            #[cfg(all(test, wholepact_financial_ci))]\n            egui_layout_tests::record_end_geometry(end.rect, end_visible);\n', ''), ('    #[cfg(all(test, wholepact_financial_ci))]\n    egui_layout_tests::record_review_geometry(&_ci_scroll);\n', ''), ('\n#[cfg(all(test, wholepact_financial_ci))]\n#[path = "financial_source_ui/egui_layout_tests.rs"]\nmod egui_layout_tests;\n', '')]
CI_TAIL = '\n// Test-only readback of the existing content-free observer; no runtime emitter.\n#[cfg(test)]\npub(super) fn take_layout_test_snapshot() -> Value {\n    FRAME.with(|cell| {\n        let mut f = cell.borrow_mut();\n        assert!(!f.failed, "layout observer rejected actual geometry");\n        let mut facts = f.facts.take().expect("layout frame began");\n        facts["widgets"] = Value::Array(std::mem::take(&mut f.widgets));\n        facts\n    })\n}\n'
TEST_SHA = 'd4e95e7d88259b9cfc5d6108ff46d2dd2ce7c07cc88b45d98ca966afb0753408'
EXPORT = 'crates/wholepact-signer/src/consent_journal/durable_delivery_admission_intent_v3/coordinated_v1/full_intent_validation_tests/retained_report_tests.rs'
EXPORT_BASE_SHA = '032745ce733a8c43f87387bcda831f2ff9b0a07da4d181b6c5663ec992d8fa92'
EXPORT_BASE_BYTES = 12177
EXPORT_TAIL_SHA = 'f9dc18dc4f76b96fcc156005093613779d81178070cf109ea77d482362931b89'
def sha(b): return hashlib.sha256(b).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=pathlib.Path,required=True);a=p.parse_args()
    ui=(a.source/UI).read_text(); ci=(a.source/CI).read_text()
    for old,new in BLOCKS:
        assert ui.count(old)==1, 'exact test-only UI hook'
        ui=ui.replace(old,new)
    assert ci.endswith(CI_TAIL) and ci.count(CI_TAIL)==1
    ci=ci[:-len(CI_TAIL)]
    for path,digest in PINS.items():
        b=ui.encode() if path==UI else ci.encode() if path==CI else (a.source/path).read_bytes()
        assert sha(b)==digest, 'exact runtime source closure '+path
    test=(a.source/TEST).read_text();assert sha(test.encode())==TEST_SHA
    exported=(a.source/EXPORT).read_bytes()
    assert sha(exported[:EXPORT_BASE_BYTES])==EXPORT_BASE_SHA, 'unchanged actual P58 regression'
    assert sha(exported[EXPORT_BASE_BYTES:])==EXPORT_TAIL_SHA, 'reviewed additive data-only export'
    # Bind the data-only effective header to actual initialization and mutation
    # sites, not a guessed amount of blank space or a toy viewport.
    clauses=[
        'self.message = "Original Pair completed only after actual StatusProof. Later Read/receive/admission/audit remain separately unapproved.";',
        'progress: [Progress::NotStarted; 2]', 'continue_effect: [ContinueEffect::None; 2]',
        'signer_display: [None, None]', 'signer_effect: [AdmissionEffect::None; 2]',
        'witness_effect: [AdmissionEffect::None; 2]',
        'self.signer_display[i] = Some(p.clone());',
        'self.progress[index(role)] = Progress::Working;',
        'self.phase = phase;\n        self.phase_frame = frame;\n        self.intent = None;\n        self.read_to_end = false;\n        self.acknowledged = false;',
        'serde_json::to_string_pretty(&serde_json::json!({"exact_admission":p,"authenticated_ready":self.v3_admit_ready_data[i]}))',
        '.max_height(390.0)', 'ui.monospace(display);',
        'end_visible = eligible && ui.is_rect_visible(end.rect);',
        'egui::ScrollArea::vertical().id_salt("financial-ci-full-panel")',
        'let options = eframe::NativeOptions {', '..Default::default()',
    ]
    assert all(c in ui for c in clauses), 'actual header/formatter/layout binding'
    for text in (
        'Arm this exact admission request to obtain one authenticated READY on the retained original owner connection. No local publication or final remote send yet.',
        'Arm exact V3 admission',
    ):
        assert text in ui and text in test, 'exact actual notice/action text'
    assert 'self.read_to_end&&self.acknowledged&&later_frame' in ui
    assert 'arm_enabled=read_to_end&&acknowledged&&frame>0;' in test
    assert 'tail_eligible(frame,last_tail,visible,ctx.will_discard())' in test
    assert all(x not in ui for x in ('set_fonts(', 'set_style(', 'set_zoom_factor(', 'set_pixels_per_point('))
    assert '"default_fonts"' in (a.source/'crates/wholepact-financial-coordinator/Cargo.toml').read_text()
    assert "'--scale=1'" in (a.source/'scripts/ci-financial-container.py').read_text()
    assert 'o->current_scale == 1' in (a.source/'scripts/ci-financial-weston-module.c').read_text()
    # Currentness/Final/OS event routing are intentionally not manufactured.
    assert 'let ctx=egui::Context::default();' in test and 'ctx.run_ui(raw,' in test
    assert 'review_display(ui,&text,' in test and 'ci_panel!(ui,' in test
    assert 'review_progress_after_pass(' in test and 'v3_admission_tail_eligible(' in test
    assert 'egui::TouchPhase::Move' in test and 'egui::TouchPhase::Start' in test
    print(json.dumps({'source_bound':True,'runtime_changed':False,'real_egui_executed':False,'genuine_authority_executed':False,'restored_sources':len(PINS)},sort_keys=True))
if __name__=='__main__':main()
