#!/usr/bin/env python3
"""Source-bound V3 deadline regression; not an authority/full-flow fixture."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "crates/wholepact-financial-coordinator-origin/src"


def read(name):
    return (SRC / name).read_text(encoding="utf-8")


def block(source, marker):
    """Extract these reviewed Rust blocks, preserving their actual contents."""
    assert source.count(marker) == 1, marker
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for pos in range(opening, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise AssertionError("Unclosed block: " + marker)


def compact(source):
    return re.sub(r"\s+", "", source)


receipt = read("signer_v3_receipt_origin.rs")
redisclosure = read("signer_v3_redisclosure_origin.rs")
clock_source = read("financial_workflow_clock.rs")
entry_source = read("signer_v3_source_entry_origin.rs")

cases = [
    (receipt, "Enrollment", "enrollment", "original_review_deadline", None,
     "enrollment_retains_exact_local_review_deadline"),
    (receipt, "Manifest", "manifest", "original_review_deadline", None,
     "manifest_retains_exact_local_review_deadline"),
    (redisclosure, "RedisclosureRead", "redisclosure_read",
     "original_read_deadline", "original_review_deadline",
     "redisclosure_read_retains_exact_local_review_deadline"),
    (redisclosure, "Redisclose", "redisclose", "original_export_deadline",
     "original_review_deadline",
     "redisclose_retains_exact_local_review_deadline"),
]

rust = [
    "use std::sync::Arc;",
    "use std::time::{Duration, Instant};",
    "type Result<T> = std::result::Result<T, &'static str>;",
    "fn rejected(message: &'static str) -> &'static str { message }",
    "#[derive(Clone)]",
    "struct Carrier { deadline: Instant, original_review: Instant }",
]

assert clock_source.count("#[cfg(test)]") == 1
clock_source = clock_source.split("#[cfg(test)]", 1)[0]
clock_source = clock_source.replace(
    "use crate::{rejected, Result};", "use super::{rejected, Result};")
rust.append("mod clocks {\n" + clock_source + "\n}")
rust.append("use clocks::{FullWorkflowClocksV1, PROFILE};")

wall = block(entry_source, "pub(super) fn wall_ceiling(")
rust.append(wall.replace("pub(super)", "pub(crate)", 1))

for source, family, offer_name, getter_name, alias_name, test_name in cases:
    binding_name = family + "Binding"
    final_name = "SignerV3" + family + "FinalV1"
    binding_struct = block(source, "struct " + binding_name + " {")
    binding_impl = block(source, "impl " + binding_name + " {")
    constructor = block(binding_impl, "fn new(")
    bounds = block(binding_impl, "fn bounds(")
    offer = block(source, "pub fn offer_v3_" + offer_name + "(")
    final_impl = block(source, "impl " + final_name + " {")
    getter = block(final_impl, "pub fn " + getter_name + "(")

    bs = compact(binding_struct)
    ctor = compact(constructor)
    bd = compact(bounds)
    of = compact(offer)

    assert "deadline:Instant," in bs
    assert "original_review:Instant," in bs
    assert "original_review:deadline," in ctor
    assert ".restrict_received(PROFILE,p.review_ceiling_ms," in ctor
    assert ".min(wall_ceiling(" in ctor
    assert "b.bounds()?;" in ctor
    assert "self.pair.channel_bounds()?;" in bd
    assert "Instant::now()>=self.deadline" in bd
    assert "wall<old" in bd
    assert "wall<self.p.facts.reviewed_at_ms" in bd
    assert "wall>=self.p.facts.expires_at_ms" in bd

    assert ".restrictive_offset(original_review,pair.channel_deadline)?" in of
    assert "original_review>pair.channel_deadline" in of
    assert "original_review>Instant::now()+Duration::from_secs(120)" in of
    assert ".deadline=original_review" not in of
    assert "binding.bounds()?;" not in of
    assert compact(getter).endswith("{self.binding.original_review}")
    assert (
        f"{binding_name}::new(Arc::clone(pair),presentation.clone())?"
        in compact(source)
    )

    setter_start = offer.index("Arc::get_mut(&mut binding)")
    assignment = ".original_review = original_review;"
    setter_end = offer.index(assignment, setter_start) + len(assignment)
    setter = offer[setter_start:setter_end]
    assert "ok_or_else" in setter
    assert setter_end < offer.index("self.core.phase.step")
    assert setter_end < offer.index("binding = Some(binding)")
    assert setter_end < offer.index("self.send(")

    rust.append(f"struct {final_name} {{ binding: Arc<Carrier> }}")
    methods = getter
    if alias_name:
        alias = block(final_impl, "pub fn " + alias_name + "(")
        assert compact(alias).endswith("{self.binding.deadline}")
        methods += "\n" + alias
    rust.append(f"impl {final_name} {{\n{methods}\n}}")
    rust.append(
        f"fn retain_{offer_name}(mut binding: Arc<Carrier>, "
        "original_review: Instant) -> Result<Arc<Carrier>> {\n"
        + setter + "\nOk(binding)\n}"
    )

    alias_assertion = (
        f"assert_eq!(action.{alias_name}(), operative);"
        if alias_name else ""
    )
    rust.append(f"""
#[test]
fn {test_name}() {{
    let epoch = Instant::now();
    let clocks = FullWorkflowClocksV1::from_initial_epoch(epoch).unwrap();
    let cap = epoch + Duration::from_secs(60);
    for micros in [0, 999] {{
        let raw = epoch + Duration::from_secs(30)
            + Duration::from_micros(micros);
        let wire = clocks.restrictive_offset(raw, cap).unwrap();
        assert_eq!(wire, 30_000);
        let operative = clocks.restrict_received(
            PROFILE, wire, cap, epoch).unwrap();
        assert_eq!(operative, epoch + Duration::from_secs(30));
        if micros != 0 {{
            assert_ne!(operative, raw);
        }}
        let received = Arc::new(Carrier {{
            deadline: operative, original_review: operative
        }});
        assert_eq!(received.original_review, operative);
        let binding = retain_{offer_name}(received, raw).unwrap();
        assert_eq!(binding.deadline, operative);
        let action = {final_name} {{ binding }};
        assert_eq!(action.{getter_name}(), raw);
        assert_ne!(action.{getter_name}(), raw + Duration::from_nanos(1));
        {alias_assertion}
        assert_eq!(clocks.restrict_received(
            PROFILE, wire, cap, epoch + Duration::from_secs(20)
        ).unwrap(), operative);
        assert!(clocks.restrict_received(
            PROFILE, wire, cap, operative).is_err());

        let wall_cap = wall_ceiling(epoch, 1_000, 900, 1_010).unwrap();
        assert_eq!(wall_cap, epoch + Duration::from_millis(10));
        let shortened = operative.min(wall_cap);
        let binding = retain_{offer_name}(Arc::new(Carrier {{
            deadline: shortened, original_review: shortened
        }}), raw).unwrap();
        assert_eq!(binding.deadline, shortened);
        let action = {final_name} {{ binding }};
        assert_eq!(action.{getter_name}(), raw);
        assert!(shortened < raw);
        assert!(wall_ceiling(epoch, 1_010, 900, 1_010).is_err());
        assert!(wall_ceiling(epoch, 899, 900, 1_010).is_err());
    }}
    let carrier = Arc::new(Carrier {{ deadline: cap, original_review: cap }});
    let shared = Arc::clone(&carrier);
    assert!(retain_{offer_name}(carrier, cap).is_err());
    assert_eq!(shared.deadline, cap);
}}
""")

with tempfile.TemporaryDirectory(prefix="v3-deadline-source-test-") as tmp:
    tmp = Path(tmp)
    generated = tmp / "deadline_identity.rs"
    executable = tmp / "deadline_identity_tests"
    generated.write_text("\n".join(rust), encoding="utf-8")
    version = subprocess.run(
        ["rustc", "--version"], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
    ).stdout.strip()
    assert version == "rustc 1.99.0 (b940084d7 2026-09-28)", version
    subprocess.run(
        ["rustc", "--edition=2021", "--test", str(generated),
         "-o", str(executable)],
        check=True, timeout=60,
    )
    listed = subprocess.run(
        [str(executable), "--list"], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
    ).stdout
    expected = sorted(case[-1] + ": test" for case in cases)
    assert sorted(line for line in listed.splitlines()
                  if line.endswith(": test")) == expected
    result = subprocess.run(
        [str(executable), "--test-threads=1", "--nocapture"],
        check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30,
    )
    print(result.stdout)
    assert "test result: ok. 4 passed; 0 failed; 0 ignored;" in result.stdout
    print("Four exact source-extracted inert-carrier tests passed; not authority or full-flow proof.")
