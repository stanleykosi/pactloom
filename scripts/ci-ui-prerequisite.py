#!/usr/bin/env python3
"""Reuse only CI70's historical successful bootstrap prerequisite, never its failed UI."""
import hashlib
import json
import subprocess
import sys
import urllib.request

BASE = "e2ad650efe7d9a5db94662e6713b7447fc4f6f81"
TREE = "2233fea29dd353be0b47fd71d107fac5106df68c"
RUN = 39604966999
JOB = 119238687858
ALLOWED = frozenset((
    ".github/workflows/durable-native-linux.yml",
    "scripts/ci-ui-image.py", "scripts/ci-ui-supervisor.py",
    "scripts/tests/test_ci_ui_image.py", "scripts/tests/test_ci_ui_supervisor.py",
    "scripts/ci-ui-prerequisite.py", "scripts/tests/test_ci_ui_prerequisite.py",
    "scripts/ci-ui-setup-wrapper.py", "scripts/ci-ui-output.py",
    "scripts/ci-ui-container.py", "scripts/tests/test_ci_ui_setup.py",
    "scripts/tests/test_ci_ui_container.py",
    "scripts/ci-ui-artifacts.py", "scripts/tests/test_ci_ui_artifacts.py",
    "scripts/ci-ui-reuse.py", "scripts/tests/test_ci_ui_reuse.py",
    "scripts/ci-ui-reuse-runner.py", "scripts/tests/test_ci_ui_reuse_runner.py",
    "scripts/ci-ui-reuse-pin.json", "scripts/ci-ui-linux.sh",
))
# This one cfg(test) Host fixture is NOT in the bootstrap production image.
# Permit only the independently reviewed exact parent-side O_NOCTTY correction,
# not arbitrary Rust changes or a broadened path allowlist.
FIXTURE = "crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification.rs"
FIXTURE_BEFORE = "cb895f688b0060d858d0a61fe1958ac105a0ebb877a613dd035157ba3d73d34c"
FIXTURE_AFTER = "74024b0ab7fd7d1931d3fbd369598290b481ace0346baf5498b08f96bb79117c"
STEPS = (
    "Isolated bootstrap profile (UI uses seven reap/lifetime prerequisites)",
    "Verify bootstrap containers and temporary image removed",
)

def verify_jobs(value):
    jobs = value.get("jobs", [])
    matches = [j for j in jobs if j.get("id") == JOB]
    if len(matches) != 1:
        raise ValueError("job_identity")
    job = matches[0]
    if (job.get("run_id"), job.get("run_attempt"), job.get("head_sha"),
        job.get("head_branch"), job.get("status"), job.get("conclusion")) != (
        RUN, 1, BASE, "qualification/durable-proposal-v1", "completed", "failure"):
        raise ValueError("run_identity")
    for name in STEPS:
        rows = [s for s in job.get("steps", []) if s.get("name") == name]
        if len(rows) != 1 or rows[0].get("status") != "completed" or rows[0].get("conclusion") != "success":
            raise ValueError("historical_prerequisite")

def verify_paths(paths, fixture_hashes=None):
    changed = set(paths)
    if FIXTURE in changed:
        if fixture_hashes != (FIXTURE_BEFORE, FIXTURE_AFTER):
            raise ValueError("test_fixture_delta")
        changed.remove(FIXTURE)
    if not changed <= ALLOWED:
        raise ValueError("source_closure_changed")

# Fixed public reason codes only. Never emit exception text, response bodies or paths.
FAILURE_CODES = frozenset(("job_identity", "run_identity", "historical_prerequisite",
    "test_fixture_delta", "source_closure_changed", "baseline_tree", "working_tree",
    "evidence_size"))
def failure_code(error):
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in FAILURE_CODES:
        return error.args[0]
    if isinstance(error, subprocess.TimeoutExpired):
        return "git_timeout"
    if isinstance(error, subprocess.CalledProcessError):
        return "git_command"
    return "evidence_or_internal"

def git(*args):
    return subprocess.check_output(["git", *args], timeout=30, stderr=subprocess.DEVNULL)

def main():
    try:
        if git("rev-parse", BASE + "^{tree}").decode().strip() != TREE:
            raise ValueError("baseline_tree")
        if git("status", "--porcelain", "--untracked-files=all"):
            raise ValueError("working_tree")
        paths = git("diff", "--no-renames", "--name-only", "-z", BASE, "HEAD").decode().split("\0")
        paths = [p for p in paths if p]
        fixture_hashes = None
        if FIXTURE in paths:
            fixture_hashes = tuple(hashlib.sha256(git("show", rev + ":" + FIXTURE)).hexdigest() for rev in (BASE, "HEAD"))
        verify_paths(paths, fixture_hashes)
        request = urllib.request.Request(
            "https://api.github.com/repos/stanleykosi/pactloom/actions/runs/39604966999/jobs?per_page=100",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "pactloom-public-prerequisite"})
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(262145)
        if len(raw) > 262144:
            raise ValueError("evidence_size")
        verify_jobs(json.loads(raw))
    except Exception as error:
        print("CI_UI_PREREQUISITE historical_reuse=false verified=false code=" + failure_code(error), flush=True)
        return 1
    print("CI_UI_PREREQUISITE historical_reuse=true verified=true run=39604966999 job=119238687858 source=" + BASE + " current_bootstrap_executed=false", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
