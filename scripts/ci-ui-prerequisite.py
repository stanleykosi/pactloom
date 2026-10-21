#!/usr/bin/env python3
"""Reuse only CI70's historical successful bootstrap prerequisite, never its failed UI."""
import hashlib
import json
import subprocess
import sys
import urllib.request
import urllib.error
import time
import socket

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
    "scripts/ci-ui-controller.py", "scripts/tests/test_ci_ui_controller.py",
    "scripts/ci-ui-weston-module.c",
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
# Exact reviewed CI-only diagnostic delta. Bootstrap excludes wholepact_delivery_ci.
# This is NOT permission for other Rust changes or reuse of the old UI binaries.
CI_DIAGNOSTIC_HASHES = {'crates/wholepact-authority/src/native_witness_owner/coordinated_delivery_append_v1.rs': ('b8c51672832e8c3530ee1fad1b1b2abd7cad41e5aaf9a1874c4b5c6804c447fb', '83ba6e5d2a759598156a2b1958bb8ed81ce3c97e4da0a22c99749f94f86ebb79'), 'crates/wholepact-authority/src/native_witness_owner/coordinated_delivery_append_v1/presentation.rs': ('d864faba68c3c3c775f4faa50944d5ad22a6b822a8f28e3c40daba391849e58a', 'c5b43800450c1c7d1a5251a695ac36f19310cd017b448a2a25f175b144ac5106'), 'crates/wholepact-financial-coordinator-origin/src/delivery_observer.rs': ('99a7bb782a7da4e8d6a9a8ff01e9fac00110dbe6174528bfd1f1e4d50e4a63b3', 'fe5e2b316d72caca19d32d5b8dac155dec99fec1a0a327fefc233d414b8dcc8d'), 'crates/wholepact-financial-coordinator-origin/src/lib.rs': ('9d2500892dfebce39a66dfbe998b1664e68b20cc64fe003a9d6797e74b0b7e31', '81a48e3d5837a9bdd3eb90e90df0bdcf2d8132c0fe60462a7784b56e50f7d9b1'), 'crates/wholepact-financial-coordinator/src/delivery_ui.rs': ('01e07c4dbcc9da938e67a12bb9d059b25350b4f592516603a512799227c7c1e8', 'e5dbb8f321689b51b9e3ab97f70f80e42921eca7b368345a2aa2e693209efd00')}
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

def verify_paths(paths, fixture_hashes=None, diagnostic_hashes=None):
    changed = set(paths)
    if FIXTURE in changed:
        if fixture_hashes != (FIXTURE_BEFORE, FIXTURE_AFTER):
            raise ValueError("test_fixture_delta")
        changed.remove(FIXTURE)
    diagnostic_paths = changed & CI_DIAGNOSTIC_HASHES.keys()
    if diagnostic_paths:
        if diagnostic_paths != CI_DIAGNOSTIC_HASHES.keys() or diagnostic_hashes != CI_DIAGNOSTIC_HASHES:
            raise ValueError("ci_diagnostic_delta")
        changed -= diagnostic_paths
    if not changed <= ALLOWED:
        raise ValueError("source_closure_changed")

# Fixed public reason codes only. Never emit exception text, response bodies or paths.
FAILURE_CODES = frozenset(("job_identity", "run_identity", "historical_prerequisite",
    "test_fixture_delta", "ci_diagnostic_delta", "source_closure_changed", "baseline_tree", "working_tree",
    "evidence_size"))
def failure_code(error):
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in FAILURE_CODES:
        return error.args[0]
    if isinstance(error, subprocess.TimeoutExpired):
        return "git_timeout"
    if isinstance(error, subprocess.CalledProcessError):
        return "git_command"
    if isinstance(error, urllib.error.HTTPError):
        return "evidence_http"
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "evidence_timeout"
    if isinstance(error, urllib.error.URLError):
        return "evidence_timeout" if isinstance(error.reason, (TimeoutError, socket.timeout)) else "evidence_network"
    if isinstance(error, (json.JSONDecodeError, UnicodeDecodeError)):
        return "evidence_json"
    return "evidence_or_internal"

def fetch_evidence(request):
    """Same exact public GET, at most two attempts; no credentials or fallback.

    Only explicit gateway/service transient failures retry. Authorization,
    rate-limit, missing evidence and invalid evidence always fail immediately.
    Each request retains the original 20-second socket timeout and byte ceiling.
    """
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read(262145)
            if len(raw) > 262144:
                raise ValueError("evidence_size")
            return json.loads(raw)
        except urllib.error.HTTPError as error:
            retry = attempt == 0 and error.code in (502, 503, 504)
            error.close()  # body is neither read nor emitted
            if not retry: raise
            time.sleep(0.25)
    raise AssertionError("unreachable")

def failure_suffix(error):
    # A numeric HTTP status is safe; URLs, bodies, headers and exception text are not.
    if isinstance(error, urllib.error.HTTPError) and type(error.code) is int and 100 <= error.code <= 599:
        return " http_status=" + str(error.code)
    return ""

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
        diagnostic_hashes = {
            path: tuple(hashlib.sha256(git("show", rev + ":" + path)).hexdigest() for rev in (BASE, "HEAD"))
            for path in paths if path in CI_DIAGNOSTIC_HASHES}
        verify_paths(paths, fixture_hashes, diagnostic_hashes)
        request = urllib.request.Request(
            "https://api.github.com/repos/stanleykosi/pactloom/actions/runs/39604966999/jobs?per_page=100",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "pactloom-public-prerequisite"})
        verify_jobs(fetch_evidence(request))
    except Exception as error:
        print("CI_UI_PREREQUISITE historical_reuse=false verified=false code=" + failure_code(error) + failure_suffix(error), flush=True)
        return 1
    print("CI_UI_PREREQUISITE historical_reuse=true verified=true run=39604966999 job=119238687858 source=" + BASE + " current_bootstrap_executed=false", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
