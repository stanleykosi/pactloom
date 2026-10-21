#!/usr/bin/env python3
"""Reuse only CI70's historical successful bootstrap prerequisite, never its failed UI."""
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
))
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

def verify_paths(paths):
    if not set(paths) <= ALLOWED:
        raise ValueError("source_closure_changed")

def git(*args):
    return subprocess.check_output(["git", *args], timeout=30, stderr=subprocess.DEVNULL)

def main():
    try:
        if git("rev-parse", BASE + "^{tree}").decode().strip() != TREE:
            raise ValueError("baseline_tree")
        if git("status", "--porcelain", "--untracked-files=all"):
            raise ValueError("working_tree")
        paths = git("diff", "--no-renames", "--name-only", "-z", BASE, "HEAD").decode().split("\0")
        verify_paths([p for p in paths if p])
        request = urllib.request.Request(
            "https://api.github.com/repos/stanleykosi/pactloom/actions/runs/39604966999/jobs?per_page=100",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "pactloom-public-prerequisite"})
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(262145)
        if len(raw) > 262144:
            raise ValueError("evidence_size")
        verify_jobs(json.loads(raw))
    except Exception:
        print("CI_UI_PREREQUISITE historical_reuse=false verified=false", flush=True)
        return 1
    print("CI_UI_PREREQUISITE historical_reuse=true verified=true run=39604966999 job=119238687858 source=" + BASE + " current_bootstrap_executed=false", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
