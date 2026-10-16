#!/usr/bin/env python3
"""Only runs the metadata planner. Never invoke the host, signer or any runtime.

Usage: python3 joined_acceptance_plan.py /absolute/planner /absolute/source-root
All fixture IDs are synthetic strings; no account or financial fixture exists.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY = Path(sys.argv[1]).resolve()
SOURCE = Path(sys.argv[2]).resolve()
del sys.argv[1:3]


class PlannerCli(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wholepact-plan-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "metadata.json"
        self.value = {
            "schema_version": 1,
            "route": "ordinary_two_owner",
            "network": "testnet",
            "dispatch": "disabled",
            "originals": {},
        }
        self.write()

    def write(self):
        self.config.write_text(json.dumps(self.value), encoding="utf-8")

    def run_plan(self, *extra, source=SOURCE, config=None):
        return subprocess.run(
            [str(BINARY), "--dry-run", "--config", str(config or self.config),
             "--source-root", str(source), *extra],
            cwd=self.root, capture_output=True, text=True, timeout=15, check=False,
        )

    def test_empty_dry_run_reports_pending_and_leaves_files_unchanged(self):
        before = self.config.read_bytes()
        result = self.run_plan()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["plan"]["runtime_qualification"], "not_run")
        self.assertEqual(report["plan"]["product_acceptance"], "not_established")
        self.assertFalse(report["plan"]["execution_enabled"])
        self.assertFalse(report["plan"]["dispatch_enabled"])
        self.assertEqual(len(report["plan"]["stages"]), 13)
        self.assertTrue(all(item["status"] == "source_marker_present_not_qualified"
                            for item in report["source_inventory"]))
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [self.config])

    def test_no_execution_or_dispatch_switch_is_accepted(self):
        for argument in ["--execute", "--dispatch", "--enable-dispatch", "--simulate-success"]:
            result = self.run_plan(argument)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(result.stdout)

    def test_explicit_dry_run_is_required(self):
        result = subprocess.run(
            [str(BINARY), "--config", str(self.config), "--source-root", str(SOURCE)],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stdout)

    def test_source_gaps_are_distinct_from_missing_runtime_prerequisites(self):
        empty_source = self.root / "empty-source"
        empty_source.mkdir()
        result = self.run_plan(source=empty_source)
        self.assertEqual(result.returncode, 3)
        report = json.loads(result.stdout)
        self.assertTrue(all(item["status"].startswith("source_gap")
                            for item in report["source_inventory"]))
        self.assertTrue(report["plan"]["prerequisites"])
        self.assertEqual(report["plan"]["runtime_qualification"], "not_run")

    def test_prior_original_replacement_is_rejected_without_echoing_ids(self):
        self.value["originals"] = {"job_id": "synthetic-original-job"}
        self.write()
        prior = self.root / "prior.json"
        prior.write_bytes(self.config.read_bytes())
        self.value["originals"]["job_id"] = "synthetic-substituted-job"
        self.write()
        result = self.run_plan("--prior-config", str(prior))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stdout)
        self.assertNotIn("synthetic-", result.stderr)

    def test_config_symlink_device_and_oversized_file_are_rejected(self):
        linked = self.root / "link.json"
        linked.symlink_to(self.config)
        self.assertEqual(self.run_plan(config=linked).returncode, 2)
        self.assertEqual(self.run_plan(config=Path("/dev/null")).returncode, 2)
        self.config.write_bytes(b" " * 65_537)
        self.assertEqual(self.run_plan().returncode, 2)

    def test_linked_source_root_or_ancestor_is_not_followed(self):
        link = self.root / "source-link"
        link.symlink_to(SOURCE, target_is_directory=True)
        result = self.run_plan(source=link)
        self.assertEqual(result.returncode, 3)
        source = self.root / "source"
        source.mkdir()
        (source / "crates").symlink_to(SOURCE / "crates", target_is_directory=True)
        result = self.run_plan(source=source)
        self.assertEqual(result.returncode, 3)
        report = json.loads(result.stdout)
        self.assertTrue(all(item["status"].startswith("source_gap") for item in report["source_inventory"]))

    def test_private_fields_and_approval_flags_are_not_echoed(self):
        for key in ["fvk", "credential", "peer_fvk_accepted", "approved"]:
            self.value[key] = "synthetic-do-not-echo"
            self.write()
            result = self.run_plan()
            self.assertEqual(result.returncode, 2)
            self.assertFalse(result.stdout)
            self.assertNotIn("synthetic-do-not-echo", result.stderr)
            del self.value[key]


if __name__ == "__main__":
    unittest.main(verbosity=2)
