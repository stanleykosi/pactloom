#!/usr/bin/env python3
"""Closed public projection for the real, never-funded financial lifecycle.

No raw child text, transaction material, paths or exception strings are printed.
This is synthetic native integration, never evidence of public-chain settlement.
"""
import json
import os
import pathlib
import selectors
import subprocess
import sys
import time

TEST = (
    "host::manual_enrollment::command::roster_publication_v2::"
    "sequential_construction_v3::qualification::durable_proposal_v1::"
    "delivery_admission_v2::durable_financial_dispatch_v1::"
    "original_two_owner_financial_continuation_survives_process_death"
)
PREFIX = b"CI_SYNTHETIC_DURABLE_FINANCIAL "
BOUNDARIES = frozenset(
    "OriginalPreparation ContinuationAdmission SignatureAndIntake "
    "FinalTransactionRetention ProducerDeath CompletedReopen DispatchAdmission "
    "PartialAdmissionReconciliation SavedTransactionDispatch ReaderReap RootCleanup".split()
)
OUTCOMES = frozenset("complete refused uncertain expired conflict unverified".split())
PROOFS = frozenset(
    "producer_reaped producer_group_absent reader_reaped reader_group_absent "
    "source_prefix_preserved both_continuations_authenticated "
    "both_results_before_process_death exact_completed_reopen_after_death "
    "identical_saved_bytes_dispatched partial_admission_reconciled "
    "bounded_admission_retry_same_bytes original_expiry_preserved stale_head_refused".split()
)
FIELDS = PROOFS | {
    "schema", "result", "first_failure", "boundary_outcome", "root_cleanup",
    "completed_extraction_checkpoint_count", "dedicated_dispatch_admissions",
    "synthetic_backend_only", "public_chain_verified",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def validate(row):
    if not isinstance(row, dict) or set(row) != FIELDS:
        raise ValueError()
    if type(row["schema"]) is not int or row["schema"] != 1:
        raise ValueError()
    if row["result"] not in ("passed", "failed"):
        raise ValueError()
    if row["first_failure"] is not None and row["first_failure"] not in BOUNDARIES:
        raise ValueError()
    if row["boundary_outcome"] is not None and row["boundary_outcome"] not in OUTCOMES:
        raise ValueError()
    if (row["first_failure"] is None) != (row["boundary_outcome"] is None):
        raise ValueError()
    if row["root_cleanup"] not in ("closed_absent", "unverified"):
        raise ValueError()
    for key in PROOFS | {"synthetic_backend_only", "public_chain_verified"}:
        if type(row[key]) is not bool:
            raise ValueError()
    for key, maximum in (("completed_extraction_checkpoint_count", 1), ("dedicated_dispatch_admissions", 2)):
        if type(row[key]) is not int or not 0 <= row[key] <= maximum:
            raise ValueError()
    if not row["synthetic_backend_only"] or row["public_chain_verified"]:
        raise ValueError()
    if row["result"] == "passed":
        if (
            not all(row[key] for key in PROOFS)
            or row["first_failure"] is not None
            or row["root_cleanup"] != "closed_absent"
            or row["completed_extraction_checkpoint_count"] != 1
            or row["dedicated_dispatch_admissions"] != 2
        ):
            raise ValueError()
    return row


def run(executable):
    # Rust's exact selector plus the mandatory validated completion summary
    # fail closed if the test is absent or ignored. Do not capture an unbounded
    # catalogue merely to establish a selector already fixed in this script.
    process = subprocess.Popen(
        [executable, TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    row = None
    pending = bytearray()
    overlong = False
    deadline = time.monotonic() + 1800
    status = None
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ)
            while selected.get_map():
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                for key, _ in selected.select(timeout=1):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    for byte in chunk:
                        if byte == 10:
                            if overlong:
                                raise ValueError()
                            line = bytes(pending).rstrip(b"\r")
                            harness_prefix = ("test " + TEST + " ... ").encode()
                            if line.startswith(harness_prefix):
                                line = line[len(harness_prefix):]
                            if PREFIX in line:
                                if overlong or row is not None or not line.startswith(PREFIX):
                                    raise ValueError()
                                row = validate(json.loads(
                                    line[len(PREFIX):],
                                    object_pairs_hook=unique_object,
                                ))
                            pending.clear()
                            overlong = False
                        elif len(pending) < 4096:
                            pending.append(byte)
                        else:
                            overlong = True
            if overlong or PREFIX in pending:
                raise ValueError()
        status = process.wait(timeout=10)
    finally:
        if status is None:
            process.kill()
            process.wait(timeout=10)
            print("CI_FINANCIAL_RESULT cleanup_unverified=true passed=false", flush=True)
    if row is not None and (status == 0 or row["result"] != "passed"):
        print(PREFIX.decode() + json.dumps(row, sort_keys=True, separators=(",", ":")), flush=True)
    if status != 0 or row is None or row["result"] != "passed":
        raise RuntimeError()
    print("CI_FINANCIAL_RESULT passed=true public_chain_verified=false", flush=True)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError()
        exe = pathlib.Path(sys.argv[1]).resolve(strict=True)
        target = pathlib.Path(os.environ["CARGO_TARGET_DIR"]).resolve(strict=True)
        if not exe.is_file() or not exe.is_relative_to(target):
            raise ValueError()
        run(str(exe))
    except Exception:
        print("CI_FINANCIAL_RESULT passed=false details_withheld=true", flush=True)
        sys.exit(1)
