#!/usr/bin/env python3
"""Closed isolated real-TLS mechanism evidence, never payment qualification."""
import json
import os
import pathlib
import selectors
import subprocess
import sys
import time

TEST = "connect_driver_tests::independent_connect_preserves_tls_deadline_and_cancellation"
PREFIX = b"CI_SYNTHETIC_CONNECT_DRIVER "
CASES = frozenset("direct_scheduling http_connect_scheduling cancel_before_poll cancel_during_tls drop_unconsumed_connected_result original_deadline tls_hostname_refusal".split())
FIELDS = {"schema", "cases", "cleanup_verified", "current_thread_guarantee", "public_chain_verified"}

def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError()
        out[key] = value
    return out

def validate(row):
    if type(row) is not dict or set(row) != FIELDS:
        raise ValueError()
    if type(row["schema"]) is not int or row["schema"] != 1:
        raise ValueError()
    if type(row["cases"]) is not dict or set(row["cases"]) != CASES:
        raise ValueError()
    if any(type(value) is not bool for value in row["cases"].values()):
        raise ValueError()
    if any(type(row[key]) is not bool for key in FIELDS - {"schema", "cases"}):
        raise ValueError()
    if row["current_thread_guarantee"] or row["public_chain_verified"]:
        raise ValueError()
    return row

OBSERVATION = b"CI_SYNTHETIC_CONNECT_DRIVER_OBSERVATION "
FAILURE = b"CI_SYNTHETIC_CONNECT_DRIVER_FAILURE "
CONTEXT_CASES = frozenset("unstarted direct_inline direct_driven http_connect_inline http_connect_driven cancel_before_poll expired_before_poll cancel_during_tls stalled_deadline drop_unconsumed queued_deadline direct_hostname_refusal http_connect_hostname_refusal".split())
PHASES = frozenset("started caller_resumed connect_returned assertions_passed cleanup_verified cleanup_started probe_started".split())
CHECKS = frozenset("none expect_no_http expect_local_owner expect_driven_success expect_tls_success expect_no_tls_timeout probe_ready probe_unary expect_probe_count expect_inline_failure expect_tls_timeout socket_close server_join proxy_join expect_initial_pending expect_hostname_refusal expect_accepted expect_no_tls_success caller_accepted driver_finished expect_driver_started expect_driver_success expect_original_timeout stalled_server_join".split())
COUNTS = frozenset("accepted tls_success tls_timeout tls_errors sockets_closed http_requests proxy_headers proxy_target_connected proxy_copy_finished".split())
COMMON = COUNTS | {"schema", "case", "phase", "active_check", "counts_available", "counts_clamped", "cleanup_verified", "outcome", "proxy_copy_outcome"}
OUTCOMES = frozenset("unobserved success timeout transport_unavailable other_error".split())

def validate_context(row, failure=False):
    extra = {"source_unit", "line", "column"} if failure else set()
    if type(row) is not dict or set(row) != COMMON | extra:
        raise ValueError()
    if type(row["schema"]) is not int or row["schema"] != 1:
        raise ValueError()
    for key, values in (("case", CONTEXT_CASES), ("phase", PHASES), ("active_check", CHECKS)):
        if type(row[key]) is not str or row[key] not in values:
            raise ValueError()
    if any(type(row[k]) is not int or not 0 <= row[k] <= 16 for k in COUNTS):
        raise ValueError()
    if any(type(row[k]) is not bool for k in ("counts_available", "counts_clamped", "cleanup_verified")):
        raise ValueError()
    if not row["counts_available"] and (any(row[k] for k in COUNTS) or row["counts_clamped"] or row["proxy_copy_outcome"] != "none"):
        raise ValueError()
    if type(row["outcome"]) is not str or row["outcome"] not in OUTCOMES:
        raise ValueError()
    if type(row["proxy_copy_outcome"]) is not str or row["proxy_copy_outcome"] not in {"none", "success", "io_error", "timeout"}:
        raise ValueError()
    if failure:
        if type(row["source_unit"]) is not str or row["source_unit"] not in {"connect_driver_tests", "connect_driver", "ephemeral_tls", "other"} or row["cleanup_verified"]:
            raise ValueError()
        for key, cap in (("line", 10000), ("column", 1000)):
            if type(row[key]) is not int or not 0 <= row[key] <= cap:
                raise ValueError()
    elif row["cleanup_verified"] != (row["phase"] == "cleanup_verified"):
        raise ValueError()
    return row

class ClosedFailure(Exception):
    pass

def run(executable, timeout_seconds=90):
    # Exact selector and mandatory summary reject absence without a catalogue.
    process = subprocess.Popen([executable, TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    row = last = first_failure = None
    pending = bytearray()
    total = records = 0
    status = None
    reason = None
    reaped = False
    deadline = time.monotonic() + timeout_seconds
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ)
            while selected.get_map():
                if time.monotonic() >= deadline:
                    raise ClosedFailure("Timeout")
                for key, _ in selected.select(timeout=min(0.5, max(0, deadline-time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > 65536:
                        raise ClosedFailure("OutputLimit")
                    pending.extend(chunk)
                    while b"\n" in pending:
                        line, _, rest = pending.partition(b"\n")
                        pending = bytearray(rest)
                        if len(line) > 4096:
                            raise ClosedFailure("OutputLimit")
                        harness = ("test " + TEST + " ... ").encode()
                        if line.startswith(harness):
                            line = line[len(harness):]
                        for prefix in (OBSERVATION, FAILURE, PREFIX):
                            if prefix not in line:
                                continue
                            if not line.startswith(prefix):
                                raise ClosedFailure("MalformedRecord")
                            records += 1
                            if records > 128:
                                raise ClosedFailure("OutputLimit")
                            value = json.loads(line[len(prefix):], object_pairs_hook=unique_object)
                            if prefix == OBSERVATION:
                                last = validate_context(value)
                            elif prefix == FAILURE:
                                if first_failure is not None:
                                    raise ClosedFailure("DuplicateFailure")
                                first_failure = validate_context(value, True)
                            else:
                                if row is not None:
                                    raise ClosedFailure("DuplicateSummary")
                                row = validate(value)
                            break
                    if len(pending) > 4096:
                        raise ClosedFailure("OutputLimit")
        if any(prefix in pending for prefix in (OBSERVATION, FAILURE, PREFIX)):
            raise ClosedFailure("MalformedRecord")
        status = process.wait(timeout=max(0.1, deadline-time.monotonic()))
        reaped = True
    except ClosedFailure as error:
        reason = error.args[0]
    except (ValueError, UnicodeError, TypeError, KeyError):
        reason = "MalformedRecord"
    except subprocess.TimeoutExpired:
        reason = "Timeout"
    except Exception:
        reason = "ProcessError"
    finally:
        if not reaped:
            try:
                process.kill()
                status = process.wait(timeout=10)
                reaped = True
            except Exception:
                reason = "ProcessError"
    if reason is None:
        if first_failure is not None:
            reason = "FailureObserved"
        elif status != 0:
            reason = "NonzeroExit"
        elif row is None:
            reason = "MissingSummary"
        elif not row["cleanup_verified"]:
            reason = "UnverifiedCleanup"
        elif not all(row["cases"].values()):
            reason = "IncompleteCases"
    if reason is not None:
        # Only previously validated finite values survive a later malformed line.
        # Direct child reaping is not a claim of socket/descendant cleanup.
        diagnostic = {"schema": 1, "reason": reason, "child_reaped": reaped,
                      "first_failure": first_failure if reaped else None,
                      "last_observation": last if reaped else None}
        print("CI_CONNECT_DRIVER_DIAGNOSTIC " + json.dumps(diagnostic, sort_keys=True, separators=(",", ":")), flush=True)
        print("CI_CONNECT_DRIVER_RESULT passed=false details_withheld=true cleanup_unverified=true", flush=True)
        return False
    print(PREFIX.decode() + json.dumps(row, sort_keys=True, separators=(",", ":")), flush=True)
    print("CI_CONNECT_DRIVER_RESULT passed=true payment_verified=false", flush=True)
    return True

if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError()
        passed = run(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
    except Exception:
        print("CI_CONNECT_DRIVER_RESULT passed=false details_withheld=true cleanup_unverified=true", flush=True)
        passed = False
    sys.exit(0 if passed else 1)
