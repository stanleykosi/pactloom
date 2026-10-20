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

def run(executable):
    # Exact selection plus mandatory closed summary rejects absent/ignored tests
    # without an unbounded catalogue subprocess.
    process = subprocess.Popen([executable, TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    row = None
    pending = bytearray()
    total = 0
    status = None
    deadline = time.monotonic() + 90
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ)
            while selected.get_map():
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                for key, _ in selected.select(timeout=0.5):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > 65536:
                        raise ValueError()
                    pending.extend(chunk)
                    while b"\n" in pending:
                        line, _, rest = pending.partition(b"\n")
                        pending = bytearray(rest)
                        if len(line) > 4096:
                            raise ValueError()
                        harness = ("test " + TEST + " ... ").encode()
                        if line.startswith(harness):
                            line = line[len(harness):]
                        if PREFIX in line:
                            if row is not None or not line.startswith(PREFIX):
                                raise ValueError()
                            row = validate(json.loads(line[len(PREFIX):], object_pairs_hook=unique_object))
                    if len(pending) > 4096:
                        raise ValueError()
        if PREFIX in pending:
            raise ValueError()
        status = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        if status is None:
            process.kill()
            process.wait(timeout=10)
    if status != 0 or row is None or not row["cleanup_verified"] or not all(row["cases"].values()):
        raise ValueError()
    print(PREFIX.decode() + json.dumps(row, sort_keys=True, separators=(",", ":")), flush=True)
    print("CI_CONNECT_DRIVER_RESULT passed=true payment_verified=false", flush=True)

if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError()
        run(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
    except Exception:
        print("CI_CONNECT_DRIVER_RESULT passed=false details_withheld=true cleanup_unverified=true", flush=True)
        sys.exit(1)
