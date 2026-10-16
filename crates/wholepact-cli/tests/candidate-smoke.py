#!/usr/bin/env python3
"""Real CLI -> authenticated service -> durable store. Synthetic claims only."""
import hashlib
import json
import pathlib
import socket
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
CLI = ROOT / "target/debug/wholepact"
SERVICE = ROOT / "target/debug/wholepact-service"
checks = []


def check(label, passed):
    assert passed, label
    checks.append(label)


with tempfile.TemporaryDirectory(prefix="wholepact-candidate-cli-") as tmp:
    tmp = pathlib.Path(tmp)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = [str(CLI), "--development-fixture", "--json", "--server", f"http://127.0.0.1:{port}"]

    def cli(*args):
        result = subprocess.run(base + list(map(str, args)), capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout), result.stderr

    def start():
        process = subprocess.Popen([str(SERVICE), "--development-fixture", "--bind", f"127.0.0.1:{port}", "--database", str(tmp / "synthetic.sqlite")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if process.poll() is not None:
                raise AssertionError("Synthetic service exited before readiness")
            try:
                cli("health")
                return process
            except AssertionError:
                time.sleep(.05)
        process.terminate()
        process.wait(timeout=10)
        raise AssertionError("Service readiness timed out")

    def file(name, value):
        path = tmp / name
        path.write_text(json.dumps(value))
        return path

    payload = json.loads((ROOT / "crates/wholepact-engine/tests/fixtures/candidate-request.json").read_text())
    agreement = payload["manifest"]["agreement"]
    agreement_id = agreement["agreement_id"]
    candidate_file = file("candidate.json", payload)
    process = start()
    try:
        created, _ = cli("agreements", "create", file("agreement.json", agreement), "--idempotency-key", "cli-candidate-agreement")
        check("CLI created exact synthetic agreement", created["revision"] == 1)
        for index, participant in enumerate(payload["manifest"]["participants"]):
            intent = dict(intent_id=f"intent-{index}", agreement_id=agreement_id, participant_id=participant["participant_id"], desired_contribution=participant["contribution"], maximum_net_debit=participant["maximum_net_debit"], fee_cap=participant["fee_cap"], conditions=[], valid_until=None, status="active")
            cli("intents", "add", agreement_id, file(f"intent-{index}.json", intent), "--revision", index + 1, "--idempotency-key", f"cli-candidate-intent-{index}")
        frozen, metadata = cli("candidates", "create", agreement_id, candidate_file, "--revision", 3, "--idempotency-key", "cli-candidate-freeze")
        candidate_id = frozen["candidates"][0]["candidate_id"]
        operation_id = next(line.removeprefix("Operation ID: ") for line in metadata.splitlines() if line.startswith("Operation ID: "))
        check("CLI exposes durable operation ID", bool(operation_id))
        shown, _ = cli("candidates", "show", candidate_id)
        check("CLI returns the frozen manifest", shown["proposal"]["manifest"] == payload["manifest"])
        reviewed, _ = cli("candidates", "verify", candidate_id, "--revision", 4, "--idempotency-key", "cli-candidate-review")
        report = reviewed["candidates"][0]["reviews"][0]
        check("CLI review stays nonbinding", report["status"] == "claims_checked_only" and not report["authorization_allowed"] and not report["economic_terms_verified"])
        process.terminate()
        process.wait(timeout=10)
        process = start()
        replay, metadata = cli("candidates", "create", agreement_id, candidate_file, "--revision", 3, "--idempotency-key", "cli-candidate-freeze")
        check("CLI exact replay survives process restart", replay == frozen and f"Operation ID: {operation_id}" in metadata)
        operation, _ = cli("operation", operation_id)
        check("CLI fetches original successful operation", operation["operation_id"] == operation_id and operation["status"] == "succeeded")
        latest, _ = cli("agreements", "show", agreement_id)
        check("Restart preserves unknown metadata exposure and chain axes", latest["revision"] == 5 and latest["authorization_exposure"] == "unknown" and latest["chain_observation"] == "unknown")
        roster_file = file("roster.json", {"selected_intent_ids": ["intent-0", "intent-1"]})
        selected, _ = cli("intents", "select", agreement_id, roster_file, "--revision", 5, "--idempotency-key", "cli-planning-roster-0001")
        check("CLI selects a nonbinding exact roster", selected["roster_selected"] and all(i["status"] == "selected" for i in selected["intents"]))
        preview, _ = cli("proposals", "create", agreement_id, "--revision", 6, "--idempotency-key", "cli-planning-preview-0001")
        older_preview = preview["proposals"][0]["proposal_id"]
        withdrawn, _ = cli("intents", "withdraw", agreement_id, "intent-0", "--revision", 7, "--idempotency-key", "cli-planning-withdraw-01")
        check("Selected withdrawal preserves explicit roster history", withdrawn["roster_selected"] and withdrawn["intents"][0]["status"] == "withdrawn")
        successor = json.loads(json.dumps(payload))
        successor["previous_candidate_id"] = candidate_id
        successor["manifest"]["expiry_height"] += 1
        successor_file = file("successor.json", successor)
        rejected = subprocess.run(base + ["candidates", "create", agreement_id, str(successor_file), "--revision", "8", "--idempotency-key", "cli-planning-invalid-01"], capture_output=True, text=True, timeout=30)
        check("Incomplete selected roster cannot silently fall back", rejected.returncode != 0)
        replacement = dict(intent_id="intent-alice-renewed", agreement_id=agreement_id, participant_id=payload["manifest"]["participants"][0]["participant_id"], desired_contribution=payload["manifest"]["participants"][0]["contribution"], maximum_net_debit=payload["manifest"]["participants"][0]["maximum_net_debit"], fee_cap=payload["manifest"]["participants"][0]["fee_cap"], conditions=[], valid_until=None, status="active")
        cli("intents", "add", agreement_id, file("renewed-intent.json", replacement), "--revision", 8, "--idempotency-key", "cli-planning-renewed-01")
        cli("intents", "select", agreement_id, file("renewed-roster.json", {"selected_intent_ids":["intent-alice-renewed", "intent-1"]}), "--revision", 9, "--idempotency-key", "cli-planning-roster-0002")
        newer, _ = cli("proposals", "create", agreement_id, "--revision", 10, "--idempotency-key", "cli-planning-preview-0002")
        comparison, _ = cli("proposals", "compare", older_preview, newer["proposals"][1]["proposal_id"])
        check("Terms comparison requires fresh review and has no signing grant", comparison["material_change"] and comparison["renewed_review_required"] and not comparison["signable"])
        successor_state, _ = cli("candidates", "create", agreement_id, successor_file, "--revision", 11, "--idempotency-key", "cli-planning-successor-01")
        successor_id = successor_state["candidates"][1]["candidate_id"]
        comparison, _ = cli("candidates", "compare", candidate_id, successor_id)
        check("Candidate comparison identifies exact changed expiry", any(c["field"] == "expiry_height" for c in comparison["changes"]) and not comparison["signable"])
        jobs, _ = cli("candidates", "proof-jobs", successor_id)
        check("Cached job status makes no liveness or authorization assertion", jobs["jobs"] == [] and not jobs["current_worker_liveness_known"] and not jobs["authorization_allowed"])
        recovery, _ = cli("recovery")
        check("Recovery refuses new authority while observations are stale", recovery["observation_stale"] and not recovery["new_authorization_allowed"])
        participants = payload["manifest"]["participants"]
        sponsor_terms = dict(schema_version=1, network_profile_id=agreement["network_profile_id"], agreement_scope=[agreement_id], sponsor=dict(participant_id=participants[1]["participant_id"], account_id=participants[1]["account_id"]), eligible_contributors=[dict(participant_id=participants[0]["participant_id"], account_id=participants[0]["account_id"])], beneficiaries=[dict(recipient_id=r["recipient_id"], address=r["address"], maximum_amount=r["amount"]) for r in agreement["recipients"]], rate_numerator=2, rate_denominator=1, maximum_match="200000", minimum_qualifying_total="0", fee_cap="10000", maximum_net_debit="210000", aggregate_budget="500000", assurance={"kind":"independently_verified"}, identity_requirements=[], privacy_profile=agreement["privacy_profile"], expires_at=None)
        sponsor_request = file("sponsor-policy.json", {"policy_id":"synthetic-sponsor-policy", "terms":sponsor_terms})
        policy, _ = cli("sponsors", "create", agreement_id, sponsor_request, "--revision", 12, "--idempotency-key", "cli-sponsor-policy-create")
        check("Reusable sponsor policy creates constraints without authority", policy["policy"]["state"] == "draft" and not policy["policy"]["authorization_allowed"])
        preview_file = file("sponsor-preview.json", {"candidate_id":successor_id, "expected_policy_version":1})
        preview, _ = cli("sponsors", "preview", agreement_id, "synthetic-sponsor-policy", preview_file)
        check("Sponsor formula is exact but unverifiable with unknown exposure", preview["formula"]["evaluation"]["calculated_match"] == "200000" and preview["status"] == "match_unverifiable" and preview["budget"]["remaining_budget"] is None)
        paused, _ = cli("sponsors", "state", agreement_id, "synthetic-sponsor-policy", file("sponsor-paused.json", {"policy_id":"synthetic-sponsor-policy", "expected_policy_version":1, "state":"paused"}), "--revision", 13, "--idempotency-key", "cli-sponsor-policy-pause")
        check("Paused sponsor preparation remains non-authorizing", paused["policy"]["state"] == "paused" and not paused["policy"]["authorization_allowed"])
        refused = subprocess.run(base + ["sponsors", "preview", agreement_id, "synthetic-sponsor-policy", str(preview_file)], capture_output=True, text=True, timeout=30)
        check("Paused policy cannot preview fresh matching", refused.returncode != 0 and "INVALID_TRANSITION" in refused.stderr)
        health, _ = cli("health")
        check("Ordinary service reports no operator or background observation", health["operator_status"] == "not_configured" and not health["background_observation"] and health["operator_tasks"] is None)
        invitations = subprocess.run(base + ["invitations", "list"], capture_output=True, text=True, timeout=30)
        check("Invitation CLI never invents an inbox when native runtime is absent", invitations.returncode != 0 and "UNSUPPORTED_CAPABILITY" in invitations.stderr)
        for resource in ["accounts", "authorizations", "records"]:
            unavailable = subprocess.run(base + [resource], capture_output=True, text=True, timeout=30)
            check(f"{resource} is unavailable rather than reported empty", unavailable.returncode != 0 and "UNSUPPORTED_CAPABILITY" in unavailable.stderr)

    finally:
        process.terminate()
        process.wait(timeout=10)

report = dict(scope="synthetic-claimed-candidate-cli-api-no-witness-signing-or-chain", checks=checks, service_sha256=hashlib.sha256(SERVICE.read_bytes()).hexdigest(), cli_sha256=hashlib.sha256(CLI.read_bytes()).hexdigest())
destination = ROOT / "reports/client-flow-cli-acceptance.json"
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(dict(passed=len(checks), report=str(destination))))
