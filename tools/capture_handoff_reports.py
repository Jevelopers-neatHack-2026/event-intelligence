#!/usr/bin/env python3
"""Capture four local handoff reports. Capture success never means readiness."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

KINDS = ("handoff-contracts", "handoff-metering", "provider-readiness", "handoff-consumer")
MANIFEST = "tests/contracts/handoff-manifest.json"
LIMIT = 1_048_576
TIMEOUT = 30
ROOT = Path(__file__).resolve().parent.parent


def utc():
    return datetime.now(timezone.utc).isoformat()


def run_bounded(argv, cwd, output, name, *, timeout=TIMEOUT, limit=LIMIT):
    """Retain bounded raw streams; kill the process group on timeout/overflow."""
    result = {"argv": list(argv), "started_at": utc(), "exit_code": None, "fault": None}
    paths = {key: output / (name + "." + key) for key in ("stdout", "stderr")}
    sizes = dict.fromkeys(paths, 0)
    proc = None
    deadline = time.monotonic() + timeout
    killed_at = None
    with paths["stdout"].open("xb") as out, paths["stderr"].open("xb") as err:
        files = {"stdout": out, "stderr": err}
        with selectors.DefaultSelector() as selector:
            try:
                proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True, shell=False)
                selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
                selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map() or proc.poll() is None:
                    now = time.monotonic()
                    if killed_at is None and (result["fault"] or now >= deadline):
                        result["fault"] = result["fault"] or "timeout"
                        killed_at = now
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if killed_at is not None and now - killed_at >= 1:
                        result["drain_incomplete"] = bool(selector.get_map())
                        break
                    for key, _ in selector.select(0.02):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        remaining = limit - sizes[key.data]
                        files[key.data].write(chunk[:remaining])
                        sizes[key.data] += min(len(chunk), remaining)
                        if len(chunk) > remaining:
                            result["fault"] = result["fault"] or "output_limit"
                try:
                    result["exit_code"] = proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    result["fault"] = result["fault"] or "reap_timeout"
            except OSError:
                result["fault"] = result["fault"] or "process_error"
            finally:
                if proc is not None:
                    if proc.poll() is None:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            proc.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
                    for stream in (proc.stdout, proc.stderr):
                        if stream is not None and not stream.closed:
                            stream.close()
    result["completed_at"] = utc()
    result["streams"] = {
        key: {"file": path.name, "retained_bytes": path.stat().st_size,
              "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for key, path in paths.items()
    }
    result["streams_complete"] = result["fault"] is None
    return result


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def reject_constant(_):
    raise ValueError("non-finite JSON")


def validate_report(raw, exit_code, kind):
    """Validate capture consistency only, not external evidence or authority."""
    report = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                        parse_constant=reject_constant)
    if type(report) is not dict or type(exit_code) is not int:
        raise ValueError("report/exit shape")
    expected = {"tool": "event-intelligence-handoff-checker", "tool_version": "0.1.0",
                "kind": kind, "manifest": MANIFEST}
    if any(report.get(key) != value for key, value in expected.items()):
        raise ValueError("report identity")
    if report.get("ready") is not False or type(report.get("exit_code")) is not int:
        raise ValueError("readiness/exit shape")
    status = report.get("readiness_status")
    if (status, report["exit_code"], exit_code) not in (("BLOCKED", 1, 1), ("INVALID", 2, 2)):
        raise ValueError("exit/status mismatch")
    checks, missing, summary = (report.get(key) for key in
                                ("checks", "missing_deliverables", "summary"))
    if type(checks) is not list or type(missing) is not list or type(summary) is not dict:
        raise ValueError("report collections")
    if any(type(item) is not dict or type(item.get("status")) is not str for item in checks):
        raise ValueError("check shape")
    if any(type(item) is not dict for item in missing):
        raise ValueError("missing-deliverable shape")
    counts = {"checks": len(checks), "missing_deliverables": len(missing),
              "failed_or_invalid": sum(item["status"] in ("invalid", "mismatch", "fail")
                                       for item in checks)}
    if any(type(summary.get(key)) is not int or summary[key] != count
           for key, count in counts.items()):
        raise ValueError("summary mismatch")
    if status == "INVALID" or counts["failed_or_invalid"] or not missing:
        raise ValueError("invalid or unexpectedly unblocked report")
    return {**expected, "readiness_status": status, "ready": False, "exit_code": exit_code,
            "summary": summary}


def source_identity(output, phase):
    values = {}
    records = []
    for name, args in (("head", ["rev-parse", "--verify", "HEAD"]),
                       ("tree", ["rev-parse", "--verify", "HEAD^{tree}"]),
                       ("status", ["status", "--porcelain=v1", "--untracked-files=all"])):
        run = run_bounded(["git", *args], ROOT, output, phase + "-" + name,
                          timeout=10, limit=65536)
        records.append(run)
        if run["fault"] or run["exit_code"] != 0:
            raise ValueError("source identity unavailable")
        values[name] = (output / run["streams"]["stdout"]["file"]).read_text().strip()
    if not all(re.fullmatch(r"[0-9a-f]{40}", values[key]) for key in ("head", "tree")):
        raise ValueError("source identity malformed")
    if values["status"]:
        raise ValueError("source is not clean")
    return {**values, "commands": records}


def capture_scopes(output):
    results = []
    for kind in KINDS:
        argv = [sys.executable, "-I", "-B", "tools/verify_handoff.py",
                "--kind", kind, "--manifest", MANIFEST]
        run = run_bounded(argv, ROOT, output, kind)
        item = {"kind": kind, "capture_status": "FAILED", "run": run}
        if not run["fault"]:
            try:
                raw = (output / run["streams"]["stdout"]["file"]).read_bytes()
                item["report"] = validate_report(raw, run["exit_code"], kind)
                item["capture_status"] = "CAPTURED_BLOCKED"
            except (ValueError, UnicodeError, RecursionError):
                item["validation_error"] = "malformed, invalid or inconsistent report"
        results.append(item)
    return results


def emit_logs(output):
    """Mirror retained bytes safely for API log auditing; no GitHub command text."""
    names = [kind + "." + stream for kind in KINDS for stream in ("stdout", "stderr")]
    for name in [*names, "receipt.json"]:
        path = output / name
        if not path.is_file():
            continue
        raw = path.read_bytes()
        for offset in range(0, max(1, len(raw)), 16384):
            record = {"file": name, "encoding": "base64", "offset": offset,
                      "total_bytes": len(raw),
                      "data": base64.b64encode(raw[offset:offset + 16384]).decode("ascii")}
            print("HANDOFF_CAPTURE_BYTES " + json.dumps(record, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    temporary_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    output = Path(args.output)
    if not output.is_absolute() or output.parent.resolve(strict=True) != temporary_root:
        parser.error("output must be a new direct child of RUNNER_TEMP")
    if ROOT == temporary_root or ROOT in temporary_root.parents:
        parser.error("RUNNER_TEMP must be outside the checkout")
    output.mkdir(mode=0o700)  # Existing destinations are never overwritten.
    receipt = {"schema": "event-intelligence/private-handoff-report-capture/1",
               "started_at": utc(), "capture_status": "FAILED",
               "readiness_pass": False, "python": sys.version, "groups": [],
               "limits": {"timeout_seconds_per_scope": TIMEOUT,
                          "retained_bytes_per_stream": LIMIT},
               "meaning": "Capturing BLOCKED reports is not release readiness or acceptance."}
    try:
        receipt["source_before"] = source_identity(output, "before")
        receipt["groups"] = capture_scopes(output)
        receipt["source_after"] = source_identity(output, "after")
        before, after = receipt["source_before"], receipt["source_after"]
        if any(before[key] != after[key] for key in ("head", "tree", "status")):
            raise ValueError("source changed")
        if len(receipt["groups"]) == 4 and all(
                item["capture_status"] == "CAPTURED_BLOCKED" for item in receipt["groups"]):
            receipt["capture_status"] = "CAPTURED_BLOCKED"
    except (OSError, ValueError):
        receipt["error"] = "setup, source identity or artifact I/O failure; inspect retained streams"
    finally:
        receipt["completed_at"] = utc()
        with (output / "receipt.json").open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True)
            stream.write("\n")
    emit_logs(output)
    print(json.dumps({"capture_status": receipt["capture_status"], "readiness_pass": False}))
    return 0 if receipt["capture_status"] == "CAPTURED_BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
