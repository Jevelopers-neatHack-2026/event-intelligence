"""Capture-helper controls; these are not product or readiness tests."""
import base64
import importlib.util
import io
import json
from pathlib import Path
from contextlib import redirect_stdout
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("capture_handoff", ROOT / "tools/capture_handoff_reports.py")
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


def report(kind="handoff-contracts"):
    return {"tool": "event-intelligence-handoff-checker", "tool_version": "0.1.0",
            "kind": kind, "manifest": capture.MANIFEST, "ready": False,
            "readiness_status": "BLOCKED", "exit_code": 1,
            "checks": [{"status": "missing"}], "missing_deliverables": [{"id": "owner-input"}],
            "summary": {"checks": 1, "missing_deliverables": 1, "failed_or_invalid": 0}}


class CaptureTests(unittest.TestCase):
    def test_blocked_is_capture_only(self):
        value = capture.validate_report(json.dumps(report()).encode(), 1, capture.KINDS[0])
        self.assertEqual(value["readiness_status"], "BLOCKED")
        self.assertIs(value["ready"], False)

    def test_invalid_is_not_success(self):
        value = report()
        value.update(readiness_status="INVALID", exit_code=2)
        value["checks"][0]["status"] = "invalid"
        value["summary"]["failed_or_invalid"] = 1
        with self.assertRaises(ValueError):
            capture.validate_report(json.dumps(value).encode(), 2, capture.KINDS[0])

    def test_duplicate_and_malformed_json(self):
        for raw in (b'{"ready":false,"ready":false}', b'{broken', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                capture.validate_report(raw, 1, capture.KINDS[0])

    def test_exit_mismatch_and_boolean_rejected(self):
        for code in (0, 2, True, None):
            with self.subTest(code=code), self.assertRaises(ValueError):
                capture.validate_report(json.dumps(report()).encode(), code, capture.KINDS[0])
        value = report()
        value["exit_code"] = True
        with self.assertRaises(ValueError):
            capture.validate_report(json.dumps(value).encode(), 1, capture.KINDS[0])

    def test_scope_and_manifest_mismatch_rejected(self):
        for field, value in (("kind", "provider-readiness"), ("manifest", "../other.json"),
                             ("ready", True), ("readiness_status", "READY")):
            changed = report()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                capture.validate_report(json.dumps(changed).encode(), 1, capture.KINDS[0])

    def test_summary_counts_and_missing_inventory(self):
        for value in (False, 2, 1.0):
            changed = report()
            changed["summary"]["checks"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                capture.validate_report(json.dumps(changed).encode(), 1, capture.KINDS[0])
        changed = report()
        changed["missing_deliverables"] = []
        changed["summary"]["missing_deliverables"] = 0
        with self.assertRaises(ValueError):
            capture.validate_report(json.dumps(changed).encode(), 1, capture.KINDS[0])

    def test_nonfinite_json_rejected(self):
        raw = json.dumps(report()).replace('"checks": 1', '"checks": NaN').encode()
        with self.assertRaises(ValueError):
            capture.validate_report(raw, 1, capture.KINDS[0])

    def test_native_raw_streams_and_actual_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            command = [sys.executable, "-I", "-B", "-c",
                       "import os; os.write(1,b'raw\\x00out'); os.write(2,b'err\\xff'); raise SystemExit(7)"]
            result = capture.run_bounded(command, ROOT, out, "normal")
            self.assertEqual(result["exit_code"], 7)
            self.assertIsNone(result["fault"])
            self.assertEqual((out / "normal.stdout").read_bytes(), b"raw\x00out")
            self.assertEqual((out / "normal.stderr").read_bytes(), b"err\xff")

    def test_native_timeout_preserves_any_captured_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            command = [sys.executable, "-I", "-B", "-c",
                       "import os,time; os.write(1,b'before-timeout'); time.sleep(10)"]
            result = capture.run_bounded(command, ROOT, out, "timeout", timeout=1)
            self.assertEqual(result["fault"], "timeout")
            self.assertNotEqual(result["exit_code"], 0)
            self.assertIn((out / "timeout.stdout").read_bytes(), (b"", b"before-timeout"))
            self.assertIs(result["streams_complete"], False)

    def test_native_output_bound_is_explicit_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            command = [sys.executable, "-I", "-B", "-c", "import os; os.write(1,b'x'*4096)"]
            result = capture.run_bounded(command, ROOT, out, "overflow", limit=64)
            self.assertEqual(result["fault"], "output_limit")
            self.assertEqual((out / "overflow.stdout").read_bytes(), b"x" * 64)
            self.assertIs(result["streams_complete"], False)

    def test_existing_stream_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "old.stdout").write_bytes(b"original")
            with self.assertRaises(FileExistsError):
                capture.run_bounded([sys.executable, "-c", "raise SystemExit(99)"], ROOT, out, "old")
            self.assertEqual((out / "old.stdout").read_bytes(), b"original")

    def test_log_mirror_preserves_bytes_without_workflow_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            raw = b"::error::not-a-command\n" + bytes(range(256)) * 70
            name = capture.KINDS[0] + ".stdout"
            (out / name).write_bytes(raw)
            (out / "receipt.json").write_bytes(b"{}\n")
            log = io.StringIO()
            with redirect_stdout(log):
                capture.emit_logs(out)
            records = []
            for line in log.getvalue().splitlines():
                self.assertTrue(line.startswith("HANDOFF_CAPTURE_BYTES "))
                records.append(json.loads(line.split(" ", 1)[1]))
            parts = [item for item in records if item["file"] == name]
            self.assertEqual([item["offset"] for item in parts], [0, 16384])
            self.assertTrue(all(item["total_bytes"] == len(raw) for item in parts))
            self.assertEqual(b"".join(base64.b64decode(item["data"]) for item in parts), raw)

    def test_all_four_fixed_commands_retained_after_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            calls = []
            def run(argv, cwd, output, name):
                calls.append(list(argv))
                index = capture.KINDS.index(name)
                value = report(name)
                if index == 0:
                    value.update(readiness_status="INVALID", exit_code=2)
                    value["checks"][0]["status"] = "invalid"
                    value["summary"]["failed_or_invalid"] = 1
                raw = b"{broken" if index == 1 else json.dumps(value).encode()
                (output / (name + ".stdout")).write_bytes(raw)
                (output / (name + ".stderr")).write_bytes(b"retained")
                return {"fault": "timeout" if index == 2 else None,
                        "exit_code": value["exit_code"],
                        "streams": {"stdout": {"file": name + ".stdout"}}}
            with patch.object(capture, "run_bounded", side_effect=run):
                results = capture.capture_scopes(out)
            self.assertEqual([item["kind"] for item in results], list(capture.KINDS))
            self.assertEqual([item["capture_status"] for item in results],
                             ["FAILED", "FAILED", "FAILED", "CAPTURED_BLOCKED"])
            self.assertEqual(calls, [
                [sys.executable, "-I", "-B", "tools/verify_handoff.py", "--kind", kind,
                 "--manifest", "tests/contracts/handoff-manifest.json"] for kind in capture.KINDS])
            self.assertEqual(len(list(out.iterdir())), 8)


if __name__ == "__main__":
    unittest.main()
