"""Helper-only data controls; no OCR, native installer or readiness execution."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("composition_mirror",
    Path(__file__).resolve().parents[2] / "tools/mirror-composition-evidence.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
STAMP = "2026-10-13T00-00-00.000Z-12345678-1234-1234-1234-123456789abc"
INIT = "tools/local-ocr/runtime/initialization-attempts/" + STAMP


class MirrorControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lines = []

    def put(self, name, raw=b"{}\n"):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(raw)
        return file

    def fixture(self, mode="scanned-pdf"):
        for name in (
            "src/extraction/local-ocr/profile.json", "tools/local-ocr/lock.json",
            "tools/local-ocr/provenance.json", "tools/local-ocr/runtime/manifest.json",
        ):
            self.put(name)
        self.put("tools/local-ocr/runtime/host-provenance.json", b"[]\n")
        for name in ("giflib-source-COPYING", "leptonica-source-leptonica-license.txt",
                     "libgif7-copyright.txt", "liblept5-copyright.txt", "libtesseract5-copyright.txt",
                     "tessdata-fast-LICENSE", "tesseract-LICENSE", "tesseract-ocr-eng-copyright.txt"):
            self.put("tools/local-ocr/notices/" + name)
        for name in M.INITIALIZER:
            self.put(INIT + "/" + name)
        component = mode + "-ocr"
        self.put("src/extraction/" + component + "/profile.mjs", b"// synthetic control\n")
        self.put("tools/" + component + "/runtime/verification.json")
        for name in M.VERIFICATION:
            self.put("tools/" + component + "/runtime/verification/" + STAMP + "/" + name)
        if mode == "scanned-pdf":
            for name in ("src/extraction/scanned-pdf/profile.json", "tools/scanned-pdf/lock.json",
                         "tools/scanned-pdf/runtime/manifest.json"):
                self.put(name)
            return None
        for name in ("tools/static-raster/requirements.txt", "tools/static-raster/PILLOW-LICENSE.txt",
                     "tests/extraction/static-image-ocr/fixtures/provenance.json"):
            self.put(name)
        return self.put("raster/runtime.json").parent

    def capture(self, mode="scanned-pdf", raster=None):
        return M.mirror(self.root, mode, self.lines.append, raster)

    def test_01_fixed_modes_and_optional_standalone(self):
        self.fixture()
        result = self.capture()
        self.assertTrue(result["captureComplete"])
        self.assertEqual(result["acceptanceAuthority"], "none")
        absent = [x for x in result["members"] if x["status"] == "optional_absent"]
        self.assertEqual([x["file"] for x in absent], ["tools/local-ocr/runtime/verification.json"])
        raster = self.fixture("static-image")
        self.assertTrue(self.capture("static-image", raster)["captureComplete"])

    def test_02_missing_required_continues_later_capture(self):
        self.fixture()
        (self.root / "tools/local-ocr/lock.json").unlink()
        result = self.capture()
        self.assertFalse(result["captureComplete"])
        self.assertTrue(any(x["file"] == "tools/scanned-pdf/runtime/manifest.json"
                            and x["status"] == "captured" for x in result["members"]))

    def test_03_oversize_refusal_keeps_other_evidence(self):
        self.fixture()
        with (self.root / "tools/local-ocr/lock.json").open("wb") as stream:
            stream.truncate(M.MAX_FILE + 1)
        result = self.capture()
        self.assertFalse(result["captureComplete"])
        self.assertTrue(any(x["file"].endswith("stdout.tap") and x["status"] == "captured"
                            for x in result["members"]))

    def test_04_aggregate_limit_is_not_silent_truncation(self):
        self.fixture()
        with patch.object(M, "MAX_TOTAL", 8):
            result = self.capture()
        self.assertFalse(result["captureComplete"])
        self.assertLessEqual(result["totalBytes"], 8)
        self.assertTrue(any(x["status"] == "refused" for x in result["members"]))

    def test_05_file_symlink_is_not_read(self):
        self.fixture()
        target = self.put("not-admitted", b"DO_NOT_MIRROR_TARGET")
        linked = self.root / "tools/local-ocr/lock.json"
        linked.unlink()
        linked.symlink_to(target)
        result = self.capture()
        self.assertFalse(result["captureComplete"])
        self.assertFalse(any(base64.b64encode(b"DO_NOT_MIRROR_TARGET").decode() in x for x in self.lines))

    def test_06_parent_symlink_is_not_followed(self):
        self.fixture()
        runtime = self.root / "tools/scanned-pdf/runtime"
        moved = self.root / "not-admitted-runtime"
        runtime.rename(moved)
        runtime.symlink_to(moved, target_is_directory=True)
        self.assertFalse(self.capture()["captureComplete"])

    def test_07_attempt_symlink_is_refused(self):
        self.fixture()
        directory = self.root / INIT
        moved = self.root / "not-admitted-attempt"
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        result = self.capture()
        self.assertFalse(result["captureComplete"])
        self.assertTrue(any(x["code"] == "unsafe_attempt_directory" for x in result["errors"]))

    def test_08_fifo_is_refused_without_blocking(self):
        self.fixture()
        fifo = self.root / "tools/local-ocr/lock.json"
        fifo.unlink()
        os.mkfifo(fifo)
        self.assertFalse(self.capture()["captureComplete"])

    def test_09_changed_identity_is_refused(self):
        file = self.put("sample", b"hello")
        original = os.stat(file)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        before = SimpleNamespace(**{key: getattr(original, key) for key in fields})
        after = SimpleNamespace(**{key: getattr(original, key) for key in fields})
        after.st_mtime_ns += 1
        with patch.object(M.os, "fstat", side_effect=[before, after]):
            with self.assertRaisesRegex(ValueError, "changed_during_read"):
                M.read_member(self.root, "sample", 100)

    def test_10_unexpected_attempt_member_preserves_known_members(self):
        self.fixture()
        self.put(INIT + "/arbitrary-native-library.so", b"FORBIDDEN")
        result = self.capture()
        self.assertFalse(result["captureComplete"])
        self.assertTrue(any(x["code"] == "unexpected_member" for x in result["errors"]))
        self.assertTrue(any(x["file"] == INIT + "/summary.json" and x["status"] == "captured"
                            for x in result["members"]))
        self.assertFalse(any(x["file"].endswith(".so") for x in result["members"]))

    def test_11_chunk_offsets_hash_and_empty_stream_are_exact(self):
        self.fixture()
        name = "tools/local-ocr/lock.json"
        raw = b"x" * (M.CHUNK + 7)
        self.put(name, raw)
        self.put(INIT + "/stderr.txt", b"")
        result = self.capture()
        self.assertTrue(result["captureComplete"])
        chunks = [json.loads(x.split(" ", 1)[1]) for x in self.lines]
        selected = [x for x in chunks if x["file"] == name]
        self.assertEqual([x["offset"] for x in selected], [0, M.CHUNK])
        rebuilt = b"".join(base64.b64decode(x["data"], validate=True) for x in selected)
        self.assertEqual(rebuilt, raw)
        member = next(x for x in result["members"] if x["file"] == name)
        self.assertEqual(member["sha256"], hashlib.sha256(raw).hexdigest())
        empty = [x for x in chunks if x["file"] == INIT + "/stderr.txt"]
        self.assertEqual(len(empty), 1)
        self.assertEqual((empty[0]["offset"], empty[0]["total_bytes"], empty[0]["data"]), (0, 0, ""))

    def test_12_failed_startup_missing_source_is_explicit_and_incomplete_core_fails(self):
        self.fixture()
        for name in M.BEFORE_AFTER:
            (self.root / INIT / name).unlink()
        result = self.capture()
        absent = [x["file"] for x in result["members"] if x["status"] == "optional_absent"]
        self.assertTrue(all(INIT + "/" + x in absent for x in M.BEFORE_AFTER))
        self.assertTrue(result["captureComplete"])  # Capture, not startup/source success.
        (self.root / INIT / "summary.json").unlink()
        self.assertFalse(self.capture()["captureComplete"])

    def test_13_attempt_bound_and_invalid_mode(self):
        self.fixture()
        with patch.object(M, "MAX_ATTEMPTS", 0):
            result = self.capture()
        self.assertFalse(result["captureComplete"])
        self.assertTrue(any(x["file"] == "tools/scanned-pdf/runtime/manifest.json"
                            and x["status"] == "captured" for x in result["members"]))
        with self.assertRaisesRegex(ValueError, "invalid_mode"):
            self.capture("arbitrary")


    def test_14_projected_host_notices_are_captured_and_joined(self):
        self.fixture()
        raw = b"synthetic copyright notice\n"
        name = "host-notices/libexample-amd64-copyright.txt"
        notice = {"file": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        self.put("tools/local-ocr/runtime/" + name, raw)
        self.put("tools/local-ocr/runtime/host-provenance.json",
                 json.dumps([{"packageMetadata": [{"notice": notice}, {"notice": notice}]}]).encode())
        result = self.capture()
        self.assertTrue(result["captureComplete"])
        members = [x for x in result["members"] if x["file"] == "tools/local-ocr/runtime/" + name]
        self.assertEqual(len(members), 1)
        self.assertTrue(members[0]["referenceMatches"])

    def test_15_untrusted_notice_paths_duplicates_and_nonfinite_are_rejected(self):
        notice = {"file": "../private", "bytes": 1, "sha256": "0" * 64}
        for raw in (json.dumps([{"packageMetadata": [{"notice": notice}]}]).encode(),
                    b'[{"packageMetadata":[],"packageMetadata":[]}]',
                    b'[{"packageMetadata":[],"untrusted":NaN}]',
                    b'{}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.notice_refs(raw)

    def test_16_missing_and_changed_host_notice_cannot_be_capture_complete(self):
        self.fixture()
        name = "host-notices/libexample-copyright.txt"
        notice = {"file": name, "bytes": 5, "sha256": hashlib.sha256(b"right").hexdigest()}
        self.put("tools/local-ocr/runtime/host-provenance.json",
                 json.dumps([{"packageMetadata": [{"notice": notice}]}]).encode())
        self.assertFalse(self.capture()["captureComplete"])
        self.put("tools/local-ocr/runtime/" + name, b"wrong")
        result = self.capture()
        self.assertFalse(result["captureComplete"])
        self.assertTrue(any(x["code"] == "notice_digest_or_length_mismatch" for x in result["errors"]))
        self.assertTrue(any(x["file"].endswith("stdout.tap") and x["status"] == "captured"
                            for x in result["members"]))

    def test_17_directory_scan_stops_at_the_declared_bound(self):
        for name in ("one", "two", "three"):
            self.put(name)
        fd = M.directory(self.root)
        try:
            with self.assertRaisesRegex(ValueError, "directory_entry_limit"):
                M.listed(fd, 2)
        finally:
            os.close(fd)


    def candidate_fixture(self):
        self.fixture("scanned-pdf")  # Reuse the exact common OCR/PDF inputs.
        self.put("tests/extraction/ocr-candidates/fixtures/provenance.json")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        runner = Path(temporary.name)
        candidate = runner / "ei-ocr-candidate-evidence"
        raster = runner / "ei-ocr-candidate-jpeg-runtime"
        candidate.mkdir()
        raster.mkdir()
        for name in M.CANDIDATE_FILES:
            (candidate / name).write_bytes(("synthetic " + name + "\n").encode())
        (raster / "runtime.json").write_bytes(b"{}\n")
        return runner, candidate, raster

    def candidate_capture(self, candidate, raster):
        return M.mirror(self.root, "ocr-candidates", self.lines.append, raster, candidate)

    def test_18_candidate_mode_has_exact_nine_files_and_shared_native_receipts(self):
        runner, candidate, raster = self.candidate_fixture()
        (candidate / "unrequested-private-input").write_bytes(b"DO_NOT_CAPTURE")
        result = self.candidate_capture(candidate, raster)
        self.assertTrue(result["captureComplete"])
        expected_names = ("wrapper.stdout", "wrapper.stderr", "labelled.native-result.json",
                          "doors.native-result.json", "labelled-pdf.native-result.json",
                          "native-cancel-recovery.json", "native-fixture-origin.json",
                          "candidate-report.json", "question-preparation.json")
        self.assertEqual(M.CANDIDATE_FILES, expected_names)
        rows = [x for x in result["members"] if x["file"].startswith("ocr-candidate-evidence/")]
        self.assertEqual([x["file"].split("/", 1)[1] for x in rows], list(expected_names))
        self.assertTrue(all(x["required"] and x["status"] == "captured" for x in rows))
        expected = ("tools/local-ocr/runtime/manifest.json", "tools/scanned-pdf/runtime/manifest.json",
                    "ocr-candidate-jpeg-runtime/runtime.json",
                    "tests/extraction/ocr-candidates/fixtures/provenance.json")
        self.assertTrue(all(any(x["file"] == name and x["status"] == "captured"
                                for x in result["members"]) for name in expected))
        self.assertFalse(any("unrequested-private-input" in x["file"] for x in result["members"]))
        self.assertFalse(any("scanned-pdf-ocr/runtime/verification" in x["file"]
                             for x in result["members"]))
        self.assertEqual(result["acceptanceAuthority"], "none")

    def test_19_candidate_missing_file_preserves_later_evidence_and_recovers(self):
        runner, candidate, raster = self.candidate_fixture()
        selected = candidate / "labelled.native-result.json"
        raw = selected.read_bytes()
        selected.unlink()
        result = self.candidate_capture(candidate, raster)
        self.assertFalse(result["captureComplete"])
        self.assertTrue(any(x["file"] == "ocr-candidate-evidence/labelled.native-result.json"
                            and x["status"] == "missing_required" for x in result["members"]))
        self.assertTrue(any(x["file"] == "ocr-candidate-evidence/question-preparation.json"
                            and x["status"] == "captured" for x in result["members"]))
        selected.write_bytes(raw)
        self.assertTrue(self.candidate_capture(candidate, raster)["captureComplete"])

    def test_20_candidate_leaf_and_raster_symlinks_refuse_then_recover(self):
        runner, candidate, raster = self.candidate_fixture()
        target = runner / "private"
        target.write_bytes(b"DO_NOT_MIRROR_TARGET")
        for selected in (candidate / "candidate-report.json", raster / "runtime.json"):
            original = selected.read_bytes()
            selected.unlink()
            selected.symlink_to(target)
            self.lines.clear()
            self.assertFalse(self.candidate_capture(candidate, raster)["captureComplete"])
            encoded = base64.b64encode(target.read_bytes()).decode()
            self.assertFalse(any(encoded in line for line in self.lines))
            selected.unlink()
            selected.write_bytes(original)
            self.assertTrue(self.candidate_capture(candidate, raster)["captureComplete"])

    def test_21_candidate_environment_paths_are_fixed_canonical_and_outside_checkout(self):
        runner, candidate, raster = self.candidate_fixture()
        selectors = (("EI_OCR_CANDIDATE_CAPTURE", "ei-ocr-candidate-evidence", candidate),
                     ("EI_STATIC_IMAGE_OCR_RASTER_RUNTIME", "ei-ocr-candidate-jpeg-runtime", raster))
        for variable, basename, selected in selectors:
            with self.subTest(variable=variable), patch.dict(M.os.environ,
                    {"RUNNER_TEMP": str(runner), variable: str(selected)}):
                self.assertEqual(M.candidate_runner_child(self.root, variable, basename), selected)
                for bad in (basename, str(runner), str(selected / ".." / basename)):
                    with patch.dict(M.os.environ, {variable: bad}), self.assertRaises(ValueError):
                        M.candidate_runner_child(self.root, variable, basename)
                link = runner / ("linked-" + basename)
                link.symlink_to(selected, target_is_directory=True)
                with patch.dict(M.os.environ, {variable: str(link)}), self.assertRaises(ValueError):
                    M.candidate_runner_child(self.root, variable, basename)
                for parent in (self.root, self.root / "runner"):
                    nested = parent / basename
                    nested.mkdir(parents=True)
                    with patch.dict(M.os.environ, {"RUNNER_TEMP": str(parent), variable: str(nested)}):
                        with self.assertRaises(ValueError):
                            M.candidate_runner_child(self.root, variable, basename)
                with patch.dict(M.os.environ, {"RUNNER_TEMP": "relative"}), self.assertRaises(ValueError):
                    M.candidate_runner_child(self.root, variable, basename)
                temporary_link = self.root / ("temporary-link-" + basename)
                temporary_link.symlink_to(runner, target_is_directory=True)
                with patch.dict(M.os.environ, {"RUNNER_TEMP": str(temporary_link),
                                              variable: str(temporary_link / basename)}):
                    with self.assertRaises(ValueError):
                        M.candidate_runner_child(self.root, variable, basename)
        with self.assertRaises(ValueError):
            M.candidate_runner_child(self.root, "UNRELATED_VARIABLE", "arbitrary")

    def test_22_candidate_unavailable_root_lists_every_required_file_without_fallback(self):
        runner, candidate, raster = self.candidate_fixture()
        result = self.candidate_capture(None, raster)
        self.assertFalse(result["captureComplete"])
        rows = [x for x in result["members"] if x["file"].startswith("ocr-candidate-evidence/")]
        self.assertEqual(len(rows), 9)
        self.assertTrue(all(x["required"] and x["status"] == "unavailable_root" for x in rows))
        self.assertTrue(any(x["file"] == "ocr-candidate-jpeg-runtime/runtime.json"
                            and x["status"] == "captured" for x in result["members"]))
        result = self.candidate_capture(candidate, None)
        self.assertFalse(result["captureComplete"])
        self.assertTrue(any(x["file"] == "ocr-candidate-evidence/question-preparation.json"
                            and x["status"] == "captured" for x in result["members"]))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(MirrorControls)
    if suite.countTestCases() != 22:
        raise SystemExit("Required helper-only inventory changed")
    outcome = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() and outcome.testsRun == 22 and not outcome.skipped else 1)
