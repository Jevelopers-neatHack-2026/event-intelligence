"""Bounded CI mirror of fixed synthetic composition evidence; never a readiness result."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_ATTEMPTS = 32
MAX_HOST_NOTICES = 64
NOTICE = re.compile(r"host-notices/[a-z0-9][a-z0-9.+-]{0,180}-copyright\.txt\Z")
CHUNK = 16384
ATTEMPT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}(?:\.\d{3,6})?(?:Z|\+00-00)-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
BEFORE_AFTER = ("source-before.json", "source-after.json")
INITIALIZER = ("started.json", *BEFORE_AFTER, "stdout.txt", "stderr.txt", "summary.json")
VERIFICATION = ("source-map.json", "stdout.tap", "stderr.txt", "summary.json")
CANDIDATE_FILES = ("wrapper.stdout", "wrapper.stderr", "labelled.native-result.json",
                   "doors.native-result.json", "labelled-pdf.native-result.json",
                   "native-cancel-recovery.json", "native-fixture-origin.json",
                   "candidate-report.json", "question-preparation.json")


def directory(root, relative=""):
    """Walk only named relative components, retaining no-follow directory handles."""
    parts = relative.split("/") if relative else []
    if any(part in ("", ".", "..") for part in parts) or relative.startswith("/"):
        raise ValueError("invalid_relative_path")
    fd = os.open(root, FLAGS | os.O_DIRECTORY)
    try:
        for part in parts:
            following = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = following
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_member(root, relative, limit):
    parent, name = relative.rsplit("/", 1) if "/" in relative else ("", relative)
    if name in ("", ".", ".."):
        raise ValueError("invalid_relative_path")
    parent_fd = directory(root, parent)
    try:
        fd = os.open(name, FLAGS | os.O_NONBLOCK, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not_regular")
        if before.st_size > min(MAX_FILE, limit):
            raise ValueError("size_limit")
        raw = stream.read(min(MAX_FILE, limit) + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if len(raw) != before.st_size or identity(before) != identity(after):
        raise ValueError("changed_during_read")
    return raw, stat.S_IMODE(before.st_mode)



def listed(fd, maximum):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(names) >= maximum:
                raise ValueError("directory_entry_limit")
            names.append(entry.name)
    return sorted(names)


def notice_refs(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("nonfinite_json")
    records = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                         parse_constant=invalid_constant)
    if not isinstance(records, list) or len(records) > 256:
        raise ValueError("host_record_inventory")
    notices = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("host_record")
        packages = record.get("packageMetadata")
        if not isinstance(packages, list) or len(packages) > 32:
            raise ValueError("package_inventory")
        for package in packages:
            if not isinstance(package, dict):
                raise ValueError("package_record")
            if "notice" not in package:
                continue  # The retained provenance class still describes this limitation.
            notice = package["notice"]
            if (not isinstance(notice, dict) or set(notice) != {"file", "bytes", "sha256"}
                    or not isinstance(notice["file"], str) or not NOTICE.fullmatch(notice["file"])
                    or type(notice["bytes"]) is not int or not 0 <= notice["bytes"] <= MAX_FILE
                    or not isinstance(notice["sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", notice["sha256"])):
                raise ValueError("unsafe_notice_reference")
            name = notice["file"]
            expected = (notice["bytes"], notice["sha256"])
            if name in notices and notices[name] != expected:
                raise ValueError("conflicting_notice_reference")
            notices[name] = expected
            if len(notices) > MAX_HOST_NOTICES:
                raise ValueError("notice_inventory_limit")
    return sorted(notices.items())


def mirror(root, mode, emit, raster_root=None, candidate_root=None):
    if mode not in ("scanned-pdf", "static-image", "ocr-candidates"):
        raise ValueError("invalid_mode")
    root = Path(root)
    members, errors, total = [], [], 0

    def problem(label, code):
        errors.append({"file": label, "code": code})

    def one(base, name, required=True, label=None, expected=None):
        nonlocal total
        label = name if label is None else label
        row = {"file": label, "required": required}
        try:
            raw, permissions = read_member(base, name, MAX_TOTAL - total)
        except FileNotFoundError:
            row["status"] = "missing_required" if required else "optional_absent"
            if required:
                problem(label, "missing")
        except (OSError, ValueError):
            row["status"] = "refused"
            problem(label, "unsafe_changed_or_over_limit")
        else:
            total += len(raw)
            row.update(status="captured", bytes=len(raw), mode=permissions,
                       sha256=hashlib.sha256(raw).hexdigest())
            if expected is not None:
                row["expectedBytes"], row["expectedSha256"] = expected
                row["referenceMatches"] = (len(raw), row["sha256"]) == expected
                if not row["referenceMatches"]:
                    problem(label, "notice_digest_or_length_mismatch")
            for offset in range(0, max(1, len(raw)), CHUNK):
                emit("COMPOSITION_CAPTURE_BYTES " + json.dumps({
                    "file": label, "encoding": "base64", "offset": offset,
                    "total_bytes": len(raw),
                    "data": base64.b64encode(raw[offset:offset + CHUNK]).decode("ascii"),
                }, sort_keys=True))
        members.append(row)
        return raw if row["status"] == "captured" else None

    def attempts(relative, names, optional=()):
        try:
            fd = directory(root, relative)
            try:
                entries = listed(fd, MAX_ATTEMPTS)
                if not entries or len(entries) > MAX_ATTEMPTS:
                    raise ValueError("attempt_count")
                if any(not ATTEMPT.fullmatch(name) for name in entries):
                    raise ValueError("attempt_name")
                for attempt in entries:
                    sub = relative + "/" + attempt
                    try:
                        child = os.open(attempt, FLAGS | os.O_DIRECTORY, dir_fd=fd)
                        try:
                            found = set(listed(child, len(names) + 1))
                            if found - set(names):
                                problem(sub, "unexpected_member")
                        finally:
                            os.close(child)
                    except (OSError, ValueError):
                        problem(sub, "unsafe_attempt_directory")
                        continue
                    for name in names:
                        one(root, sub + "/" + name, name not in optional)
                if listed(fd, MAX_ATTEMPTS) != entries:
                    problem(relative, "attempt_inventory_changed")
            finally:
                os.close(fd)
        except (OSError, ValueError):
            problem(relative, "missing_or_invalid_attempt_inventory")

    for name in (
        "src/extraction/local-ocr/profile.json", "tools/local-ocr/lock.json",
        "tools/local-ocr/provenance.json", "tools/local-ocr/runtime/manifest.json",
        "tools/local-ocr/notices/giflib-source-COPYING",
        "tools/local-ocr/notices/leptonica-source-leptonica-license.txt",
        "tools/local-ocr/notices/libgif7-copyright.txt", "tools/local-ocr/notices/liblept5-copyright.txt",
        "tools/local-ocr/notices/libtesseract5-copyright.txt", "tools/local-ocr/notices/tessdata-fast-LICENSE",
        "tools/local-ocr/notices/tesseract-LICENSE", "tools/local-ocr/notices/tesseract-ocr-eng-copyright.txt",
    ):
        one(root, name)
    provenance = one(root, "tools/local-ocr/runtime/host-provenance.json")
    if provenance is not None:
        try:
            references = notice_refs(provenance)
        except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
            problem("tools/local-ocr/runtime/host-provenance.json", "invalid_notice_inventory")
        else:
            for name, expected in references:
                one(root, "tools/local-ocr/runtime/" + name, expected=expected)
    # A composed route does not execute the standalone OCR verifier.
    one(root, "tools/local-ocr/runtime/verification.json", False)
    attempts("tools/local-ocr/runtime/initialization-attempts", INITIALIZER, BEFORE_AFTER)
    if mode == "ocr-candidates":
        one(root, "tests/extraction/ocr-candidates/fixtures/provenance.json")
        for name in CANDIDATE_FILES:
            label = "ocr-candidate-evidence/" + name
            if candidate_root is None:
                members.append({"file": label, "required": True, "status": "unavailable_root"})
                problem(label, "missing_or_invalid_runner_evidence")
            else:
                one(candidate_root, name, label=label)
        if raster_root is None:
            problem("ocr-candidate-jpeg-runtime/runtime.json", "missing_or_invalid_runner_runtime")
        else:
            one(raster_root, "runtime.json", label="ocr-candidate-jpeg-runtime/runtime.json")
    else:
        component = mode + "-ocr"
        one(root, "src/extraction/" + component + "/profile.mjs")
        one(root, "tools/" + component + "/runtime/verification.json")
        attempts("tools/" + component + "/runtime/verification", VERIFICATION)
    if mode in ("scanned-pdf", "ocr-candidates"):
        for name in ("src/extraction/scanned-pdf/profile.json", "tools/scanned-pdf/lock.json",
                     "tools/scanned-pdf/runtime/manifest.json"):
            one(root, name)
    else:
        for name in ("tools/static-raster/requirements.txt", "tools/static-raster/PILLOW-LICENSE.txt",
                     "tests/extraction/static-image-ocr/fixtures/provenance.json"):
            one(root, name)
        if raster_root is None:
            problem("static-raster/runtime.json", "missing_or_invalid_runner_runtime")
        else:
            one(raster_root, "runtime.json", label="static-raster/runtime.json")
    return {"schemaVersion": "ei-composition-evidence-mirror/1", "mode": mode,
            "evidenceMode": "local-synthetic-native-evidence", "acceptanceAuthority": "none",
            "captureComplete": not errors, "members": members, "errors": errors,
            "totalBytes": total,
            "limits": {"fileBytes": MAX_FILE, "totalBytes": MAX_TOTAL,
                       "attemptsPerDirectory": MAX_ATTEMPTS, "hostNoticeRefs": MAX_HOST_NOTICES, "chunkBytes": CHUNK},
            "optionalNotes": {
                "standaloneOcrVerification": "not produced by composed routes",
                "initializerSourceBeforeAfter": "may be absent on failed startup; absence is explicit, never a source-integrity pass",
            }}


def source_identity(root):
    result = {}
    for label, expression in (("revision", "HEAD"), ("tree", "HEAD^{tree}")):
        value = subprocess.run(["git", "rev-parse", expression], cwd=root, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout
        if not re.fullmatch(rb"[0-9a-f]{40}\n", value):
            raise ValueError("source_identity")
        result[label] = value.decode("ascii").strip()
    return result


def raster_from_environment(root):
    temporary = Path(os.environ["RUNNER_TEMP"])
    raster = Path(os.environ["EI_STATIC_IMAGE_OCR_RASTER_RUNTIME"])
    if (not temporary.is_absolute() or temporary.is_symlink()
            or temporary.resolve(strict=True) != temporary
            or not raster.is_absolute() or raster.is_symlink()
            or raster.resolve(strict=True) != raster
            or raster != temporary / "ei-static-image-ocr-raster"
            or temporary == root or root in temporary.parents):
        raise ValueError("invalid_runner_runtime")
    return raster


def candidate_runner_child(root, variable, basename):
    """Admit only one of the two fixed candidate paths, never a caller-selected tree."""
    if (variable, basename) not in (
            ("EI_OCR_CANDIDATE_CAPTURE", "ei-ocr-candidate-evidence"),
            ("EI_STATIC_IMAGE_OCR_RASTER_RUNTIME", "ei-ocr-candidate-jpeg-runtime")):
        raise ValueError("invalid_candidate_path_selector")
    temporary = Path(os.environ["RUNNER_TEMP"])
    selected = Path(os.environ[variable])
    if (not temporary.is_absolute() or temporary.is_symlink()
            or temporary.resolve(strict=True) != temporary
            or not selected.is_absolute() or selected.is_symlink()
            or selected.resolve(strict=True) != selected
            or selected != temporary / basename
            or temporary == root or root in temporary.parents):
        raise ValueError("invalid_candidate_runner_path")
    return selected


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("scanned-pdf", "static-image", "ocr-candidates"):
        raise SystemExit("choose one fixed composition mode")
    root = Path(__file__).resolve().parents[1]
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    source, source_error, raster, candidate = None, False, None, None
    try:
        source = source_identity(root)
    except (OSError, ValueError, subprocess.SubprocessError):
        source_error = True
    if sys.argv[1] == "static-image":
        try:
            raster = raster_from_environment(root)
        except (KeyError, OSError, ValueError):
            pass
    if sys.argv[1] == "ocr-candidates":
        try:
            candidate = candidate_runner_child(root, "EI_OCR_CANDIDATE_CAPTURE", "ei-ocr-candidate-evidence")
        except (KeyError, OSError, ValueError, RuntimeError):
            pass
        try:
            raster = candidate_runner_child(root, "EI_STATIC_IMAGE_OCR_RASTER_RUNTIME", "ei-ocr-candidate-jpeg-runtime")
        except (KeyError, OSError, ValueError, RuntimeError):
            pass
    result = mirror(root, sys.argv[1], lambda line: print(line, flush=True), raster, candidate)
    result.update(startedAt=started, finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  source=source, productReadiness="not_evaluated")
    if source_error:
        result["errors"].append({"file": "checkout", "code": "source_identity_unavailable"})
        result["captureComplete"] = False
    print("COMPOSITION_CAPTURE_MANIFEST_JSON=" + json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["captureComplete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
