"""Bounded, immutable evidence for trusted startup only; no raster or environment capture."""
import datetime
import hashlib
import json
import math
import os
import pathlib
import platform
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid

MAX_STDOUT = 256 * 1024
MAX_STDERR = 64 * 1024
MAX_SECONDS = 20
REAP_SECONDS = 1
ENV_POLICY = "fixed startup environment; values are not recorded"
EVIDENCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROFILE = json.loads((EVIDENCE_ROOT / "src/extraction/local-ocr/profile.json").read_text())
LOCK_SHA256 = hashlib.sha256((EVIDENCE_ROOT / "tools/local-ocr/lock.json").read_bytes()).hexdigest()
INITIALIZER_CODES = {"INVALID_OPTIONS", "RUNTIME_MISMATCH", "MODEL_UNAVAILABLE", "OUTPUT_LIMIT", "OCR_FAILURE"}


class InitializationFailure(ValueError):
    pass


def digest(value):
    return hashlib.sha256(value).hexdigest()


def source_identity(root):
    def git(*arguments):
        result = subprocess.run(["/usr/bin/git", "-C", str(root), *arguments],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=5, check=True)
        if len(result.stdout) > 1024 * 1024:
            raise ValueError("Source inventory exceeds the diagnostic bound.")
        return result.stdout.decode("utf-8")
    names = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0")) - {""})
    if not 1 <= len(names) <= 4096:
        raise ValueError("Source inventory is unavailable or exceeds the diagnostic bound.")
    files, total_bytes = [], 0
    for name in names:
        path = root / name
        if path.is_symlink():
            data = os.readlink(path).encode()
        else:
            if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Source entry exceeds the diagnostic bound.")
            data = path.read_bytes()
        total_bytes += len(data)
        if total_bytes > 64 * 1024 * 1024:
            raise ValueError("Source inventory exceeds the aggregate diagnostic bound.")
        files.append({"path": name, "mode": path.lstat().st_mode & 0o777,
                      "bytes": len(data), "sha256": digest(data)})
    return {"revision": git("rev-parse", "HEAD").strip(), "tree": git("rev-parse", "HEAD^{tree}").strip(),
            "dirty": bool(git("status", "--porcelain")), "files": files}


def fixed_error(value, *, allow_extra=False):
    keys = {"kind", "protocol", "profile", "code", "rasterSha256", "closureSha256", "enforcementControlsPassed"}
    if (not isinstance(value, dict) or
        not keys <= set(value) or not allow_extra and set(value) != keys or
        value["kind"] != "rejected" or value["protocol"] != PROFILE["protocol"] or value["profile"] != PROFILE["profile"] or
        not isinstance(value["code"], str) or value["code"] not in INITIALIZER_CODES or
        value["rasterSha256"] is not None or value["closureSha256"] is not None or
        type(value["enforcementControlsPassed"]) is not int or value["enforcementControlsPassed"] != 0):
        return None
    return {key: value[key] for key in ("kind", "protocol", "profile", "code", "rasterSha256", "closureSha256", "enforcementControlsPassed")}


def fixed_diagnostic(value):
    if not isinstance(value, dict) or set(value) != {"initializationDiagnostic"}:
        return None
    item = value["initializationDiagnostic"]
    if (not isinstance(item, dict) or
        set(item) != {"schema", "phase", "exceptionType", "classification", "errno", "frames"} or
        type(item["schema"]) is not int or item["schema"] != 2 or
        item["phase"] not in ("options", "initialize", "describe_runtime") or
        item["exceptionType"] not in ("Rejection", "OSError", "FileNotFoundError", "PermissionError", "MemoryError",
            "ImportError", "ModuleNotFoundError", "ValueError", "TypeError", "RuntimeError", "UnicodeError",
            "UnicodeDecodeError", "JSONDecodeError", "OverflowError", "RecursionError", "Exception") or
        item["classification"] not in ("fixed_policy_rejection", "operating_system_error", "module_import_error",
                                      "memory_error", "initialization_error") or
        not (item["errno"] is None or type(item["errno"]) is int and 1 <= item["errno"] <= 4095) or
        not isinstance(item["frames"], list) or not 0 <= len(item["frames"]) <= 8):
        return None
    for frame in item["frames"]:
        if (not isinstance(frame, dict) or set(frame) != {"file", "function", "line"} or
            frame["file"] not in ("worker.py", "native.py", "isolation.py", "errors.py", "__init__.py", "pathlib.py", "other_source") or
            frame["function"] not in ("main", "initialize", "verify_dependencies", "describe_runtime", "__init__",
                                     "reject", "read_bytes", "read_text", "open", "stat", "resolve", "strict", "other_function") or
            type(frame["line"]) is not int or not 0 <= frame["line"] <= 1000000):
            return None
    return {"initializationDiagnostic": item}


def fixed_descriptor(value):
    # This is a privacy projection, not a replacement for the installer's
    # existing native descriptor verification. Arbitrary paths are represented
    # by their hashes, never copied from subprocess text into stream evidence.
    if not isinstance(value, dict) or set(value) != {"descriptor", "closureSha256"}:
        return None
    descriptor = value["descriptor"]
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "schema", "pythonVersion", "python", "platform", "machine", "startup", "threadPolicy",
        "tesseractVersion", "leptonicaVersion", "modelSha256", "dependencyLockSha256", "files"}:
        return None
    if (type(descriptor["schema"]) is not int or descriptor["schema"] != 1 or
        descriptor["platform"] != "Linux" or descriptor["machine"] != "x86_64" or
        descriptor["startup"] != {"isolated": 1, "noSite": 1, "dontWriteBytecode": 1} or
        any(type(value) is not int for value in descriptor["startup"].values()) or
        descriptor["threadPolicy"] != {"OMP_THREAD_LIMIT": "1", "OMP_NUM_THREADS": "1"} or
        any(descriptor[key] != PROFILE[key] for key in ("pythonVersion", "tesseractVersion", "leptonicaVersion", "modelSha256")) or
        descriptor["dependencyLockSha256"] != LOCK_SHA256 or
        not isinstance(descriptor["python"], str) or not 1 <= len(descriptor["python"]) <= 4096 or
        not isinstance(descriptor["files"], list) or not 1 <= len(descriptor["files"]) <= 4096 or
        not isinstance(value["closureSha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["closureSha256"])):
        return None
    if digest(json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()) != value["closureSha256"]:
        return None
    files = []
    for item in descriptor["files"]:
        if (not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256", "mode", "mappedNative"} or
            not isinstance(item["path"], str) or not 1 <= len(item["path"]) <= 4096 or
            type(item["bytes"]) is not int or not 0 <= item["bytes"] <= 9007199254740991 or
            type(item["mode"]) is not int or not 0 <= item["mode"] <= 0o777 or
            type(item["mappedNative"]) is not bool or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            return None
        files.append({"pathSha256": digest(item["path"].encode()), **{key: item[key] for key in ("bytes", "sha256", "mode", "mappedNative")}})
    projected = {key: descriptor[key] for key in descriptor if key not in ("python", "files")}
    projected.update({"pythonPathSha256": digest(descriptor["python"].encode()), "files": files})
    return {"kind": "validated_runtime_descriptor_projection", "closureSha256": value["closureSha256"], "descriptor": projected}


def structured_stream(data, limit, stream, complete):
    # There is no reliable credential grammar for arbitrary subprocess text.
    # Keep only validated fixed fields; malformed or truncated text is omitted.
    # Prefix digests and lengths remain in summary.json, not in free-form text.
    reason, projected = "empty_stream", None
    if data:
        reason = "incomplete_or_truncated_stream" if not complete else "unrecognized_structure"
        if complete:
            try:
                def unique(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError("Duplicate diagnostic key.")
                        result[key] = value
                    return result
                value = json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite diagnostic value.")))
                projected = fixed_diagnostic(value) if stream == "stderr" else (fixed_error(value) or fixed_descriptor(value))
            except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
                reason = "invalid_json"
    if projected is not None:
        reason = "validated_fixed_fields"
    elif data:
        projected = {"diagnosticTextOmitted": True, "reason": reason}
    encoded = (json.dumps(projected, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii") if projected is not None else b""
    cut = len(encoded) > limit
    if cut:
        encoded = b""
        reason = "projection_exceeds_stream_limit"
    return encoded, cut, encoded != data, reason


def write_once(path, data):
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fchmod(handle.fileno(), 0o444)
        os.fsync(handle.fileno())


def run_initializer(command, *, cwd, attempts_root, env, timeout_seconds=MAX_SECONDS,
                    stdout_limit=MAX_STDOUT, stderr_limit=MAX_STDERR):
    """Run the fixed development initializer, persist its outcome, then return or raise.

    The caller supplies the existing trusted command, never media/caller options.
    Lower limits and synthetic commands are used only by the separate test fixture.
    Successful initialization is not a complete installation or OCR result.
    """
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or
        not 0 < timeout_seconds <= MAX_SECONDS or
        type(stdout_limit) is not int or not 1 <= stdout_limit <= MAX_STDOUT or
        type(stderr_limit) is not int or not 1 <= stderr_limit <= MAX_STDERR):
        raise ValueError("Invalid initializer evidence limits.")
    cwd, attempts_root = pathlib.Path(cwd).resolve(), pathlib.Path(attempts_root).absolute()
    if attempts_root.resolve() != attempts_root or attempts_root.is_symlink():
        raise ValueError("Refusing a linked initializer evidence destination.")
    attempts_root.mkdir(parents=True, exist_ok=True)
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    stamp = started_at.replace(":", "-")
    directory = attempts_root / (stamp + "-" + str(uuid.uuid4()))
    directory.mkdir(mode=0o700)
    begin = time.monotonic()
    row = {"schema": 1, "mode": "trusted startup only; no raster, OCR request, environment values or provider input",
           "attempt": directory.name, "startedAt": started_at, "stage": "source_identity", "outcome": "incomplete",
           "argv": list(command), "cwd": str(cwd), "environmentPolicy": ENV_POLICY,
           "python": {"path": str(pathlib.Path(sys.executable).resolve()), "version": platform.python_version(),
                      "sha256": digest(pathlib.Path(sys.executable).resolve().read_bytes())},
           "limits": {"timeoutSeconds": timeout_seconds, "stdoutBytes": stdout_limit, "stderrBytes": stderr_limit,
                      "reapSeconds": REAP_SECONDS},
           "pid": None, "exitCode": None, "signal": None, "timedOut": False, "killed": False, "reaped": False,
           "workerCode": None, "exceptionType": None, "sourceUnchanged": None}
    write_once(directory / "started.json", (json.dumps(row, indent=2) + "\n").encode())
    capture = {"stdout": bytearray(), "stderr": bytearray()}
    observed = {"stdout": 0, "stderr": 0}
    eof_seen = {"stdout": False, "stderr": False}
    stream_limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    process, before, manifest, cleanup_deadline = None, None, None, None
    deadline = begin + timeout_seconds
    def stop():
        nonlocal cleanup_deadline
        if process is not None and not row["reaped"]:
            if cleanup_deadline is None:
                cleanup_deadline = time.monotonic() + REAP_SECONDS
            try:
                os.killpg(process.pid, signal.SIGKILL)
                row["killed"] = True
            except ProcessLookupError:
                pass
    try:
        before = source_identity(cwd)
        write_once(directory / "source-before.json", (json.dumps(before, indent=2) + "\n").encode())
        row["source"] = {key: value for key, value in before.items() if key != "files"}
        row["source"]["files"] = len(before["files"])
        row["source"]["mapSha256"] = digest((directory / "source-before.json").read_bytes())
        if time.monotonic() >= deadline:
            row["timedOut"], row["outcome"] = True, "timeout"
            raise InitializationFailure("Initializer budget expired before process entry.")
        row["stage"] = "describe_runtime"
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        row["pid"] = process.pid
        with selectors.DefaultSelector() as selector:
            for name in ("stdout", "stderr"):
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            stop_deadline = None
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if now >= deadline and stop_deadline is None:
                    row["timedOut"], row["outcome"] = True, "timeout"
                    stop(); stop_deadline = cleanup_deadline
                if stop_deadline is not None and now >= stop_deadline:
                    break
                wait_until = stop_deadline if stop_deadline is not None else deadline
                for key, _ in selector.select(max(0, min(0.05, wait_until - now))):
                    data = os.read(key.fileobj.fileno(), 16384)
                    if not data:
                        eof_seen[key.data] = True
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    name = key.data
                    observed[name] += len(data)
                    remaining = stream_limits[name] - len(capture[name])
                    capture[name].extend(data[:remaining])
                    if observed[name] > stream_limits[name] and stop_deadline is None:
                        row["outcome"] = "output_limit"
                        stop(); stop_deadline = cleanup_deadline
        if process.poll() is None:
            stop()
        try:
            row["exitCode"] = process.wait(timeout=max(0, (cleanup_deadline or deadline) - time.monotonic()))
            row["reaped"] = True
        except subprocess.TimeoutExpired:
            row["outcome"] = "reap_timeout"
        if row["exitCode"] is not None and row["exitCode"] < 0:
            row["signal"] = -row["exitCode"]
        if row["outcome"] != "incomplete":
            raise InitializationFailure("Initializer did not complete within the evidence limits.")
        if row["exitCode"] != 0:
            row["outcome"] = "nonzero_exit"
            raise InitializationFailure("Initializer process failed.")
        row["stage"] = "manifest_validation"
        try:
            manifest = json.loads(bytes(capture["stdout"]))
        except (ValueError, UnicodeError):
            row["outcome"] = "invalid_json" if capture["stdout"] else "empty_stdout"
            raise InitializationFailure("Initializer did not return a JSON manifest.") from None
        if not isinstance(manifest, dict) or set(manifest) != {"descriptor", "closureSha256"}:
            code = manifest.get("code") if isinstance(manifest, dict) else None
            # A validated fixed error core remains useful even when its stream
            # has extra fields that the stricter persisted projection omits.
            if fixed_error(manifest, allow_extra=True) is not None:
                row["workerCode"] = code
            row["outcome"] = "worker_rejection" if isinstance(manifest, dict) and manifest.get("kind") == "rejected" else "invalid_manifest"
            raise InitializationFailure("Initializer refused or returned an invalid manifest.")
        row["outcome"] = "initialized"
    except Exception as error:
        row["exceptionType"] = type(error).__name__
        if row["outcome"] == "incomplete":
            row["outcome"] = "source_identity_failure" if row["stage"] == "source_identity" else "spawn_or_capture_failure"
        stop()
        if process is not None and not row["reaped"]:
            try:
                row["exitCode"] = process.wait(timeout=max(0, (cleanup_deadline or deadline) - time.monotonic()))
                row["reaped"] = True
            except subprocess.TimeoutExpired:
                row["outcome"] = "reap_timeout"
    finally:
        if process is not None:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
        row["failureStage"] = row["stage"] if row["outcome"] != "initialized" else None
        row["stage"] = "recording_evidence"
        if before is not None:
            try:
                after = source_identity(cwd)
                write_once(directory / "source-after.json", (json.dumps(after, indent=2) + "\n").encode())
                row["sourceUnchanged"] = before == after
                if not row["sourceUnchanged"]:
                    row["outcome"], row["failureStage"] = "source_changed", "source_after"
            except Exception as error:
                row["outcome"], row["exceptionType"] = "source_identity_failure", type(error).__name__
                row["failureStage"] = "source_after"
        if row["outcome"] == "initialized" and time.monotonic() >= deadline:
            row["outcome"], row["timedOut"], row["failureStage"] = "timeout", True, "final_deadline"
        if row["exitCode"] is not None and row["exitCode"] < 0:
            row["signal"] = -row["exitCode"]
        row["streams"] = {}
        for name in ("stdout", "stderr"):
            raw = bytes(capture[name])
            complete = observed[name] == len(raw) and eof_seen[name]
            safe, sanitation_cut, changed, reason = structured_stream(raw, stream_limits[name], name, complete)
            write_once(directory / (name + ".txt"), safe)
            row["streams"][name] = {"observedBytes": observed[name], "capturedBytes": len(raw),
                "capturedSha256": digest(raw), "captureTruncated": observed[name] > len(raw),
                "endOfStreamObserved": eof_seen[name],
                "storedBytes": len(safe), "storedSha256": digest(safe), "sanitized": changed,
                "sanitizationTruncated": sanitation_cut, "evidencePolicy": "validated-fixed-fields-v2",
                "projectionReason": reason, "file": name + ".txt"}
        row["elapsedSeconds"] = time.monotonic() - begin
        row["finishedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        row["stage"] = "finished"
        write_once(directory / "summary.json", (json.dumps(row, indent=2) + "\n").encode())
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if row["outcome"] != "initialized":
        raise InitializationFailure("Runtime initialization failed; preserved attempt " + directory.name + ".")
    return manifest
