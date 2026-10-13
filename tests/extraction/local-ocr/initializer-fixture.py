"""Explicit synthetic startup processes; never an OCR/provider success fixture."""
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

PROFILE = json.loads((pathlib.Path(__file__).resolve().parents[3] / "src/extraction/local-ocr/profile.json").read_text())

def rejection(code="RUNTIME_MISMATCH"):
    return {"kind": "rejected", "protocol": PROFILE["protocol"], "profile": PROFILE["profile"], "code": code,
            "rasterSha256": None, "closureSha256": None, "enforcementControlsPassed": 0}

def diagnostic():
    return {"initializationDiagnostic": {"schema": 2, "phase": "initialize", "exceptionType": "OSError",
            "classification": "operating_system_error", "errno": 2,
            "frames": [{"file": "native.py", "function": "__init__", "line": 10}]}}

def child(mode):
    if mode == "valid":
        print(json.dumps({"descriptor": {"syntheticStartupFixture": True}, "closureSha256": "0" * 64}))
    elif mode == "malformed":
        print("not JSON")
        print("synthetic startup diagnostic", file=sys.stderr)
    elif mode == "empty":
        pass
    elif mode == "rejected":
        print(json.dumps(rejection()))
    elif mode == "model_unavailable":
        worker_fault(pathlib.Path(__file__).resolve().parents[3], "--describe-runtime", mode)
    elif mode == "nonzero":
        child("valid")
        print("synthetic startup exit seven", file=sys.stderr)
        sys.exit(7)
    elif mode == "timeout":
        print("entered actual synthetic child", flush=True)
        time.sleep(10)
    elif mode in ("stdout_limit", "stderr_limit"):
        fd = 1 if mode == "stdout_limit" else 2
        for _ in range(1024):
            os.write(fd, b"bounded-fault" * 1024)
    elif mode == "signal":
        os.kill(os.getpid(), signal.SIGTERM)
    elif mode == "invalid_utf8":
        os.write(1, b"\xff\xfeinvalid")
    elif mode == "redaction":
        child("rejected")
        # These are explicit synthetic canaries, never real credentials.
        print("Authorization: Bearer SYNTHETIC_AUTH_CANARY", file=sys.stderr)
        print('password="SYNTHETIC_PASSWORD_CANARY"', file=sys.stderr)
        print("https://synthetic-user:synthetic-password@example.invalid/init?token=SYNTHETIC_URL_CANARY#fragment", file=sys.stderr)
        print("\x1b[31mloader diagnostic\x00\x90", file=sys.stderr)
    elif mode in ("redaction_quoted", "redaction_truncated_url", "redaction_json"):
        child("rejected")
        if mode == "redaction_quoted":
            print('password="synthetic-prefix SYNTHETIC_QUOTED_SECRET_TAIL"', file=sys.stderr)
        elif mode == "redaction_truncated_url":
            print('https://synthetic-user:SYNTHETIC_URI_SECRET' + 'x' * 6000 + '@example.invalid/startup', file=sys.stderr)
        else:
            print(json.dumps({"message": 'password="synthetic-prefix SYNTHETIC_QUOTED_SECRET_TAIL"'}), file=sys.stderr)
    elif mode in ("structured_diagnostic", "diagnostic_extra", "diagnostic_unknown_value", "diagnostic_duplicate"):
        child("rejected")
        value = diagnostic()
        if mode == "diagnostic_extra":
            value["initializationDiagnostic"]["message"] = "SYNTHETIC_STRUCTURED_SECRET"
        elif mode == "diagnostic_unknown_value":
            value["initializationDiagnostic"]["frames"][0]["file"] = "SYNTHETIC_STRUCTURED_SECRET"
        encoded = json.dumps(value)
        if mode == "diagnostic_duplicate":
            encoded = encoded.replace('"schema": 2', '"schema": "SYNTHETIC_DUPLICATE_SECRET", "schema": 2')
        print(encoded, file=sys.stderr)
    elif mode == "unknown_code":
        print(json.dumps(rejection("SYNTHETIC_CODE_SECRET")))
    elif mode == "error_extra":
        print(json.dumps({**rejection(), "privateText": "SYNTHETIC_STDOUT_SECRET"}))
    elif mode == "invalid_manifest":
        print(json.dumps({"descriptor": {}, "closureSha256": "0" * 64, "extra": True}))
    elif mode == "source_changed":
        pathlib.Path("bound.txt").write_text("changed by explicit synthetic child\n")
        child("valid")
    else:
        raise AssertionError("Unknown synthetic initializer mode")


def probe(root, mode):
    sys.path.insert(0, str(root / "tools/local-ocr"))
    from initialization_evidence import InitializationFailure, run_initializer
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "OMP_THREAD_LIMIT": "1", "OMP_NUM_THREADS": "1"}
    script = str(pathlib.Path(__file__).resolve())
    with tempfile.TemporaryDirectory(prefix="ei-ocr-initializer-test-") as temporary:
        directory = pathlib.Path(temporary)
        attempts = directory / "attempts"
        cwd = root
        if mode == "source_changed":
            cwd = directory / "source"
            cwd.mkdir()
            (cwd / "bound.txt").write_text("initial synthetic source\n")
            subprocess.run(["/usr/bin/git", "init", "--quiet", str(cwd)], check=True)
            subprocess.run(["/usr/bin/git", "-C", str(cwd), "add", "bound.txt"], check=True)
            subprocess.run(["/usr/bin/git", "-C", str(cwd), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                            "commit", "--quiet", "-m", "Synthetic source binding"], check=True)
        command = [str(pathlib.Path(sys.executable).resolve()), "-I", "-S", "-B", script, "--child", mode]
        if mode == "spawn_failure":
            command = [str(directory / "absent-executable")]
        outcome = None
        try:
            result = run_initializer(command, cwd=cwd, attempts_root=attempts, env=env,
                                     timeout_seconds=2.5 if mode == "timeout" else 10,
                                     stdout_limit=4096, stderr_limit=4096)
            outcome = {"returned": result}
        except InitializationFailure as error:
            outcome = {"raised": type(error).__name__}
        records = []
        for attempt in sorted(attempts.iterdir()):
            summary = json.loads((attempt / "summary.json").read_text())
            streams = {}
            for name in ("stdout", "stderr"):
                raw = (attempt / (name + ".txt")).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == summary["streams"][name]["storedSha256"]
                assert len(raw) == summary["streams"][name]["storedBytes"] <= 4096
                streams[name] = raw.decode("utf-8")
            files = {p.name: {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "mode": p.stat().st_mode & 0o777}
                     for p in attempt.iterdir() if p.is_file()}
            assert all(row["mode"] == 0o444 for row in files.values())
            if summary["pid"] is not None:
                # Source-after Git calls occur after the initializer was waited.
                # A numeric PID may already identify another process by now;
                # directly require that this parent has no live/waitable child
                # with that identity, rather than inspecting unrelated /proc data.
                try:
                    still_owned = os.waitpid(summary["pid"], os.WNOHANG)
                except ChildProcessError:
                    still_owned = None
                assert still_owned is None, "owned child was not reaped by the initializer"
                assert summary["reaped"] is True
            records.append({"summary": summary, "streams": streams, "files": files})
        print(json.dumps({"mode": "explicit synthetic initializer subprocess", "case": mode, "result": outcome, "records": records}))

def worker_fault(root, option, mode="default"):
    # An explicitly injected pre-input exception exercises the real worker's
    # two error routes. It does not claim a native-loader failure occurred.
    sys.path.insert(0, str(root / "src/extraction/local-ocr"))
    import worker
    def fail(site, profile):
        if mode == "model_unavailable":
            worker.reject("MODEL_UNAVAILABLE")
        if mode == "quoted_space":
            raise OSError('password="synthetic-prefix SYNTHETIC_QUOTED_SECRET_TAIL"')
        if mode == "truncated_userinfo":
            raise OSError('https://synthetic-user:SYNTHETIC_URI_SECRET' + 'x' * 3000 + '@example.invalid/startup')
        if mode == "stringification_trap":
            class UntrustedMessage(OSError):
                def __str__(self):
                    raise AssertionError("SYNTHETIC_STRINGIFICATION_SECRET")
            raise UntrustedMessage(13, "SYNTHETIC_STRINGIFICATION_SECRET")
        raise OSError("synthetic loader failure; token=SYNTHETIC_STAGE_CANARY; "
                      "https://user:password@example.invalid/init?key=SYNTHETIC_STAGE_URL\n\x1b" + "x" * 5000)
    worker.Engine = fail
    sys.argv = [str(root / "src/extraction/local-ocr/worker.py"), option]
    worker.main()


if __name__ == "__main__":
    if sys.argv[1] == "--child":
        child(sys.argv[2])
    elif sys.argv[1] == "--probe":
        probe(pathlib.Path(sys.argv[2]).resolve(), sys.argv[3])
    elif sys.argv[1] == "--worker-fault":
        worker_fault(pathlib.Path(sys.argv[2]).resolve(), sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "default")
    else:
        raise AssertionError("Unknown fixture entry")
