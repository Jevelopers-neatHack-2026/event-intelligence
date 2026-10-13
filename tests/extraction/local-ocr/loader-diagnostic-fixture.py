"""Synthetic loader faults; real worker, child ownership and structured collector."""
import hashlib
import json
import os
import pathlib
import struct
import sys
import tempfile

ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "OMP_THREAD_LIMIT": "1", "OMP_NUM_THREADS": "1"}

def worker_fault(root, mode):
    sys.path.insert(0, str(root / "src/extraction/local-ocr"))
    import worker
    import native
    original = native.C.CDLL
    target = "libtesseract.so.5.0.3" if mode == "tesseract_missing" else "liblept.so.5.0.4"
    dependency = "libarchive.so.13" if mode == "tesseract_missing" else "libgif.so.7"

    def load(name, *args, **kwargs):
        if not (type(name) is str and name.endswith(target)):
            return original(name, *args, **kwargs)
        message = dependency + ": cannot open shared object file: No such file or directory"
        if mode == "permission":
            message = dependency + ": cannot open shared object file: Permission denied"
        elif mode == "private_prefix":
            message = "SYNTHETIC_LOADER_PRIVATE_PREFIX " + message
        elif mode == "private_suffix":
            message += " SYNTHETIC_LOADER_PRIVATE_SUFFIX"
        elif mode == "oversized":
            message = "https://SYNTHETIC_LOADER_PRIVATE_URI" + "x" * 5000 + "@example.invalid/"
        elif mode == "unknown_dependency":
            message = "SYNTHETIC_LOADER_PRIVATE_LIBRARY.so: cannot open shared object file: No such file or directory"
        elif mode == "foreign_dependency":
            message = "libarchive.so.13: cannot open shared object file: No such file or directory"
        elif mode == "multi_args":
            raise OSError(message, "SYNTHETIC_LOADER_PRIVATE_SECOND_ARG")
        elif mode == "non_string_args":
            class Trap:
                def __str__(self):
                    raise AssertionError("SYNTHETIC_LOADER_PRIVATE_STRINGIFIER")
                def __repr__(self):
                    raise AssertionError("SYNTHETIC_LOADER_PRIVATE_REPR")
            raise OSError(Trap())
        elif mode == "string_subclass":
            class Trap(str):
                def __eq__(self, other):
                    raise AssertionError("SYNTHETIC_LOADER_PRIVATE_EQUALITY")
                def __len__(self):
                    raise AssertionError("SYNTHETIC_LOADER_PRIVATE_LENGTH")
            raise OSError(Trap(message))
        elif mode == "subclass_args_getter":
            class Trap(OSError):
                @property
                def args(self):
                    raise AssertionError("SYNTHETIC_LOADER_PRIVATE_ARGS_GETTER")
                def __str__(self):
                    raise AssertionError("SYNTHETIC_LOADER_PRIVATE_STRINGIFIER")
            raise Trap(message)
        elif mode == "dict_subclass":
            class Trap(dict):
                def __getitem__(self, key):
                    raise AssertionError("SYNTHETIC_LOADER_PRIVATE_DICT_GET")
                def __setitem__(self, key, value):
                    raise AssertionError("SYNTHETIC_LOADER_PRIVATE_DICT_SET")
                def get(self, key, default=None):
                    raise AssertionError("SYNTHETIC_LOADER_PRIVATE_DICT_GETTER")
            error = OSError(message)
            error.__dict__ = Trap()
            raise error
        elif mode == "real_missing_file":
            # A real dlopen failure for an absent synthetic local file. Its
            # unrecognized absolute path must never become a diagnostic value.
            with tempfile.TemporaryDirectory(prefix="ei-loader-missing-") as temporary:
                return original(str(pathlib.Path(temporary) / "SYNTHETIC_LOADER_PRIVATE_MISSING.so"), *args, **kwargs)
        raise OSError(message)

    native.C.CDLL = load
    sys.argv = [str(root / "src/extraction/local-ocr/worker.py"), "--recognize" if mode == "recognition" else "--describe-runtime"]
    worker.main()

def collector_fault(root, mode):
    profile = json.loads((root / "src/extraction/local-ocr/profile.json").read_text())
    print(json.dumps({"kind": "rejected", "protocol": profile["protocol"], "profile": profile["profile"],
                      "code": "OCR_FAILURE", "rasterSha256": None, "closureSha256": None, "enforcementControlsPassed": 0}))
    item = {"schema": 3, "phase": "initialize", "exceptionType": "OSError", "classification": "operating_system_error",
            "errno": None, "frames": [{"file": "native.py", "function": "_load_library", "line": 14}],
            "loader": {"target": "leptonica", "reason": "dependency_not_found", "dependency": "libgif.so.7"}}
    if mode == "extra":
        item["loader"]["message"] = "SYNTHETIC_LOADER_PRIVATE_EXTRA"
    elif mode == "unknown_target":
        item["loader"]["target"] = "SYNTHETIC_LOADER_PRIVATE_TARGET"
    elif mode == "unknown_dependency":
        item["loader"]["dependency"] = "SYNTHETIC_LOADER_PRIVATE_DEPENDENCY"
    elif mode == "unknown_reason":
        item["loader"]["reason"] = "SYNTHETIC_LOADER_PRIVATE_REASON"
    elif mode == "foreign_dependency":
        item["loader"]["dependency"] = "libarchive.so.13"
    elif mode == "unclassified_nonnull":
        item["loader"]["reason"] = "unclassified"
    elif mode == "old_schema_extra":
        item["schema"] = 2
    encoded = json.dumps({"initializationDiagnostic": item})
    if mode == "malformed":
        encoded = encoded[:-2] + "SYNTHETIC_LOADER_PRIVATE_TRUNCATED"
    elif mode == "duplicate":
        encoded = encoded.replace('"target": "leptonica"', '"target": "SYNTHETIC_LOADER_PRIVATE_DUPLICATE", "target": "leptonica"')
    print(encoded, file=sys.stderr)

def probe(root, family, mode):
    sys.path.insert(0, str(root / "tools/local-ocr"))
    from initialization_evidence import InitializationFailure, run_initializer
    with tempfile.TemporaryDirectory(prefix="ei-loader-evidence-") as temporary:
        attempts = pathlib.Path(temporary) / "attempts"
        command = [sys.executable, "-I", "-S", "-B", str(pathlib.Path(__file__).resolve()), "--child", str(root), family, mode]
        raised = False
        try:
            run_initializer(command, cwd=root, attempts_root=attempts, env=ENV, timeout_seconds=10)
        except InitializationFailure:
            raised = True
        directory, = attempts.iterdir()
        summary = json.loads((directory / "summary.json").read_text())
        streams = {name: (directory / (name + ".txt")).read_text() for name in ("stdout", "stderr")}
        files = {p.name: {"bytes": p.stat().st_size, "mode": p.stat().st_mode & 0o777,
                          "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in directory.iterdir()}
        assert all(item["mode"] == 0o444 for item in files.values())
        for name in ("stdout", "stderr"):
            data = streams[name].encode()
            assert hashlib.sha256(data).hexdigest() == summary["streams"][name]["storedSha256"]
            assert len(data) == summary["streams"][name]["storedBytes"] <= 8193
        try:
            owned = os.waitpid(summary["pid"], os.WNOHANG)
        except ChildProcessError:
            owned = None
        assert owned is None, "the initializer must reap its actual owned child"
        print(json.dumps({"family": family, "case": mode, "raised": raised, "summary": summary, "streams": streams, "files": files}))

def elf_inventory(root):
    # Independent test-only ELF64 section decoding. Inputs are first verified
    # against the existing lock; this does not add a production ELF parser.
    lock = json.loads((root / "tools/local-ocr/lock.json").read_text())
    expected = {item["path"]: item for package in lock["packages"] for item in package["files"]}
    actual = {}
    for target, filename in (("leptonica", "liblept.so.5.0.4"), ("tesseract", "libtesseract.so.5.0.3")):
        name = "usr/lib/x86_64-linux-gnu/" + filename
        data = (root / "tools/local-ocr/runtime/site" / name).read_bytes()
        assert len(data) == expected[name]["bytes"] and hashlib.sha256(data).hexdigest() == expected[name]["sha256"]
        assert data[:6] == b"\x7fELF\x02\x01"
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        assert header[11] == 64 and 0 < header[12] < 256
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + index * header[11]) for index in range(header[12])]
        dynamic, = [section for section in sections if section[1] == 6]
        assert dynamic[9] == 16 and dynamic[5] % 16 == 0
        strings = sections[dynamic[6]]
        assert strings[1] == 3
        string_data = data[strings[4]:strings[4] + strings[5]]
        needed = []
        for offset in range(dynamic[4], dynamic[4] + dynamic[5], 16):
            tag, value = struct.unpack_from("<qQ", data, offset)
            if tag == 1:
                end = string_data.index(b"\0", value)
                needed.append(string_data[value:end].decode("ascii"))
        actual[target] = needed
    sys.path.insert(0, str(root / "src/extraction/local-ocr"))
    import worker
    sys.path.insert(0, str(root / "tools/local-ocr"))
    import initialization_evidence
    assert {key: list(value) for key, value in worker.LOADER_NEEDED.items()} == actual
    assert {key: list(value) for key, value in initialization_evidence.LOADER_NEEDED.items()} == actual
    print(json.dumps({"mode": "exact pinned ELF inventory; no native execution", "needed": actual}))

if sys.argv[1] == "--child":
    root, family, mode = pathlib.Path(sys.argv[2]).resolve(), sys.argv[3], sys.argv[4]
    worker_fault(root, mode) if family == "worker" else collector_fault(root, mode)
elif sys.argv[1] == "--elf-inventory":
    elf_inventory(pathlib.Path(sys.argv[2]).resolve())
else:
    probe(pathlib.Path(sys.argv[2]).resolve(), sys.argv[3], sys.argv[4])
