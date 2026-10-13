"""Trusted model/runtime initialization, mandatory native seal, then bounded byte input."""
import hashlib
import json
import os
import pathlib
import platform
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TOOLS = ROOT/"tools/local-ocr"
SITE = TOOLS/"runtime/site"
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from errors import Rejection, reject
from native import Engine
from isolation import seal

PROFILE = json.loads((HERE/"profile.json").read_text())
LOCK_BYTES = (TOOLS/"lock.json").read_bytes()
LOCK = json.loads(LOCK_BYTES)
sha = lambda data: hashlib.sha256(data).hexdigest()

def exact_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject("INVALID_INPUT")
        result[key] = value
    return result

def verify_dependencies():
    expected = {item["path"]:item for package in LOCK["packages"] for item in package["files"]}
    if SITE.resolve() != SITE or not SITE.is_dir():
        reject("RUNTIME_MISMATCH")
    entries = list(SITE.rglob("*"))
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in entries):
        reject("RUNTIME_MISMATCH")
    if {str(p.relative_to(SITE)) for p in entries if p.is_file()} != set(expected):
        reject("RUNTIME_MISMATCH")
    for name, item in expected.items():
        path = SITE/name
        content = path.read_bytes()
        if path.stat().st_mode & 0o777 != 0o444 or len(content) != item["bytes"] or sha(content) != item["sha256"]:
            reject("RUNTIME_MISMATCH")

def initialize():
    if (platform.python_version() != PROFILE["pythonVersion"] or platform.system() != "Linux" or
        platform.machine() != "x86_64" or not sys.flags.isolated or not sys.flags.no_site or
        not sys.flags.dont_write_bytecode or os.environ.get("OMP_THREAD_LIMIT") != "1" or
        os.environ.get("OMP_NUM_THREADS") != "1"):
        reject("RUNTIME_MISMATCH")
    verify_dependencies()
    engine = Engine(SITE, PROFILE)
    # Warm fixed standard-library encodings and hash/JSON paths before capture.
    json.dumps({"warm":"é"}, allow_nan=False); b"warm".decode("utf-8"); sha(b"warm")
    return engine

def describe_runtime():
    paths = {pathlib.Path(sys.executable).resolve(), pathlib.Path("/usr/bin/prlimit").resolve()}
    for module in list(sys.modules.values()):
        for attribute in ("__file__", "__cached__"):
            value = getattr(module, attribute, None)
            if value and pathlib.Path(value).is_file():
                paths.add(pathlib.Path(value).resolve())
    mapped = set()
    for line in pathlib.Path("/proc/self/maps").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[-1].startswith("/") and pathlib.Path(fields[-1]).is_file():
            mapped.add(pathlib.Path(fields[-1]).resolve())
    expected_libraries = {SITE/"usr/lib/x86_64-linux-gnu/libtesseract.so.5.0.3", SITE/"usr/lib/x86_64-linux-gnu/liblept.so.5.0.4"}
    if {p for p in mapped if p.name.startswith(("libtesseract.so", "liblept.so"))} != expected_libraries:
        reject("RUNTIME_MISMATCH")
    paths.update(mapped)
    files = []
    for path in sorted(paths):
        if path.is_relative_to(HERE) or path.is_relative_to(SITE):
            continue
        content = path.read_bytes()
        files.append({"path":str(path), "bytes":len(content), "sha256":sha(content), "mode":path.stat().st_mode & 0o777,
                      "mappedNative":path in mapped})
    return {"schema":1, "pythonVersion":platform.python_version(), "python":str(pathlib.Path(sys.executable).resolve()),
            "platform":platform.system(), "machine":platform.machine(),
            "startup":{"isolated":sys.flags.isolated, "noSite":sys.flags.no_site, "dontWriteBytecode":sys.flags.dont_write_bytecode},
            "threadPolicy":{"OMP_THREAD_LIMIT":"1", "OMP_NUM_THREADS":"1"},
            "tesseractVersion":PROFILE["tesseractVersion"], "leptonicaVersion":PROFILE["leptonicaVersion"],
            "modelSha256":PROFILE["modelSha256"], "dependencyLockSha256":sha(LOCK_BYTES), "files":files}

def read_input():
    # The caller has already installed seccomp. No source path/URL is accepted.
    data = sys.stdin.buffer.read(PROFILE["maxInputBytes"]+PROFILE["maxHeaderBytes"]+5)
    if len(data) < 6:
        reject("INVALID_INPUT")
    length = struct.unpack(">I", data[:4])[0]
    if not 2 <= length <= PROFILE["maxHeaderBytes"] or 4+length >= len(data):
        reject("INVALID_INPUT")
    try:
        header = json.loads(data[4:4+length].decode("utf-8"), object_pairs_hook=exact_object,
                            parse_constant=lambda _: reject("INVALID_INPUT"))
    except (ValueError, UnicodeError):
        reject("INVALID_INPUT")
    if not isinstance(header, dict) or set(header) != {"width", "height", "format", "rasterSha256", "maxTextBytes", "maxWords"}:
        reject("INVALID_INPUT")
    width, height = header["width"], header["height"]
    if type(width) is not int or type(height) is not int or width < 1 or height < 1:
        reject("INVALID_INPUT")
    if width > PROFILE["maxDimension"] or height > PROFILE["maxDimension"]:
        reject("DIMENSION_LIMIT")
    if width*height > PROFILE["maxPixels"]:
        reject("PIXEL_LIMIT")
    if header["format"] not in ("gray8", "rgba8"):
        reject("UNSUPPORTED_RASTER")
    channels = 1 if header["format"] == "gray8" else 4
    pixels = data[4+length:]
    if len(pixels) > PROFILE["maxInputBytes"]:
        reject("INPUT_TOO_LARGE")
    if len(pixels) != width*height*channels or header["rasterSha256"] != sha(pixels):
        reject("INVALID_INPUT")
    if channels == 4 and any(alpha != 255 for alpha in pixels[3::4]):
        reject("UNSUPPORTED_RASTER")
    for key in ("maxTextBytes", "maxWords"):
        if type(header[key]) is not int or not 1 <= header[key] <= PROFILE[key]:
            reject("INVALID_LIMIT")
    return header, pixels, channels

def emit(value):
    data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(data) > PROFILE["maxOutputBytes"]:
        reject("OUTPUT_LIMIT")
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()

def initialization_diagnostic(error, phase):
    # This runs only for the trusted, pre-input --describe-runtime operation.
    # Never stringify an exception or retain arbitrary messages. Known source
    # frame identifiers are useful for diagnosis without exposing locals,
    # paths, filenames supplied by a caller, environment, model bytes or media.
    exception_types = {"Rejection", "OSError", "FileNotFoundError", "PermissionError", "MemoryError",
                       "ImportError", "ModuleNotFoundError", "ValueError", "TypeError", "RuntimeError",
                       "UnicodeError", "UnicodeDecodeError", "JSONDecodeError", "OverflowError", "RecursionError"}
    source_files = {"worker.py", "native.py", "isolation.py", "errors.py", "__init__.py", "pathlib.py"}
    source_functions = {"main", "initialize", "verify_dependencies", "describe_runtime", "__init__",
                        "reject", "read_bytes", "read_text", "open", "stat", "resolve", "strict"}
    if isinstance(error, Rejection):
        classification = "fixed_policy_rejection"
    elif isinstance(error, OSError):
        classification = "operating_system_error"
    elif isinstance(error, ImportError):
        classification = "module_import_error"
    elif isinstance(error, MemoryError):
        classification = "memory_error"
    else:
        classification = "initialization_error"
    error_number = error.errno if isinstance(error, OSError) else None
    if type(error_number) is not int or not 1 <= error_number <= 4095:
        error_number = None
    exception_type = type(error).__name__
    if exception_type not in exception_types:
        exception_type = "Exception"
    frames = []
    trace = error.__traceback__
    while trace is not None and len(frames) < 8:
        name = pathlib.Path(trace.tb_frame.f_code.co_filename).name
        function = trace.tb_frame.f_code.co_name
        frames.append({"file": name if name in source_files else "other_source",
                       "function": function if function in source_functions else "other_function",
                       "line": trace.tb_lineno if 0 <= trace.tb_lineno <= 1000000 else 0})
        trace = trace.tb_next
    value = {"initializationDiagnostic": {"schema": 2, "phase": phase,
             "exceptionType": exception_type, "classification": classification, "errno": error_number, "frames": frames}}
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(data) <= 8192:
        sys.stderr.buffer.write(data + b"\n")
        sys.stderr.buffer.flush()

def main():
    engine, closure, raster_sha, controls = None, None, None, 0
    initialization_phase = "options"
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("--recognize", "--describe-runtime"):
            reject("INVALID_OPTIONS")
        initialization_phase = "initialize"
        engine = initialize()
        initialization_phase = "describe_runtime"
        descriptor = describe_runtime()
        closure = sha(json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode())
        if sys.argv[1] == "--describe-runtime":
            print(json.dumps({"descriptor":descriptor, "closureSha256":closure}, sort_keys=True))
            return
        manifest = json.loads((TOOLS/"runtime/manifest.json").read_text())
        if descriptor != manifest["descriptor"] or closure != manifest["closureSha256"]:
            reject("RUNTIME_MISMATCH")
        controls = seal()
        header, pixels, channels = read_input()
        raster_sha = header["rasterSha256"]
        words, count = engine.read(pixels, header["width"], header["height"], channels,
                                   PROFILE, header["maxTextBytes"], header["maxWords"])
        emit({"kind":"observed", "protocol":PROFILE["protocol"], "profile":PROFILE["profile"],
              "tesseractVersion":PROFILE["tesseractVersion"], "modelSha256":PROFILE["modelSha256"],
              "closureSha256":closure, "syscallPolicy":PROFILE["syscallPolicy"], "enforcementControlsPassed":controls,
              "rasterSha256":raster_sha, "width":header["width"], "height":header["height"], "format":header["format"],
              "maxTextBytes":header["maxTextBytes"], "maxWords":header["maxWords"], "tokenUtf8Bytes":count, "words":words})
    except Exception as error:
        if len(sys.argv) == 2 and sys.argv[1] == "--describe-runtime":
            initialization_diagnostic(error, initialization_phase)
        code = error.code if isinstance(error, Rejection) else "OCR_FAILURE"
        emit({"kind":"rejected", "protocol":PROFILE["protocol"], "profile":PROFILE["profile"],
              "code":code, "rasterSha256":raster_sha, "closureSha256":closure if controls == 8 else None,
              "enforcementControlsPassed":controls})
    finally:
        if engine:
            engine.close()

if __name__ == "__main__":
    main()
