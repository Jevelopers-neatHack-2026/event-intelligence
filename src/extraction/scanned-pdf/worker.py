"""Fixed private worker. Trusted initialization/pin checks precede the first input read."""
import ctypes as C
import hashlib
import json
import os
import pathlib
import platform
import struct
import sys
import zlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TOOLS = ROOT/"tools"/"scanned-pdf"
SITE = TOOLS/"runtime"/"site"
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from policy import Rejection, admit, reject
from native import render
from isolation import seal

PROFILE = json.loads((HERE/"profile.json").read_text())
LOCK = json.loads((TOOLS/"lock.json").read_text())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_wheel_files():
    expected = {item["path"]:item for item in LOCK["files"]}
    if SITE.resolve() != SITE or not SITE.is_dir():
        reject("RUNTIME_MISMATCH")
    entries = list(SITE.rglob("*"))
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in entries):
        reject("RUNTIME_MISMATCH")
    actual = {str(p.relative_to(SITE)) for p in entries if p.is_file()}
    if actual != set(expected):
        reject("RUNTIME_MISMATCH")
    for name, item in expected.items():
        path = SITE/name
        content = path.read_bytes()
        if path.stat().st_mode & 0o777 != 0o444 or len(content) != item["bytes"] or sha(content) != item["sha256"]:
            reject("RUNTIME_MISMATCH")


def describe_runtime():
    paths = {pathlib.Path(sys.executable).resolve(), pathlib.Path("/usr/bin/prlimit").resolve()}
    for module in list(sys.modules.values()):
        for attr in ("__file__", "__cached__"):
            value = getattr(module, attr, None)
            if value and pathlib.Path(value).is_file():
                paths.add(pathlib.Path(value).resolve())
    for line in pathlib.Path("/proc/self/maps").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[-1].startswith("/") and pathlib.Path(fields[-1]).is_file():
            paths.add(pathlib.Path(fields[-1]).resolve())
    files = []
    for path in sorted(paths):
        if path.is_relative_to(HERE) or path.is_relative_to(SITE):
            continue  # Repository source and exact wheel members have separate bindings.
        content = path.read_bytes()
        files.append({"path":str(path), "bytes":len(content), "sha256":sha(content),
                      "mode":path.stat().st_mode & 0o777})
    return {"schema":1, "pythonVersion":platform.python_version(),
            "python":str(pathlib.Path(sys.executable).resolve()),
            "platform":platform.system(), "machine":platform.machine(),
            "startup":{"isolated":sys.flags.isolated, "noSite":sys.flags.no_site,
                       "dontWriteBytecode":sys.flags.dont_write_bytecode},
            "wheelSha256":LOCK["wheelSha256"], "pdfiumVersion":PROFILE["pdfiumVersion"],
            "files":files}


def initialize():
    if (platform.python_version() != PROFILE["pythonVersion"] or
        not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode or
        platform.system() != "Linux" or platform.machine() != "x86_64"):
        reject("RUNTIME_MISMATCH")
    verify_wheel_files()
    sys.path.insert(0, str(SITE))
    import pypdfium2_raw as pdf
    from pypdfium2_raw.version import PDFIUM_INFO
    if PDFIUM_INFO.version != PROFILE["pdfiumVersion"] or PDFIUM_INFO.flags != ():
        reject("RUNTIME_MISMATCH")
    config = pdf.FPDF_LIBRARY_CONFIG(version=2, m_pUserFontPaths=None, m_pIsolate=None, m_v8EmbedderSlot=0)
    pdf.FPDF_InitLibraryWithConfig(C.byref(config))
    callback = pdf.IFSDK_PAUSE._fields_[1][1](lambda _: 0)
    pause = pdf.IFSDK_PAUSE(version=1, NeedToPauseNow=callback, user=None)
    # Warm trusted standard-library paths before closure capture and sealing.
    json.dumps({"warm":1}); zlib.compress(b"warm"); sha(b"warm")
    return pdf, pause, callback


def emit(header, outputs=()):
    encoded = json.dumps(header, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(encoded) > PROFILE["maxHeaderBytes"]:
        raise RuntimeError("bounded header")
    sys.stdout.buffer.write(struct.pack(">I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    for output in outputs:
        sys.stdout.buffer.write(output["bytes"])
    sys.stdout.buffer.flush()


def main():
    source_sha = None
    pdf = None
    max_output = PROFILE["maxOutputBytes"]
    controls = 0
    closure_sha = None
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in ("--render", "--describe-runtime"):
            reject("INVALID_OPTIONS")
        if sys.argv[1] == "--render":
            max_output = int(sys.argv[2])
            if not 1 <= max_output <= PROFILE["maxOutputBytes"]:
                reject("INVALID_LIMIT")
        pdf, pause, callback = initialize()
        descriptor = describe_runtime()
        descriptor_bytes = json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()
        closure_sha = sha(descriptor_bytes)
        if sys.argv[1] == "--describe-runtime":
            print(json.dumps({"descriptor":descriptor, "closureSha256":closure_sha}, sort_keys=True))
            return
        manifest = json.loads((TOOLS/"runtime"/"manifest.json").read_text())
        if descriptor != manifest["descriptor"] or closure_sha != manifest["closureSha256"]:
            reject("RUNTIME_MISMATCH")
        controls = seal()
        # No source bytes are read, parsed or decoded until native restrictions succeed.
        data = sys.stdin.buffer.read(PROFILE["maxInputBytes"]+1)
        if not data:
            reject("INVALID_INPUT")
        if len(data) > PROFILE["maxInputBytes"]:
            reject("INPUT_TOO_LARGE")
        source_sha = sha(data)
        admitted = admit(data, PROFILE)
        if sum(page["width"]*page["height"]*4 for page in admitted) > max_output:
            reject("OUTPUT_LIMIT")
        outputs = render(pdf, data, admitted, pause, PROFILE, max_output)
        header = {
            "kind":"decoded", "protocol":PROFILE["protocol"], "profile":PROFILE["profile"],
            "pythonVersion":PROFILE["pythonVersion"], "pdfiumVersion":PROFILE["pdfiumVersion"],
            "sourceSha256":source_sha, "closureSha256":closure_sha,
            "syscallPolicy":PROFILE["syscallPolicy"], "enforcementControlsPassed":controls,
            "maxOutputBytes":max_output, "pages":[{k:v for k,v in page.items() if k != "bytes"} for page in outputs],
        }
        emit(header, outputs)
    except Exception as error:
        code = error.code if isinstance(error, Rejection) else "DECODER_FAILURE"
        emit({"kind":"rejected", "protocol":PROFILE["protocol"], "profile":PROFILE["profile"],
              "pythonVersion":PROFILE["pythonVersion"], "pdfiumVersion":PROFILE["pdfiumVersion"],
              "sourceSha256":source_sha, "closureSha256":closure_sha if controls == 8 else None,
              "syscallPolicy":PROFILE["syscallPolicy"], "enforcementControlsPassed":controls,
              "maxOutputBytes":max_output, "code":code})
    finally:
        if pdf:
            pdf.FPDF_DestroyLibrary()


if __name__ == "__main__":
    main()
