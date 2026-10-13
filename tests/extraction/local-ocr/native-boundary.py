"""Actual Tesseract native configuration-file denial, then real OCR recovery."""
import ctypes as C
import errno
import hashlib
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/"src/extraction/local-ocr"))
import worker
from native import bind

engine = worker.initialize()
descriptor = worker.describe_runtime()
manifest = json.loads((ROOT/"tools/local-ocr/runtime/manifest.json").read_text())
# This separately bound probe adds its own main module to the production closure.
probe = str(pathlib.Path(__file__).resolve())
assert any(item["path"] == probe for item in descriptor["files"])
descriptor["files"] = [item for item in descriptor["files"] if item["path"] != probe]
assert descriptor == manifest["descriptor"]
canary = sys.argv[1].encode()
read_config = bind(engine.library, "TessBaseAPIReadConfigFile", [C.c_void_p, C.c_char_p], None)
print_variables = bind(engine.library, "TessBaseAPIPrintVariablesToFile", [C.c_void_p, C.c_char_p], C.c_int)
get_mode = bind(engine.library, "TessBaseAPIGetPageSegMode", [C.c_void_p], C.c_int)
libc = C.CDLL(None, use_errno=True)
open_file = bind(libc, "open", [C.c_char_p, C.c_int], C.c_int)
unlink_file = bind(libc, "unlink", [C.c_char_p], C.c_int)

# A real, valid owned config is readable before sealing. It would change PSM.
read_config(engine.handle, canary)
assert get_mode(engine.handle) == 13
engine.set_mode(engine.handle, 6)
inherited = os.open(canary, os.O_RDONLY)
assert len(os.listdir("/proc/self/task")) == 1
controls = worker.seal()
try:
    os.fstat(inherited)
except OSError as error:
    assert error.errno == errno.EBADF
else:
    raise AssertionError("preopened own descriptor survived the seal")

C.set_errno(0)
read_config(engine.handle, canary)
assert get_mode(engine.handle) == 6 and C.get_errno() == errno.EPERM
C.set_errno(0)
assert print_variables(engine.handle, canary) == 0 and C.get_errno() == errno.EPERM
C.set_errno(0)
assert open_file(canary, os.O_RDONLY) == -1 and C.get_errno() == errno.EPERM
C.set_errno(0)
assert unlink_file(canary) == -1 and C.get_errno() == errno.EPERM
extra = engine.create()
C.set_errno(0)
assert engine.init(extra, canary, b"eng", 1) != 0
engine.delete(extra)
pixels = sys.stdin.buffer.read(220001)
assert len(pixels) == 220000 and hashlib.sha256(pixels).hexdigest() == "50f86c14d6b77e84ffb70a933a80ab9a0cb0226d2301f1044b024414ee43d168"
words, count = engine.read(pixels, 1000, 220, 1, worker.PROFILE, 32768, 2048)
assert " ".join(word["text"] for word in words) == "TICKET STUB 2026 DOORS OPEN AT 7 PM"
engine.close()
print(json.dumps({"mode":"actual native Tesseract on synthetic raster after native file/config/model denial",
 "controls":controls, "validConfigChangedModeBeforeSeal":True, "nativeReadConfigDenied":True,
 "nativeWriteConfigDenied":True, "nativeModelReopenDenied":True, "openDenied":True, "unlinkDenied":True,
 "inheritedDescriptorClosed":True, "postSealOcrWords":len(words), "tokenUtf8Bytes":count}, sort_keys=True))
