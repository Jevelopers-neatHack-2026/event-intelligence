"""Synthetic own-file controls; the production API does not expose path loading."""
import ctypes as C
import errno
import hashlib
import json
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
marker = pathlib.Path(sys.argv[2]).resolve()
sys.path.insert(0, str(root/"src/extraction/scanned-pdf"))
import worker

pdf, pause, callback = worker.initialize()
libc = C.CDLL(None, use_errno=True)
libc.syscall.restype = C.c_long
encoded = os.fsencode(marker)
document = pdf.FPDF_LoadDocument(encoded, None)
assert document, "the synthetic control file must load before the filter"
assert pdf.FPDF_GetPageCount(document) == 1
pdf.FPDF_CloseDocument(document)
owned_fd = os.open(marker, os.O_RDONLY)
controls = worker.seal()
try:
    os.read(owned_fd, 1)
    raise AssertionError("an extra inherited descriptor remained open")
except OSError as error:
    assert error.errno == errno.EBADF
blocked = pdf.FPDF_LoadDocument(encoded, None)
assert not blocked, "native PDFium path loading must fail after seal"
native_error = pdf.FPDF_GetLastError()
assert native_error == pdf.FPDF_ERR_FILE
attempts = {}
for name, number, args in [
    ("openat", 257, [C.c_int(-100), C.c_char_p(encoded), C.c_int(0), C.c_uint(0)]),
    ("unlink", 87, [C.c_char_p(encoded)]),
    ("socket", 41, [C.c_int(2), C.c_int(1), C.c_int(0)]),
    ("connect_invalid_fd", 42, [C.c_int(-1), C.c_void_p(), C.c_uint(0)]),
]:
    C.set_errno(0)
    value = libc.syscall(C.c_long(number), *args)
    attempts[name] = {"value":value, "errno":C.get_errno()}
    assert attempts[name] == {"value":-1, "errno":errno.EPERM}
data = sys.stdin.buffer.read(worker.PROFILE["maxInputBytes"]+1)
admitted = worker.admit(data, worker.PROFILE)
rendered = worker.render(pdf, data, admitted, pause, worker.PROFILE, 16777216)
assert rendered[0]["bytes"].hex() == "ff0000ff00ff00ff0000ffffffffffff"
print(json.dumps({
    "mode":"synthetic own-file native access controls plus actual in-memory PDFium recovery after seccomp",
    "beforeSealPathLoad":True, "afterSealPathLoad":False, "nativeError":native_error,
    "extraDescriptorClosed":True, "enforcementControlsPassed":controls, "attempts":attempts,
    "sourceSha256":hashlib.sha256(data).hexdigest(), "pageSha256":rendered[0]["sha256"],
    "pixelsExact":True,
}))
pdf.FPDF_DestroyLibrary()
