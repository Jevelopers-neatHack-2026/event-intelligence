"""Measured OCR-only Linux x86_64 native boundary; requires a sole initialized thread."""
import ctypes as C
import errno
import os
import platform
from errors import reject

class Filter(C.Structure):
    _fields_ = [("code", C.c_ushort), ("jt", C.c_ubyte), ("jf", C.c_ubyte), ("k", C.c_uint32)]

class Program(C.Structure):
    _fields_ = [("length", C.c_ushort), ("filters", C.POINTER(Filter))]

def seal():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        reject("ISOLATION_UNAVAILABLE")
    # OpenMP is fixed to one thread before loading the library. Verify the real
    # process, then deny creation of any thread/process after this point.
    try:
        if len(os.listdir("/proc/self/task")) != 1:
            reject("ISOLATION_UNAVAILABLE")
        descriptors = [int(name) for name in os.listdir("/proc/self/fd") if int(name) > 2]
    except OSError:
        reject("ISOLATION_UNAVAILABLE")
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                reject("ISOLATION_UNAVAILABLE")
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                reject("ISOLATION_UNAVAILABLE")
        else:
            reject("ISOLATION_UNAVAILABLE")
    libc = C.CDLL(None, use_errno=True)
    libc.prctl.restype = C.c_int
    libc.syscall.restype = C.c_long
    # Needed by this separately exercised Tesseract/Leptonica configuration:
    # existing byte pipes, memory, signal return, clocks, pid/tid and futex.
    # Default denial includes file opening/path metadata/deletion, socket/connect,
    # exec, clone, io_uring, descriptor duplication and namespaces. This is not a
    # claim of complete host-OS containment or CPU speculation protection.
    allowed = (0, 1, 3, 5, 8, 9, 10, 11, 12, 13, 14, 15, 25, 28, 39, 60,
               131, 186, 202, 228, 231)
    instructions = [
        (0x20, 0, 0, 4), (0x15, 1, 0, 0xc000003e), (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000), (0x06, 0, 0, 0x00050001),
    ]
    for number in allowed:
        instructions.extend(((0x15, 0, 1, number), (0x06, 0, 0, 0x7fff0000)))
    instructions.append((0x06, 0, 0, 0x00050001))
    filters = (Filter*len(instructions))(*(Filter(*item) for item in instructions))
    program = Program(len(instructions), filters)
    if libc.prctl(C.c_int(38), C.c_ulong(1), C.c_ulong(0), C.c_ulong(0), C.c_ulong(0)) != 0:
        reject("ISOLATION_UNAVAILABLE")
    if libc.prctl(C.c_int(39), C.c_ulong(0), C.c_ulong(0), C.c_ulong(0), C.c_ulong(0)) != 1:
        reject("ISOLATION_UNAVAILABLE")
    if libc.prctl(C.c_int(22), C.c_ulong(2), C.byref(program), C.c_ulong(0), C.c_ulong(0)) != 0:
        reject("ISOLATION_UNAVAILABLE")
    # Deliberate invalid-argument controls; not counters of input-attempted I/O.
    controls = (
        (41, C.c_int(2), C.c_int(1), C.c_int(0)),
        (42, C.c_int(-1), C.c_void_p(), C.c_uint(0)),
        (257, C.c_int(-100), C.c_char_p(), C.c_int(0), C.c_uint(0)),
        (87, C.c_char_p()),
        (263, C.c_int(-100), C.c_char_p(), C.c_int(0)),
        (59, C.c_char_p(), C.c_void_p(), C.c_void_p()),
        (435, C.c_void_p(), C.c_size_t(0)),
        (425, C.c_uint(0), C.c_void_p()),
    )
    for number, *args in controls:
        C.set_errno(0)
        if libc.syscall(C.c_long(number), *args) != -1 or C.get_errno() != errno.EPERM:
            reject("ISOLATION_UNAVAILABLE")
    return len(controls)
