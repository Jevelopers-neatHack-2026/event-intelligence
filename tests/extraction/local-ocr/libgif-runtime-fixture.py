"""Actual native dependency checks, with one explicitly injected preload omission."""
import ctypes as C
import hashlib
import json
import os
import pathlib
import shutil
import struct
import sys
import tempfile

ROOT = pathlib.Path(sys.argv[1]).resolve()
MODE = sys.argv[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "src/extraction/local-ocr"))
import worker
import native

LIBRARY = ROOT / "tools/local-ocr/runtime/site/usr/lib/x86_64-linux-gnu/libgif.so.7.2.0"
EXPECTED_SHA = "70ac81372d0ddbdf03dbdd7a9f994df625928cedf794b7c0a06c9eac27a4edc3"

class DlInfo(C.Structure):
    _fields_ = [("filename", C.c_char_p), ("base", C.c_void_p),
                ("symbol", C.c_char_p), ("address", C.c_void_p)]

def elf():
    # Independent test-only ELF64 inspection of the newly pinned dependency.
    data = LIBRARY.read_bytes()
    assert len(data) == 38904 and hashlib.sha256(data).hexdigest() == EXPECTED_SHA
    assert data[:6] == b"\x7fELF\x02\x01"
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    assert header[11] == 64 and 0 < header[12] < 256
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + index * 64) for index in range(header[12])]
    dynamic, = [section for section in sections if section[1] == 6]
    assert dynamic[9] == 16 and dynamic[5] % 16 == 0
    strings = sections[dynamic[6]]
    assert strings[1] == 3
    text = data[strings[4]:strings[4] + strings[5]]
    needed, soname = [], []
    for offset in range(dynamic[4], dynamic[4] + dynamic[5], 16):
        tag, value = struct.unpack_from("<qQ", data, offset)
        if tag in (1, 14):
            name = text[value:text.index(b"\0", value)].decode("ascii")
            (needed if tag == 1 else soname).append(name)
    assert needed == ["libc.so.6"] and soname == ["libgif.so.7"]
    print(json.dumps({"mode": "passive exact pinned ELF inventory", "sha256": EXPECTED_SHA,
                      "dtNeeded": needed, "soname": soname, "bytes": len(data)}))

def inspect():
    assert hashlib.sha256(LIBRARY.read_bytes()).hexdigest() == EXPECTED_SHA
    assert MODE in ("ordinary", "ambient-named", "ambient-renamed", "preloaded-pin", "without-preload")
    result = {"mode": MODE, "errorCode": None, "initialized": False, "descriptorAccepted": False,
              "preexistingSoname": False, "loadedTargets": [], "inputRead": False,
              "injectedFault": "omit absolute GIF preload only" if MODE == "without-preload" else None}
    original_load = native._load_library
    def observe_load(path, target, **options):
        result["loadedTargets"].append(target)
        return original_load(path, target, **options)
    native._load_library = observe_load
    with tempfile.TemporaryDirectory(prefix="ei-ocr-gif-origin-") as directory:
        if MODE in ("ambient-named", "ambient-renamed", "preloaded-pin"):
            ambient = LIBRARY
            if MODE != "preloaded-pin":
                ambient = pathlib.Path(directory) / ("foreign-native.so" if MODE == "ambient-renamed" else LIBRARY.name)
                shutil.copyfile(LIBRARY, ambient)
            loaded = C.CDLL(str(ambient), mode=C.RTLD_GLOBAL)
            present = C.CDLL("libgif.so.7", mode=os.RTLD_NOLOAD | os.RTLD_NOW)
            assert loaded._handle == present._handle
            result["preexistingSoname"] = True
        if MODE == "without-preload":
            original_cdll = C.CDLL
            def omit_preload(name, *args, **kwargs):
                if str(name) == str(LIBRARY):
                    return original_cdll(None)
                return original_cdll(name, *args, **kwargs)
            C.CDLL = omit_preload
        engine = None
        try:
            engine = worker.initialize()
            result["initialized"] = True
            descriptor = worker.describe_runtime()
            result["descriptorAccepted"] = True
            # This proves dependency lookup origin, not every ELF relocation or
            # containment of arbitrary hostile code already in the process.
            dladdr = native.bind(C.CDLL(None), "dladdr", [C.c_void_p, C.POINTER(DlInfo)], C.c_int)
            info = DlInfo()
            assert dladdr(C.cast(engine.lept.DGifOpen, C.c_void_p), C.byref(info)) == 1
            result["dependencyLookupPath"] = str(pathlib.Path(os.fsdecode(info.filename)).resolve())
            result["expectedPath"] = str(LIBRARY)
            result["hostGifFiles"] = [item["path"] for item in descriptor["files"]
                                      if item["mappedNative"] and pathlib.Path(item["path"]).name.startswith("libgif.so")]
        except worker.Rejection as error:
            result["errorCode"] = error.code
        except OSError:
            result["errorCode"] = "OCR_FAILURE"
        finally:
            if engine:
                engine.close()
    print(json.dumps(result, sort_keys=True))

elf() if MODE == "elf" else inspect()
