"""Fixed private Pillow worker. Only the supervised Node reader is a bounded API."""
import ctypes
import _socket
import hashlib
import io
import json
import os
import pathlib
import platform
import resource
import socket
import struct
import sys
import warnings

PROTOCOL = "ei-static-jpeg-webp-worker/1"
CONFIG = "ei-static-jpeg-webp/1"
WHEEL_SHA256 = "78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91"
MAX_INPUT = 10 * 1024 * 1024
MAX_PIXELS = 4 * 1024 * 1024
MAX_OUTPUT = 20 * 1024 * 1024
MAX_HEADER = 4096
PACKAGE_ROOTS = ["PIL", "pillow.libs", "pillow-12.3.0.dist-info"]
JPEG_LIBRARY = "libjpeg-31e2ca52.so.62.4.0"
JPEG_LIBRARY_SHA256 = "6d7c754529b30aff22efaaf88ba02061714591702c03f297f00ccb32ee6d9d9a"
WEBP_LIBRARY = "libwebp-51b0b3f7.so.7.2.0"
WEBP_LIBRARY_SHA256 = "7df9ad3680dd09d756511334791c8c896207863816eb2910840e5fc4ae10028a"


class Refusal(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class JpegMessageParameters(ctypes.Union):
    _fields_ = [("integers", ctypes.c_int * 8), ("string", ctypes.c_char * 80)]


class JpegErrorManager(ctypes.Structure):
    # Exact public jpeg_error_mgr fields from libjpeg-turbo 3.1.4.1 jpeglib.h.
    # The fixed wheel targets the JPEG6.2 ABI on Linux x86-64. No callback is
    # replaced: fatal errors exit this supervised child, and warnings remain
    # visible on its bounded stderr as well as in num_warnings.
    _fields_ = [("error_exit", ctypes.c_void_p), ("emit_message", ctypes.c_void_p),
                ("output_message", ctypes.c_void_p), ("format_message", ctypes.c_void_p),
                ("reset_error_mgr", ctypes.c_void_p), ("msg_code", ctypes.c_int),
                ("msg_parm", JpegMessageParameters), ("trace_level", ctypes.c_int),
                ("num_warnings", ctypes.c_long), ("jpeg_message_table", ctypes.c_void_p),
                ("last_jpeg_message", ctypes.c_int), ("addon_message_table", ctypes.c_void_p),
                ("first_addon_message", ctypes.c_int), ("last_addon_message", ctypes.c_int)]


class JpegContext(ctypes.Structure):
    # Only the documented common err pointer is accessed. The remaining context
    # is opaque; jpeg_CreateDecompress checks both ABI62 and its exact 632-byte
    # size before any source input. A mismatch fails in the disposable child.
    _fields_ = [("err", ctypes.POINTER(JpegErrorManager)), ("opaque", ctypes.c_ubyte * 624)]


class StrictJpeg:
    def __init__(self, library):
        if (ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8
                or ctypes.sizeof(JpegContext) != 632 or ctypes.sizeof(JpegErrorManager) != 168
                or library.name != JPEG_LIBRARY or file_digest(library) != JPEG_LIBRARY_SHA256):
            raise Refusal("DECODER_UNAVAILABLE")
        self.library = ctypes.CDLL(str(library))
        self.api = {}
        signatures = {
            "jpeg_std_error": ([ctypes.POINTER(JpegErrorManager)], ctypes.POINTER(JpegErrorManager)),
            "jpeg_CreateDecompress": ([ctypes.POINTER(JpegContext), ctypes.c_int, ctypes.c_size_t], None),
            "jpeg_mem_src": ([ctypes.POINTER(JpegContext), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulong], None),
            "jpeg_read_header": ([ctypes.POINTER(JpegContext), ctypes.c_int], ctypes.c_int),
            "jpeg_read_coefficients": ([ctypes.POINTER(JpegContext)], ctypes.c_void_p),
            "jpeg_finish_decompress": ([ctypes.POINTER(JpegContext)], ctypes.c_int),
            "jpeg_destroy_decompress": ([ctypes.POINTER(JpegContext)], None),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.library, name)
            function.argtypes = arguments
            function.restype = result
            self.api[name] = function

    def validate(self, data):
        # Pillow intentionally discards libjpeg warnings. Its successful load
        # alone can therefore include repaired/filled pixels. Read all native
        # coefficients first with the original error manager and require zero
        # warnings; this prepass does not itself claim a pixel result.
        error = JpegErrorManager()
        context = JpegContext()
        context.err = self.api["jpeg_std_error"](ctypes.byref(error))
        self.api["jpeg_CreateDecompress"](ctypes.byref(context), 62, ctypes.sizeof(context))
        try:
            source = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
            self.api["jpeg_mem_src"](ctypes.byref(context), source, len(data))
            if (self.api["jpeg_read_header"](ctypes.byref(context), 1) != 1
                    or not self.api["jpeg_read_coefficients"](ctypes.byref(context))
                    or self.api["jpeg_finish_decompress"](ctypes.byref(context)) != 1
                    or error.num_warnings != 0):
                raise Refusal("MALFORMED_IMAGE")
        finally:
            self.api["jpeg_destroy_decompress"](ctypes.byref(context))


class StrictWebp:
    """Require native completion using only each declared compressed payload.

    The public API intentionally supplies no consumed-byte count. This prevents
    borrowing a RIFF pad or following chunk; it does not impose a canonical
    compressed representation or reject an otherwise complete alternate stream.
    """
    def __init__(self, library):
        if library.name != WEBP_LIBRARY or file_digest(library) != WEBP_LIBRARY_SHA256:
            raise Refusal("DECODER_UNAVAILABLE")
        self.library = ctypes.CDLL(str(library))
        self.info = self.library.WebPGetInfo
        self.info.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
        self.info.restype = ctypes.c_int
        self.decode = self.library.WebPDecodeRGBAInto
        self.decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.c_int]
        self.decode.restype = ctypes.c_void_p
        version = self.library.WebPGetDecoderVersion
        version.argtypes = []
        version.restype = ctypes.c_int
        if version() != 0x010600:
            raise Refusal("DECODER_UNAVAILABLE")

    def complete(self, payload, width, height):
        source = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        actual_width, actual_height = ctypes.c_int(), ctypes.c_int()
        if (not self.info(source, len(payload), ctypes.byref(actual_width), ctypes.byref(actual_height))
                or (actual_width.value, actual_height.value) != (width, height)):
            raise Refusal("MALFORMED_IMAGE")
        output = (ctypes.c_ubyte * (width * height * 4))()
        result = self.decode(source, len(payload), output, len(output), width * 4)
        if not result:
            raise Refusal("MALFORMED_IMAGE")
        if result != ctypes.addressof(output):
            raise Refusal("PROTOCOL_ERROR")
        return hashlib.sha256(output).hexdigest()

    def validate(self, data, profile):
        width, height = profile["width"], profile["height"]
        if (type(width) is not int or type(height) is not int or not 1 <= width <= 4096
                or not 1 <= height <= 4096 or width * height > MAX_PIXELS):
            raise Refusal("PROTOCOL_ERROR")
        if (data[:4] != b"RIFF" or data[8:12] != b"WEBP"
                or int.from_bytes(data[4:8], "little") + 8 != len(data)):
            raise Refusal("PROTOCOL_ERROR")
        at, chunks = 12, []
        while at < len(data):
            if len(chunks) >= 1024 or at + 8 > len(data):
                raise Refusal("PROTOCOL_ERROR")
            size = int.from_bytes(data[at + 4:at + 8], "little")
            end = at + 8 + size
            if end + (size & 1) > len(data):
                raise Refusal("PROTOCOL_ERROR")
            chunks.append((data[at:at + 4], data[at + 8:end]))
            at = end + (size & 1)
        if not chunks or chunks[-1][0] not in {b"VP8 ", b"VP8L"}:
            raise Refusal("PROTOCOL_ERROR")
        native_sha = self.complete(chunks[-1][1], width, height)
        for kind, alpha in chunks:
            if kind != b"ALPH":
                continue
            if not alpha or alpha[0] & 3 > 1:
                raise Refusal("MALFORMED_IMAGE")
            if alpha[0] & 3 == 0:
                if len(alpha) != width * height + 1:
                    raise Refusal("MALFORMED_IMAGE")
            else:
                # The specification defines ALPH compression as a headerless
                # VP8L image stream of implicit canvas dimensions. Add only that
                # five-byte header; never add RIFF padding or following bytes.
                header = b"\x2f" + ((width - 1) | ((height - 1) << 14)).to_bytes(4, "little")
                self.complete(header + alpha[1:], width, height)
            # Native opaque VP8 validation is separate from Pillow's actual
            # ALPH filtering/composition. It does not claim RGBA equivalence.
            return None
        return native_sha


def load_runtime(directory, expected_manifest):
    if (sys.implementation.name != "cpython" or platform.python_version() != "3.12.14"
            or sys.platform != "linux" or platform.machine() != "x86_64"
            or not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode):
        raise Refusal("DECODER_UNAVAILABLE")
    expected_limits = {resource.RLIMIT_AS: 512 * 1024 * 1024, resource.RLIMIT_CPU: 5,
                       resource.RLIMIT_NOFILE: 64, resource.RLIMIT_CORE: 0, resource.RLIMIT_FSIZE: 0}
    if any(resource.getrlimit(kind) != (value, value) for kind, value in expected_limits.items()):
        raise Refusal("ISOLATION_UNAVAILABLE")
    root = pathlib.Path(directory)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise Refusal("DECODER_UNAVAILABLE")
    marker = root / "runtime.json"
    if marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 256 * 1024:
        raise Refusal("DECODER_UNAVAILABLE")
    raw = marker.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_manifest:
        raise Refusal("DECODER_UNAVAILABLE")
    manifest = json.loads(raw)
    expected = {"schema": "ei-static-raster-runtime/1", "pythonVersion": "3.12.14",
                "implementation": "CPython", "architecture": "x86_64", "pillowVersion": "12.3.0",
                "jpegVersion": "6.2", "webpVersion": "1.6.0", "wheelSha256": WHEEL_SHA256,
                "sitePackages": "lib/python3.12/site-packages"}
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise Refusal("DECODER_UNAVAILABLE")
    executable = pathlib.Path(sys.executable).resolve(strict=True)
    if str(executable) != manifest["pythonExecutable"] or file_digest(executable) != manifest["pythonSha256"]:
        raise Refusal("DECODER_UNAVAILABLE")
    site = root / manifest["sitePackages"]
    entries = manifest["files"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 512:
        raise Refusal("DECODER_UNAVAILABLE")
    expected_files = set()
    for entry in entries:
        relative = pathlib.PurePosixPath(entry["path"])
        if (relative.is_absolute() or ".." in relative.parts or relative.parts[0] not in PACKAGE_ROOTS
                or str(relative) in expected_files or type(entry["bytes"]) is not int
                or not 0 <= entry["bytes"] <= 32 * 1024 * 1024):
            raise Refusal("DECODER_UNAVAILABLE")
        path = site / relative
        if (path.resolve(strict=True) != path or not path.is_file()
                or path.stat().st_size != entry["bytes"] or file_digest(path) != entry["sha256"]):
            raise Refusal("DECODER_UNAVAILABLE")
        expected_files.add(str(relative))
    actual = {str(path.relative_to(site)) for name in PACKAGE_ROOTS
              for path in (site / name).rglob("*") if path.is_file() or path.is_symlink()}
    if actual != expected_files:
        raise Refusal("DECODER_UNAVAILABLE")
    sys.path.append(str(site))
    import PIL
    from PIL import Image, ImageFile, JpegImagePlugin, WebPImagePlugin, features
    if (PIL.__version__ != "12.3.0" or features.version_codec("jpg") != "6.2"
            or features.version_module("webp") != "1.6.0"):
        raise Refusal("DECODER_UNAVAILABLE")
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    ImageFile.LOAD_TRUNCATED_IMAGES = False
    warnings.simplefilter("error", Image.DecompressionBombWarning)
    # Image.open(BytesIO, formats=[...]) still invokes preinit. Finish its fixed
    # imports before the per-image filesystem guard; the format list stays exact.
    Image.preinit()
    return (Image, StrictJpeg(site / "pillow.libs" / JPEG_LIBRARY),
            StrictWebp(site / "pillow.libs" / WEBP_LIBRARY))


def install_io_guard():
    """Cooperative Python guard, NOT an OS egress or hostile-native-code sandbox."""
    state = {"network": 0, "forbiddenIo": False}

    def deny_network(*_args, **_kwargs):
        state["network"] += 1
        raise Refusal("REMOTE_RESOURCE_ATTEMPT")

    for name in ["socket", "socketpair", "create_connection", "create_server", "getaddrinfo",
                 "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"]:
        setattr(socket, name, deny_network)
        # Cached Python socket wrappers call this module dynamically. Block that
        # entry before lazy IDNA imports can raise a different, swallowed refusal.
        # Keep the native socket class intact: captured Python subclasses call
        # its __init__ dynamically, which must still reach the socket audit.
        if name != "socket" and hasattr(_socket, name):
            setattr(_socket, name, deny_network)

    def audit(event, args):
        if event.startswith("socket."):
            deny_network()
        if (event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.fork", "os.forkpty",
                      "os.exec", "os.spawn", "ctypes.dlopen", "ctypes.dlsym"}
                or event.startswith("os.exec")):
            state["forbiddenIo"] = True
            raise Refusal("RESOURCE_LIMIT")
        if event == "open":
            # Imports are finished. The decoder only uses existing stdio and
            # BytesIO; untrusted image bytes cannot choose a filesystem path.
            state["forbiddenIo"] = True
            raise Refusal("RESOURCE_LIMIT")

    sys.addaudithook(audit)
    return state


def decode_pixels(image_api, data, request):
    profile = request["profile"]
    width, height = profile["width"], profile["height"]
    if (type(width) is not int or type(height) is not int or width < 1 or height < 1
            or width > 4096 or height > 4096 or width * height > MAX_PIXELS
            or profile["frames"] != 1 or profile["sourceFormat"] not in {"jpeg", "webp"}
            or profile["sourceMode"] not in {"L", "RGB", "RGBA"}):
        raise Refusal("PROTOCOL_ERROR")
    rows = (width * 4 + 1) * height
    output_length = 57 + 2 + rows + ((rows + 65534) // 65535) * 5 + 4
    if output_length > request["maxOutputBytes"]:
        raise Refusal("OUTPUT_LIMIT")
    expected_format = "JPEG" if profile["sourceFormat"] == "jpeg" else "WEBP"
    with image_api.open(io.BytesIO(data), formats=[expected_format]) as image:
        if (image.format != expected_format or image.size != (width, height)
                or image.mode != profile["sourceMode"] or getattr(image, "n_frames", 1) != 1
                or getattr(image, "is_animated", False)):
            raise Refusal("PROTOCOL_ERROR")
        if any(key in image.info for key in ["exif", "icc_profile", "xmp", "comment", "adobe"]):
            raise Refusal("UNSUPPORTED_FEATURE")
        image.load()  # Mandatory native decode; open()/headers alone are not pixels.
        if image.size != (width, height) or image.mode != profile["sourceMode"]:
            raise Refusal("PROTOCOL_ERROR")
        with image.convert("RGBA") as rgba:
            rgba.load()
            if rgba.size != (width, height) or rgba.mode != "RGBA":
                raise Refusal("PROTOCOL_ERROR")
            pixels = rgba.tobytes("raw", "RGBA")
    if len(pixels) != width * height * 4:
        raise Refusal("PROTOCOL_ERROR")
    return pixels


def main():
    common = {"protocol": PROTOCOL, "configVersion": CONFIG, "pythonVersion": platform.python_version(),
              "pillowVersion": "12.3.0", "jpegVersion": "6.2", "webpVersion": "1.6.0",
              "wheelSha256": WHEEL_SHA256, "runtimeManifestSha256": None, "sourceSha256": None,
              "networkApiAttemptCount": 0, "decodedRgbaBytes": 0}
    payload = b""
    guard = {"network": 0}
    try:
        if len(sys.argv) != 4 or len(sys.argv[3]) > MAX_HEADER:
            raise Refusal("PROTOCOL_ERROR")
        directory, manifest_sha, serialized_request = sys.argv[1:]
        common["runtimeManifestSha256"] = manifest_sha
        request = json.loads(serialized_request)
        common["sourceSha256"] = request["sourceSha256"]
        if type(request["maxOutputBytes"]) is not int or not 1 <= request["maxOutputBytes"] <= MAX_OUTPUT:
            raise Refusal("INVALID_LIMIT")
        try:
            image_api, strict_jpeg, strict_webp = load_runtime(directory, manifest_sha)
        except Refusal:
            raise
        except Exception:
            # Incomplete or malformed installation metadata is unavailable;
            # it cannot become an image decode or a partial pixel response.
            raise Refusal("DECODER_UNAVAILABLE") from None
        guard = install_io_guard()
        data = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise Refusal("INPUT_TOO_LARGE")
        if not data or hashlib.sha256(data).hexdigest() != request["sourceSha256"]:
            raise Refusal("PROTOCOL_ERROR")
        if request["profile"]["sourceFormat"] == "jpeg":
            strict_jpeg.validate(data)
            native_webp_sha = None
        else:
            native_webp_sha = strict_webp.validate(data, request["profile"])
        payload = decode_pixels(image_api, data, request)
        if native_webp_sha and hashlib.sha256(payload).hexdigest() != native_webp_sha:
            raise Refusal("PROTOCOL_ERROR")
        if guard["network"]:
            raise Refusal("REMOTE_RESOURCE_ATTEMPT")
        if guard["forbiddenIo"]:
            raise Refusal("RESOURCE_LIMIT")
        header = {**common, "kind": "decoded", **request["profile"],
                  "decodedRgbaBytes": len(payload), "rgbaSha256": hashlib.sha256(payload).hexdigest()}
    except Refusal as error:
        payload = b""
        header = {**common, "kind": "rejected", "code": error.code}
    except MemoryError:
        payload = b""
        header = {**common, "kind": "rejected", "code": "RESOURCE_LIMIT"}
    except Exception:
        payload = b""
        header = {**common, "kind": "rejected", "code": "DECODER_FAILURE"}
    header["networkApiAttemptCount"] = guard["network"]
    raw_header = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    if len(raw_header) > MAX_HEADER or len(payload) > 16 * 1024 * 1024:
        raise RuntimeError("Worker framing limit")
    sys.stdout.buffer.write(struct.pack(">I", len(raw_header)))
    sys.stdout.buffer.write(raw_header)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
