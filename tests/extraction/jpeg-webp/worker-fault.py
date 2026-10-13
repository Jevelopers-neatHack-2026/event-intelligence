"""Synthetic worker/protocol faults inside real supervised Linux processes.

This fixture is never an accepted decoder implementation. Production source is
loaded unchanged when a mode instruments an actual codec or guard boundary.
"""
import ctypes
import hashlib
import importlib.util
import json
import os
import pathlib
import resource
import socket
import struct
import subprocess
import sys
import time
import urllib.request

mode, worker_path = sys.argv[1:3]
canary_port = None
if mode.startswith("network-url:"):
    mode, port = mode.split(":", 1)
    canary_port = int(port)
sys.argv = [worker_path, *sys.argv[3:]]
request = json.loads(sys.argv[3])
spec = importlib.util.spec_from_file_location("actual_static_raster_worker", worker_path)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def diagnostic(value):
    os.write(3, (json.dumps(value, sort_keys=True) + "\n").encode())


if mode.startswith("frame-"):
    # Deliberate protocol double. The gray input and pixels have separately
    # passed the real codec suite; these responses test only parent validation.
    profile = request["profile"]
    pixels = bytes([19, 19, 19, 255]) * (profile["width"] * profile["height"])
    header = {"protocol": worker.PROTOCOL, "configVersion": worker.CONFIG, "pythonVersion": "3.12.14",
              "pillowVersion": "12.3.0", "jpegVersion": "6.2", "webpVersion": "1.6.0",
              "wheelSha256": worker.WHEEL_SHA256, "runtimeManifestSha256": sys.argv[2],
              "sourceSha256": request["sourceSha256"], "networkApiAttemptCount": 0,
              "kind": "decoded", **profile, "decodedRgbaBytes": len(pixels),
              "rgbaSha256": hashlib.sha256(pixels).hexdigest()}
    if mode == "frame-dimensions":
        header["width"], header["height"] = header["height"], header["width"]
    elif mode == "frame-format":
        header["sourceFormat"] = "webp"
    elif mode == "frame-mode":
        header["sourceMode"] = "RGBA"
    elif mode == "frame-frames":
        header["frames"] = 2
    elif mode == "frame-source":
        header["sourceSha256"] = "0" * 64
    elif mode == "frame-pixel-hash":
        header["rgbaSha256"] = "0" * 64
    elif mode == "frame-pixels":
        pixels = bytes([0]) + pixels[1:]
    elif mode == "frame-runtime":
        header["runtimeManifestSha256"] = "0" * 64
    elif mode == "frame-wheel":
        header["wheelSha256"] = "0" * 64
    elif mode == "frame-python":
        header["pythonVersion"] = "3.12.0"
    elif mode == "frame-protocol":
        header["protocol"] = "invented-acceptance"
    elif mode == "frame-extra":
        header["acceptedFacts"] = True
    elif mode == "frame-network":
        header["networkApiAttemptCount"] = 1
    elif mode == "frame-rejection-payload":
        for key in [*profile, "rgbaSha256"]:
            del header[key]
        header.update(kind="rejected", code="MALFORMED_IMAGE", decodedRgbaBytes=0)
    raw = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    if mode == "frame-duplicate":
        raw = b'{"width":123,' + raw[1:]
    if mode == "frame-invalid-utf8":
        raw = raw.replace(b"decoded", b"decod\xffd", 1)
    if mode == "frame-bom":
        raw = b"\xef\xbb\xbf" + raw
    frame = struct.pack(">I", len(raw)) + raw + pixels
    if mode == "frame-truncated":
        frame = frame[:-1]
    elif mode == "frame-tail":
        frame += b"x"
    elif mode == "frame-header-cap":
        frame = struct.pack(">I", 4097) + b"{}"
    elif mode == "frame-output-cap":
        frame = b"x" * (len(pixels) + 4096 + 5)
    elif mode == "frame-stderr-cap":
        os.write(2, b"x" * (16 * 1024 + 1))
    elif mode == "frame-stderr":
        os.write(2, b"synthetic codec warning\n")
    os.write(1, frame)
    if mode == "frame-nonzero":
        os._exit(7)
    raise SystemExit(0)

if mode == "exit":
    os._exit(7)

original_decode = worker.decode_pixels
original_guard = worker.install_io_guard
original_socket = socket.socket
original_lookup = socket.getaddrinfo


def instrumented_decode(image_api, data, submitted):
    diagnostic({"phase": "decode-entry", "mode": mode,
                "limits": {"as": resource.getrlimit(resource.RLIMIT_AS), "cpu": resource.getrlimit(resource.RLIMIT_CPU),
                           "nofile": resource.getrlimit(resource.RLIMIT_NOFILE), "fsize": resource.getrlimit(resource.RLIMIT_FSIZE)},
                "environmentKeys": sorted(os.environ)})
    if mode == "sleep":
        time.sleep(30)
    elif mode == "cpu":
        while True:
            pass
    elif mode == "memory":
        _too_large = bytearray(513 * 1024 * 1024)
        raise AssertionError("Address-space cap did not reject allocation")
    elif mode == "network-current":
        try:
            socket.socket()
        except worker.Refusal:
            pass  # A swallowed violation still invalidates the result.
    elif mode == "network-captured":
        try:
            original_socket()
        except worker.Refusal:
            pass
    elif mode == "network-lookup":
        try:
            original_lookup("127.0.0.1", 9)
        except worker.Refusal:
            pass
    elif mode == "network-url":
        urllib.request.urlopen("http://127.0.0.1:" + str(canary_port) + "/", timeout=0.2)
    elif mode == "subprocess":
        subprocess.run(["/bin/true"], check=True)
    elif mode == "file-read":
        pathlib.Path(worker_path).read_bytes()  # Nonsensitive, fixed test source.
    elif mode == "file-read-swallowed":
        try:
            pathlib.Path(worker_path).read_bytes()
        except worker.Refusal:
            pass  # A caught filesystem refusal cannot promote later pixels.
    elif mode == "file-write":
        pathlib.Path("synthetic-forbidden-output").write_bytes(b"synthetic")
    return original_decode(image_api, data, submitted)


def instrumented_guard():
    if mode == "fd":
        descriptors = []
        try:
            while True:
                descriptors.append(os.open("/dev/null", os.O_RDONLY))
        except OSError as error:
            assert error.errno == 24
            diagnostic({"phase": "fd-cap", "opened": len(descriptors), "limit": resource.getrlimit(resource.RLIMIT_NOFILE)})
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
    if mode == "abi":
        native = worker.StrictJpeg(pathlib.Path(sys.argv[1]) / "lib/python3.12/site-packages/pillow.libs" / worker.JPEG_LIBRARY)
        error = worker.JpegErrorManager()
        context = worker.JpegContext()
        context.err = native.api["jpeg_std_error"](ctypes.byref(error))
        diagnostic({"phase": "abi-negative", "correctSize": ctypes.sizeof(context), "suppliedSize": ctypes.sizeof(context) - 8})
        native.api["jpeg_CreateDecompress"](ctypes.byref(context), 62, ctypes.sizeof(context) - 8)
        raise AssertionError("Native ABI guard did not reject a wrong context size")
    return original_guard()


worker.decode_pixels = instrumented_decode
worker.install_io_guard = instrumented_guard
worker.main()
