"""Explicit local fixture authoring only; never invoked by the reader or test runner.

Lossy expected pixels are recorded from a separate pinned-codec reference decode.
Lossless alpha/RGB and uniform grayscale are also asserted against source pixels.
"""
import base64
import hashlib
import io
import json
import pathlib
import sys

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
output = pathlib.Path(sys.argv[2])
if output.exists():
    raise SystemExit("Refusing to overwrite fixture evidence")
sys.path.append(str(runtime / "lib/python3.12/site-packages"))
import PIL
from PIL import Image, features

if PIL.__version__ != "12.3.0":
    raise SystemExit("Wrong fixture codec")
fixtures = {}


def add(name, image, format, options, exact_source=False, accepted=True):
    stream = io.BytesIO()
    image.save(stream, format, **options)
    data = stream.getvalue()
    with Image.open(io.BytesIO(data), formats=[format]) as reference:
        reference.load()
        rgba = reference.convert("RGBA").tobytes()
        info = {"mode": reference.mode, "frames": getattr(reference, "n_frames", 1)}
    if exact_source:
        assert rgba == image.convert("RGBA").tobytes(), name
    fixtures[name] = {"bytesBase64": base64.b64encode(data).decode(), "sourceSha256": hashlib.sha256(data).hexdigest(),
                      "sourceByteLength": len(data), "width": image.width, "height": image.height,
                      "expectedRgbaSha256": hashlib.sha256(rgba).hexdigest(), "expectedDecodedRgbaBytes": len(rgba),
                      "referenceMode": info["mode"], "referenceFrames": info["frames"], "acceptedProfile": accepted,
                      "reference": "separate Pillow native load and RGBA conversion", "exactSourcePixels": exact_source}
    if len(rgba) <= 4096:
        fixtures[name]["expectedRgbaBase64"] = base64.b64encode(rgba).decode()
    return data


gray = Image.new("L", (8, 4), 19)
add("jpeg-gray-baseline", gray, "JPEG", {"quality": 95}, exact_source=True)
rgb = Image.new("RGB", (4, 3))
rgb.putdata([(x * 47 % 256, x * 89 % 256, x * 137 % 256) for x in range(12)])
add("jpeg-rgb-baseline", rgb, "JPEG", {"quality": 95, "subsampling": 0})
add("jpeg-rgb-progressive", rgb, "JPEG", {"quality": 95, "subsampling": 0, "progressive": True})
pattern = Image.new("RGB", (64, 16))
pattern.putdata([((x * 43 + x // 7) % 256, x * 97 % 256, x * 193 % 256) for x in range(1024)])
restart = add("jpeg-restart-stuffed", pattern, "JPEG", {"quality": 93, "subsampling": 0, "restart_marker_blocks": 1})
assert b"\xff\x00" in restart and b"\xff\xdd" in restart and any(bytes([255, x]) in restart for x in range(0xd0, 0xd8))
add("webp-rgb-lossy", rgb, "WEBP", {"quality": 90, "method": 6})
add("webp-rgb-lossless", rgb, "WEBP", {"lossless": True, "exact": True}, exact_source=True)
rgba = Image.new("RGBA", (4, 3))
rgba.putdata([(x * 47 % 256, x * 89 % 256, x * 137 % 256, [0, 64, 128, 255][x % 4]) for x in range(12)])
add("webp-rgba-lossless", rgba, "WEBP", {"lossless": True, "exact": True}, exact_source=True)
add("webp-rgba-lossy", rgba, "WEBP", {"quality": 90, "method": 6, "exact": True})
alpha_pattern = Image.new("RGBA", (64, 32))
alpha_pattern.putdata([(19, 41, 97, [0, 64, 128, 255][x % 4]) for x in range(64 * 32)])
compressed_alpha = add("webp-rgba-compressed-alpha", alpha_pattern, "WEBP", {"quality": 90, "method": 6, "exact": True})
alpha_at = compressed_alpha.index(b"ALPH")
assert compressed_alpha[alpha_at + 8] & 3 == 1, "Required real compressed ALPH fixture"
add("jpeg-pixel-limit", Image.new("L", (2048, 2048), 19), "JPEG", {"quality": 95}, exact_source=True)
add("jpeg-cmyk", Image.new("CMYK", (2, 2), (0, 0, 0, 128)), "JPEG", {}, accepted=False)
exif = Image.Exif(); exif[274] = 6
add("jpeg-exif-orientation", rgb, "JPEG", {"exif": exif}, accepted=False)
add("webp-icc", rgb, "WEBP", {"icc_profile": b"synthetic-unaccepted-color-profile"}, accepted=False)
add("webp-xmp", rgb, "WEBP", {"xmp": b"<x:xmpmeta>synthetic</x:xmpmeta>"}, accepted=False)
add("webp-exif", rgb, "WEBP", {"exif": exif}, accepted=False)
second = Image.new("RGB", rgb.size, (255, 0, 0))
stream = io.BytesIO(); rgb.save(stream, "WEBP", save_all=True, append_images=[second], duration=[50, 50], loop=0, lossless=True)
data = stream.getvalue()
fixtures["webp-animation"] = {"bytesBase64": base64.b64encode(data).decode(), "sourceSha256": hashlib.sha256(data).hexdigest(),
                              "sourceByteLength": len(data), "acceptedProfile": False, "referenceFrames": 2}
document = {"mode": "synthetic authored pixels; real local pinned encoders and independent reference load; no provider activity",
            "runtime": {"python": sys.version.split()[0], "pillow": PIL.__version__, "jpeg": features.version_codec("jpg"), "webp": features.version_module("webp")},
            "fixtures": fixtures}
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
print(json.dumps({"fixtures": len(fixtures), "path": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "mode": document["mode"]}))
