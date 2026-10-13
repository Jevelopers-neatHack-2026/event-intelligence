#!/usr/bin/env python3
"""Explicit offline setup. Decoding never installs packages or contacts a registry."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import venv

VERSION = "3.12.14"
WHEEL_NAME = "pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"
WHEEL_SHA256 = "78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91"
WHEEL_BYTES = 6940830
PACKAGE_ROOTS = ["PIL", "pillow.libs", "pillow-12.3.0.dist-info"]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=pathlib.Path)
    parser.add_argument("--destination", required=True, type=pathlib.Path,
                        help="New, nonexistent absolute directory; never overwrites an environment")
    args = parser.parse_args()
    if (sys.implementation.name != "cpython" or platform.python_version() != VERSION
            or sys.platform != "linux" or platform.machine() != "x86_64"):
        parser.error("Requires CPython 3.12.14 on Linux x86-64")
    wheel = args.wheel.resolve(strict=True)
    if (not wheel.is_file() or wheel.name != WHEEL_NAME or wheel.stat().st_size != WHEEL_BYTES
            or digest(wheel) != WHEEL_SHA256):
        parser.error("The exact pinned Pillow wheel is required")
    destination = args.destination
    if (not destination.is_absolute() or destination.exists() or destination.is_symlink()
            or destination != destination.resolve()):
        parser.error("Destination must be a new canonical absolute path")
    # Incomplete setup is deliberately retained after failure; it has no runtime.json
    # and cannot be admitted by the reader. Do not erase diagnostic evidence.
    venv.EnvBuilder(with_pip=True, clear=False, symlinks=True).create(destination)
    python = destination / "bin" / "python"
    requirements = pathlib.Path(__file__).with_name("requirements.txt").resolve()
    command = [str(python), "-I", "-m", "pip", "--isolated", "install", "--no-index",
               "--find-links", str(wheel.parent), "--require-hashes", "--only-binary=:all:",
               "--no-deps", "--no-compile", "--disable-pip-version-check", "-r", str(requirements)]
    subprocess.run(command, check=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    site = destination / "lib" / "python3.12" / "site-packages"
    # -I -S avoids site initialization and .pth execution. Runtime import paths are
    # explicit, and this setup probe uses the same exact package directory.
    probe = ("import sys,json;sys.path.append(sys.argv[1]);import PIL;from PIL import features;"
             "print(json.dumps({'pillow':PIL.__version__,'jpeg':features.version_codec('jpg'),"
             "'webp':features.version_module('webp')}))")
    result = subprocess.run([str(python), "-I", "-S", "-B", "-c", probe, str(site)],
                            check=True, capture_output=True, text=True,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    if result.stderr or json.loads(result.stdout) != {"pillow": "12.3.0", "jpeg": "6.2", "webp": "1.6.0"}:
        raise RuntimeError("Pinned native codec feature check failed")
    files = []
    for name in PACKAGE_ROOTS:
        package = site / name
        if not package.is_dir() or package.is_symlink():
            raise RuntimeError("Missing pinned package directory")
        for path in sorted(package.rglob("*")):
            if path.is_symlink():
                raise RuntimeError("Unexpected package symlink")
            if path.is_file():
                files.append({"path": str(path.relative_to(site)), "bytes": path.stat().st_size,
                              "sha256": digest(path)})
    if not files or len(files) > 512:
        raise RuntimeError("Unexpected installed dependency inventory")
    executable = pathlib.Path(sys.executable).resolve(strict=True)
    manifest = {"schema": "ei-static-raster-runtime/1", "pythonVersion": VERSION,
                "implementation": "CPython", "architecture": "x86_64",
                "pythonExecutable": str(executable), "pythonSha256": digest(executable),
                "pillowVersion": "12.3.0", "jpegVersion": "6.2", "webpVersion": "1.6.0",
                "wheelFilename": WHEEL_NAME, "wheelSha256": WHEEL_SHA256,
                "sitePackages": "lib/python3.12/site-packages", "files": files}
    data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) > 256 * 1024:
        raise RuntimeError("Runtime manifest exceeded the fixed bound")
    marker = destination / "runtime.json"
    with marker.open("xb") as stream:
        stream.write(data)
    print(json.dumps({"status": "installed", "runtimeDirectory": str(destination),
                      "runtimeManifestSha256": hashlib.sha256(data).hexdigest(),
                      "wheelSha256": WHEEL_SHA256, "installedFiles": len(files),
                      "mode": "explicit offline setup; no media decode or provider call"}, sort_keys=True))


if __name__ == "__main__":
    main()
