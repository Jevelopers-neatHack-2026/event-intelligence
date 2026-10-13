"""Development-only exact-wheel installer; runtime requests never download or provision."""
import argparse
import base64
import csv
import hashlib
import io
import json
import os
import pathlib
import platform
import subprocess
import sys
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCK = json.loads((HERE/"lock.json").read_text())
RUNTIME = HERE/"runtime"
WORKER = ROOT/"src/extraction/scanned-pdf/worker.py"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=pathlib.Path, help="Offline exact wheel; otherwise download the pinned development dependency")
    parser.add_argument("--check", action="store_true", help="Check the existing local installation without download or replacement")
    options = parser.parse_args()
    if platform.python_version() != LOCK["pythonVersion"] or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("Requires the declared CPython3.12.14 / Linux x86_64 profile.")
    if RUNTIME.is_symlink():
        raise SystemExit("Refusing a symlink runtime destination.")
    if not options.check:
        if RUNTIME.exists():
            raise SystemExit("Runtime already exists; use --check. Replacement is an explicit owner operation.")
        if options.wheel is None:
            wheels = HERE/"wheels"
            wheels.mkdir(exist_ok=True)
            requirements = HERE/"requirements.txt"
            subprocess.run([
                sys.executable, "-m", "pip", "download", "--disable-pip-version-check",
                "--only-binary=:all:", "--no-deps", "--require-hashes",
                "--index-url", "https://pypi.org/simple", "--dest", str(wheels), "-r", str(requirements),
            ], check=True)
            wheel = wheels/LOCK["wheel"]
        else:
            wheel = options.wheel.resolve(strict=True)
        data = wheel.read_bytes()
        if len(data) != LOCK["wheelBytes"] or hashlib.sha256(data).hexdigest() != LOCK["wheelSha256"]:
            raise SystemExit("Exact wheel bytes/digest mismatch; no extraction performed.")
        expected = {item["path"]:item for item in LOCK["files"]}
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = [item for item in archive.infolist() if not item.is_dir()]
            if len(infos) != len(expected) or {item.filename for item in infos} != set(expected):
                raise SystemExit("Wheel member set differs from the reviewed lock.")
            contents = {}
            for info in infos:
                path = pathlib.PurePosixPath(info.filename)
                if path.is_absolute() or ".." in path.parts or "\\" in info.filename or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise SystemExit("Unsafe wheel member.")
                content = archive.read(info)
                if len(content) != expected[info.filename]["bytes"] or hashlib.sha256(content).hexdigest() != expected[info.filename]["sha256"]:
                    raise SystemExit("Wheel member digest mismatch.")
                contents[info.filename] = content
            record_name = "pypdfium2-5.14.0.dist-info/RECORD"
            records = list(csv.reader(io.StringIO(contents[record_name].decode())))
            if len(records) != len(contents) or {row[0] for row in records} != set(contents):
                raise SystemExit("Wheel RECORD member set mismatch.")
            for name, digest, size in records:
                if name == record_name:
                    continue
                actual = "sha256="+base64.urlsafe_b64encode(hashlib.sha256(contents[name]).digest()).decode().rstrip("=")
                if digest != actual or int(size) != len(contents[name]):
                    raise SystemExit("Wheel RECORD digest mismatch.")
            # Extraction preserves every reviewed byte and notice. No entrypoint,
            # setup script, transitive dependency or pip-mutated RECORD is installed.
            for name, content in contents.items():
                target = RUNTIME/"site"/name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o444)
    command = [
        "/usr/bin/prlimit", "--as=1073741824:1073741824", "--cpu=5:5",
        "--core=0:0", "--nofile=64:64", "--", str(pathlib.Path(sys.executable).resolve()),
        "-I", "-S", "-B", str(WORKER), "--describe-runtime", "trusted-installation",
    ]
    result = subprocess.run(command, cwd=ROOT, env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"},
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=True)
    manifest = json.loads(result.stdout)
    if set(manifest) != {"descriptor", "closureSha256"} or "files" not in manifest["descriptor"]:
        raise SystemExit("Runtime description failed; inspect the retained installation before retrying.")
    if options.check:
        if json.loads((RUNTIME/"manifest.json").read_text()) != manifest:
            raise SystemExit("Loaded runtime closure differs from its local installation receipt.")
    else:
        (RUNTIME/"manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n")
    print(json.dumps({"mode":"trusted development dependency intake/check; no media/provider request",
        "checked":options.check, "wheelSha256":LOCK["wheelSha256"], "wheelMembers":len(LOCK["files"]),
        "python":manifest["descriptor"]["python"], "loadedRuntimeFiles":len(manifest["descriptor"]["files"]),
        "closureSha256":manifest["closureSha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
