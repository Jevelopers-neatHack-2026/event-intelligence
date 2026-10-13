"""Trusted development intake, no package scripts or runtime network provisioning."""
import argparse
import hashlib
import io
import json
import os
import pathlib
import platform
import subprocess
import sys
import tarfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from initialization_evidence import run_initializer

LOCK = json.loads((HERE/"lock.json").read_text())
RUNTIME = HERE/"runtime"
WORKER = ROOT/"src/extraction/local-ocr/worker.py"
ENV = {"PATH":"/usr/bin:/bin", "LANG":"C.UTF-8", "LC_ALL":"C.UTF-8", "OMP_THREAD_LIMIT":"1", "OMP_NUM_THREADS":"1"}
sha = lambda data: hashlib.sha256(data).hexdigest()

def contents_for(package, data):
    if len(data) != package["bytes"] or sha(data) != package["sha256"]:
        raise ValueError("Exact reviewed archive digest/length mismatch; no extraction performed.")
    # Only the data tar stream is decoded. dpkg installation, maintainer scripts,
    # global package changes, model execution and network requests are absent.
    result = subprocess.run(["/usr/bin/dpkg-deb", "--fsys-tarfile", "/dev/stdin"], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True)
    if len(result.stdout) > 24*1024*1024:
        raise ValueError("Reviewed data tar exceeds the intake ceiling.")
    expected = {item["path"]:item for item in package["files"]}
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != package["dataMemberCount"]:
            raise ValueError("Unexpected package member inventory.")
        for member in members:
            name = member.name.removeprefix("./")
            pure = pathlib.PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or "\\" in name:
                raise ValueError("Unsafe archive name.")
            if not member.isfile():
                if not member.isdir() and not member.issym():
                    raise ValueError("Unexpected non-regular package member.")
                continue  # No archive link is installed or followed.
            if name not in expected or name in contents or member.size > 8*1024*1024:
                raise ValueError("Unexpected package file.")
            content = archive.extractfile(member).read()
            if len(content) != expected[name]["bytes"] or sha(content) != expected[name]["sha256"]:
                raise ValueError("Package file differs from the exact reviewed member.")
            contents[name] = content
    if set(contents) != set(expected):
        raise ValueError("Missing reviewed package files.")
    return contents

def host_provenance(descriptor):
    records = []
    for item in descriptor["files"]:
        if not item["mappedNative"]:
            continue
        query = subprocess.run(["/usr/bin/dpkg-query", "-S", item["path"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        packages = []
        if query.returncode == 0:
            for line in query.stdout.decode().splitlines():
                package = line.split(": ", 1)[0]
                version = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n", package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                notice = pathlib.Path("/usr/share/doc")/package.split(":",1)[0]/"copyright"
                row = {"package":package, "queryExit":version.returncode, "identity":version.stdout.decode().strip()}
                if notice.is_file():
                    data = notice.read_bytes()
                    name = package.replace(":", "-")+"-copyright.txt"
                    destination = RUNTIME/"host-notices"/name
                    destination.parent.mkdir(exist_ok=True)
                    destination.write_bytes(data)
                    row["notice"] = {"file":"host-notices/"+name, "bytes":len(data), "sha256":sha(data)}
                packages.append(row)
        records.append({**item, "packageMetadata":packages,
                        "provenanceClass":"distro-metadata" if packages else "runtime-owned-file-digest-only"})
    return records

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archives", type=pathlib.Path, help="Directory containing the three exact offline .deb archives")
    parser.add_argument("--check", action="store_true", help="Verify the installed files and loaded closure; no downloads or replacement")
    options = parser.parse_args()
    if platform.python_version() != LOCK["pythonVersion"] or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("Requires CPython3.12.14 / Linux x86_64 and the declared compatible host libraries.")
    if RUNTIME.is_symlink():
        raise SystemExit("Refusing a symlink runtime destination.")
    if not options.check:
        if RUNTIME.exists():
            raise SystemExit("Runtime exists; use --check. Replacement requires an explicit development operation.")
        staged = {}
        for package in LOCK["packages"]:
            if options.archives:
                data = (options.archives/package["archive"]).read_bytes()
            else:
                import urllib.request
                with urllib.request.urlopen(package["url"], timeout=30) as response:
                    if response.url != package["url"]:
                        raise ValueError("Pinned development archive unexpectedly redirected.")
                    data = response.read(package["bytes"]+1)
                archives = HERE/"archives"
                archives.mkdir(exist_ok=True)
                # A mismatched download is not installed and is left for diagnosis.
                (archives/package["archive"]).write_bytes(data)
            entries = contents_for(package, data)
            if set(staged) & set(entries):
                raise ValueError("Overlapping pinned package files.")
            staged.update(entries)
        for name, data in staged.items():
            target = RUNTIME/"site"/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o444)
    command = ["/usr/bin/prlimit", "--as=1073741824:1073741824", "--cpu=5:5", "--core=0:0", "--nofile=64:64", "--",
               str(pathlib.Path(sys.executable).resolve()), "-I", "-S", "-B", str(WORKER), "--describe-runtime"]
    manifest = run_initializer(command, cwd=ROOT, env=ENV,
                               attempts_root=RUNTIME/"initialization-attempts")
    if options.check:
        if json.loads((RUNTIME/"manifest.json").read_text()) != manifest:
            raise ValueError("Loaded runtime closure differs from its trusted installation receipt.")
    else:
        (RUNTIME/"manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n")
        provenance = host_provenance(manifest["descriptor"])
        (RUNTIME/"host-provenance.json").write_text(json.dumps(provenance, indent=2)+"\n")
    print(json.dumps({"mode":"trusted development dependency intake/check; no OCR/provider request",
        "checked":options.check, "packages":len(LOCK["packages"]), "pinnedFiles":sum(len(p["files"]) for p in LOCK["packages"]),
        "modelSha256":LOCK["modelSha256"], "loadedRuntimeFiles":len(manifest["descriptor"]["files"]),
        "closureSha256":manifest["closureSha256"]}, sort_keys=True))

if __name__ == "__main__":
    main()
