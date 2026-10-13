import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { input } from "./helpers.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const python = JSON.parse(readFileSync(path.join(root, "tools/local-ocr/runtime/manifest.json"))).descriptor.python;
const env = { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", OMP_THREAD_LIMIT: "1", OMP_NUM_THREADS: "1" };
const limits = ["--as=1073741824:1073741824", "--cpu=5:5", "--core=0:0", "--nofile=64:64", "--", python, "-I", "-S", "-B"];
const library = "tools/local-ocr/runtime/site/usr/lib/x86_64-linux-gnu/libgif.so.7.2.0";

function inspect(mode) {
  const result = spawnSync("/usr/bin/prlimit", [...limits,
    "tests/extraction/local-ocr/libgif-runtime-fixture.py", root, mode],
  { cwd: root, env, timeout: 15000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr?.toString());
  assert.equal(result.signal, null);
  return JSON.parse(result.stdout);
}

function clone(t) {
  const directory = mkdtempSync(path.join(tmpdir(), "ei-ocr-pinned-gif-"));
  for (const relative of ["src/extraction/local-ocr", "tools/local-ocr"]) {
    mkdirSync(path.dirname(path.join(directory, relative)), { recursive: true });
    cpSync(path.join(root, relative), path.join(directory, relative), { recursive: true,
      filter: (source) => !["archives", "verification", "initialization-attempts"].some((part) =>
        source.includes(path.sep + part + path.sep) || source.endsWith(path.sep + part)) });
  }
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function refusedBeforeInput(directory) {
  const result = spawnSync("/usr/bin/prlimit", [...limits, "src/extraction/local-ocr/worker.py", "--recognize"],
    { cwd: directory, env, input: Buffer.from("not a valid frame"), timeout: 15000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr?.toString());
  assert.equal(result.signal, null);
  assert.equal(result.stderr.length, 0, "recognition must not leak startup diagnostics");
  const refusal = JSON.parse(result.stdout);
  assert.equal(refusal.kind, "rejected");
  assert.equal(refusal.code, "RUNTIME_MISMATCH");
  assert.equal(refusal.enforcementControlsPassed, 0);
  assert.equal(refusal.rasterSha256, null);
  assert.equal(refusal.closureSha256, null);
}

test("actual Leptonica dependency lookup uses the exact staged gif library after an absent prior handle", () => {
  const result = inspect("ordinary");
  assert.equal(result.preexistingSoname, false);
  assert.equal(result.initialized, true);
  assert.equal(result.descriptorAccepted, true);
  assert.equal(result.errorCode, null);
  assert.equal(result.dependencyLookupPath, result.expectedPath);
  assert.deepEqual(result.hostGifFiles, []);
  assert.deepEqual(result.loadedTargets, ["leptonica", "tesseract"]);
  assert.equal(result.inputRead, false);
});

for (const mode of ["ambient-named", "ambient-renamed", "preloaded-pin"]) {
  test(`an actual prior libgif SONAME handle is refused before Leptonica: ${mode}`, () => {
    const result = inspect(mode);
    assert.equal(result.preexistingSoname, true);
    assert.equal(result.errorCode, "RUNTIME_MISMATCH");
    assert.equal(result.initialized, false);
    assert.equal(result.descriptorAccepted, false);
    assert.deepEqual(result.loadedTargets, []);
    assert.equal(result.inputRead, false);
  });
}

test("injected omission of the absolute gif preload cannot pass the real mapped-closure gate", () => {
  const result = inspect("without-preload");
  assert.equal(result.injectedFault, "omit absolute GIF preload only");
  assert.equal(result.descriptorAccepted, false);
  // Compatible test hosts may have an ambient libgif; otherwise the actual
  // Leptonica load itself refuses. Neither result may reach source input.
  assert.ok(["RUNTIME_MISMATCH", "OCR_FAILURE"].includes(result.errorCode));
  assert.equal(result.inputRead, false);
});

for (const fault of ["missing", "tampered", "writable", "symlink"]) {
  test(`pinned gif ${fault} is refused before pixels and restoring the owned clone recovers real OCR`, async (t) => {
    const directory = clone(t);
    const file = path.join(directory, library);
    const original = readFileSync(file);
    if (fault === "missing") rmSync(file);
    if (fault === "tampered") {
      const changed = Buffer.from(original); changed[100] ^= 1;
      chmodSync(file, 0o644); writeFileSync(file, changed); chmodSync(file, 0o444);
    }
    if (fault === "writable") chmodSync(file, 0o644);
    if (fault === "symlink") { rmSync(file); symlinkSync(path.join(root, library), file); }
    refusedBeforeInput(directory);
    rmSync(file, { force: true }); writeFileSync(file, original); chmodSync(file, 0o444);
    const api = await import(pathToFileURL(path.join(directory, "src/extraction/local-ocr/index.mjs")));
    const recovered = await api.readLocalOcr(input());
    assert.equal(recovered.kind, "observed");
    assert.equal(recovered.status, "no-text-observed");
  });
}

test("independent exact ELF inspection confirms libgif SONAME and sole compatible-host libc dependency", () => {
  const result = inspect("elf");
  assert.equal(result.bytes, 38904);
  assert.equal(result.sha256, "70ac81372d0ddbdf03dbdd7a9f994df625928cedf794b7c0a06c9eac27a4edc3");
  assert.deepEqual(result.soname, ["libgif.so.7"]);
  assert.deepEqual(result.dtNeeded, ["libc.so.6"]);
});
