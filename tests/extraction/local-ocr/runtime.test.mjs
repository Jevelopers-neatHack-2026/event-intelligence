import test from "node:test";
import assert from "node:assert/strict";
import childProcess, { spawnSync } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, cpSync, rmSync, chmodSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readLocalOcr } from "../../../src/extraction/local-ocr/index.mjs";
import { input } from "./helpers.mjs";
const root = fileURLToPath(new URL("../../../", import.meta.url));
const manifest = JSON.parse(readFileSync(path.join(root, "tools/local-ocr/runtime/manifest.json"), "utf8"));
const python = manifest.descriptor.python;
const env = { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", OMP_THREAD_LIMIT: "1", OMP_NUM_THREADS: "1" };
const limits = ["--as=1073741824:1073741824", "--cpu=5:5", "--core=0:0", "--nofile=64:64", "--", python, "-I", "-S", "-B"];
const modelPath = "tools/local-ocr/runtime/site/usr/share/tesseract-ocr/5/tessdata/eng.traineddata";

function clone(t) {
  const directory = mkdtempSync(path.join(tmpdir(), "ei-local-ocr-runtime-"));
  for (const relative of ["src/extraction/local-ocr", "tools/local-ocr"]) {
    mkdirSync(path.dirname(path.join(directory, relative)), { recursive: true });
    cpSync(path.join(root, relative), path.join(directory, relative), { recursive: true,
      filter: (source) => !source.includes(path.sep + "archives" + path.sep) && !source.endsWith(path.sep + "archives") });
  }
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function runWorker(directory, overrideEnv = {}) {
  const result = spawnSync("/usr/bin/prlimit", [...limits, "src/extraction/local-ocr/worker.py", "--recognize"],
    { cwd: directory, env: { ...env, ...overrideEnv }, input: Buffer.from("not a valid frame"), timeout: 15000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr?.toString());
  return JSON.parse(result.stdout);
}
function assertPreInput(refusal, code = "RUNTIME_MISMATCH") {
  assert.equal(refusal.kind, "rejected"); assert.equal(refusal.code, code);
  assert.equal(refusal.enforcementControlsPassed, 0); assert.equal(refusal.rasterSha256, null);
}

test("exact model byte drift is rejected before source input; restoring owned clone recovers real OCR", async (t) => {
  const directory = clone(t); const model = path.join(directory, modelPath);
  const original = readFileSync(model); const modified = Buffer.from(original); modified[100] ^= 1;
  chmodSync(model, 0o644); writeFileSync(model, modified); chmodSync(model, 0o444);
  assertPreInput(runWorker(directory));
  chmodSync(model, 0o644); writeFileSync(model, original); chmodSync(model, 0o444);
  const restored = await import(pathToFileURL(path.join(directory, "src/extraction/local-ocr/index.mjs")));
  const result = await restored.readLocalOcr(input());
  assert.equal(result.kind, "observed"); assert.equal(result.status, "no-text-observed");
});

test("an undeclared second model cannot enter the runtime closure", (t) => {
  const directory = clone(t);
  writeFileSync(path.join(directory, path.dirname(modelPath), "osd.traineddata"), "undeclared");
  assertPreInput(runWorker(directory));
});

test("native library drift is detected before loading the changed library", (t) => {
  const directory = clone(t);
  const library = path.join(directory, "tools/local-ocr/runtime/site/usr/lib/x86_64-linux-gnu/libtesseract.so.5.0.3");
  chmodSync(library, 0o644); writeFileSync(library, "not an ELF image"); chmodSync(library, 0o444);
  assertPreInput(runWorker(directory));
});

test("a model symlink is refused even when its target has the expected bytes", (t) => {
  const directory = clone(t); const model = path.join(directory, modelPath);
  rmSync(model); symlinkSync(path.join(root, modelPath), model);
  assertPreInput(runWorker(directory));
});

test("writable model permissions are refused before source input", (t) => {
  const directory = clone(t); chmodSync(path.join(directory, modelPath), 0o644);
  assertPreInput(runWorker(directory));
});

test("changed host library receipt cannot silently become the current closure", (t) => {
  const directory = clone(t);
  const receipt = path.join(directory, "tools/local-ocr/runtime/manifest.json");
  const changed = JSON.parse(readFileSync(receipt)); changed.descriptor.files[0].sha256 = "0".repeat(64);
  writeFileSync(receipt, JSON.stringify(changed));
  assertPreInput(runWorker(directory));
});

test("missing installation receipt is a concrete unavailable result", async (t) => {
  const directory = clone(t); rmSync(path.join(directory, "tools/local-ocr/runtime/manifest.json"));
  const api = await import(pathToFileURL(path.join(directory, "src/extraction/local-ocr/index.mjs")));
  assert.equal((await api.readLocalOcr(input())).code, "OCR_UNAVAILABLE");
});

test("unbounded OpenMP configuration is refused before native initialization", () => {
  assertPreInput(runWorker(root, { OMP_THREAD_LIMIT: "2" }));
});

test("offline installer check reproduces the exact loaded closure without source input", () => {
  const result = spawnSync(python, ["tools/local-ocr/install.py", "--check"], { cwd: root, env, timeout: 20000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr?.toString());
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.checked, true); assert.equal(receipt.pinnedFiles, 46);
  assert.equal(receipt.closureSha256, manifest.closureSha256);
});

test("wrong archive bytes are rejected before any package decompressor runs", () => {
  const script = `import importlib.util,pathlib,json\np=pathlib.Path('tools/local-ocr/install.py').resolve()\ns=importlib.util.spec_from_file_location('ocr_install',p)\nm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\ncalled=[]\nm.subprocess.run=lambda *a,**k:called.append(a)\ntry:m.contents_for(m.LOCK['packages'][0],b'wrong archive')\nexcept ValueError:pass\nelse:raise AssertionError('archive accepted')\nassert not called\nprint(json.dumps({'rejectedBeforeDecompressor':True}))`;
  const result = spawnSync(python, ["-I", "-S", "-B", "-c", script], { cwd: root, env, timeout: 10000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr?.toString());
  assert.equal(JSON.parse(result.stdout).rejectedBeforeDecompressor, true);
});

test("actual byte-pipe completion cancellation kills and closes the worker, then recovers", async (t) => {
  const original = childProcess.spawn;
  const controller = new AbortController();
  let entered = 0, closed = 0, spawned = 0;
  t.mock.method(childProcess, "spawn", function (...args) {
    const child = original.apply(this, args); spawned += 1;
    if (spawned === 1) child.stdin.once("finish", () => { entered += 1; controller.abort(); });
    child.once("close", () => { closed += 1; });
    return child;
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  const large = input(Buffer.alloc(2048 * 2048, 255), 2048, 2048);
  const refusal = await readLocalOcr(large, { signal: controller.signal });
  assert.equal(entered, 1, "actual worker must drain the bounded input pipe before cancellation");
  assert.equal(refusal.code, "CANCELLED"); assert.equal(closed, 1);
  assert.equal((await readLocalOcr(input())).kind, "observed");
  assert.equal(closed, 2);
});

test("actual synchronous bootstrap counts against the original deadline and subsequent request recovers", async () => {
  const refused = await readLocalOcr(input(), { timeoutMs: 1 });
  assert.equal(refused.code, "TIMEOUT");
  assert.equal((await readLocalOcr(input())).kind, "observed");
});
