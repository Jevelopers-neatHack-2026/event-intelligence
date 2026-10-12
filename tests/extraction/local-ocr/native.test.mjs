import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fixture, input, hash } from "./helpers.mjs";
const root = fileURLToPath(new URL("../../../", import.meta.url));
const runtime = JSON.parse(readFileSync(path.join(root, "tools/local-ocr/runtime/manifest.json"), "utf8"));
const python = runtime.descriptor.python;
const env = { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", OMP_THREAD_LIMIT: "1", OMP_NUM_THREADS: "1" };
const limits = ["--as=1073741824:1073741824", "--cpu=5:5", "--core=0:0", "--nofile=64:64", "--", python, "-I", "-S", "-B"];

test("required real native config/model/file restrictions, inherited FD closure, then actual OCR recovery", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "ei-local-ocr-native-"));
  const canary = path.join(directory, "owned-valid-tess-config");
  const content = Buffer.from("tessedit_pageseg_mode 13\n");
  writeFileSync(canary, content);
  try {
    const result = spawnSync("/usr/bin/prlimit", [...limits, "tests/extraction/local-ocr/native-boundary.py", canary],
      { cwd: root, env, input: fixture().bytes, timeout: 15000, maxBuffer: 1024 * 1024 });
    assert.equal(result.status, 0, result.stderr?.toString());
    const evidence = JSON.parse(result.stdout);
    assert.equal(evidence.controls, 8);
    assert.equal(evidence.postSealOcrWords, 8);
    for (const [key, value] of Object.entries(evidence)) if (key.endsWith("Denied") || key.endsWith("Closed") || key.endsWith("BeforeSeal")) assert.equal(value, true);
    assert.deepEqual(readFileSync(canary), content);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("all 26 synthetic native TSV boundary vectors run with no skipped case", () => {
  const result = spawnSync(python, ["-I", "-S", "-B", "tests/extraction/local-ocr/tsv-vectors.py"],
    { cwd: root, env, timeout: 10000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr?.toString()+result.stdout?.toString());
  const evidence = JSON.parse(result.stdout);
  assert.equal(evidence.cases.length, 26);
  assert.ok(evidence.cases.every((entry) => entry.passed));
});

function frame(header, bytes = input().bytes) {
  const encoded = Buffer.from(typeof header === "string" ? header : JSON.stringify(header));
  const length = Buffer.alloc(4); length.writeUInt32BE(encoded.length);
  return Buffer.concat([length, encoded, bytes]);
}
function header() {
  return { width: 100, height: 40, format: "gray8", rasterSha256: hash(input().bytes), maxTextBytes: 32768, maxWords: 2048 };
}
for (const [name, make, code] of [
  ["empty input", () => Buffer.alloc(0), "INVALID_INPUT"],
  ["duplicate header key", () => frame(JSON.stringify(header()).replace('"width":100', '"width":100,"width":100')), "INVALID_INPUT"],
  ["native dimension ceiling", () => frame({ ...header(), width: 4097 }), "DIMENSION_LIMIT"],
  ["native pixel ceiling", () => frame({ ...header(), width: 4096, height: 1025 }), "PIXEL_LIMIT"],
  ["boolean dimensions", () => frame({ ...header(), width: true }), "INVALID_INPUT"],
  ["foreign format", () => frame({ ...header(), format: "image/png" }), "UNSUPPORTED_RASTER"],
  ["path in worker header", () => frame({ ...header(), path: "/private/secret" }), "INVALID_INPUT"],
  ["mismatched derivative", () => frame({ ...header(), rasterSha256: "0".repeat(64) }), "INVALID_INPUT"],
  ["incorrect raster length", () => frame(header(), Buffer.alloc(3999)), "INVALID_INPUT"],
  ["invalid native word budget", () => frame({ ...header(), maxWords: 0 }), "INVALID_LIMIT"],
]) test(`actual sealed worker rejects ${name}`, () => {
  const result = spawnSync("/usr/bin/prlimit", [...limits, "src/extraction/local-ocr/worker.py", "--recognize"],
    { cwd: root, env, input: make(), timeout: 15000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr?.toString());
  const refusal = JSON.parse(result.stdout);
  assert.equal(refusal.kind, "rejected"); assert.equal(refusal.code, code);
  assert.equal(refusal.enforcementControlsPassed, 8);
  assert.equal(refusal.words, undefined);
});
