import test from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import { readStaticPng } from "../../../src/extraction/png/index.mjs";
import { createStaticJpegWebpReader } from "../../../src/extraction/jpeg-webp/index.mjs";
import { image, encodedPng, rasterRuntime } from "./fixtures.mjs";

assert.equal(typeof rasterRuntime, "string", "Actual deadline-overlay checks require the explicit reviewed JPEG/WebP runtime");
const raster = createStaticJpegWebpReader({ runtimeDirectory: rasterRuntime });
const readers = [["PNG", readStaticPng, () => encodedPng({ blank: true }).bytes], ["JPEG/WebP", raster.read, () => image("english-baseline.jpeg").bytes]];
for (const [name, read, input] of readers) {
  for (const value of [NaN, Infinity, -1, null, "renew", Number.MAX_SAFE_INTEGER + 1]) test(name + " absolute deadline rejects invalid bounds: " + String(value), async () => {
    assert.equal((await read(input(), { deadlineAtMs: value })).code, "INVALID_LIMIT");
  });
  test(name + " absolute deadline data descriptors reject getters without calling them", async () => {
    let calls = 0; const options = {};
    Object.defineProperty(options, "deadlineAtMs", { get() { calls += 1; return Number.MAX_SAFE_INTEGER; } });
    assert.equal((await read(input(), options)).code, "INVALID_OPTIONS"); assert.equal(calls, 0);
  });
  test(name + " already exhausted absolute budget refuses before a child and still recovers", async (t) => {
    let calls = 0; const original = childProcess.spawn;
    t.mock.method(childProcess, "spawn", function (...args) { calls += 1; return original.apply(this, args); });
    syncBuiltinESMExports(); t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
    const result = await read(input(), { timeoutMs: 5000, deadlineAtMs: performance.now() - 1 });
    assert.equal(result.kind, "rejected"); assert.equal(result.code, "TIMEOUT"); assert.equal(calls, 0);
    assert.equal((await read(input())).kind, "decoded"); assert.equal(calls, 1);
  });
  test(name + " future absolute value cannot extend a shorter relative budget", async () => {
    const result = await read(input(), { timeoutMs: 1, deadlineAtMs: performance.now() + 60000 });
    assert.equal(result.kind, "rejected"); assert.equal(result.code, "TIMEOUT");
    assert.equal((await read(input(), { timeoutMs: 5000, deadlineAtMs: performance.now() + 5000 })).kind, "decoded");
  });
  test(name + " native cancellation keeps its result even with an expired absolute option", async () => {
    const controller = new AbortController(); controller.abort();
    assert.equal((await read(input(), { signal: controller.signal, deadlineAtMs: 0 })).code, "CANCELLED");
  });
}
