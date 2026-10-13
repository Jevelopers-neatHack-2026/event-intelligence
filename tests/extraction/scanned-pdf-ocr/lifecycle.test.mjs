import test from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import { createScannedPdfOcrReader } from "../../../src/extraction/scanned-pdf-ocr/reader.mjs";
import { readScannedPdf } from "../../../src/extraction/scanned-pdf/index.mjs";
import { readLocalOcr } from "../../../src/extraction/local-ocr/index.mjs";
import { fakePdf, fakeOcr, source, wait } from "./fake-stages.mjs";
import { blankPdf } from "./fixtures.mjs";

test("synthetic stages receive the identical absolute monotonic deadline and decreasing remaining allowances", async () => {
  const calls = [];
  const reader = createScannedPdfOcrReader({ readPdf: async (bytes, options) => {
    calls.push({ ...options }); await wait(10); return fakePdf(bytes, options);
  }, readOcr: async (input, options) => { calls.push({ ...options }); await wait(10); return fakeOcr(input, options); } });
  assert.equal((await reader(source(), { timeoutMs: 1000 })).kind, "observed");
  assert.equal(calls.length, 3); assert.ok(calls.every((call) => call.deadlineAtMs === calls[0].deadlineAtMs));
  assert.ok(calls[0].timeoutMs > calls[1].timeoutMs && calls[1].timeoutMs > calls[2].timeoutMs);
  assert.equal(calls[2].maxWords, calls[1].maxWords - 1); assert.equal(calls[2].maxTextBytes, calls[1].maxTextBytes - 7);
});

test("synthetic queued expiry retains admission deadline and never invokes a reader", async () => {
  let release, calls = 0;
  const reader = createScannedPdfOcrReader({ readPdf: (bytes, options) => {
    calls += 1; return new Promise((resolve) => { release = () => resolve(fakePdf(bytes, options)); });
  }, readOcr: async (...args) => fakeOcr(...args) });
  const first = reader(source()); const expired = await reader(source(), { timeoutMs: 5 });
  assert.equal(expired.code, "TIMEOUT"); assert.equal(calls, 1);
  release(); assert.equal((await first).kind, "observed");
});

test("synthetic queued cancellation leaves the unrelated active stage untouched", async () => {
  let release, activeSignal, calls = 0;
  const controller = new AbortController();
  const reader = createScannedPdfOcrReader({ readPdf: (bytes, options) => {
    calls += 1; activeSignal = options.signal; return new Promise((resolve) => { release = () => resolve(fakePdf(bytes, options)); });
  }, readOcr: async (...args) => fakeOcr(...args) });
  const first = reader(source()); const pending = reader(source(), { signal: controller.signal }); controller.abort();
  assert.equal((await pending).code, "CANCELLED"); assert.equal(calls, 1); assert.equal(activeSignal.aborted, false);
  release(); assert.equal((await first).kind, "observed");
});

test("synthetic one-active/four-queued bound rejects the sixth operation then recovers all admitted calls", async () => {
  let release, calls = 0;
  const reader = createScannedPdfOcrReader({ readPdf: (bytes, options) => {
    calls += 1;
    if (calls === 1) return new Promise((resolve) => { release = () => resolve(fakePdf(bytes, options)); });
    return Promise.resolve(fakePdf(bytes, options));
  }, readOcr: async (...args) => fakeOcr(...args) });
  const admitted = Array.from({ length: 5 }, () => reader(source()));
  assert.equal((await reader(source())).code, "QUEUE_FULL"); assert.equal(calls, 1);
  release(); assert.ok((await Promise.all(admitted)).every((value) => value.kind === "observed")); assert.equal(calls, 5);
});

for (const mode of ["cancel", "timeout"]) test("synthetic " + mode + " waits for the stage's close-equivalent settlement without a new cleanup allowance", async () => {
  let release, firstSignal, calls = 0, delivered = false;
  const controller = new AbortController();
  const reader = createScannedPdfOcrReader({ readPdf: (bytes, options) => {
    calls += 1;
    if (calls === 1) { firstSignal = options.signal; return new Promise((resolve) => { release = () => resolve(fakePdf(bytes, options)); }); }
    return Promise.resolve(fakePdf(bytes, options));
  }, readOcr: async (...args) => fakeOcr(...args) });
  const pending = reader(source(), mode === "cancel" ? { signal: controller.signal } : { timeoutMs: 5 });
  pending.then(() => { delivered = true; });
  const recovery = reader(source());
  if (mode === "cancel") controller.abort();
  await wait(15);
  assert.equal(firstSignal.aborted, true); assert.equal(delivered, false); assert.equal(calls, 1);
  release(); assert.equal((await pending).code, mode === "cancel" ? "CANCELLED" : "TIMEOUT");
  assert.equal((await recovery).kind, "observed"); assert.equal(calls, 2);
});

test("synthetic cancellation between pages does not dispatch another OCR call", async () => {
  let calls = 0; const controller = new AbortController();
  const reader = createScannedPdfOcrReader({ readPdf: async (...args) => fakePdf(...args), readOcr: async (...args) => {
    calls += 1; const result = fakeOcr(...args); controller.abort(); return result;
  } });
  assert.equal((await reader(source(), { signal: controller.signal })).code, "CANCELLED"); assert.equal(calls, 1);
});

for (const mode of ["sync throw", "rejected promise"]) test("synthetic stage " + mode + " is observed, sanitized and does not strand the next operation", async () => {
  let calls = 0;
  const reader = createScannedPdfOcrReader({ readPdf: (bytes, options) => {
    if (calls++ === 0) {
      if (mode === "sync throw") throw new Error("private transcript");
      return Promise.reject(new Error("private transcript"));
    }
    return Promise.resolve(fakePdf(bytes, options));
  }, readOcr: async (...args) => fakeOcr(...args) });
  const result = await reader(source());
  assert.equal(result.code, "STAGE_FAILURE"); assert.equal(JSON.stringify(result).includes("private transcript"), false);
  assert.equal((await reader(source())).kind, "observed");
});

test("a non-Promise stage thenable is refused without executing its getter", async () => {
  let called = 0;
  const reader = createScannedPdfOcrReader({ readPdf: () => ({ get then() { called += 1; throw new Error("getter"); } }),
    readOcr: async (...args) => fakeOcr(...args) });
  assert.equal((await reader(source())).code, "STAGE_PROTOCOL_ERROR"); assert.equal(called, 0);
});

for (const options of [{ maxWords: 2 }, { maxTextBytes: 14 }]) test("synthetic aggregate budget stops before the third page: " + JSON.stringify(options), async () => {
  let calls = 0;
  const reader = createScannedPdfOcrReader({ readPdf: async (bytes, limits) => fakePdf(bytes, limits, 3), readOcr: async (...args) => {
    calls += 1; return fakeOcr(...args);
  } });
  const result = await reader(source(), options);
  assert.equal(result.code, "OUTPUT_LIMIT"); assert.equal(result.page, 3); assert.equal(calls, 2); assert.equal("pages" in result, false);
});

test("actual delayed renderer handoff carries the already-expired absolute deadline and starts no child", async (t) => {
  let spawned = 0;
  t.mock.method(childProcess, "spawn", () => { spawned += 1; throw new Error("must not spawn"); });
  syncBuiltinESMExports(); t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  const reader = createScannedPdfOcrReader({ readPdf: (bytes, options) => {
    while (performance.now() <= options.deadlineAtMs + 2) {}
    return readScannedPdf(bytes, options);
  }, readOcr: readLocalOcr });
  assert.equal((await reader(blankPdf(), { timeoutMs: 10 })).code, "TIMEOUT"); assert.equal(spawned, 0);
});
