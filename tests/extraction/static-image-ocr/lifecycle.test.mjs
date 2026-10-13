import test from "node:test";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { createStaticImageOcrReaderWithPorts } from "../../../src/extraction/static-image-ocr/reader.mjs";
import { PROFILE } from "../../../src/extraction/static-image-ocr/profile.mjs";
import { source, fakeImage, fakeOcr, wait } from "./fake-stages.mjs";

const blockUntil = (deadline) => { while (performance.now() < deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(5, deadline - performance.now())); };
const good = { readPng: async (...args) => fakeImage(...args), readJpegWebp: async (...args) => fakeImage(...args, "jpeg"), readOcr: async (...args) => fakeOcr(...args) };

for (const stage of ["readPng", "readOcr"]) test("synthetic synchronous abort and rejected native Promise is observed at " + stage, async () => {
  const controller = new AbortController(); let bad = true;
  const read = createStaticImageOcrReaderWithPorts({ ...good, [stage]: async (...args) => {
    if (bad) { controller.abort(); throw new Error("SYNTHETIC_PRIVATE_REJECTION"); }
    return good[stage](...args);
  } });
  const result = await read(source(), { signal: controller.signal }); assert.equal(result.code, "CANCELLED");
  await new Promise(setImmediate); await new Promise(setImmediate);
  bad = false; assert.equal((await read(source())).kind, "observed");
});
for (const stage of ["readPng", "readOcr"]) test("ordinary thenable stage result is refused without assimilation: " + stage, async () => {
  let calls = 0;
  const read = createStaticImageOcrReaderWithPorts({ ...good, [stage]: () => ({ then() { calls += 1; } }) });
  assert.equal((await read(source())).code, "STAGE_PROTOCOL_ERROR"); assert.equal(calls, 0);
});
test("both stage options carry one original absolute deadline, with lower remaining relative budget", async () => {
  const seen = [];
  const read = createStaticImageOcrReaderWithPorts({ ...good, readPng: async (bytes, options) => {
    seen.push(options); await wait(30); return fakeImage(bytes, options);
  }, readOcr: async (input, options) => { seen.push(options); return fakeOcr(input, options); } });
  const start = performance.now(); const result = await read(source(), { timeoutMs: 2000 });
  assert.equal(result.kind, "observed"); assert.equal(seen.length, 2);
  assert.equal(seen[0].deadlineAtMs, seen[1].deadlineAtMs);
  assert.ok(seen[0].deadlineAtMs >= start + 2000 && seen[0].deadlineAtMs < start + 2010);
  assert.ok(seen[1].timeoutMs < seen[0].timeoutMs);
});
test("late synthetic decoder completion cannot dispatch OCR or reset the original deadline", async () => {
  let calls = 0; let late = true;
  const read = createStaticImageOcrReaderWithPorts({ ...good, readPng: async (bytes, options) => {
    if (late) blockUntil(options.deadlineAtMs + 10); return fakeImage(bytes, options);
  }, readOcr: async (...args) => { calls += 1; return fakeOcr(...args); } });
  assert.equal((await read(source(), { timeoutMs: 100 })).code, "TIMEOUT"); assert.equal(calls, 0);
  late = false; assert.equal((await read(source())).kind, "observed");
});
test("late pixel-copy completion is rejected before OCR despite a valid raw hash", async () => {
  let calls = 0; let late = true;
  const read = createStaticImageOcrReaderWithPorts({ ...good, readPng: async (bytes, options) => {
    const result = fakeImage(bytes, options); const copy = result.copyRgbaBytes;
    result.copyRgbaBytes = () => { if (late) blockUntil(options.deadlineAtMs + 10); return copy(); }; return result;
  }, readOcr: async (...args) => { calls += 1; return fakeOcr(...args); } });
  assert.equal((await read(source(), { timeoutMs: 100 })).code, "TIMEOUT"); assert.equal(calls, 0);
  late = false; assert.equal((await read(source())).kind, "observed");
});
for (const kind of ["cancel", "deadline"]) test("final native-microtask " + kind + " after report serialization wins before promise delivery", async (t) => {
  const controller = new AbortController(); let deadline, entries = 0;
  const original = JSON.stringify;
  const read = createStaticImageOcrReaderWithPorts({ ...good, readPng: async (bytes, options) => { deadline = options.deadlineAtMs; return fakeImage(bytes, options); } });
  t.mock.method(JSON, "stringify", function (value, ...rest) {
    if (value?.kind === "observed" && value.profile === PROFILE) {
      entries += 1;
      queueMicrotask(() => { if (kind === "cancel") controller.abort(); else blockUntil(deadline + 10); });
    }
    return original(value, ...rest);
  });
  const result = await read(source(), { signal: controller.signal, timeoutMs: 100 });
  assert.equal(entries, 1); assert.equal(result.code, kind === "cancel" ? "CANCELLED" : "TIMEOUT"); assert.equal("words" in result, false);
  t.mock.restoreAll(); assert.equal((await read(source())).kind, "observed");
});
