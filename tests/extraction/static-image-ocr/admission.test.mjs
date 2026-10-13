import test from "node:test";
import assert from "node:assert/strict";
import { createStaticImageOcrReader } from "../../../src/extraction/static-image-ocr/index.mjs";
import { createStaticImageOcrReaderWithPorts } from "../../../src/extraction/static-image-ocr/reader.mjs";
import { STATIC_IMAGE_OCR_LIMITS } from "../../../src/extraction/static-image-ocr/profile.mjs";
import { source, fakeImage, fakeOcr, wait } from "./fake-stages.mjs";

function reader(counts = { image: 0, ocr: 0 }) {
  return createStaticImageOcrReaderWithPorts({ readPng: async (...args) => { counts.image += 1; return fakeImage(...args); },
    readJpegWebp: async (...args) => { counts.image += 1; return fakeImage(...args, "jpeg"); },
    readOcr: async (...args) => { counts.ocr += 1; return fakeOcr(...args); } });
}

for (const value of [null, "bytes", {}, [], new DataView(new ArrayBuffer(5)), new Uint16Array(4), Buffer.alloc(0),
  new Uint8Array(new SharedArrayBuffer(8)), new Proxy(new Uint8Array(8), {})]) {
  test("synthetic admission refuses invalid input without stage entry: " + Object.prototype.toString.call(value), async () => {
    const counts = { image: 0, ocr: 0 }; const result = await reader(counts)(value);
    assert.equal(result.code, "INVALID_INPUT"); assert.deepEqual(counts, { image: 0, ocr: 0 });
  });
}
test("source input over ten MiB cannot enter either stage", async () => {
  const counts = { image: 0, ocr: 0 };
  assert.equal((await reader(counts)(Buffer.alloc(STATIC_IMAGE_OCR_LIMITS.maxInputBytes + 1))).code, "INPUT_TOO_LARGE");
  assert.equal(counts.image, 0);
});
for (const bytes of [Buffer.from("<script>source</script>"), Buffer.from("GIF89a"), Buffer.from("RIFF\0\0\0\0webp"),
  Buffer.from("524946c60000000057454250", "hex")]) {
  test("exact dispatch refuses unsupported or high-bit signature: " + bytes.toString("hex"), async () => {
    const counts = { image: 0, ocr: 0 };
    assert.equal((await reader(counts)(bytes)).code, "UNSUPPORTED_FORMAT"); assert.equal(counts.image, 0);
  });
}
for (const options of [{ decoder: () => {} }, { readOcr: () => {} }, { sourceSha256: "f".repeat(64) },
  { deadlineAtMs: Number.MAX_SAFE_INTEGER }, { tenant: "forged" }, null, [], new Proxy({}, {})]) {
  test("request options cannot supply a decoder, provenance, authority or foreign budget: " + String(options), async () => {
    const counts = { image: 0, ocr: 0 };
    assert.equal((await reader(counts)(source(), options)).code, "INVALID_OPTIONS"); assert.equal(counts.image, 0);
  });
}
for (const [key, value] of [["timeoutMs", 0], ["timeoutMs", 30001], ["timeoutMs", NaN], ["timeoutMs", null],
  ["maxWords", 2049], ["maxWords", 1.5], ["maxTextBytes", 32769], ["maxOutputBytes", 1048577]]) {
  test("limits only lower fixed composition bounds: " + key + "=" + value, async () => {
    const counts = { image: 0, ocr: 0 };
    assert.equal((await reader(counts)(source(), { [key]: value })).code, "INVALID_LIMIT"); assert.equal(counts.image, 0);
  });
}
test("native signal brand and option descriptors are checked without invoking getters", async () => {
  let calls = 0; const read = reader();
  const options = {}; Object.defineProperty(options, "timeoutMs", { get() { calls += 1; return 100; } });
  assert.equal((await read(source(), options)).code, "INVALID_OPTIONS");
  assert.equal((await read(source(), { signal: { get aborted() { calls += 1; return false; } } })).code, "INVALID_OPTIONS");
  assert.equal(calls, 0);
  const controller = new AbortController(); controller.abort();
  assert.equal((await read(source(), { signal: controller.signal })).code, "CANCELLED");
});
test("public factory accepts only a canonical explicit trusted runtime, never arbitrary stage callbacks", () => {
  for (const value of [undefined, null, {}, { runtimeDirectory: "relative" }, { runtimeDirectory: "/tmp/../runtime" },
    { runtimeDirectory: "/trusted/runtime", readPng: () => {} }, new Proxy({ runtimeDirectory: "/trusted/runtime" }, {})]) {
    assert.throws(() => createStaticImageOcrReader(value), TypeError);
  }
  assert.ok(Object.isFrozen(createStaticImageOcrReader({ runtimeDirectory: "/trusted/runtime" })));
});
test("admission is shared across factories; canceled queued jobs release capacity without calling a stage", async () => {
  let release; const gate = new Promise((resolve) => { release = resolve; });
  let calls = 0;
  const make = () => createStaticImageOcrReaderWithPorts({ readPng: async (...args) => { calls += 1; await gate; return fakeImage(...args); },
    readJpegWebp: async (...args) => fakeImage(...args, "jpeg"), readOcr: async (...args) => fakeOcr(...args) });
  const a = make(), b = make();
  const controller = new AbortController();
  const first = a(source());
  const pending = [b(source(), { signal: controller.signal }), a(source()), b(source()), a(source())];
  try {
    assert.equal(calls, 1);
    assert.equal((await b(source())).code, "QUEUE_FULL");
    controller.abort(); assert.equal((await pending[0]).code, "CANCELLED");
    pending.push(b(source())); assert.equal(calls, 1);
  } finally { release(); }
  assert.equal((await first).kind, "observed");
  const outcomes = await Promise.all(pending);
  assert.equal(outcomes.filter((result) => result.kind === "observed").length, 4);
  assert.equal(calls, 5);
  assert.equal((await a(source())).kind, "observed");
});
test("queued deadline expires against its original admission without decoder entry and subsequent work recovers", async () => {
  let release; const gate = new Promise((resolve) => { release = resolve; }); let calls = 0;
  const read = createStaticImageOcrReaderWithPorts({ readPng: async (...args) => { calls += 1; await gate; return fakeImage(...args); },
    readJpegWebp: async (...args) => fakeImage(...args, "jpeg"), readOcr: async (...args) => fakeOcr(...args) });
  const active = read(source()); const queued = read(source(), { timeoutMs: 25 });
  try { assert.equal((await queued).code, "TIMEOUT"); assert.equal(calls, 1); }
  finally { release(); }
  assert.equal((await active).kind, "observed"); assert.equal((await read(source())).kind, "observed");
});
test("canceling an active synthetic stage retains admission until its promise settles, then recovers", async () => {
  const controller = new AbortController(); let release, entered = 0;
  const gate = new Promise((resolve) => { release = resolve; });
  const read = createStaticImageOcrReaderWithPorts({ readPng: async (...args) => { entered += 1; await gate; return fakeImage(...args); },
    readJpegWebp: async (...args) => fakeImage(...args, "jpeg"), readOcr: async (...args) => fakeOcr(...args) });
  let settled = false; const first = read(source(), { signal: controller.signal }).then((value) => { settled = true; return value; });
  controller.abort(); const queued = read(source());
  try { await wait(5); assert.equal(settled, false); assert.equal(entered, 1); }
  finally { release(); }
  assert.equal((await first).code, "CANCELLED"); assert.equal((await queued).kind, "observed");
});
