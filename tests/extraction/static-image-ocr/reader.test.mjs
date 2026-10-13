import test from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import { createStaticImageOcrReader } from "../../../src/extraction/static-image-ocr/index.mjs";
import { createStaticImageOcrReaderWithPorts } from "../../../src/extraction/static-image-ocr/reader.mjs";
import { PROFILE } from "../../../src/extraction/static-image-ocr/profile.mjs";
import { readStaticPng } from "../../../src/extraction/png/index.mjs";
import { createStaticJpegWebpReader } from "../../../src/extraction/jpeg-webp/index.mjs";
import { readLocalOcr } from "../../../src/extraction/local-ocr/index.mjs";
import { png, chunk } from "../png/fixtures.mjs";
import { hash, image, encodedPng, expectedText, rasterRuntime } from "./fixtures.mjs";

assert.equal(typeof rasterRuntime, "string", "Required native image tests need the explicit pinned JPEG/WebP runtime; no skip fallback");
const raster = createStaticJpegWebpReader({ runtimeDirectory: rasterRuntime });
const real = { readPng: readStaticPng, readJpegWebp: raster.read, readOcr: readLocalOcr };
const read = createStaticImageOcrReader({ runtimeDirectory: rasterRuntime }).read;
const blockUntil = (deadline) => { while (performance.now() < deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(10, deadline - performance.now())); };

for (const name of ["png", "english-baseline.jpeg", "english-progressive.jpeg", "english-lossless.webp", "english-lossy.webp"]) {
  test("actual synthetic " + name + " → owned verified RGBA → native OCR preserves exact literal source/word geometry", async () => {
    const fixture = name === "png" ? encodedPng() : image(name);
    const result = await read(fixture.bytes);
    assert.equal(result.kind, "observed", JSON.stringify(result));
    assert.equal(result.sourceSha256, hash(fixture.bytes)); assert.equal(result.sourceAuthority, "unverified");
    assert.equal(result.sourceBinding, "local-static-image-reader-byte-chain");
    assert.equal(result.completeness, "incomplete-unverified-ocr"); assert.equal(result.requiresReview, true);
    assert.equal(result.image.width, 1000); assert.equal(result.image.height, 220); assert.equal(result.image.pixelByteLength, 880000);
    assert.equal(result.image.rgbaSha256, fixture.rgbaSha256);
    assert.equal(result.words.map((word) => word.text).join(" "), expectedText);
    assert.equal(result.tokenUtf8Bytes, 28); assert.equal(result.words.length, 8);
    assert.equal(result.decoder.networkPolicy, "cooperative-api-guard-only");
    assert.equal(result.observer.enforcementControlsPassed, 8);
    for (const word of result.words) {
      assert.equal(word.provenance.sourceSha256, hash(fixture.bytes)); assert.equal(word.provenance.page, 1);
      assert.equal(word.provenance.derivativeSha256, fixture.rgbaSha256); assert.equal(word.provenance.format, "rgba8");
      assert.equal(word.provenance.sourceBinding, "caller-supplied-unverified");
      assert.equal(word.confidenceMeaning, "uncalibrated-engine-score"); assert.equal(word.requiresReview, true);
      assert.ok(word.box.left >= 0 && word.box.left + word.box.width <= 1000);
      assert.ok(word.box.top >= 0 && word.box.top + word.box.height <= 220);
      assert.ok(Object.isFrozen(word) && Object.isFrozen(word.box) && Object.isFrozen(word.provenance));
    }
    assert.ok(Object.isFrozen(result) && Object.isFrozen(result.words) && Object.isFrozen(result.image));
    assert.equal("copyRgbaBytes" in result.image, false);
    assert.throws(() => { result.words[0].text = "correction"; }, TypeError);
  });
}
test("actual opaque blank PNG returns no-text-observed with uncertainty intact", async () => {
  const result = await read(encodedPng({ blank: true }).bytes);
  assert.equal(result.kind, "observed"); assert.equal(result.status, "no-text-observed");
  assert.equal(result.words.length, 0); assert.equal(result.completeness, "incomplete-unverified-ocr");
});
for (const name of ["png", "english-baseline.jpeg"]) test("actual input snapshot and subarray survive caller mutation: " + name, async () => {
  const bytes = name === "png" ? encodedPng().bytes : image(name).bytes;
  const expected = hash(bytes); const container = Buffer.concat([Buffer.from("prefix"), bytes, Buffer.from("suffix")]);
  const view = container.subarray(6, 6 + bytes.length); const pending = read(view); view.fill(0);
  const result = await pending; assert.equal(result.kind, "observed"); assert.equal(result.sourceSha256, expected);
  assert.equal(result.words.map((word) => word.text).join(" "), expectedText);
});
for (const name of ["png", "webp"]) test("actual nonopaque " + name + " is refused before OCR without a background assumption and recovery succeeds", async () => {
  let calls = 0;
  const composed = createStaticImageOcrReaderWithPorts({ ...real, readOcr: (...args) => { calls += 1; return readLocalOcr(...args); } });
  const bytes = name === "png" ? encodedPng({ transparent: true }).bytes : image("transparent.webp").bytes;
  const result = await composed(bytes);
  assert.equal(result.kind, "rejected"); assert.equal(result.code, "NON_OPAQUE_IMAGE"); assert.equal(result.stage, "pixels");
  assert.equal(calls, 0); assert.equal("words" in result, false);
  assert.equal((await composed(encodedPng({ blank: true }).bytes)).kind, "observed"); assert.equal(calls, 1);
});
for (const [name, make] of [
  ["PNG truncated", () => encodedPng().bytes.subarray(0, -10)],
  ["JPEG trailing bytes", () => Buffer.concat([image("english-baseline.jpeg").bytes, Buffer.from([1])])],
  ["WebP truncated", () => image("english-lossless.webp").bytes.subarray(0, -1)],
  ["PNG metadata", () => png({ before: [chunk("tEXt", Buffer.from("url\0https://example.invalid/never-request"))] })],
]) test("actual " + name + " remains an image-stage refusal before OCR", async () => {
  let calls = 0;
  const composed = createStaticImageOcrReaderWithPorts({ ...real, readOcr: (...args) => { calls += 1; return readLocalOcr(...args); } });
  const result = await composed(make()); assert.equal(result.kind, "rejected"); assert.equal(result.code, "IMAGE_REJECTED");
  assert.equal(result.stage, "decode"); assert.equal(calls, 0); assert.equal("words" in result, false);
  assert.equal((await composed(encodedPng({ blank: true }).bytes)).kind, "observed");
});
for (const options of [{ maxWords: 1 }, { maxTextBytes: 1 }, { maxOutputBytes: 100 }]) test("actual lowered output budget refuses complete observation rather than publishing a partial result: " + JSON.stringify(options), async () => {
  const result = await read(encodedPng().bytes, options);
  assert.equal(result.kind, "rejected");
  if (options.maxOutputBytes) { assert.equal(result.code, "OUTPUT_LIMIT"); assert.equal(result.stage, "aggregate"); }
  else { assert.equal(result.code, "OCR_REJECTED"); assert.equal(result.componentCode, "OUTPUT_LIMIT"); }
  assert.equal("words" in result, false); assert.equal((await read(encodedPng({ blank: true }).bytes)).kind, "observed");
});

function observeChildren(t, onSpawn = () => {}) {
  const original = childProcess.spawn; const counts = { spawned: 0, closed: 0 };
  t.mock.method(childProcess, "spawn", function (...args) {
    const child = original.apply(this, args); counts.spawned += 1; child.once("close", () => { counts.closed += 1; });
    onSpawn(child, args); return child;
  });
  syncBuiltinESMExports(); t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); }); return counts;
}
for (const stage of ["png", "jpeg-webp", "local-ocr"]) test("actual cancellation after " + stage + " child input closes every child before settling and permits recovery", async (t) => {
  const controller = new AbortController(); let entered = 0;
  const counts = observeChildren(t, (child, args) => {
    if (args[1].some((part) => typeof part === "string" && part.includes("/" + stage + "/")) && entered === 0) {
      child.stdin.once("finish", () => { entered += 1; controller.abort(); });
    }
  });
  const bytes = stage === "jpeg-webp" ? image("english-baseline.jpeg").bytes : encodedPng().bytes;
  const result = await read(bytes, { signal: controller.signal });
  assert.equal(entered, 1); assert.equal(result.code, "CANCELLED"); assert.equal("words" in result, false);
  assert.equal(counts.closed, counts.spawned); assert.equal(counts.spawned, stage === "local-ocr" ? 2 : 1);
  assert.equal((await read(encodedPng({ blank: true }).bytes)).kind, "observed"); assert.equal(counts.closed, counts.spawned);
});
test("actual completed decoder followed by a late handoff starts no OCR and preserves the original deadline", async (t) => {
  let late = true, ocrCalls = 0, entered = 0; const counts = observeChildren(t);
  const composed = createStaticImageOcrReaderWithPorts({ ...real, readPng: async (bytes, options) => {
    const result = await readStaticPng(bytes, options);
    if (late) { assert.equal(result.kind, "decoded"); assert.ok(performance.now() < options.deadlineAtMs); entered += 1; blockUntil(options.deadlineAtMs + 10); }
    return result;
  }, readOcr: (...args) => { ocrCalls += 1; return readLocalOcr(...args); } });
  const result = await composed(encodedPng().bytes, { timeoutMs: 2000 });
  assert.equal(entered, 1); assert.equal(result.code, "TIMEOUT"); assert.equal(ocrCalls, 0);
  assert.equal(counts.spawned, 1); assert.equal(counts.closed, 1);
  late = false; assert.equal((await composed(encodedPng({ blank: true }).bytes)).kind, "observed");
  assert.equal(ocrCalls, 1); assert.equal(counts.closed, counts.spawned);
});
test("actual final report freezing cannot return literal text after the original deadline", async (t) => {
  const original = Object.freeze; let deadline, entered = 0; const counts = observeChildren(t);
  const composed = createStaticImageOcrReaderWithPorts({ ...real, readPng: (bytes, options) => { deadline = options.deadlineAtMs; return readStaticPng(bytes, options); } });
  t.mock.method(Object, "freeze", function (value) {
    if (value?.kind === "observed" && value.profile === PROFILE) {
      assert.ok(performance.now() < deadline, "real image and OCR enter the final boundary before expiry"); entered += 1; blockUntil(deadline + 10);
    }
    return original(value);
  });
  const result = await composed(encodedPng().bytes, { timeoutMs: 2500 });
  assert.equal(entered, 1); assert.equal(result.code, "TIMEOUT"); assert.equal("words" in result, false);
  assert.equal(counts.spawned, 2); assert.equal(counts.closed, 2);
  t.mock.restoreAll(); syncBuiltinESMExports(); assert.equal((await composed(encodedPng({ blank: true }).bytes)).kind, "observed");
});
