import assert from "node:assert/strict";
import test from "node:test";
import { createStaticJpegWebpReader, STATIC_JPEG_WEBP_READER_LIMITS } from "../../../src/extraction/jpeg-webp/index.mjs";
import { fixture, fixtureDocument, hash, pixelsFromPng, runtimeDirectory } from "./fixtures.mjs";

const reader = createStaticJpegWebpReader({ runtimeDirectory: runtimeDirectory() });
for (const [name, expected] of Object.entries(fixtureDocument.fixtures)) {
  if (!expected.acceptedProfile) continue;
  test("loads actual static pixels and an independently checked PNG: " + name, async () => {
    const { bytes } = fixture(name);
    const result = await reader.read(bytes);
    assert.equal(result.kind, "decoded", JSON.stringify(result));
    assert.equal(result.completeness, "incomplete-pixels-only");
    assert.equal(result.requiresInspection, true);
    assert.equal(result.sourceSha256, expected.sourceSha256);
    assert.equal(result.width, expected.width); assert.equal(result.height, expected.height);
    assert.equal(result.sourceMode, expected.referenceMode); assert.equal(result.frames, 1);
    assert.equal(result.decodedRgbaBytes, expected.expectedDecodedRgbaBytes);
    assert.equal(result.rgbaSha256, expected.expectedRgbaSha256);
    assert.equal(result.networkApiAttemptCount, 0);
    const normalized = result.copyNormalizedBytes();
    assert.equal(normalized.length, result.normalizedByteLength);
    assert.equal(hash(normalized), result.normalizedSha256);
    const pixels = pixelsFromPng(normalized, expected.width, expected.height);
    const raw = result.copyRgbaBytes();
    assert.equal(Object.getPrototypeOf(raw), Uint8Array.prototype);
    assert.equal(raw.length, result.decodedRgbaBytes);
    assert.deepEqual(Buffer.from(raw), pixels);
    assert.equal(hash(raw), result.rgbaSha256);
    assert.equal(hash(pixels), expected.expectedRgbaSha256);
    if (expected.expectedRgbaBase64) assert.deepEqual(pixels, Buffer.from(expected.expectedRgbaBase64, "base64"));
    if (name.startsWith("jpeg-gray") || name === "jpeg-pixel-limit") {
      for (let at = 0; at < pixels.length; at += 4) {
        assert.equal(pixels[at], 19); assert.equal(pixels[at + 1], 19); assert.equal(pixels[at + 2], 19); assert.equal(pixels[at + 3], 255);
      }
    }
    if (name === "webp-rgba-compressed-alpha") {
      for (let at = 0; at < pixels.length; at += 4) assert.equal(pixels[at + 3], [0, 64, 128, 255][(at / 4) % 4]);
    }
  });
}

test("snapshot, immutable result and deterministic repeated derivative retain separate byte ownership", async () => {
  const { bytes, expected } = fixture("webp-rgba-lossless");
  const original = Buffer.from(bytes);
  const pending = reader.read(bytes);
  bytes.fill(0);
  const first = await pending;
  assert.equal(first.kind, "decoded", JSON.stringify(first));
  assert.equal(first.sourceSha256, expected.sourceSha256);
  const copy = first.copyNormalizedBytes(); copy.fill(0);
  const rawCopy = first.copyRgbaBytes(), rawSecond = first.copyRgbaBytes();
  assert.notEqual(rawCopy.buffer, rawSecond.buffer);
  assert.notEqual(rawCopy.buffer, copy.buffer);
  rawCopy.fill(0);
  assert.equal(hash(rawSecond), first.rgbaSha256);
  assert.equal(hash(first.copyRgbaBytes()), first.rgbaSha256);
  assert.equal(hash(first.copyNormalizedBytes()), first.normalizedSha256);
  assert.ok(Object.isFrozen(first)); assert.ok(Object.isFrozen(first.decoder)); assert.ok(Object.isFrozen(first.limits));
  assert.throws(() => { first.width = 100; }, TypeError);
  const second = await reader.read(original);
  assert.equal(second.kind, "decoded");
  assert.equal(second.rgbaSha256, first.rgbaSha256); assert.equal(second.normalizedSha256, first.normalizedSha256);
  assert.deepEqual(second.copyNormalizedBytes(), first.copyNormalizedBytes());
  assert.deepEqual(second.copyRgbaBytes(), first.copyRgbaBytes());
  // Actual 1f3c074 baseline output; exposing raw pixels does not re-encode it.
  assert.equal(first.normalizedSha256, "753e23545db5ce1d4742c03c3518491f0cfb740e052d52d082f98cd4b4826ae4");
});

test("refuses unavailable explicit runtime and returns no partial pixels", async () => {
  const absent = createStaticJpegWebpReader({ runtimeDirectory: "/nonexistent-ei-jpeg-webp-runtime" });
  const result = await absent.read(fixture("jpeg-gray-baseline").bytes);
  assert.equal(result.kind, "rejected"); assert.equal(result.code, "DECODER_UNAVAILABLE");
  assert.equal(result.copyNormalizedBytes, undefined); assert.equal(result.rgbaSha256, undefined);
  assert.equal(result.copyRgbaBytes, undefined);
});

test("lower-only output cap checks exact deterministic PNG length", async () => {
  const bytes = fixture("webp-rgba-lossless").bytes;
  const baseline = await reader.read(bytes); assert.equal(baseline.kind, "decoded");
  const refused = await reader.read(bytes, { maxOutputBytes: baseline.normalizedByteLength - 1 });
  assert.equal(refused.code, "OUTPUT_LIMIT");
  assert.equal(refused.copyRgbaBytes, undefined);
  const exact = await reader.read(bytes, { maxOutputBytes: baseline.normalizedByteLength });
  assert.equal(exact.kind, "decoded"); assert.equal(exact.normalizedSha256, baseline.normalizedSha256);
  assert.deepEqual(exact.copyRgbaBytes(), baseline.copyRgbaBytes());
});

test("validates trusted configuration without invoking caller accessors or proxy traps", () => {
  let accessed = 0;
  assert.throws(() => createStaticJpegWebpReader({ get runtimeDirectory() { accessed += 1; return runtimeDirectory(); } }), TypeError);
  assert.throws(() => createStaticJpegWebpReader(new Proxy({}, { get() { accessed += 1; } })), TypeError);
  for (const configuration of [null, {}, { runtimeDirectory: "relative" }, { runtimeDirectory: "/tmp/../tmp" }, { runtimeDirectory: runtimeDirectory(), extra: true }]) assert.throws(() => createStaticJpegWebpReader(configuration), TypeError);
  assert.equal(accessed, 0);
});

test("validates untrusted inputs and option descriptors without coercion", async () => {
  let accessed = 0; const bytes = fixture("jpeg-gray-baseline").bytes;
  const cases = [
    [bytes, { get timeoutMs() { accessed += 1; return 1; } }, "INVALID_OPTIONS"],
    [bytes, { timeoutMs: NaN }, "INVALID_LIMIT"], [bytes, { timeoutMs: Infinity }, "INVALID_LIMIT"],
    [bytes, { timeoutMs: "1" }, "INVALID_LIMIT"], [bytes, { timeoutMs: null }, "INVALID_LIMIT"],
    [bytes, { timeoutMs: 0 }, "INVALID_LIMIT"], [bytes, { timeoutMs: 10001 }, "INVALID_LIMIT"],
    [bytes, { maxOutputBytes: STATIC_JPEG_WEBP_READER_LIMITS.maxOutputBytes + 1 }, "INVALID_LIMIT"],
    [bytes, { maxOutputBytes: null }, "INVALID_LIMIT"], [bytes, { signal: { aborted: false } }, "INVALID_OPTIONS"],
    [bytes, new Proxy({}, { get() { accessed += 1; } }), "INVALID_OPTIONS"],
    [new Proxy(bytes, { get() { accessed += 1; } }), undefined, "INVALID_INPUT"],
    [new Uint8Array(new SharedArrayBuffer(4)), undefined, "INVALID_INPUT"],
    ["https://example.invalid/image.jpg", undefined, "INVALID_INPUT"],
    [Buffer.alloc(0), undefined, "INVALID_INPUT"],
    [Buffer.alloc(STATIC_JPEG_WEBP_READER_LIMITS.maxInputBytes + 1), undefined, "INPUT_TOO_LARGE"],
  ];
  for (const [input, options, code] of cases) {
    const result = await reader.read(input, options); assert.equal(result.kind, "rejected"); assert.equal(result.code, code);
  }
  assert.equal(accessed, 0);
});

test("pre-aborted work creates no pixels and a fresh reader recovers", async () => {
  const controller = new AbortController(); controller.abort();
  const result = await reader.read(fixture("jpeg-gray-baseline").bytes, { signal: controller.signal });
  assert.equal(result.code, "CANCELLED");
  assert.equal((await reader.read(fixture("jpeg-gray-baseline").bytes)).kind, "decoded");
});
