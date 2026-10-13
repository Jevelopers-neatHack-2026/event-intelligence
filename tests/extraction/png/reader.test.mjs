import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readStaticPng, STATIC_PNG_READER_LIMITS } from "../../../src/extraction/png/index.mjs";
import { chunk, png, readNormalized } from "./fixtures.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("actual Linux child reconstructs an incomplete private pixel derivative, not facts or permissions", async () => {
  assert.equal(process.platform, "linux", "This required child check must execute on Linux, not skip.");
  const source = png({ width: 2, height: 2, colorType: 2,
    scanlines: Buffer.from("010a141efb05dc040af6dcebf706", "hex") });
  const result = await readStaticPng(source);
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.equal(result.completeness, "incomplete-pixels-only");
  assert.equal(result.requiresInspection, true);
  assert.equal(result.sourceSha256, hash(source));
  assert.equal(result.networkApiAttemptCount, 0);
  assert.equal(result.outputColorType, 6);
  assert.equal(result.decoder.nodeVersion, process.versions.node);
  assert.equal(result.decoder.zlibVersion, process.versions.zlib);
  assert.deepEqual(readNormalized(Buffer.from(result.copyNormalizedBytes())).rgba,
    Buffer.from("0a141eff0519faff140afaffff0100ff", "hex"));
  assert.equal(result.normalizedSha256, hash(result.copyNormalizedBytes()));
  assert.equal(Object.hasOwn(result, "facts"), false);
  assert.equal(Object.hasOwn(result, "permissions"), false);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.decoder) && Object.isFrozen(result.limits));
});

test("input snapshot and retained derivative copies do not share writable caller bytes", async () => {
  const source = png();
  const originalHash = hash(source);
  const pending = readStaticPng(source);
  source.fill(0);
  const result = await pending;
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.equal(result.sourceSha256, originalHash);
  const first = result.copyNormalizedBytes();
  const second = result.copyNormalizedBytes();
  assert.notEqual(first.buffer, second.buffer);
  first.fill(0);
  assert.equal(hash(second), result.normalizedSha256);
  assert.equal(hash(result.copyNormalizedBytes()), result.normalizedSha256);
});

test("typed-array intrinsic snapshot ignores caller accessors and iterator", async () => {
  const source = new Uint8Array(png());
  let invoked = 0;
  for (const name of ["byteLength", "buffer", "byteOffset", Symbol.iterator]) {
    Object.defineProperty(source, name, { get() { invoked += 1; throw new Error("untrusted accessor"); } });
  }
  const result = await readStaticPng(source);
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.equal(invoked, 0);
});

test("only owned byte arrays are accepted; URLs, proxies, shared backing and detached views are rejected", async () => {
  let invoked = 0;
  const proxy = new Proxy(png(), { get() { invoked += 1; throw new Error("proxy"); } });
  const shared = new Uint8Array(new SharedArrayBuffer(16));
  const detached = new Uint8Array(16);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  class Subclass extends Uint8Array {}
  for (const source of ["https://example.invalid/image.png", {}, [], new DataView(new ArrayBuffer(10)),
    new Uint8ClampedArray(5), new Subclass(5), proxy, shared, detached, new Uint8Array(0)]) {
    const result = await readStaticPng(source);
    assert.equal(result.kind, "rejected");
    assert.equal(result.code, "INVALID_INPUT");
    assert.equal(result.sourceSha256, undefined);
  }
  assert.equal(invoked, 0);
});

test("options fail closed without invoking getters, proxies, methods or forged signals", async () => {
  let invoked = 0;
  const accessor = { get timeoutMs() { invoked += 1; return 10; } };
  const proxy = new Proxy({}, { ownKeys() { invoked += 1; throw new Error("proxy"); } });
  const fakeSignal = { get aborted() { invoked += 1; return false; }, addEventListener() { invoked += 1; } };
  for (const options of [null, [], proxy, accessor, { sourceUrl: "https://example.invalid/" },
    { [Symbol("unknown")]: true }, { signal: fakeSignal }, { signal: null }, Object.create({ timeoutMs: 1 })]) {
    const result = await readStaticPng(png(), options);
    assert.equal(result.code, "INVALID_OPTIONS");
  }
  assert.equal(invoked, 0);
  for (const options of [{ timeoutMs: 0 }, { timeoutMs: NaN }, { timeoutMs: 10001 },
    { timeoutMs: null }, { timeoutMs: "1" }, { maxOutputBytes: 0 }, { maxOutputBytes: null },
    { maxOutputBytes: STATIC_PNG_READER_LIMITS.maxOutputBytes + 1 }]) {
    assert.equal((await readStaticPng(png(), options)).code, "INVALID_LIMIT");
  }
});

test("native AbortSignal methods and aborted getter are used instead of caller shadows", async () => {
  const controller = new AbortController();
  let invoked = 0;
  for (const name of ["aborted", "addEventListener", "removeEventListener"]) {
    Object.defineProperty(controller.signal, name, { get() { invoked += 1; throw new Error("shadow"); } });
  }
  const result = await readStaticPng(png(), { signal: controller.signal });
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.equal(invoked, 0);
  controller.abort("private reason must not be emitted");
  const cancelled = await readStaticPng(png(), { signal: controller.signal });
  assert.equal(cancelled.code, "CANCELLED");
  assert.equal(JSON.stringify(cancelled).includes("private reason"), false);
  assert.equal(invoked, 0);
});

test("real child rejection preserves hash and returns no derivative for unsupported metadata or corrupt pixels", async () => {
  for (const [source, code] of [
    [png({ before: [chunk("tEXt", Buffer.from("source=https://example.invalid/private-token"))] }), "UNSUPPORTED_PNG_FEATURE"],
    [png({ scanlines: Buffer.from([5, 1, 2, 3, 4]) }), "MALFORMED_PNG"],
    [png({ scanlines: Buffer.alloc(100000) }), "RESOURCE_LIMIT"],
  ]) {
    const result = await readStaticPng(source);
    assert.equal(result.kind, "rejected");
    assert.equal(result.code, code, JSON.stringify(result));
    assert.equal(result.sourceSha256, hash(source));
    assert.equal(Object.hasOwn(result, "copyNormalizedBytes"), false);
    assert.equal(JSON.stringify(result).includes("private-token"), false);
  }
  assert.equal((await readStaticPng(png())).kind, "decoded");
});

test("real child output cap rejects insufficient bytes and recovers at the exact deterministic size", async () => {
  const complete = await readStaticPng(png());
  assert.equal(complete.kind, "decoded", JSON.stringify(complete));
  const limited = await readStaticPng(png(), { maxOutputBytes: complete.normalizedByteLength - 1 });
  assert.equal(limited.code, "OUTPUT_LIMIT");
  const recovered = await readStaticPng(png(), { maxOutputBytes: complete.normalizedByteLength });
  assert.equal(recovered.kind, "decoded", JSON.stringify(recovered));
  assert.equal(recovered.normalizedSha256, complete.normalizedSha256);
});

test("oversized input is rejected before any source derivative is exposed", async () => {
  const result = await readStaticPng(new Uint8Array(STATIC_PNG_READER_LIMITS.maxInputBytes + 1));
  assert.equal(result.code, "INPUT_TOO_LARGE");
  assert.equal(result.sourceSha256, undefined);
});

test("actual child decodes the exact four-megapixel / maximum-row / inflated-byte boundary", async () => {
  const width = 1024;
  const height = 4096;
  const source = png({ width, height, scanlines: Buffer.alloc((width * 4 + 1) * height) });
  const result = await readStaticPng(source);
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.equal(result.width, width);
  assert.equal(result.height, height);
  assert.equal(result.decodedRgbaBytes, 4 * STATIC_PNG_READER_LIMITS.maxPixels);
  assert.equal(result.rgbaSha256, hash(Buffer.alloc(width * height * 4)));
  assert.equal(result.normalizedSha256, hash(result.copyNormalizedBytes()));
});
