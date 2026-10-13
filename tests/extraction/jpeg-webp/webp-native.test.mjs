import assert from "node:assert/strict";
import test from "node:test";
import { createStaticJpegWebpReader } from "../../../src/extraction/jpeg-webp/index.mjs";
import { inspectStaticRasterProfile } from "../../../src/extraction/jpeg-webp/profile.mjs";
import { fixture, hash, pixelsFromPng, runtimeDirectory, webpChunk, webpChunks, webpContainer } from "./fixtures.mjs";

const reader = createStaticJpegWebpReader({ runtimeDirectory: runtimeDirectory() });
function replacePayload(name, transform) {
  const { bytes, expected } = fixture(name);
  const chunks = webpChunks(bytes);
  chunks.at(-1).data = transform(chunks.at(-1).data);
  return { bytes: webpContainer(chunks.map((item) => webpChunk(item.type, item.data))), expected };
}

for (const name of ["webp-rgb-lossless", "webp-rgba-lossless"]) {
  test("exact declared native payload cannot borrow RIFF padding: " + name, async () => {
    const { bytes } = replacePayload(name, (data) => data.subarray(0, data.length - 1));
    assert.equal(inspectStaticRasterProfile(bytes).kind, "profile", "the container is complete but its lossless payload is insufficient");
    const result = await reader.read(bytes);
    assert.equal(result.kind, "rejected", JSON.stringify(result));
    assert.equal(result.code, "MALFORMED_IMAGE");
    assert.equal(result.copyNormalizedBytes, undefined);
    assert.equal((await reader.read(fixture(name).bytes)).kind, "decoded");
  });
}

test("bounded unused WebP payload bytes are stripped from the deterministic derivative", async () => {
  // Native completion is not a consumed-byte/canonical-bitstream attestation.
  // This source gets a distinct identity even though its complete decoded pixels agree.
  const { bytes, expected } = replacePayload("webp-rgba-lossless", (data) => Buffer.concat([data, Buffer.from("<script>synthetic()</script>")]));
  const result = await reader.read(bytes);
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.equal(result.sourceSha256, hash(bytes)); assert.notEqual(result.sourceSha256, expected.sourceSha256);
  assert.equal(result.rgbaSha256, expected.expectedRgbaSha256);
  const png = result.copyNormalizedBytes();
  assert.equal(hash(pixelsFromPng(png, expected.width, expected.height)), expected.expectedRgbaSha256);
  assert.equal(Buffer.from(png).includes(Buffer.from("<script>")), false);
});

test("a shorter VP8 payload that completes natively is not rejected for differing source bytes", async () => {
  const { bytes, expected } = replacePayload("webp-rgb-lossy", (data) => data.subarray(0, data.length - 1));
  const result = await reader.read(bytes);
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.equal(result.sourceSha256, hash(bytes)); assert.notEqual(result.sourceSha256, expected.sourceSha256);
  assert.equal(result.rgbaSha256, expected.expectedRgbaSha256);
});

for (const [name, change, compression] of [
  ["raw alpha missing sample", (data) => data.subarray(0, data.length - 1), 0],
  ["raw alpha extra sample", (data) => Buffer.concat([data, Buffer.from([0])]), 0],
  ["compressed alpha incomplete stream", (data) => data.subarray(0, Math.max(2, Math.floor(data.length / 2))), 1],
]) {
  test("declared ALPH payload completion and recovery: " + name, async () => {
    const fixtureName = compression === 1 ? "webp-rgba-compressed-alpha" : "webp-rgba-lossy";
    const original = fixture(fixtureName).bytes;
    const chunks = webpChunks(original);
    const alpha = chunks.find((item) => item.type === "ALPH");
    assert.ok(alpha); assert.equal(alpha.data[0] & 3, compression, "required real encoded alpha mode");
    alpha.data = change(alpha.data);
    const bytes = webpContainer(chunks.map((item) => webpChunk(item.type, item.data)));
    assert.equal(inspectStaticRasterProfile(bytes).kind, "profile", "negative must reach the native payload guard");
    const result = await reader.read(bytes);
    assert.equal(result.kind, "rejected", JSON.stringify(result)); assert.equal(result.code, "MALFORMED_IMAGE");
    assert.equal(result.copyNormalizedBytes, undefined);
    assert.equal((await reader.read(original)).kind, "decoded", "real alpha image must recover");
  });
}
