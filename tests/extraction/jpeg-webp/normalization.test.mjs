import assert from "node:assert/strict";
import test from "node:test";
import { normalizeRgba, normalizedPngLength } from "../../../src/extraction/jpeg-webp/rgba-png.mjs";
import { pixelsFromPng, hash } from "./fixtures.mjs";

test("stored-DEFLATE PNG crosses exact block boundaries and keeps alpha bytes", () => {
  for (const [width, height] of [[1, 1], [4096, 1], [4096, 4], [128, 128]]) {
    const bytes = Buffer.alloc(width * height * 4);
    for (let at = 0; at < bytes.length; at += 1) bytes[at] = at % 251;
    const result = normalizeRgba(bytes, width, height, 20 * 1024 * 1024);
    assert.equal(result.kind, "normalized"); assert.equal(result.normalized.length, normalizedPngLength(width, height));
    assert.deepEqual(pixelsFromPng(result.normalized, width, height), bytes);
    assert.equal(result.rgbaSha256, hash(bytes)); assert.equal(result.normalizedSha256, hash(result.normalized));
  }
});

test("normalizer enforces a lower output ceiling before returning a derivative", () => {
  const bytes = Buffer.from([1, 2, 3, 4]); const size = normalizedPngLength(1, 1);
  assert.equal(normalizeRgba(bytes, 1, 1, size).kind, "normalized");
  assert.deepEqual(normalizeRgba(bytes, 1, 1, size - 1), { kind: "rejected", code: "OUTPUT_LIMIT" });
});

test("normalizer rejects dimensions, payload size and noninteger limits without partial output", () => {
  for (const [bytes, width, height, maxOutput] of [[Buffer.alloc(3), 1, 1, 100], [Buffer.alloc(4), 0, 1, 100],
    [Buffer.alloc(4), 4097, 1, 100], [Buffer.alloc(4), 2048, 2049, 100], [Buffer.alloc(4), 1, NaN, 100],
    [Buffer.alloc(4), 1, 1, Infinity], [Buffer.alloc(4), 1, 1, 20 * 1024 * 1024 + 1]]) {
    assert.deepEqual(normalizeRgba(bytes, width, height, maxOutput), { kind: "rejected", code: "PROTOCOL_ERROR" });
  }
});
