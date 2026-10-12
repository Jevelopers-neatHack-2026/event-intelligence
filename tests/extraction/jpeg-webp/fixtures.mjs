import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { inflateSync, crc32 } from "node:zlib";
export const fixtureDocument = JSON.parse(readFileSync(new URL("./fixtures.json", import.meta.url), "utf8"));
export function fixture(name) {
  const expected = fixtureDocument.fixtures[name];
  assert.ok(expected, name);
  const bytes = Buffer.from(expected.bytesBase64, "base64");
  assert.equal(bytes.length, expected.sourceByteLength);
  assert.equal(hash(bytes), expected.sourceSha256);
  return { bytes, expected };
}
export function hash(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
export function runtimeDirectory() {
  const directory = process.env.EI_JPEG_WEBP_TEST_RUNTIME;
  assert.ok(directory, "EI_JPEG_WEBP_TEST_RUNTIME must explicitly name the installed fixture runtime");
  return directory;
}
/** Independent zlib/PNG structural consumer; does not import production normalization. */
export function pixelsFromPng(bytes, width, height) {
  bytes = Buffer.from(bytes);
  assert.equal(bytes.toString("hex", 0, 8), "89504e470d0a1a0a");
  const chunks = [];
  for (let offset = 8; offset < bytes.length;) {
    const size = bytes.readUInt32BE(offset);
    const type = bytes.toString("ascii", offset + 4, offset + 8);
    const end = offset + 8 + size;
    assert.ok(end + 4 <= bytes.length);
    assert.equal(crc32(bytes.subarray(offset + 4, end)), bytes.readUInt32BE(end));
    chunks.push({ type, bytes: bytes.subarray(offset + 8, end) });
    offset = end + 4;
    if (type === "IEND") assert.equal(offset, bytes.length);
  }
  assert.deepEqual(chunks.map((x) => x.type), ["IHDR", "IDAT", "IEND"]);
  assert.equal(chunks[0].bytes.length, 13);
  assert.equal(chunks[0].bytes.readUInt32BE(0), width);
  assert.equal(chunks[0].bytes.readUInt32BE(4), height);
  assert.equal(chunks[0].bytes.toString("hex", 8), "0806000000");
  const rows = inflateSync(chunks[1].bytes, { maxOutputLength: (width * 4 + 1) * height });
  assert.equal(rows.length, (width * 4 + 1) * height);
  const pixels = Buffer.alloc(width * height * 4);
  for (let row = 0; row < height; row += 1) {
    assert.equal(rows[row * (width * 4 + 1)], 0);
    rows.copy(pixels, row * width * 4, row * (width * 4 + 1) + 1, (row + 1) * (width * 4 + 1));
  }
  return pixels;
}
export function jpegSegment(marker, data) {
  const head = Buffer.from([255, marker, 0, 0]); head.writeUInt16BE(data.length + 2, 2);
  return Buffer.concat([head, data]);
}
export function webpChunk(type, data, padding = 0) {
  const head = Buffer.alloc(8); head.write(type, 0, 4, "ascii"); head.writeUInt32LE(data.length, 4);
  return Buffer.concat([head, data, data.length & 1 ? Buffer.from([padding]) : Buffer.alloc(0)]);
}
export function webpContainer(chunks) {
  const body = Buffer.concat(chunks); const head = Buffer.from("524946460000000057454250", "hex");
  head.writeUInt32LE(body.length + 4, 4); return Buffer.concat([head, body]);
}
export function webpChunks(bytes) {
  const result = [];
  for (let at = 12; at < bytes.length;) {
    const size = bytes.readUInt32LE(at + 4);
    result.push({ type: bytes.toString("ascii", at, at + 4), data: bytes.subarray(at + 8, at + 8 + size) });
    at += 8 + size + (size & 1);
  }
  return result;
}
