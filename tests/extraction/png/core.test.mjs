import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { decodeStaticPngForWorker } from "../../../src/extraction/png/core.mjs";
import { PNG_LIMITS } from "../../../src/extraction/png/constants.mjs";
import { chunk, png, PNG_SIGNATURE, readNormalized, referenceCrc } from "./fixtures.mjs";

const decode = (bytes, cap = PNG_LIMITS.maxOutputBytes) => decodeStaticPngForWorker(bytes, cap);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

function rejected(bytes, code, cap) {
  assert.deepEqual(decode(bytes, cap), { kind: "rejected", code });
}

test("independent CRC reference matches the standard check vector", () => {
  assert.equal(referenceCrc(Buffer.from("123456789")), 0xcbf43926);
});

const firstRowVectors = [
  [0, "050a0f1402040810"],
  [1, "050a0f14fdfaf9fc"],
  [2, "050a0f1402040810"],
  [3, "050a0f1400ff0106"],
  [4, "050a0f14fdfaf9fc"],
];
for (const [filter, encoded] of firstRowVectors) {
  test("filter " + filter + " reconstructs literal first-row RGBA bytes including wraparound", () => {
    const result = decode(png({ width: 2, scanlines: Buffer.concat([Buffer.from([filter]), Buffer.from(encoded, "hex")]) }));
    assert.equal(result.kind, "decoded");
    const expected = Buffer.from("050a0f1402040810", "hex");
    assert.deepEqual(readNormalized(result.normalized).rgba, expected);
    assert.deepEqual(result.rgba, expected);
    assert.equal(result.rgbaSha256, hash(expected));
    assert.equal(result.normalizedSha256, hash(result.normalized));
  });
}

test("RGB Sub and Paeth rows use channel distance three, preserve tie ordering and add opaque alpha", () => {
  const result = decode(png({ width: 2, height: 2, colorType: 2,
    scanlines: Buffer.from("010a141efb05dc040af6dcebf706", "hex") }));
  assert.equal(result.kind, "decoded");
  assert.equal(result.sourceColorType, 2);
  assert.equal(result.decodedRgbaBytes, 16);
  assert.deepEqual(readNormalized(result.normalized).rgba, Buffer.from("0a141eff0519faff140afaffff0100ff", "hex"));
  assert.deepEqual(result.rgba, Buffer.from("0a141eff0519faff140afaffff0100ff", "hex"));
});

test("Up and Average use the reconstructed preceding row, including first-column floor and byte wrap", () => {
  const result = decode(png({ width: 2, height: 3,
    scanlines: Buffer.from("000a141e28323c46500201ff03fc0506f70a030008fcf0fb190e08", "hex") }));
  assert.equal(result.kind, "decoded");
  const expected = Buffer.from("0a141e28323c46500b13212437423d5a05110c02"+"19423236", "hex");
  assert.deepEqual(readNormalized(result.normalized).rgba, expected);
  assert.deepEqual(result.rgba, expected);
});

test("contiguous empty/split IDAT chunks describe the same pixels and deterministic normalized bytes", () => {
  const compressed = deflateSync(Buffer.from("0001020304", "hex"));
  const a = decode(png({ compressed }));
  const b = decode(png({ dataParts: [Buffer.alloc(0), compressed.subarray(0, 3), compressed.subarray(3), Buffer.alloc(0)] }));
  assert.equal(a.kind, "decoded");
  assert.equal(b.kind, "decoded");
  assert.deepEqual(a.normalized, b.normalized);
  assert.deepEqual(a.rgba, b.rgba);
  assert.deepEqual(decode(a.normalized).normalized, a.normalized);
});

for (const [name, bytes] of [
  ["bad signature", Buffer.from("not a PNG")],
  ["truncated chunk", png().subarray(0, -1)],
  ["empty chunk sequence", PNG_SIGNATURE],
  ["no IEND", png().subarray(0, -12)],
  ["trailing input", Buffer.concat([png(), Buffer.from([0])])],
  ["duplicate IHDR", Buffer.concat([png().subarray(0, 33), png().subarray(8)])],
  ["IDAT before header", Buffer.concat([PNG_SIGNATURE, chunk("IDAT"), png().subarray(8)])],
  ["IEND without compressed stream", png({ dataParts: [Buffer.alloc(0)] })],
  ["nonempty IEND", Buffer.concat([png().subarray(0, -12), chunk("IEND", Buffer.from([1]))])],
  ["invalid reserved chunk case", png({ before: [chunk("texT")] })],
  ["invalid chunk name", png({ before: [chunk("te1T")] })],
  ["zero width", png({ width: 0 })],
  ["zero height", png({ height: 0 })],
]) {
  test(name + " is rejected without a derivative", () => rejected(bytes, "MALFORMED_PNG"));
}

test("chunk length and CRC are checked before using the claimed bytes", () => {
  const crc = Buffer.from(png());
  crc[crc.length - 1] ^= 1;
  rejected(crc, "MALFORMED_PNG");
  const tooLong = Buffer.from(png());
  tooLong.writeUInt32BE(0x7fffffff, 8);
  rejected(tooLong, "MALFORMED_PNG");
  tooLong.writeUInt32BE(0x80000000, 8);
  rejected(tooLong, "MALFORMED_PNG");
});

for (const [name, options] of [
  ["grayscale", { colorType: 0 }], ["indexed color", { colorType: 3 }],
  ["grayscale alpha", { colorType: 4 }], ["16-bit", { bitDepth: 16 }],
  ["low bit depth", { bitDepth: 1 }], ["Adam7", { interlace: 1 }],
  ["unknown compression", { compression: 1 }], ["unknown filter method", { filter: 1 }],
]) {
  test(name + " is an explicit unsupported profile, never a dimension-only success", () => {
    rejected(png(options), "UNSUPPORTED_PNG_FEATURE");
  });
}

for (const type of ["PLTE", "tRNS", "gAMA", "iCCP", "sRGB", "tEXt", "eXIf", "acTL", "fcTL", "fdAT", "zzZZ"]) {
  test(type + " metadata/animation/unknown chunk is rejected explicitly", () => {
    rejected(png({ before: [chunk(type)] }), "UNSUPPORTED_PNG_FEATURE");
  });
}

test("width, rows and total pixels are bounded before decompression", () => {
  for (const options of [{ width: 4097 }, { height: 4097 }, { width: 2049, height: 2048 }]) {
    rejected(png({ ...options, compressed: Buffer.from("invalid zlib") }), "DIMENSION_LIMIT");
  }
});

test("input bytes and chunk work are capped", () => {
  rejected(Buffer.alloc(PNG_LIMITS.maxInputBytes + 1), "INPUT_TOO_LARGE");
  const parts = Array.from({ length: PNG_LIMITS.maxChunks - 2 }, () => Buffer.alloc(0));
  parts.push(deflateSync(Buffer.from("0001020304", "hex")));
  rejected(png({ dataParts: parts }), "RESOURCE_LIMIT");
});

test("exact chunk-count ceiling is accepted with complete pixel reconstruction", () => {
  const parts = Array.from({ length: PNG_LIMITS.maxChunks - 3 }, () => Buffer.alloc(0));
  parts.push(deflateSync(Buffer.from("0001020304", "hex")));
  const result = decode(png({ dataParts: parts }));
  assert.equal(result.kind, "decoded");
  assert.deepEqual(readNormalized(result.normalized).rgba, Buffer.from([1, 2, 3, 4]));
});

test("inflation expansion is stopped by the expected scanline byte ceiling", () => {
  rejected(png({ scanlines: Buffer.alloc(1024 * 1024) }), "RESOURCE_LIMIT");
});

test("short row, bad filter, invalid zlib and checksum failure fail closed", () => {
  rejected(png({ scanlines: Buffer.from([0, 1]) }), "MALFORMED_PNG");
  rejected(png({ scanlines: Buffer.from([5, 1, 2, 3, 4]) }), "MALFORMED_PNG");
  rejected(png({ compressed: Buffer.from([1, 2, 3]) }), "MALFORMED_PNG");
  const corrupted = deflateSync(Buffer.from("0001020304", "hex"));
  corrupted[corrupted.length - 1] ^= 1;
  rejected(png({ compressed: corrupted }), "MALFORMED_PNG");
  const dictionaryStream = deflateSync(Buffer.from("0001020304", "hex"), { dictionary: Buffer.from("external-dictionary") });
  rejected(png({ compressed: dictionaryStream }), "MALFORMED_PNG");
});

test("complete IDAT consumption rejects trailing junk, a second zlib stream and an extra row", () => {
  const stream = deflateSync(Buffer.from("0001020304", "hex"));
  rejected(png({ compressed: Buffer.concat([stream, Buffer.from([0, 1, 2])]) }), "MALFORMED_PNG");
  rejected(png({ compressed: Buffer.concat([stream, stream]) }), "MALFORMED_PNG");
  rejected(png({ scanlines: Buffer.from("00010203040001020304", "hex") }), "RESOURCE_LIMIT");
});

test("a lower derivative cap is enforced on actual output, and subsequent decode recovers", () => {
  const complete = decode(png());
  assert.equal(complete.kind, "decoded");
  rejected(png(), "OUTPUT_LIMIT", complete.normalized.length - 1);
  rejected(png(), "OUTPUT_LIMIT", 1);
  assert.deepEqual(decode(png(), complete.normalized.length).normalized, complete.normalized);
});
