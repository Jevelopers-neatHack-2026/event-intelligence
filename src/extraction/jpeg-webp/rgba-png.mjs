import { createHash } from "node:crypto";
import { crc32 } from "node:zlib";
import { RASTER_LIMITS } from "./constants.mjs";

export function normalizedPngLength(width, height) {
  const rows = (width * 4 + 1) * height;
  return 57 + 2 + rows + Math.ceil(rows / 65535) * 5 + 4;
}
function chunk(type, data) {
  const result = Buffer.alloc(data.length + 12);
  result.writeUInt32BE(data.length, 0);
  result.write(type, 4, 4, "ascii");
  data.copy(result, 8);
  result.writeUInt32BE(crc32(result.subarray(4, result.length - 4)), result.length - 4);
  return result;
}
function adler32(bytes) {
  let a = 1, b = 0;
  for (let offset = 0; offset < bytes.length;) {
    const end = Math.min(offset + 5552, bytes.length);
    while (offset < end) { a += bytes[offset++]; b += a; }
    a %= 65521; b %= 65521;
  }
  return ((b << 16) | a) >>> 0;
}

/** Parent-owned deterministic PNG encoding, with no codec-compressor choices. */
export function normalizeRgba(bytes, width, height, maxOutputBytes) {
  if (!Buffer.isBuffer(bytes) || !Number.isInteger(width) || !Number.isInteger(height) ||
      width < 1 || height < 1 || width > RASTER_LIMITS.maxDimension || height > RASTER_LIMITS.maxDimension ||
      width * height > RASTER_LIMITS.maxPixels || bytes.length !== width * height * 4 ||
      !Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > RASTER_LIMITS.maxOutputBytes) {
    return { kind: "rejected", code: "PROTOCOL_ERROR" };
  }
  if (normalizedPngLength(width, height) > maxOutputBytes) return { kind: "rejected", code: "OUTPUT_LIMIT" };
  const stride = width * 4 + 1;
  const rows = Buffer.alloc(stride * height);
  for (let row = 0; row < height; row += 1) bytes.copy(rows, row * stride + 1, row * width * 4, (row + 1) * width * 4);
  const stream = Buffer.alloc(2 + rows.length + Math.ceil(rows.length / 65535) * 5 + 4);
  stream[0] = 0x78; stream[1] = 0x01;
  let at = 2;
  for (let offset = 0; offset < rows.length;) {
    const size = Math.min(65535, rows.length - offset);
    stream[at++] = offset + size === rows.length ? 1 : 0;
    stream.writeUInt16LE(size, at); stream.writeUInt16LE(size ^ 0xffff, at + 2); at += 4;
    rows.copy(stream, at, offset, offset + size); at += size; offset += size;
  }
  stream.writeUInt32BE(adler32(rows), at);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 6;
  const normalized = Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), chunk("IHDR", ihdr), chunk("IDAT", stream), chunk("IEND", Buffer.alloc(0))]);
  return { kind: "normalized", normalized,
    rgbaSha256: createHash("sha256").update(bytes).digest("hex"),
    normalizedSha256: createHash("sha256").update(normalized).digest("hex") };
}
