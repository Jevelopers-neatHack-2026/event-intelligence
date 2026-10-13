// Worker-only byte codec. Callers use reader.mjs for queue, wall and OS bounds.
import { createHash } from "node:crypto";
import { constants, crc32, deflateSync, inflateSync } from "node:zlib";
import { PNG_LIMITS } from "./constants.mjs";

const SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const OUTPUT_OVERHEAD = 57; // Signature, IHDR, one IDAT header/CRC, IEND.

class PngFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new PngFailure(code);
}

function header(data) {
  if (data.length !== 13) fail("MALFORMED_PNG");
  const width = data.readUInt32BE(0);
  const height = data.readUInt32BE(4);
  if (width === 0 || height === 0) fail("MALFORMED_PNG");
  if (width > PNG_LIMITS.maxDimension || height > PNG_LIMITS.maxRows ||
      width * height > PNG_LIMITS.maxPixels) fail("DIMENSION_LIMIT");
  if (data[8] !== 8 || ![2, 6].includes(data[9]) ||
      data[10] !== 0 || data[11] !== 0 || data[12] !== 0) {
    fail("UNSUPPORTED_PNG_FEATURE");
  }
  return { width, height, sourceColorType: data[9], channels: data[9] === 2 ? 3 : 4 };
}

function parse(bytes) {
  if (bytes.length < 8 || !bytes.subarray(0, 8).equals(SIGNATURE)) fail("MALFORMED_PNG");
  let cursor = 8;
  let count = 0;
  let image;
  const parts = [];
  let compressedBytes = 0;
  let previous = "";
  while (cursor < bytes.length) {
    if (++count > PNG_LIMITS.maxChunks) fail("RESOURCE_LIMIT");
    if (bytes.length - cursor < 12) fail("MALFORMED_PNG");
    const length = bytes.readUInt32BE(cursor);
    if (length > 0x7fffffff || length > bytes.length - cursor - 12) fail("MALFORMED_PNG");
    const typeBytes = bytes.subarray(cursor + 4, cursor + 8);
    if (!typeBytes.every((b) => (b >= 65 && b <= 90) || (b >= 97 && b <= 122)) ||
        (typeBytes[2] & 32) !== 0) fail("MALFORMED_PNG");
    const type = typeBytes.toString("ascii");
    const end = cursor + 8 + length;
    if (crc32(bytes.subarray(cursor + 4, end)) !== bytes.readUInt32BE(end)) {
      fail("MALFORMED_PNG");
    }
    const data = bytes.subarray(cursor + 8, end);
    if (!image && type !== "IHDR") fail("MALFORMED_PNG");
    switch (type) {
      case "IHDR":
        if (image || cursor !== 8) fail("MALFORMED_PNG");
        image = header(data);
        break;
      case "IDAT":
        if (previous !== "IHDR" && previous !== "IDAT") fail("MALFORMED_PNG");
        parts.push(data);
        compressedBytes += data.length;
        break;
      case "IEND":
        if (length !== 0 || previous !== "IDAT" || compressedBytes === 0 ||
            end + 4 !== bytes.length) fail("MALFORMED_PNG");
        return { ...image, compressed: Buffer.concat(parts, compressedBytes) };
      default:
        // Even ancillary color/profile/text chunks are outside this first profile.
        // Never silently discard semantics or treat an animation as a still image.
        fail("UNSUPPORTED_PNG_FEATURE");
    }
    previous = type;
    cursor = end + 4;
  }
  fail("MALFORMED_PNG");
}

function paeth(left, above, upperLeft) {
  const p = left + above - upperLeft;
  const a = Math.abs(p - left);
  const b = Math.abs(p - above);
  const c = Math.abs(p - upperLeft);
  return a <= b && a <= c ? left : b <= c ? above : upperLeft;
}

function inflateAndReconstruct(image) {
  const rowBytes = image.width * image.channels;
  const stride = rowBytes + 1;
  const expected = stride * image.height;
  if (!Number.isSafeInteger(expected) || expected > PNG_LIMITS.maxInflatedBytes) {
    fail("RESOURCE_LIMIT");
  }
  let inflated;
  try {
    inflated = inflateSync(image.compressed, { maxOutputLength: expected, info: true });
  } catch (error) {
    fail(error?.code === "ERR_BUFFER_TOO_LARGE" ? "RESOURCE_LIMIT" : "MALFORMED_PNG");
  }
  // The fixed Node/zlib combination is tested for trailing and concatenated streams.
  // A prefix accepted by zlib is not acceptance of the complete IDAT payload.
  if (inflated.buffer.length !== expected ||
      inflated.engine.bytesWritten !== image.compressed.length) fail("MALFORMED_PNG");
  const bytes = inflated.buffer;
  for (let row = 0; row < image.height; row += 1) {
    const start = row * stride + 1;
    const filter = bytes[start - 1];
    if (filter > 4) fail("MALFORMED_PNG");
    for (let column = 0; column < rowBytes; column += 1) {
      const at = start + column;
      const left = column >= image.channels ? bytes[at - image.channels] : 0;
      const above = row > 0 ? bytes[at - stride] : 0;
      const upperLeft = row > 0 && column >= image.channels
        ? bytes[at - stride - image.channels] : 0;
      let predictor = 0;
      if (filter === 1) predictor = left;
      else if (filter === 2) predictor = above;
      else if (filter === 3) predictor = Math.floor((left + above) / 2);
      else if (filter === 4) predictor = paeth(left, above, upperLeft);
      bytes[at] = (bytes[at] + predictor) & 255;
    }
  }
  return { bytes, stride };
}

function chunk(type, data) {
  const result = Buffer.alloc(data.length + 12);
  result.writeUInt32BE(data.length, 0);
  result.write(type, 4, 4, "ascii");
  data.copy(result, 8);
  result.writeUInt32BE(crc32(result.subarray(4, result.length - 4)), result.length - 4);
  return result;
}

export function decodeStaticPngForWorker(bytes, maxOutputBytes) {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length === 0) fail("INVALID_INPUT");
    if (bytes.length > PNG_LIMITS.maxInputBytes) fail("INPUT_TOO_LARGE");
    if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 ||
        maxOutputBytes > PNG_LIMITS.maxOutputBytes) fail("INVALID_LIMIT");
    const image = parse(bytes);
    const reconstructed = inflateAndReconstruct(image);
    const rgbaStride = image.width * 4 + 1;
    const normalizedRows = Buffer.alloc(rgbaStride * image.height);
    const pixelHash = createHash("sha256");
    for (let row = 0; row < image.height; row += 1) {
      const from = row * reconstructed.stride + 1;
      const to = row * rgbaStride + 1;
      for (let pixel = 0; pixel < image.width; pixel += 1) {
        const input = from + pixel * image.channels;
        const output = to + pixel * 4;
        normalizedRows[output] = reconstructed.bytes[input];
        normalizedRows[output + 1] = reconstructed.bytes[input + 1];
        normalizedRows[output + 2] = reconstructed.bytes[input + 2];
        normalizedRows[output + 3] = image.channels === 4 ? reconstructed.bytes[input + 3] : 255;
      }
      pixelHash.update(normalizedRows.subarray(to, to + image.width * 4));
    }
    if (maxOutputBytes <= OUTPUT_OVERHEAD) fail("OUTPUT_LIMIT");
    let compressed;
    try {
      compressed = deflateSync(normalizedRows, {
        level: 9, windowBits: 15, memLevel: 8, strategy: constants.Z_DEFAULT_STRATEGY,
        maxOutputLength: maxOutputBytes - OUTPUT_OVERHEAD,
      });
    } catch (error) {
      fail(error?.code === "ERR_BUFFER_TOO_LARGE" ? "OUTPUT_LIMIT" : "DECODER_FAILURE");
    }
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(image.width, 0);
    ihdr.writeUInt32BE(image.height, 4);
    ihdr[8] = 8;
    ihdr[9] = 6;
    const normalized = Buffer.concat([
      SIGNATURE, chunk("IHDR", ihdr), chunk("IDAT", compressed), chunk("IEND", Buffer.alloc(0)),
    ]);
    if (normalized.length > maxOutputBytes) fail("OUTPUT_LIMIT");
    // The raw payload comes from the same normalized sample rows. Keep the
    // established PNG encoder and its hashes unchanged; omit only filter bytes.
    const rgba = Buffer.alloc(image.width * image.height * 4);
    for (let row = 0; row < image.height; row += 1) {
      const from = row * rgbaStride + 1;
      normalizedRows.copy(rgba, row * image.width * 4, from, from + image.width * 4);
    }
    return {
      kind: "decoded",
      width: image.width,
      height: image.height,
      sourceColorType: image.sourceColorType,
      decodedRgbaBytes: image.width * image.height * 4,
      rgbaSha256: pixelHash.digest("hex"),
      normalizedSha256: createHash("sha256").update(normalized).digest("hex"),
      normalized,
      rgba,
    };
  } catch (error) {
    return { kind: "rejected", code: error instanceof PngFailure ? error.code : "DECODER_FAILURE" };
  }
}
