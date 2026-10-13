import { RASTER_LIMITS } from "./constants.mjs";

class ProfileFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}
function fail(code = "MALFORMED_IMAGE") { throw new ProfileFailure(code); }
function dimension(width, height) {
  if (width === 0 || height === 0) fail();
  if (width > RASTER_LIMITS.maxDimension || height > RASTER_LIMITS.maxDimension ||
      width * height > RASTER_LIMITS.maxPixels) fail("DIMENSION_LIMIT");
}

function jpeg(bytes) {
  let cursor = 2;
  let count = 0;
  let frame;
  let scans = 0;
  let entropy = false;
  let jfif = false;
  while (cursor < bytes.length) {
    let marker;
    if (entropy) {
      const at = bytes.indexOf(255, cursor);
      if (at < 0) fail();
      cursor = at + 1;
      // JPEG entropy permits FF00 byte stuffing and restart markers. Fill bytes
      // are permitted before a marker, but not before a stuffed zero.
      const fillStart = cursor;
      while (cursor < bytes.length && bytes[cursor] === 255) cursor += 1;
      if (cursor >= bytes.length) fail();
      marker = bytes[cursor++];
      if (marker === 0) {
        if (cursor - fillStart !== 1) fail();
        continue;
      }
      if (marker >= 0xd0 && marker <= 0xd7) continue;
      entropy = false;
    } else {
      if (bytes[cursor++] !== 255) fail();
      while (cursor < bytes.length && bytes[cursor] === 255) cursor += 1;
      if (cursor >= bytes.length) fail();
      marker = bytes[cursor++];
    }
    if (++count > RASTER_LIMITS.maxSegments) fail("RESOURCE_LIMIT");
    if (marker === 0xd9) {
      if (!frame || scans === 0 || cursor !== bytes.length) fail();
      return Object.freeze({ ...frame, frames: 1 });
    }
    if (marker === 0 || marker === 0xd8 || marker >= 0xd0 && marker <= 0xd7) fail();
    if (marker === 0x01) fail("UNSUPPORTED_FEATURE");
    if (cursor + 2 > bytes.length) fail();
    const length = bytes.readUInt16BE(cursor);
    if (length < 2 || length > bytes.length - cursor) fail();
    const data = bytes.subarray(cursor + 2, cursor + length);
    cursor += length;
    if (marker === 0xe0) {
      // Exactly one ordinary JFIF header. No thumbnail, density/orientation/color
      // policy, JFXX extension or embedded secondary image is silently applied.
      if (jfif || frame || data.length !== 14 || data.toString("hex", 0, 5) !== "4a46494600" ||
          data[5] !== 1 || data[6] > 2 || data[7] !== 0 ||
          data.readUInt16BE(8) !== 1 || data.readUInt16BE(10) !== 1 ||
          data[12] !== 0 || data[13] !== 0) fail("UNSUPPORTED_FEATURE");
      jfif = true;
    } else if (marker === 0xc0 || marker === 0xc2) {
      if (frame || scans !== 0 || data.length < 6) fail();
      const height = data.readUInt16BE(1);
      const width = data.readUInt16BE(3);
      dimension(width, height);
      const components = data[5];
      if (data[0] !== 8 || ![1, 3].includes(components)) fail("UNSUPPORTED_FEATURE");
      if (data.length !== 6 + components * 3) fail();
      for (let index = 0; index < components; index += 1) {
        const at = 6 + 3 * index;
        if (data[at] !== index + 1) fail("UNSUPPORTED_FEATURE");
        if ((data[at + 1] >> 4) < 1 || (data[at + 1] >> 4) > 4 ||
            (data[at + 1] & 15) < 1 || (data[at + 1] & 15) > 4 || data[at + 2] > 3) fail();
      }
      frame = { sourceFormat: "jpeg", encoding: marker === 0xc0 ? "baseline" : "progressive",
        width, height, sourceMode: components === 1 ? "L" : "RGB" };
    } else if (marker === 0xda) {
      if (!frame || data.length < 6) fail();
      const count = data[0];
      const components = frame.sourceMode === "L" ? 1 : 3;
      if (count < 1 || count > components || data.length !== 1 + count * 2 + 3) fail();
      const seen = new Set();
      for (let index = 0; index < count; index += 1) {
        const id = data[1 + index * 2];
        const selectors = data[2 + index * 2];
        if (id < 1 || id > components || seen.has(id) || (selectors >> 4) > 3 || (selectors & 15) > 3) fail();
        seen.add(id);
      }
      const spectral = data.subarray(1 + 2 * count);
      if (spectral[0] > spectral[1] || spectral[1] > 63 || (spectral[2] >> 4) > 13 || (spectral[2] & 15) > 13) fail();
      if (frame.encoding === "baseline" && (spectral[0] !== 0 || spectral[1] !== 63 || spectral[2] !== 0)) fail();
      scans += 1;
      entropy = true;
    } else if (marker === 0xdb || marker === 0xc4) {
      if (data.length === 0) fail(); // Native load validates the quantization/Huffman tables.
    } else if (marker === 0xdd) {
      if (data.length !== 2) fail();
    } else {
      // Includes EXIF/ICC/XMP/Adobe/MPF, comments, arithmetic/lossless JPEG,
      // deferred-height DNL and all other SOF or extension marker semantics.
      fail("UNSUPPORTED_FEATURE");
    }
  }
  fail();
}

function webp(bytes) {
  if (bytes.length < 20 || bytes.readUInt32LE(4) + 8 !== bytes.length) fail();
  const chunks = [];
  let cursor = 12;
  while (cursor < bytes.length) {
    if (chunks.length >= RASTER_LIMITS.maxSegments) fail("RESOURCE_LIMIT");
    if (bytes.length - cursor < 8) fail();
    const type = bytes.toString("latin1", cursor, cursor + 4);
    const length = bytes.readUInt32LE(cursor + 4);
    const end = cursor + 8 + length;
    if (end > bytes.length || end + (length & 1) > bytes.length ||
        (length & 1) && bytes[end] !== 0) fail();
    chunks.push({ type, data: bytes.subarray(cursor + 8, end) });
    cursor = end + (length & 1);
  }
  const sequence = chunks.map((x) => x.type).join(",");
  if (!["VP8 ", "VP8L", "VP8X,ALPH,VP8 ", "VP8X,VP8L"].includes(sequence)) fail("UNSUPPORTED_FEATURE");
  let canvas;
  if (chunks[0].type === "VP8X") {
    const data = chunks[0].data;
    // This extended profile only carries alpha. Every metadata/animation and
    // reserved flag is rejected, even when its corresponding chunk is absent.
    if (data.length !== 10) fail();
    if (data[0] !== 0x10 || data[1] !== 0 || data[2] !== 0 || data[3] !== 0) fail("UNSUPPORTED_FEATURE");
    canvas = { width: data.readUIntLE(4, 3) + 1, height: data.readUIntLE(7, 3) + 1 };
    dimension(canvas.width, canvas.height);
  }
  if (chunks[1]?.type === "ALPH") {
    const data = chunks[1].data;
    if (data.length < 2) fail();
    if ((data[0] & 0xc0) !== 0 || (data[0] & 3) > 1 || ((data[0] >> 4) & 3) > 1) fail("UNSUPPORTED_FEATURE");
  }
  const image = chunks.at(-1);
  let width, height, alpha;
  if (image.type === "VP8L") {
    if (image.data.length < 5 || image.data[0] !== 0x2f) fail();
    const bits = image.data.readUInt32LE(1);
    if (bits >>> 29 !== 0) fail("UNSUPPORTED_FEATURE");
    width = (bits & 0x3fff) + 1;
    height = ((bits >>> 14) & 0x3fff) + 1;
    alpha = (bits & 0x10000000) !== 0;
    if (canvas && !alpha) fail();
  } else {
    const data = image.data;
    if (data.length < 10 || data.toString("hex", 3, 6) !== "9d012a") fail();
    if ((data[0] & 1) !== 0 || ((data[0] >> 1) & 7) > 3 || (data[0] & 0x10) === 0 ||
        (data.readUInt16LE(6) & 0xc000) !== 0 || (data.readUInt16LE(8) & 0xc000) !== 0) fail("UNSUPPORTED_FEATURE");
    width = data.readUInt16LE(6);
    height = data.readUInt16LE(8);
    alpha = canvas !== undefined;
  }
  dimension(width, height);
  if (canvas && (canvas.width !== width || canvas.height !== height)) fail();
  return Object.freeze({ sourceFormat: "webp", encoding: image.type === "VP8L" ? "lossless" : "lossy",
    width, height, sourceMode: alpha ? "RGBA" : "RGB", frames: 1 });
}

/** Internal container policy. It never claims that compressed pixels have loaded. */
export function inspectStaticRasterProfile(bytes) {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length === 0) fail("INVALID_INPUT");
    if (bytes.length > RASTER_LIMITS.maxInputBytes) fail("INPUT_TOO_LARGE");
    if (bytes.length >= 2 && bytes[0] === 255 && bytes[1] === 0xd8) return { kind: "profile", profile: jpeg(bytes) };
    if (bytes.length >= 12 && bytes.toString("latin1", 0, 4) === "RIFF" && bytes.toString("latin1", 8, 12) === "WEBP") return { kind: "profile", profile: webp(bytes) };
    return { kind: "rejected", code: "UNSUPPORTED_FORMAT" };
  } catch (error) {
    return { kind: "rejected", code: error instanceof ProfileFailure ? error.code : "MALFORMED_IMAGE" };
  }
}
