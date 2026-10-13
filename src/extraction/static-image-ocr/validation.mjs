import { createHash } from "node:crypto";
import { types } from "node:util";
import { LOCAL_OCR_ERRORS } from "../local-ocr/index.mjs";
import { PNG_DECODER, PNG_LIMITS, PNG_ERROR_CODES, RASTER_DECODER, RASTER_LIMITS, RASTER_ERROR_CODES,
  OCR_ENGINE, OCR_PROFILE, OCR_LIMITS, STATIC_IMAGE_OCR_LIMITS as LIMITS } from "./profile.mjs";

const typed = Object.getPrototypeOf(Uint8Array.prototype);
const lengthOf = Object.getOwnPropertyDescriptor(typed, "byteLength").get;
const offsetOf = Object.getOwnPropertyDescriptor(typed, "byteOffset").get;
const backingOf = Object.getOwnPropertyDescriptor(typed, "buffer").get;
const backingLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
const copyInto = Uint8Array.prototype.set;
export const hash = (value) => createHash("sha256").update(value).digest("hex");
const hex = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const whole = (value, low, high) => Number.isInteger(value) && value >= low && value <= high;
const bad = () => { throw new TypeError("Private image stage failed its fixed boundary"); };

export function record(value, allowed, exact = true) {
  if (!value || typeof value !== "object" || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return undefined;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (exact && Reflect.ownKeys(descriptors).length !== allowed.length) return undefined;
  const result = Object.create(null);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (!allowed.includes(key) || !Object.hasOwn(descriptors[key], "value")) return undefined;
    result[key] = descriptors[key].value;
  }
  return result;
}

function array(value, maximum) {
  if (!Array.isArray(value) || types.isProxy(value)) return undefined;
  const length = Object.getOwnPropertyDescriptor(value, "length")?.value;
  if (!whole(length, 0, maximum)) return undefined;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== length + 1) return undefined;
  const result = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[index];
    if (!descriptor || !Object.hasOwn(descriptor, "value")) return undefined;
    result.push(descriptor.value);
  }
  return result;
}

function matches(value, expected) {
  const fields = record(value, Object.keys(expected));
  return !!fields && Object.entries(expected).every(([key, item]) => fields[key] === item);
}

export function snapshot(value, maximum = LIMITS.maxInputBytes) {
  if (!value || typeof value !== "object" || types.isProxy(value) ||
      ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(value))) return { error: "INVALID_INPUT" };
  try {
    const length = lengthOf.call(value);
    if (length === 0) return { error: "INVALID_INPUT" };
    if (length > maximum) return { error: "INPUT_TOO_LARGE" };
    const backing = backingOf.call(value);
    backingLength.call(backing); // Shared backing cannot establish stable source bytes.
    const bytes = Buffer.alloc(length);
    copyInto.call(bytes, new Uint8Array(backing, offsetOf.call(value), length));
    return { bytes, sha256: hash(bytes) };
  } catch { return { error: "INVALID_INPUT" }; }
}

/** Dispatch signature only; the fixed decoder must validate its full format. */
export function sourceFormat(bytes) {
  if (bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return "png";
  if (bytes.length >= 2 && bytes[0] === 255 && bytes[1] === 216) return "jpeg";
  if (bytes.length >= 12 && bytes.readUInt32BE(0) === 0x52494646 && bytes.readUInt32BE(8) === 0x57454250) return "webp";
  return undefined;
}

export function inspectImage(value, sourceSha256, format, options) {
  const png = format === "png";
  const engine = png ? PNG_DECODER : RASTER_DECODER;
  const limits = png ? PNG_LIMITS : RASTER_LIMITS;
  const errors = png ? PNG_ERROR_CODES : RASTER_ERROR_CODES;
  const common = ["kind", "completeness", "requiresInspection", "sourceSha256", "decoder", "limits", "width", "height",
    "outputColorType", "decodedRgbaBytes", "rgbaSha256", "normalizedSha256", "normalizedByteLength",
    "networkApiAttemptCount", "copyNormalizedBytes", "copyRgbaBytes"];
  const specific = png ? ["sourceColorType"] : ["runtimeManifestSha256", "sourceFormat", "encoding", "sourceMode", "frames"];
  const kind = record(value, [...common, ...specific, "code"], false)?.kind;
  if (kind === "rejected") {
    const refusal = record(value, ["kind", "code", "sourceSha256", "decoder"]);
    if (!refusal || !errors.includes(refusal.code) || !matches(refusal.decoder, engine) ||
        (refusal.sourceSha256 !== undefined && refusal.sourceSha256 !== sourceSha256)) bad();
    return { rejected: refusal.code };
  }
  const result = record(value, [...common, ...specific]);
  if (!result || result.kind !== "decoded" || result.completeness !== "incomplete-pixels-only" || result.requiresInspection !== true ||
      result.sourceSha256 !== sourceSha256 || !matches(result.decoder, engine) ||
      !matches(result.limits, { ...limits, timeoutMs: options.timeoutMs, maxOutputBytes: options.maxOutputBytes }) ||
      !whole(result.width, 1, LIMITS.maxDimension) || !whole(result.height, 1, LIMITS.maxDimension) ||
      result.width * result.height > LIMITS.maxPixels || result.decodedRgbaBytes !== result.width * result.height * 4 ||
      result.decodedRgbaBytes > LIMITS.maxPixelBytes || result.outputColorType !== 6 ||
      !hex(result.rgbaSha256) || !hex(result.normalizedSha256) ||
      !whole(result.normalizedByteLength, 1, options.maxOutputBytes) || result.networkApiAttemptCount !== 0 ||
      typeof result.copyRgbaBytes !== "function" || types.isProxy(result.copyRgbaBytes) ||
      typeof result.copyNormalizedBytes !== "function" || types.isProxy(result.copyNormalizedBytes)) bad();
  if (png) {
    if (![2, 6].includes(result.sourceColorType)) bad();
  } else if (!hex(result.runtimeManifestSha256) || result.frames !== 1 || result.sourceFormat !== format ||
      !["L", "RGB", "RGBA"].includes(result.sourceMode) ||
      (format === "jpeg" && (!["baseline", "progressive"].includes(result.encoding) || result.sourceMode === "RGBA")) ||
      (format === "webp" && (!["lossy", "lossless"].includes(result.encoding) || result.sourceMode === "L"))) bad();
  return { receiver: value, copyRgbaBytes: result.copyRgbaBytes, decoder: engine,
    image: Object.freeze({ sourceFormat: format, encoding: png ? (result.sourceColorType === 2 ? "rgb8" : "rgba8") : result.encoding,
      sourceMode: png ? (result.sourceColorType === 2 ? "RGB" : "RGBA") : result.sourceMode,
      width: result.width, height: result.height, pixelByteLength: result.decodedRgbaBytes, rgbaSha256: result.rgbaSha256,
      normalizedSha256: result.normalizedSha256, normalizedByteLength: result.normalizedByteLength,
      ...(png ? {} : { runtimeManifestSha256: result.runtimeManifestSha256 }) }) };
}

export function copyImage(checked) {
  const value = Reflect.apply(checked.copyRgbaBytes, checked.receiver, []);
  const copied = snapshot(value, LIMITS.maxPixelBytes);
  if (copied.error || copied.bytes.length !== checked.image.pixelByteLength || copied.sha256 !== checked.image.rgbaSha256) bad();
  // No assumed background, flattening, hidden-pixel removal or native OCR alpha interpretation.
  for (let index = 3; index < copied.bytes.length; index += 4) {
    if (copied.bytes[index] !== 255) return { error: "NON_OPAQUE_IMAGE" };
  }
  return { bytes: copied.bytes };
}

export function inspectOcr(value, sourceSha256, image, options) {
  const expected = { sourceSha256, page: 1, derivativeSha256: image.rgbaSha256, width: image.width, height: image.height,
    format: "rgba8", coordinateSystem: "top-left-pixels", sourceBinding: "caller-supplied-unverified" };
  const fields = ["kind", "status", "completeness", "requiresReview", "profile", "engine", "provenance", "words",
    "tokenUtf8Bytes", "syscallPolicy", "enforcementControlsPassed", "limits"];
  const kind = record(value, [...fields, "code"], false)?.kind;
  if (kind === "rejected") {
    const refusal = record(value, ["kind", "code", "provenance", "profile", "engine"]);
    if (!refusal || !LOCAL_OCR_ERRORS.includes(refusal.code) || refusal.profile !== OCR_PROFILE.profile ||
        !matches(refusal.engine, OCR_ENGINE) || (refusal.provenance !== undefined && !matches(refusal.provenance, expected))) bad();
    return { rejected: refusal.code };
  }
  const result = record(value, fields);
  if (!result || result.kind !== "observed" || result.completeness !== "incomplete-unverified-ocr" || result.requiresReview !== true ||
      result.profile !== OCR_PROFILE.profile || !matches(result.engine, OCR_ENGINE) || !matches(result.provenance, expected) ||
      result.syscallPolicy !== OCR_PROFILE.syscallPolicy || result.enforcementControlsPassed !== 8 ||
      !matches(result.limits, { ...OCR_LIMITS, timeoutMs: options.timeoutMs, maxWords: options.maxWords, maxTextBytes: options.maxTextBytes })) bad();
  const rawWords = array(result.words, options.maxWords);
  if (!rawWords || result.status !== (rawWords.length ? "text-observations" : "no-text-observed")) bad();
  const provenance = Object.freeze(expected);
  let tokenUtf8Bytes = 0;
  let previous = [0, 0, 0, 0];
  const words = rawWords.map((raw) => {
    const word = record(raw, ["text", "confidence", "block", "paragraph", "line", "word", "box", "provenance", "confidenceMeaning", "requiresReview"]);
    if (!word || typeof word.text !== "string" || !word.text.length || word.text.length > options.maxTextBytes ||
        !word.text.isWellFormed() || /[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/u.test(word.text) ||
        !Number.isFinite(word.confidence) || word.confidence < 0 || word.confidence > 100 ||
        word.confidenceMeaning !== "uncalibrated-engine-score" || word.requiresReview !== true || !matches(word.provenance, expected)) bad();
    const identity = [word.block, word.paragraph, word.line, word.word];
    if (!identity.every((part) => whole(part, 1, OCR_PROFILE.maxWords))) bad();
    let comparison = 0;
    for (let index = 0; index < 4; index += 1) if (identity[index] !== previous[index]) {
      comparison = identity[index] - previous[index]; break;
    }
    if (comparison <= 0) bad();
    previous = identity;
    const box = record(word.box, ["left", "top", "width", "height"]);
    if (!box || !whole(box.left, 0, image.width - 1) || !whole(box.top, 0, image.height - 1) ||
        !whole(box.width, 1, image.width - box.left) || !whole(box.height, 1, image.height - box.top)) bad();
    tokenUtf8Bytes += Buffer.byteLength(word.text, "utf8");
    if (tokenUtf8Bytes > options.maxTextBytes) bad();
    return Object.freeze({ text: word.text, confidence: word.confidence, confidenceMeaning: "uncalibrated-engine-score", requiresReview: true,
      block: word.block, paragraph: word.paragraph, line: word.line, word: word.word, box: Object.freeze({ ...box }), provenance });
  });
  if (result.tokenUtf8Bytes !== tokenUtf8Bytes) bad();
  return { status: result.status, provenance, words: Object.freeze(words), tokenUtf8Bytes };
}
