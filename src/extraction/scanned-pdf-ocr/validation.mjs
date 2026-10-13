import { createHash } from "node:crypto";
import { types } from "node:util";
import { SCANNED_PDF_ERRORS } from "../scanned-pdf/index.mjs";
import { LOCAL_OCR_ERRORS } from "../local-ocr/index.mjs";
import { PDF_ENGINE, PDF_PROFILE, PDF_LIMITS, OCR_ENGINE, OCR_PROFILE, OCR_LIMITS, SCANNED_PDF_OCR_LIMITS as LIMITS } from "./profile.mjs";

const typed = Object.getPrototypeOf(Uint8Array.prototype);
const lengthOf = Object.getOwnPropertyDescriptor(typed, "byteLength").get;
const offsetOf = Object.getOwnPropertyDescriptor(typed, "byteOffset").get;
const backingOf = Object.getOwnPropertyDescriptor(typed, "buffer").get;
const backingLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
const copyInto = Uint8Array.prototype.set;
export const hash = (value) => createHash("sha256").update(value).digest("hex");
const hex = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const whole = (value, minimum, maximum) => Number.isInteger(value) && value >= minimum && value <= maximum;
const bad = () => { throw new TypeError("Private stage result failed its fixed boundary"); };

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
    backingLength.call(backing); // Shared backing cannot supply a stable byte chain.
    const bytes = Buffer.alloc(length);
    copyInto.call(bytes, new Uint8Array(backing, offsetOf.call(value), length));
    return { bytes, sha256: hash(bytes) };
  } catch { return { error: "INVALID_INPUT" }; }
}

export function inspectPdf(value, sourceSha256, options) {
  const kind = record(value, ["kind", "code", "sourceSha256", "profile", "engine", "completeness", "requiresInspection",
    "pages", "totalRgbaBytes", "limits", "syscallPolicy", "enforcementControlsPassed"], false)?.kind;
  if (kind === "rejected") {
    const refusal = record(value, ["kind", "code", "sourceSha256", "profile", "engine"]);
    if (!refusal || !SCANNED_PDF_ERRORS.includes(refusal.code) || refusal.profile !== PDF_PROFILE.profile ||
        !matches(refusal.engine, PDF_ENGINE) || (refusal.sourceSha256 !== undefined && refusal.sourceSha256 !== sourceSha256)) bad();
    return { rejected: refusal.code };
  }
  const result = record(value, ["kind", "completeness", "requiresInspection", "sourceSha256", "profile", "engine", "pages",
    "totalRgbaBytes", "limits", "syscallPolicy", "enforcementControlsPassed"]);
  if (!result || result.kind !== "decoded" || result.completeness !== "incomplete-pixels-only" || result.requiresInspection !== true ||
      result.sourceSha256 !== sourceSha256 || result.profile !== PDF_PROFILE.profile || !matches(result.engine, PDF_ENGINE) ||
      result.syscallPolicy !== PDF_PROFILE.syscallPolicy || result.enforcementControlsPassed !== 8 ||
      !matches(result.limits, { ...PDF_LIMITS, timeoutMs: options.timeoutMs, maxOutputBytes: options.maxOutputBytes })) bad();
  const rawPages = array(result.pages, LIMITS.maxPages);
  if (!rawPages || !rawPages.length) bad();
  let totalPixels = 0;
  const pages = rawPages.map((raw, index) => {
    const page = record(raw, ["page", "width", "height", "pageWidthPoints", "pageHeightPoints", "byteLength", "sha256",
      "sourceSha256", "format", "colorSpace", "coordinateSystem", "stride", "copyRgbaBytes"]);
    if (!page || page.page !== index + 1 || page.sourceSha256 !== sourceSha256 || !hex(page.sha256) ||
        !whole(page.width, 1, LIMITS.maxDimension) || !whole(page.height, 1, LIMITS.maxDimension) ||
        !Number.isFinite(page.pageWidthPoints) || !Number.isFinite(page.pageHeightPoints) ||
        page.pageWidthPoints <= 0 || page.pageHeightPoints <= 0 ||
        page.pageWidthPoints > PDF_PROFILE.maxPagePoints || page.pageHeightPoints > PDF_PROFILE.maxPagePoints ||
        page.format !== "rgba8" || page.colorSpace !== "device-rgb" || page.coordinateSystem !== "top-left-pixels" ||
        page.stride !== page.width * 4 || page.byteLength !== page.width * page.height * 4 ||
        typeof page.copyRgbaBytes !== "function" || types.isProxy(page.copyRgbaBytes)) bad();
    totalPixels += page.width * page.height;
    if (totalPixels > LIMITS.maxTotalPixels) bad();
    return { ...page, receiver: raw };
  });
  if (result.totalRgbaBytes !== totalPixels * 4 || result.totalRgbaBytes > LIMITS.maxPixelBytes) bad();
  return { pages, totalPixels };
}

export function copyPage(page) {
  const value = Reflect.apply(page.copyRgbaBytes, page.receiver, []);
  const copied = snapshot(value, LIMITS.maxPixelBytes);
  if (copied.error || copied.bytes.length !== page.byteLength || copied.sha256 !== page.sha256) bad();
  for (let index = 3; index < copied.bytes.length; index += 4) if (copied.bytes[index] !== 255) bad();
  return copied.bytes;
}

export function inspectOcr(value, sourceSha256, page, options) {
  const expectedProvenance = { sourceSha256, page: page.page, derivativeSha256: page.sha256, width: page.width, height: page.height,
    format: "rgba8", coordinateSystem: "top-left-pixels", sourceBinding: "caller-supplied-unverified" };
  const kind = record(value, ["kind", "code", "provenance", "profile", "engine", "status", "completeness", "requiresReview",
    "words", "tokenUtf8Bytes", "syscallPolicy", "enforcementControlsPassed", "limits"], false)?.kind;
  if (kind === "rejected") {
    const refusal = record(value, ["kind", "code", "provenance", "profile", "engine"]);
    if (!refusal || !LOCAL_OCR_ERRORS.includes(refusal.code) || refusal.profile !== OCR_PROFILE.profile ||
        !matches(refusal.engine, OCR_ENGINE) || (refusal.provenance !== undefined && !matches(refusal.provenance, expectedProvenance))) bad();
    return { rejected: refusal.code };
  }
  const result = record(value, ["kind", "status", "completeness", "requiresReview", "profile", "engine", "provenance", "words",
    "tokenUtf8Bytes", "syscallPolicy", "enforcementControlsPassed", "limits"]);
  if (!result || result.kind !== "observed" || result.completeness !== "incomplete-unverified-ocr" || result.requiresReview !== true ||
      result.profile !== OCR_PROFILE.profile || !matches(result.engine, OCR_ENGINE) || !matches(result.provenance, expectedProvenance) ||
      result.syscallPolicy !== OCR_PROFILE.syscallPolicy || result.enforcementControlsPassed !== 8 ||
      !matches(result.limits, { ...OCR_LIMITS, timeoutMs: options.timeoutMs, maxWords: options.maxWords, maxTextBytes: options.maxTextBytes })) bad();
  const rawWords = array(result.words, options.maxWords);
  if (!rawWords || result.status !== (rawWords.length ? "text-observations" : "no-text-observed")) bad();
  const provenance = Object.freeze(expectedProvenance);
  let tokenUtf8Bytes = 0;
  let previous = [0, 0, 0, 0];
  const words = rawWords.map((raw) => {
    const word = record(raw, ["text", "confidence", "block", "paragraph", "line", "word", "box", "provenance", "confidenceMeaning", "requiresReview"]);
    if (!word || typeof word.text !== "string" || !word.text.length || word.text.length > options.maxTextBytes ||
        !word.text.isWellFormed() || /[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/u.test(word.text) ||
        !Number.isFinite(word.confidence) || word.confidence < 0 || word.confidence > 100 ||
        word.confidenceMeaning !== "uncalibrated-engine-score" || word.requiresReview !== true ||
        !matches(word.provenance, expectedProvenance)) bad();
    const identity = [word.block, word.paragraph, word.line, word.word];
    if (!identity.every((part) => whole(part, 1, OCR_PROFILE.maxWords))) bad();
    let comparison = 0;
    for (let index = 0; index < 4; index += 1) if (identity[index] !== previous[index]) {
      comparison = identity[index] - previous[index]; break;
    }
    if (comparison <= 0) bad();
    previous = identity;
    const box = record(word.box, ["left", "top", "width", "height"]);
    if (!box || !whole(box.left, 0, page.width - 1) || !whole(box.top, 0, page.height - 1) ||
        !whole(box.width, 1, page.width - box.left) || !whole(box.height, 1, page.height - box.top)) bad();
    tokenUtf8Bytes += Buffer.byteLength(word.text, "utf8");
    if (tokenUtf8Bytes > options.maxTextBytes) bad();
    return Object.freeze({ text: word.text, confidence: word.confidence, confidenceMeaning: "uncalibrated-engine-score", requiresReview: true,
      block: word.block, paragraph: word.paragraph, line: word.line, word: word.word, box: Object.freeze({ ...box }), provenance });
  });
  if (result.tokenUtf8Bytes !== tokenUtf8Bytes) bad();
  return Object.freeze({ page: page.page, sourceSha256, derivativeSha256: page.sha256, width: page.width, height: page.height,
    pageWidthPoints: page.pageWidthPoints, pageHeightPoints: page.pageHeightPoints, pixelByteLength: page.byteLength,
    format: "rgba8", coordinateSystem: "top-left-pixels", status: result.status,
    provenance, words: Object.freeze(words), tokenUtf8Bytes });
}
