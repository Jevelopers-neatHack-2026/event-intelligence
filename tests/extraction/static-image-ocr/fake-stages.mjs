// Deliberately synthetic stage responses; separate reader tests execute real native stages.
import { PNG_DECODER, PNG_LIMITS, RASTER_DECODER, RASTER_LIMITS, OCR_ENGINE, OCR_PROFILE, OCR_LIMITS } from "../../../src/extraction/static-image-ocr/profile.mjs";
import { hash, encodedPng } from "./fixtures.mjs";
export { hash };
export const source = () => encodedPng({ blank: true }).bytes;
export const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export function fakeImage(bytes, options, format = "png") {
  const pixels = Buffer.alloc(40 * 20 * 4, 255);
  const normalized = source();
  return { kind: "decoded", completeness: "incomplete-pixels-only", requiresInspection: true, sourceSha256: hash(bytes),
    decoder: { ...(format === "png" ? PNG_DECODER : RASTER_DECODER) },
    limits: { ...(format === "png" ? PNG_LIMITS : RASTER_LIMITS), timeoutMs: options.timeoutMs, maxOutputBytes: options.maxOutputBytes },
    width: 40, height: 20, outputColorType: 6, decodedRgbaBytes: pixels.length, rgbaSha256: hash(pixels),
    normalizedSha256: hash(normalized), normalizedByteLength: normalized.length, networkApiAttemptCount: 0,
    copyNormalizedBytes() { return new Uint8Array(normalized); }, copyRgbaBytes() { return new Uint8Array(pixels); },
    ...(format === "png" ? { sourceColorType: 6 } : { runtimeManifestSha256: "1".repeat(64), sourceFormat: format,
      encoding: format === "jpeg" ? "baseline" : "lossless", sourceMode: "RGB", frames: 1 }) };
}
export function fakeOcr(input, options, text = "UNCERTAIN") {
  const provenance = { sourceSha256: input.source.sha256, page: input.source.page, derivativeSha256: input.source.derivativeSha256,
    width: input.width, height: input.height, format: "rgba8", coordinateSystem: "top-left-pixels", sourceBinding: "caller-supplied-unverified" };
  const words = text === null ? [] : [{ text, confidence: 0, block: 1, paragraph: 1, line: 1, word: 1,
    box: { left: 1, top: 1, width: 8, height: 8 }, provenance: { ...provenance },
    confidenceMeaning: "uncalibrated-engine-score", requiresReview: true }];
  return { kind: "observed", status: words.length ? "text-observations" : "no-text-observed",
    completeness: "incomplete-unverified-ocr", requiresReview: true, profile: OCR_PROFILE.profile, engine: { ...OCR_ENGINE },
    provenance, words, tokenUtf8Bytes: text === null ? 0 : Buffer.byteLength(text),
    syscallPolicy: OCR_PROFILE.syscallPolicy, enforcementControlsPassed: 8,
    limits: { ...OCR_LIMITS, timeoutMs: options.timeoutMs, maxWords: options.maxWords, maxTextBytes: options.maxTextBytes } };
}
