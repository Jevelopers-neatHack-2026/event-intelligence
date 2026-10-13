// Deliberately synthetic stage responses. Native caller tests use the real modules.
import { createHash } from "node:crypto";
import { PDF_PROFILE, PDF_ENGINE, PDF_LIMITS, OCR_PROFILE, OCR_ENGINE, OCR_LIMITS } from "../../../src/extraction/scanned-pdf-ocr/profile.mjs";
export const hash = (value) => createHash("sha256").update(value).digest("hex");
export const source = () => Buffer.from("synthetic stage protocol source; not a PDF");
export const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export function fakePdf(bytes, options, count = 2) {
  const sourceSha256 = hash(bytes);
  const pixels = Buffer.alloc(40 * 20 * 4, 255);
  return { kind: "decoded", completeness: "incomplete-pixels-only", requiresInspection: true, sourceSha256,
    profile: PDF_PROFILE.profile, engine: { ...PDF_ENGINE }, totalRgbaBytes: pixels.length * count,
    limits: { ...PDF_LIMITS, timeoutMs: options.timeoutMs, maxOutputBytes: options.maxOutputBytes },
    syscallPolicy: PDF_PROFILE.syscallPolicy, enforcementControlsPassed: 8,
    pages: Array.from({ length: count }, (_, index) => ({ page: index + 1, width: 40, height: 20,
      pageWidthPoints: 40, pageHeightPoints: 20, byteLength: pixels.length, sha256: hash(pixels), sourceSha256,
      format: "rgba8", colorSpace: "device-rgb", coordinateSystem: "top-left-pixels", stride: 160,
      copyRgbaBytes() { return new Uint8Array(pixels); } })) };
}
export function fakeOcr(input, options, text = "UNKNOWN") {
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
