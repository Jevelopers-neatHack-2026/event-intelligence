import ocr from "../local-ocr/profile.json" with { type: "json" };
export { PNG_DECODER, PNG_LIMITS, PNG_ERROR_CODES } from "../png/constants.mjs";
export { RASTER_DECODER, RASTER_LIMITS, RASTER_ERROR_CODES } from "../jpeg-webp/constants.mjs";

export const PROFILE = "ei-private-static-image-ocr/1";
export const OCR_PROFILE = Object.freeze({ ...ocr });
export const OCR_ENGINE = Object.freeze({ name: "Tesseract", version: ocr.tesseractVersion, language: "eng",
  modelSha256: ocr.modelSha256, oem: 1, pageSegmentationMode: 6 });
export const OCR_LIMITS = Object.freeze(Object.fromEntries(Object.entries(ocr).filter(([key]) => key.startsWith("max") || key === "defaultTimeoutMs")));
export const STATIC_IMAGE_OCR_LIMITS = Object.freeze({
  maxInputBytes: 10 * 1024 * 1024,
  maxDimension: 4096,
  maxPixels: 4 * 1024 * 1024,
  maxPixelBytes: 16 * 1024 * 1024,
  maxWords: 2048,
  maxTextBytes: 32768,
  maxOutputBytes: 1024 * 1024,
  maxConcurrency: 1,
  maxQueued: 4,
  defaultTimeoutMs: 20000,
  maxTimeoutMs: 30000,
});
export const STATIC_IMAGE_OCR_ERRORS = Object.freeze([
  "INVALID_INPUT", "INPUT_TOO_LARGE", "UNSUPPORTED_FORMAT", "INVALID_OPTIONS", "INVALID_LIMIT",
  "CANCELLED", "TIMEOUT", "QUEUE_FULL", "IMAGE_REJECTED", "NON_OPAQUE_IMAGE", "OCR_REJECTED",
  "STAGE_PROTOCOL_ERROR", "STAGE_FAILURE", "OUTPUT_LIMIT",
]);
