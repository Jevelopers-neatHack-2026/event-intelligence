import pdf from "../scanned-pdf/profile.json" with { type: "json" };
import ocr from "../local-ocr/profile.json" with { type: "json" };

export const PROFILE = "ei-private-scanned-pdf-ocr/1";
export const PDF_PROFILE = Object.freeze({ ...pdf });
export const OCR_PROFILE = Object.freeze({ ...ocr });
export const PDF_ENGINE = Object.freeze({ name: "PDFium", version: pdf.pdfiumVersion, bindings: "pypdfium2@" + pdf.wrapperVersion });
export const OCR_ENGINE = Object.freeze({ name: "Tesseract", version: ocr.tesseractVersion, language: "eng",
  modelSha256: ocr.modelSha256, oem: 1, pageSegmentationMode: 6 });
export const PDF_LIMITS = Object.freeze(Object.fromEntries(Object.entries(pdf).filter(([key]) => key.startsWith("max") || key === "defaultTimeoutMs")));
export const OCR_LIMITS = Object.freeze(Object.fromEntries(Object.entries(ocr).filter(([key]) => key.startsWith("max") || key === "defaultTimeoutMs")));
export const SCANNED_PDF_OCR_LIMITS = Object.freeze({
  maxInputBytes: 16 * 1024 * 1024,
  maxPages: 4,
  maxDimension: 4096,
  maxTotalPixels: 4 * 1024 * 1024,
  maxPixelBytes: 16 * 1024 * 1024,
  maxWords: 2048,
  maxTextBytes: 32768,
  maxOutputBytes: 1024 * 1024,
  maxConcurrency: 1,
  maxQueued: 4,
  defaultTimeoutMs: 20000,
  maxTimeoutMs: 30000,
});
export const SCANNED_PDF_OCR_ERRORS = Object.freeze([
  "INVALID_INPUT", "INPUT_TOO_LARGE", "INVALID_OPTIONS", "INVALID_LIMIT", "CANCELLED", "TIMEOUT", "QUEUE_FULL",
  "PDF_REJECTED", "OCR_REJECTED", "STAGE_PROTOCOL_ERROR", "STAGE_FAILURE", "OUTPUT_LIMIT",
]);
