import { readScannedPdf } from "../scanned-pdf/index.mjs";
import { readLocalOcr } from "../local-ocr/index.mjs";
import { createScannedPdfOcrReader } from "./reader.mjs";
export { SCANNED_PDF_OCR_LIMITS, SCANNED_PDF_OCR_ERRORS } from "./profile.mjs";
export const readScannedPdfOcr = createScannedPdfOcrReader({ readPdf: readScannedPdf, readOcr: readLocalOcr });
