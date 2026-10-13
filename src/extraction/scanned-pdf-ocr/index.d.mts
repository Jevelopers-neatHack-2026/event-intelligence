import type { OcrWordObservation, OcrProvenance, OcrEngine } from "../local-ocr/index.mjs";
import type { ScannedPdfEngine } from "../scanned-pdf/index.mjs";
export type ScannedPdfOcrError = "INVALID_INPUT" | "INPUT_TOO_LARGE" | "INVALID_OPTIONS" | "INVALID_LIMIT" |
  "CANCELLED" | "TIMEOUT" | "QUEUE_FULL" | "PDF_REJECTED" | "OCR_REJECTED" | "STAGE_PROTOCOL_ERROR" | "STAGE_FAILURE" | "OUTPUT_LIMIT";
export interface ScannedPdfOcrOptions {
  readonly signal?: AbortSignal;
  /** One original monotonic allowance covering the entire source-to-words operation. */
  readonly timeoutMs?: number;
  /** Aggregate budgets across every supported PDF page; lower-only. */
  readonly maxWords?: number;
  readonly maxTextBytes?: number;
  readonly maxOutputBytes?: number;
}
export interface ScannedPdfOcrPage {
  readonly page: number;
  readonly sourceSha256: string;
  readonly derivativeSha256: string;
  readonly width: number;
  readonly height: number;
  readonly pageWidthPoints: number;
  readonly pageHeightPoints: number;
  readonly pixelByteLength: number;
  readonly format: "rgba8";
  readonly coordinateSystem: "top-left-pixels";
  readonly status: "text-observations" | "no-text-observed";
  readonly provenance: OcrProvenance;
  readonly words: readonly OcrWordObservation[];
  readonly tokenUtf8Bytes: number;
}
export interface ScannedPdfOcrObserved {
  readonly kind: "observed";
  readonly profile: "ei-private-scanned-pdf-ocr/1";
  readonly completeness: "incomplete-unverified-ocr";
  readonly requiresReview: true;
  readonly sourceSha256: string;
  readonly sourceBinding: "local-pdf-reader-byte-chain";
  readonly sourceAuthority: "unverified";
  readonly decoder: ScannedPdfEngine & Readonly<{ profile: "classic-full-page-rgb-flate-v1"; syscallPolicy: "linux-x86_64-preloaded-default-deny-v1"; enforcementControlsPassed: 8 }>;
  readonly observer: OcrEngine & Readonly<{ profile: "english-lstm-single-block-raster-v1"; syscallPolicy: "linux-x86_64-single-thread-ocr-default-deny-v1"; enforcementControlsPassed: 8 }>;
  readonly pages: readonly ScannedPdfOcrPage[];
  readonly totalPages: number;
  readonly totalPixels: number;
  readonly totalWords: number;
  readonly tokenUtf8Bytes: number;
  readonly limits: Readonly<Record<string, number>>;
}
export interface ScannedPdfOcrRejected {
  readonly kind: "rejected";
  readonly profile: "ei-private-scanned-pdf-ocr/1";
  readonly code: ScannedPdfOcrError;
  readonly sourceSha256?: string;
  readonly stage?: "admission" | "render" | "pixels" | "ocr" | "aggregate";
  readonly page?: number;
  readonly componentCode?: string;
}
export const SCANNED_PDF_OCR_LIMITS: Readonly<Record<string, number>>;
export const SCANNED_PDF_OCR_ERRORS: readonly ScannedPdfOcrError[];
/** Private byte-only composition; no URL, package export, provider call or accepted facts. */
export function readScannedPdfOcr(input: Uint8Array, options?: ScannedPdfOcrOptions): Promise<ScannedPdfOcrObserved | ScannedPdfOcrRejected>;
