export type ScannedPdfError =
  | "INVALID_INPUT" | "INPUT_TOO_LARGE" | "INVALID_OPTIONS" | "INVALID_LIMIT"
  | "CANCELLED" | "TIMEOUT" | "QUEUE_FULL" | "DECODER_UNAVAILABLE"
  | "RUNTIME_MISMATCH" | "ISOLATION_UNAVAILABLE" | "DECODER_FAILURE"
  | "PROTOCOL_ERROR" | "OUTPUT_LIMIT" | "PAGE_LIMIT" | "DIMENSION_LIMIT"
  | "PIXEL_LIMIT" | "STRUCTURE_LIMIT" | "MALFORMED_PDF" | "UNSUPPORTED_PDF_FEATURE"
  | "ENCRYPTED_PDF" | "ACTIVE_CONTENT" | "REMOTE_RESOURCE" | "DAMAGED_IMAGE" | "INCOMPLETE_RENDER";
export interface ScannedPdfOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
}
export interface RasterPageObservation {
  readonly page: number;
  readonly sourceSha256: string;
  readonly width: number;
  readonly height: number;
  readonly pageWidthPoints: number;
  readonly pageHeightPoints: number;
  readonly byteLength: number;
  readonly sha256: string;
  readonly format: "rgba8";
  readonly colorSpace: "device-rgb";
  readonly coordinateSystem: "top-left-pixels";
  readonly stride: number;
  copyRgbaBytes(): Uint8Array;
}
export interface ScannedPdfEngine {
  readonly name: "PDFium";
  readonly version: "156.0.8076.0";
  readonly bindings: "pypdfium2@5.14.0";
}
export interface ScannedPdfDecoded {
  readonly kind: "decoded";
  readonly completeness: "incomplete-pixels-only";
  readonly requiresInspection: true;
  readonly sourceSha256: string;
  readonly profile: "classic-full-page-rgb-flate-v1";
  readonly engine: ScannedPdfEngine;
  readonly pages: readonly RasterPageObservation[];
  readonly totalRgbaBytes: number;
  readonly limits: Readonly<Record<string, number>>;
  readonly syscallPolicy: "linux-x86_64-preloaded-default-deny-v1";
  readonly enforcementControlsPassed: 8;
}
export interface ScannedPdfRejected {
  readonly kind: "rejected";
  readonly code: ScannedPdfError;
  readonly sourceSha256?: string;
  readonly profile: "classic-full-page-rgb-flate-v1";
  readonly engine: ScannedPdfEngine;
}
export const SCANNED_PDF_LIMITS: Readonly<Record<string, number>>;
export const SCANNED_PDF_ERRORS: readonly ScannedPdfError[];
export function readScannedPdf(input: Uint8Array, options?: ScannedPdfOptions): Promise<ScannedPdfDecoded | ScannedPdfRejected>;
