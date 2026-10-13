export type LocalOcrError =
  | "INVALID_INPUT" | "INVALID_PROVENANCE" | "INPUT_TOO_LARGE" | "DIMENSION_LIMIT" | "PIXEL_LIMIT" | "UNSUPPORTED_RASTER"
  | "INVALID_OPTIONS" | "INVALID_LIMIT" | "CANCELLED" | "TIMEOUT" | "QUEUE_FULL" | "OCR_UNAVAILABLE" | "RUNTIME_MISMATCH"
  | "MODEL_UNAVAILABLE" | "ISOLATION_UNAVAILABLE" | "OCR_FAILURE" | "PROTOCOL_ERROR" | "OUTPUT_LIMIT" | "INVALID_OCR_OUTPUT";
export interface LocalOcrInput {
  readonly bytes: Uint8Array;
  readonly width: number;
  readonly height: number;
  readonly format: "gray8" | "rgba8";
  /** Caller-supplied origin is a correlation claim, not retrieval or disclosure authority. */
  readonly source: { readonly sha256: string; readonly page: number; readonly derivativeSha256: string };
}
export interface LocalOcrOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  /** Lower-only absolute deadline in this Node process's performance.now() timebase. */
  readonly deadlineAtMs?: number;
  readonly maxTextBytes?: number;
  readonly maxWords?: number;
}
export interface OcrProvenance {
  readonly sourceSha256: string;
  readonly derivativeSha256: string;
  readonly page: number;
  readonly width: number;
  readonly height: number;
  readonly format: "gray8" | "rgba8";
  readonly coordinateSystem: "top-left-pixels";
  readonly sourceBinding: "caller-supplied-unverified";
}
export interface OcrWordObservation {
  readonly text: string;
  readonly confidence: number;
  readonly confidenceMeaning: "uncalibrated-engine-score";
  readonly requiresReview: true;
  readonly block: number;
  readonly paragraph: number;
  readonly line: number;
  readonly word: number;
  readonly box: Readonly<{ left: number; top: number; width: number; height: number }>;
  readonly provenance: OcrProvenance;
}
export interface OcrEngine {
  readonly name: "Tesseract";
  readonly version: "5.3.4";
  readonly language: "eng";
  readonly modelSha256: string;
  readonly oem: 1;
  readonly pageSegmentationMode: 6;
}
export type LocalOcrResult = Readonly<{
  kind: "observed";
  status: "text-observations" | "no-text-observed";
  completeness: "incomplete-unverified-ocr";
  requiresReview: true;
  profile: "english-lstm-single-block-raster-v1";
  engine: OcrEngine;
  provenance: OcrProvenance;
  words: readonly OcrWordObservation[];
  tokenUtf8Bytes: number;
  syscallPolicy: "linux-x86_64-single-thread-ocr-default-deny-v1";
  enforcementControlsPassed: 8;
  limits: Readonly<Record<string, number>>;
}> | Readonly<{
  kind: "rejected";
  code: LocalOcrError;
  provenance?: OcrProvenance;
  profile: "english-lstm-single-block-raster-v1";
  engine: OcrEngine;
}>;
export const LOCAL_OCR_ERRORS: readonly LocalOcrError[];
export const LOCAL_OCR_LIMITS: Readonly<Record<string, number>>;
/** Private local OCR observations; absent from the package export map. */
export function readLocalOcr(input: LocalOcrInput, options?: LocalOcrOptions): Promise<LocalOcrResult>;
