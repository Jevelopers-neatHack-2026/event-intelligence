import type { StaticPngDecoded, StaticPngErrorCode } from "../png/index.mjs";
import type { StaticJpegWebpDecoded, StaticJpegWebpErrorCode } from "../jpeg-webp/index.mjs";
import type { OcrEngine, OcrProvenance, OcrWordObservation, LocalOcrError } from "../local-ocr/index.mjs";

export type StaticImageOcrError =
  | "INVALID_INPUT" | "INPUT_TOO_LARGE" | "UNSUPPORTED_FORMAT" | "INVALID_OPTIONS" | "INVALID_LIMIT"
  | "CANCELLED" | "TIMEOUT" | "QUEUE_FULL" | "IMAGE_REJECTED" | "NON_OPAQUE_IMAGE" | "OCR_REJECTED"
  | "STAGE_PROTOCOL_ERROR" | "STAGE_FAILURE" | "OUTPUT_LIMIT";
export interface StaticImageOcrOptions {
  readonly signal?: AbortSignal;
  /** One original process-monotonic budget across admission, both children and final delivery. */
  readonly timeoutMs?: number;
  readonly maxWords?: number;
  readonly maxTextBytes?: number;
  /** Cap on the serialized observation report; decoder normalized-image caps stay unchanged. */
  readonly maxOutputBytes?: number;
}
export interface StaticImageOcrLimits {
  readonly maxInputBytes: number;
  readonly maxDimension: number;
  readonly maxPixels: number;
  readonly maxPixelBytes: number;
  readonly maxWords: number;
  readonly maxTextBytes: number;
  readonly maxOutputBytes: number;
  readonly maxConcurrency: 1;
  readonly maxQueued: 4;
  readonly defaultTimeoutMs: number;
  readonly maxTimeoutMs: number;
}
export interface StaticImagePixelEvidence {
  readonly sourceFormat: "png" | "jpeg" | "webp";
  readonly encoding: "rgb8" | "rgba8" | "baseline" | "progressive" | "lossy" | "lossless";
  readonly sourceMode: "L" | "RGB" | "RGBA";
  readonly width: number;
  readonly height: number;
  readonly pixelByteLength: number;
  readonly rgbaSha256: string;
  readonly normalizedSha256: string;
  readonly normalizedByteLength: number;
  /** Present for the explicit JPEG/WebP runtime; not a host or source authority claim. */
  readonly runtimeManifestSha256?: string;
}
export type StaticImageOcrResult = Readonly<{
  kind: "observed";
  profile: "ei-private-static-image-ocr/1";
  status: "text-observations" | "no-text-observed";
  completeness: "incomplete-unverified-ocr";
  requiresReview: true;
  sourceSha256: string;
  sourceBinding: "local-static-image-reader-byte-chain";
  sourceAuthority: "unverified";
  image: StaticImagePixelEvidence;
  decoder: (StaticPngDecoded["decoder"] | StaticJpegWebpDecoded["decoder"]) & Readonly<{ networkPolicy: "cooperative-api-guard-only" }>;
  observer: OcrEngine & Readonly<{
    profile: "english-lstm-single-block-raster-v1";
    syscallPolicy: "linux-x86_64-single-thread-ocr-default-deny-v1";
    enforcementControlsPassed: 8;
  }>;
  provenance: OcrProvenance & Readonly<{ page: 1; format: "rgba8" }>;
  words: readonly OcrWordObservation[];
  tokenUtf8Bytes: number;
  limits: StaticImageOcrLimits & Readonly<{ timeoutMs: number }>;
}> | Readonly<{
  kind: "rejected";
  profile: "ei-private-static-image-ocr/1";
  code: StaticImageOcrError;
  sourceSha256?: string;
  stage?: "admission" | "decode" | "pixels" | "ocr" | "aggregate";
  componentCode?: StaticPngErrorCode | StaticJpegWebpErrorCode | LocalOcrError;
}>;
export interface StaticImageOcrReader {
  /** Copies encoded input; no caller decoder output, URL fetch or arbitrary OCR callback is accepted. */
  readonly read: (input: Uint8Array, options?: StaticImageOcrOptions) => Promise<StaticImageOcrResult>;
}
/** The trusted host selects the exact offline-installed JPEG/WebP runtime. All factories share admission. */
export function createStaticImageOcrReader(configuration: { readonly runtimeDirectory: string }): StaticImageOcrReader;
export const STATIC_IMAGE_OCR_LIMITS: StaticImageOcrLimits;
export const STATIC_IMAGE_OCR_ERRORS: readonly StaticImageOcrError[];
