export type StaticPngErrorCode =
  | "INVALID_INPUT" | "INVALID_OPTIONS" | "INVALID_LIMIT" | "INPUT_TOO_LARGE"
  | "MALFORMED_PNG" | "UNSUPPORTED_PNG_FEATURE" | "DIMENSION_LIMIT"
  | "RESOURCE_LIMIT" | "OUTPUT_LIMIT" | "CANCELLED" | "TIMEOUT" | "QUEUE_FULL"
  | "ISOLATION_UNAVAILABLE" | "DECODER_UNAVAILABLE" | "DECODER_FAILURE"
  | "PROTOCOL_ERROR" | "REMOTE_RESOURCE_ATTEMPT";

export interface StaticPngReaderLimits {
  readonly maxInputBytes: number;
  readonly maxDimension: number;
  readonly maxPixels: number;
  readonly maxRows: number;
  readonly maxInflatedBytes: number;
  readonly maxRgbaBytes: number;
  readonly maxOutputBytes: number;
  readonly maxChunks: number;
  readonly maxHeaderBytes: number;
  readonly maxAddressSpaceBytes: number;
  readonly maxCpuSeconds: number;
  readonly maxOpenFiles: number;
  readonly maxHeapMiB: number;
  readonly defaultTimeoutMs: number;
  readonly maxTimeoutMs: number;
  readonly maxConcurrency: number;
  readonly maxQueued: number;
}

interface StaticPngBase {
  readonly sourceSha256?: string;
  readonly decoder: {
    readonly name: "node-zlib-static-png";
    readonly nodeVersion: "22.23.3";
    readonly zlibVersion: "1.3.1-e00f703";
    readonly configVersion: "ei-static-png/1";
  };
}

export interface StaticPngDecoded extends StaticPngBase {
  readonly kind: "decoded";
  readonly completeness: "incomplete-pixels-only";
  readonly requiresInspection: true;
  readonly sourceSha256: string;
  readonly limits: StaticPngReaderLimits & { readonly timeoutMs: number };
  readonly width: number;
  readonly height: number;
  readonly sourceColorType: 2 | 6;
  readonly outputColorType: 6;
  readonly decodedRgbaBytes: number;
  readonly rgbaSha256: string;
  readonly normalizedSha256: string;
  readonly normalizedByteLength: number;
  /** Counts this fixed worker's guarded JS network APIs; not a native-egress attestation. */
  readonly networkApiAttemptCount: 0;
  /** Returns new mutable bytes. No mutable reference to the retained derivative is exposed. */
  readonly copyNormalizedBytes: () => Uint8Array;
  /** Fresh contiguous RGBA8 samples, row-major without padding; alpha is preserved, not flattened. */
  readonly copyRgbaBytes: () => Uint8Array;
}

export interface StaticPngRejected extends StaticPngBase {
  readonly kind: "rejected";
  readonly code: StaticPngErrorCode;
}

export type StaticPngReadResult = StaticPngDecoded | StaticPngRejected;

export interface StaticPngReaderOptions {
  /** A native AbortSignal; running work is killed and reaped before settlement. */
  readonly signal?: AbortSignal;
  /** Lower-only original wall deadline including admission, queue and return validation. */
  readonly timeoutMs?: number;
  /** Lower-only cap on normalized PNG bytes, not a provider or monetary budget. */
  readonly maxOutputBytes?: number;
}

/** Private byte-only static PNG component; no URL, OCR, permissions or canonical facts. */
export declare function readStaticPng(input: Uint8Array, options?: StaticPngReaderOptions): Promise<StaticPngReadResult>;
export declare const STATIC_PNG_READER_LIMITS: StaticPngReaderLimits;
