export type StaticJpegWebpErrorCode =
  | "INVALID_INPUT" | "INVALID_OPTIONS" | "INVALID_LIMIT" | "INPUT_TOO_LARGE"
  | "UNSUPPORTED_FORMAT" | "UNSUPPORTED_FEATURE" | "MALFORMED_IMAGE" | "DIMENSION_LIMIT"
  | "RESOURCE_LIMIT" | "OUTPUT_LIMIT" | "CANCELLED" | "TIMEOUT" | "QUEUE_FULL"
  | "ISOLATION_UNAVAILABLE" | "DECODER_UNAVAILABLE" | "DECODER_FAILURE"
  | "PROTOCOL_ERROR" | "REMOTE_RESOURCE_ATTEMPT";
export interface StaticJpegWebpLimits {
  readonly maxInputBytes: number;
  readonly maxDimension: number;
  readonly maxPixels: number;
  readonly maxFrames: 1;
  readonly maxSegments: number;
  readonly maxDecodedBytes: number;
  readonly maxOutputBytes: number;
  readonly maxHeaderBytes: number;
  readonly maxStderrBytes: number;
  readonly maxRuntimeManifestBytes: number;
  readonly maxAddressSpaceBytes: number;
  readonly maxCpuSeconds: number;
  readonly maxOpenFiles: number;
  readonly defaultTimeoutMs: number;
  readonly maxTimeoutMs: number;
  readonly maxConcurrency: number;
  readonly maxQueued: number;
}
interface Base {
  readonly sourceSha256?: string;
  readonly decoder: {
    readonly name: "pillow-static-jpeg-webp";
    readonly configVersion: "ei-static-jpeg-webp/1";
    readonly nodeVersion: "22.23.3";
    readonly pythonVersion: "3.12.14";
    readonly pillowVersion: "12.3.0";
    readonly jpegVersion: "6.2";
    readonly webpVersion: "1.6.0";
    readonly jpegValidation: "libjpeg-coefficients-no-warnings/1";
    readonly jpegLibrarySha256: "6d7c754529b30aff22efaaf88ba02061714591702c03f297f00ccb32ee6d9d9a";
    readonly webpValidation: "exact-chunk-native-completion/1";
    readonly webpLibrarySha256: "7df9ad3680dd09d756511334791c8c896207863816eb2910840e5fc4ae10028a";
    readonly wheelSha256: "78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91";
    readonly normalization: "rgba8-png-stored-deflate/1";
  };
}
export interface StaticJpegWebpDecoded extends Base {
  readonly kind: "decoded";
  readonly completeness: "incomplete-pixels-only";
  readonly requiresInspection: true;
  readonly sourceSha256: string;
  readonly runtimeManifestSha256: string;
  readonly sourceFormat: "jpeg" | "webp";
  readonly encoding: "baseline" | "progressive" | "lossy" | "lossless";
  readonly sourceMode: "L" | "RGB" | "RGBA";
  readonly frames: 1;
  readonly width: number;
  readonly height: number;
  readonly outputColorType: 6;
  readonly decodedRgbaBytes: number;
  readonly rgbaSha256: string;
  readonly normalizedSha256: string;
  readonly normalizedByteLength: number;
  readonly limits: StaticJpegWebpLimits & { readonly timeoutMs: number };
  /** Cooperative Python APIs only; no native-egress or sandbox attestation. */
  readonly networkApiAttemptCount: 0;
  /** Fresh mutable copy; the retained deterministic PNG is never exposed. */
  readonly copyNormalizedBytes: () => Uint8Array;
  /** Fresh contiguous RGBA8 samples, row-major without padding; alpha is preserved, not flattened. */
  readonly copyRgbaBytes: () => Uint8Array;
}
export interface StaticJpegWebpRejected extends Base {
  readonly kind: "rejected";
  readonly code: StaticJpegWebpErrorCode;
}
export type StaticJpegWebpReadResult = StaticJpegWebpDecoded | StaticJpegWebpRejected;
export interface StaticJpegWebpOptions {
  readonly signal?: AbortSignal;
  /** Lower-only acceptance deadline, including source validation, queue and final result. */
  readonly timeoutMs?: number;
  /** Lower-only absolute deadline in this Node process's performance.now() timebase. */
  readonly deadlineAtMs?: number;
  /** Lower-only normalized PNG byte limit; not a provider or monetary allowance. */
  readonly maxOutputBytes?: number;
}
export interface StaticJpegWebpReader {
  /** Input is copied synchronously; active rejection waits for actual child closure. */
  readonly read: (input: Uint8Array, options?: StaticJpegWebpOptions) => Promise<StaticJpegWebpReadResult>;
}
/** Trusted host input from the explicit offline installer; no implicit runtime discovery. */
export declare function createStaticJpegWebpReader(configuration: { readonly runtimeDirectory: string }): StaticJpegWebpReader;
export declare const STATIC_JPEG_WEBP_READER_LIMITS: StaticJpegWebpLimits;
