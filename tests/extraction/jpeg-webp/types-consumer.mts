import {
  createStaticJpegWebpReader, STATIC_JPEG_WEBP_READER_LIMITS,
  type StaticJpegWebpDecoded, type StaticJpegWebpErrorCode, type StaticJpegWebpReadResult,
} from "../../../src/extraction/jpeg-webp/index.mjs";

declare const authorizedRuntimeDirectory: string;
declare const privateBytes: Uint8Array;
declare const controller: AbortController;
const reader = createStaticJpegWebpReader({ runtimeDirectory: authorizedRuntimeDirectory });

async function privatePixelConsumer(): Promise<string | StaticJpegWebpErrorCode> {
  const result: StaticJpegWebpReadResult = await reader.read(privateBytes, {
    signal: controller.signal, timeoutMs: 1000, maxOutputBytes: 1024 * 1024,
  });
  if (result.kind === "rejected") {
    const code: StaticJpegWebpErrorCode = result.code;
    const possibleHash: string | undefined = result.sourceSha256;
    void possibleHash;
    // @ts-expect-error Refused reads never expose a pixel derivative.
    result.copyNormalizedBytes();
    return code;
  }
  const decoded: StaticJpegWebpDecoded = result;
  const stillIncomplete: "incomplete-pixels-only" = decoded.completeness;
  const inspectionRequired: true = decoded.requiresInspection;
  const format: "jpeg" | "webp" = decoded.sourceFormat;
  const frame: 1 = decoded.frames;
  const rgbaColorType: 6 = decoded.outputColorType;
  const guardedApiAttempts: 0 = decoded.networkApiAttemptCount;
  const copy: Uint8Array = decoded.copyNormalizedBytes();
  const runtimeIdentity: string = decoded.runtimeManifestSha256;
  void [stillIncomplete, inspectionRequired, format, frame, rgbaColorType, guardedApiAttempts, copy, runtimeIdentity];
  // @ts-expect-error A decoded dimension is immutable.
  decoded.width = 1;
  // @ts-expect-error The retained copy operation is immutable.
  decoded.copyNormalizedBytes = () => privateBytes;
  // @ts-expect-error Pixel decoding does not claim interpreted facts.
  decoded.facts;
  // @ts-expect-error Pixel decoding supplies no asset permission decision.
  decoded.permissions;
  return decoded.normalizedSha256;
}
void privatePixelConsumer;
const maxPixels: number = STATIC_JPEG_WEBP_READER_LIMITS.maxPixels;
void maxPixels;

// @ts-expect-error Runtime discovery and installation must be explicit trusted setup.
createStaticJpegWebpReader({});
// @ts-expect-error There is no URL fetch surface.
reader.read("https://example.invalid/image.webp");
// @ts-expect-error There is no provider/model adapter surface.
reader.read(privateBytes, { inspectWithModel: () => null });
// @ts-expect-error The cancellation input must be an AbortSignal.
reader.read(privateBytes, { signal: { aborted: false } });
