import {
  readStaticPng, STATIC_PNG_READER_LIMITS,
  type StaticPngDecoded, type StaticPngErrorCode, type StaticPngReadResult,
} from "../../../src/extraction/png/index.mjs";

declare const privateBytes: Uint8Array;
declare const controller: AbortController;

async function privatePixelConsumer(): Promise<string | StaticPngErrorCode> {
  const result: StaticPngReadResult = await readStaticPng(privateBytes, {
    signal: controller.signal, timeoutMs: 1000, maxOutputBytes: 1024 * 1024,
  });
  if (result.kind === "rejected") {
    const code: StaticPngErrorCode = result.code;
    const possibleHash: string | undefined = result.sourceSha256;
    void possibleHash;
    // @ts-expect-error A rejected decode never carries derivative bytes.
    result.copyNormalizedBytes();
    // @ts-expect-error A rejected decode never carries raw pixel bytes.
    result.copyRgbaBytes();
    return code;
  }
  const decoded: StaticPngDecoded = result;
  const incomplete: "incomplete-pixels-only" = decoded.completeness;
  const reviewStillRequired: true = decoded.requiresInspection;
  const privateCopy: Uint8Array = decoded.copyNormalizedBytes();
  const rawCopy: Uint8Array = decoded.copyRgbaBytes();
  const rgba: 6 = decoded.outputColorType;
  const measuredGuardedApis: 0 = decoded.networkApiAttemptCount;
  void [incomplete, reviewStillRequired, privateCopy, rawCopy, rgba, measuredGuardedApis];
  // @ts-expect-error Read-only dimensions cannot be revised into authoritative facts.
  decoded.width = 1;
  // @ts-expect-error The retained byte-copy operation is also read-only.
  decoded.copyNormalizedBytes = () => privateBytes;
  // @ts-expect-error Raw copy ownership cannot be replaced through the result.
  decoded.copyRgbaBytes = () => privateBytes;
  // @ts-expect-error There is no inspection/fact result in this component.
  decoded.facts;
  // @ts-expect-error A normalized image does not carry an asset permission decision.
  decoded.permissions;
  return decoded.sourceSha256;
}
void privatePixelConsumer;
const ceiling: number = STATIC_PNG_READER_LIMITS.maxPixels;
void ceiling;

// @ts-expect-error No URL fetching surface is provided.
readStaticPng("https://example.invalid/image.png");
// @ts-expect-error No provider callback or model invocation surface is provided.
readStaticPng(privateBytes, { inspectWithModel: () => null });
// @ts-expect-error A native cancellation signal is required, not an arbitrary adapter.
readStaticPng(privateBytes, { signal: { aborted: false } });
