import { createStaticImageOcrReader, STATIC_IMAGE_OCR_LIMITS, type StaticImageOcrResult } from "../../../src/extraction/static-image-ocr/index.mjs";
import { readStaticPng } from "../../../src/extraction/png/index.mjs";
import { createStaticJpegWebpReader } from "../../../src/extraction/jpeg-webp/index.mjs";
const reader = createStaticImageOcrReader({ runtimeDirectory: "/compile-only-reviewed-runtime" });
const source = new Uint8Array([0]);
const result: StaticImageOcrResult = await reader.read(source, { timeoutMs: 1500, maxWords: 10, maxTextBytes: 128, maxOutputBytes: 4096 });
if (result.kind === "observed") {
  const incomplete: "incomplete-unverified-ocr" = result.completeness;
  const unverified: "unverified" = result.sourceAuthority;
  const one: 1 = result.provenance.page;
  const rgba: "rgba8" = result.provenance.format;
  void [incomplete, unverified, one, rgba, result.image.rgbaSha256];
  // @ts-expect-error immutable literal word observations cannot be rewritten
  result.words[0]!.text = "corrected";
  // @ts-expect-error source bytes and decoder callbacks are not returned
  result.image.copyRgbaBytes();
  // @ts-expect-error no canonical facts or source authority is issued
  const facts: true = result.sourceAuthority;
  void facts;
}
// @ts-expect-error a request cannot supply its own decoder
createStaticImageOcrReader({ runtimeDirectory: "/compile-only-reviewed-runtime", readPng: async () => ({}) });
// @ts-expect-error a request cannot supply a decoded result instead of bytes
reader.read({ kind: "decoded", pixels: source });
// @ts-expect-error no provider/authority contract option exists
reader.read(source, { authorize: true });
// @ts-expect-error component deadline is internal to the exact composition
reader.read(source, { deadlineAtMs: 1 });
void STATIC_IMAGE_OCR_LIMITS.maxQueued;
await readStaticPng(source, { deadlineAtMs: 1, timeoutMs: 2000 });
await createStaticJpegWebpReader({ runtimeDirectory: "/compile-only-reviewed-runtime" }).read(source, { deadlineAtMs: 1 });
// @ts-expect-error absolute deadline is numeric in the process monotonic clock
readStaticPng(source, { deadlineAtMs: "renew" });
// @ts-expect-error absolute deadline is numeric in the process monotonic clock
createStaticJpegWebpReader({ runtimeDirectory: "/compile-only-reviewed-runtime" }).read(source, { deadlineAtMs: new Date() });
