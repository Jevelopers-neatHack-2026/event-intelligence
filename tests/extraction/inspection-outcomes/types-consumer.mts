import { readPngOutcome, createJpegWebpOutcomeReader, readScannedPdfOutcome, readTextPdfOutcome } from "../../../src/extraction/inspection-outcomes/index.mjs";
import type { PngOutcome, JpegWebpOutcome, ScannedPdfOutcome, TextPdfOutcome } from "../../../src/extraction/inspection-outcomes/index.mjs";
import type { StaticPngReadResult } from "../../../src/extraction/png/index.mjs";
import type { StaticJpegWebpReadResult } from "../../../src/extraction/jpeg-webp/index.mjs";
import type { ScannedPdfDecoded, ScannedPdfRejected } from "../../../src/extraction/scanned-pdf/index.mjs";
import type { PdfTextReadResult } from "../../../src/extraction/pdf/index.mjs";

export async function consume(bytes: Uint8Array, signal: AbortSignal, runtimeDirectory: string) {
  const png: PngOutcome = await readPngOutcome(bytes, { signal, timeoutMs: 1000, deadlineAtMs: 1000, maxOutputBytes: 1024 });
  const jpeg: JpegWebpOutcome = await createJpegWebpOutcomeReader({ runtimeDirectory }).read(bytes, { signal });
  const scanned: ScannedPdfOutcome = await readScannedPdfOutcome(bytes, { signal });
  const text: TextPdfOutcome = await readTextPdfOutcome(bytes, { signal, maxTextCodeUnits: 1000 });
  if (png.kind === "reader-result") {
    const original: StaticPngReadResult = png.result;
    if (original.kind === "decoded") { const copy: Uint8Array = original.copyRgbaBytes(); void copy; }
    // @ts-expect-error private outcome records are immutable
    png.category = "OBSERVATION";
  }
  if (jpeg.kind === "reader-result") { const original: StaticJpegWebpReadResult = jpeg.result; void original; }
  if (scanned.kind === "reader-result") { const original: ScannedPdfDecoded | ScannedPdfRejected = scanned.result; void original; }
  if (text.kind === "reader-result") { const original: PdfTextReadResult = text.result; void original; }
  if (png.kind === "boundary-failure") {
    // @ts-expect-error a boundary failure never fabricates a native result
    png.result;
  }
  // @ts-expect-error text PDF has no absolute-deadline option
  await readTextPdfOutcome(bytes, { deadlineAtMs: 0 });
  // @ts-expect-error no caller progress callbacks in the supported private subset
  await readTextPdfOutcome(bytes, { onPageComplete() {} });
  // @ts-expect-error no arbitrary decoder or authority callback
  await readPngOutcome(bytes, { decoder() {} });
  // @ts-expect-error no runtime executable substitution
  createJpegWebpOutcomeReader({ runtimeDirectory, executable: "/synthetic" });
}
