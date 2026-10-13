import { readScannedPdf, SCANNED_PDF_LIMITS, type ScannedPdfOptions } from "../../../src/extraction/scanned-pdf/index.mjs";

const options: ScannedPdfOptions = { signal: new AbortController().signal, maxOutputBytes: 1024 };
const result = await readScannedPdf(new Uint8Array([37, 80, 68, 70]), options);
if (result.kind === "decoded") {
  const incomplete: "incomplete-pixels-only" = result.completeness;
  const requiresInspection: true = result.requiresInspection;
  const pixels: Uint8Array = result.pages[0].copyRgbaBytes();
  const format: "rgba8" = result.pages[0].format;
  void [incomplete, requiresInspection, pixels, format, SCANNED_PDF_LIMITS];
  // @ts-expect-error Pixels do not create OCR text.
  result.text;
  // @ts-expect-error Page provenance is immutable.
  result.pages[0].page = 9;
} else {
  const code: string = result.code;
  void code;
}
// @ts-expect-error The private reader has no URL/path input.
await readScannedPdf("https://invalid.example/source.pdf");
// @ts-expect-error No provider/permission/adapter injection surface.
await readScannedPdf(new Uint8Array(), { provider: {} });
