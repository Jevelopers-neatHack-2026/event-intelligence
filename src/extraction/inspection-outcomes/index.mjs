import { readStaticPng } from "../png/index.mjs";
import { createStaticJpegWebpReader } from "../jpeg-webp/index.mjs";
import { readScannedPdf } from "../scanned-pdf/index.mjs";
import { readTextPdf } from "../pdf/index.mjs";
import { prepare, dataRecord, wrapReaderResult, boundaryFailure } from "./internal.mjs";

/** Private byte-only entrypoints. They do not fetch, inspect facts or grant rights. */
export async function readPngOutcome(input, options) {
  try {
    const prepared = prepare("png", input, options);
    if (prepared.failure) return prepared.failure;
    return wrapReaderResult("png", await readStaticPng(prepared.bytes, prepared.options));
  } catch { return boundaryFailure("png", "UNEXPECTED_READER_FAILURE"); }
}

export async function readScannedPdfOutcome(input, options) {
  try {
    const prepared = prepare("scanned-pdf", input, options);
    if (prepared.failure) return prepared.failure;
    return wrapReaderResult("scanned-pdf", await readScannedPdf(prepared.bytes, prepared.options));
  } catch { return boundaryFailure("scanned-pdf", "UNEXPECTED_READER_FAILURE"); }
}

export async function readTextPdfOutcome(input, options) {
  try {
    const prepared = prepare("text-pdf", input, options);
    if (prepared.failure) return prepared.failure;
    return wrapReaderResult("text-pdf", await readTextPdf(prepared.bytes, prepared.options));
  } catch { return boundaryFailure("text-pdf", "UNEXPECTED_READER_FAILURE"); }
}

/** Existing trusted offline-install path only; no decoder/worker/provider substitution. */
export function createJpegWebpOutcomeReader(configuration) {
  let actual;
  try {
    const record = dataRecord(configuration, ["runtimeDirectory"]);
    const runtimeDirectory = record?.runtimeDirectory?.value;
    if (typeof runtimeDirectory === "string") actual = createStaticJpegWebpReader({ runtimeDirectory });
  } catch { /* A fixed boundary failure is returned by read, without exception text. */ }
  return Object.freeze({
    async read(input, options) {
      if (!actual) return boundaryFailure("jpeg-webp", "INVALID_CONFIGURATION");
      try {
        const prepared = prepare("jpeg-webp", input, options);
        if (prepared.failure) return prepared.failure;
        return wrapReaderResult("jpeg-webp", await actual.read(prepared.bytes, prepared.options));
      } catch { return boundaryFailure("jpeg-webp", "UNEXPECTED_READER_FAILURE"); }
    },
  });
}
