import { readScannedPdfOcr, type ScannedPdfOcrPage, type ScannedPdfOcrObserved } from "../../../src/extraction/scanned-pdf-ocr/index.mjs";
import { readScannedPdf } from "../../../src/extraction/scanned-pdf/index.mjs";
import { readLocalOcr } from "../../../src/extraction/local-ocr/index.mjs";

async function inspect(bytes: Uint8Array, signal: AbortSignal) {
  const result = await readScannedPdfOcr(bytes, { signal, timeoutMs: 5000, maxWords: 20, maxTextBytes: 500, maxOutputBytes: 16000 });
  if (result.kind === "rejected") { const code: string = result.code; return code; }
  const observed: ScannedPdfOcrObserved = result;
  const incomplete: "incomplete-unverified-ocr" = observed.completeness;
  const unverified: "unverified" = observed.sourceAuthority;
  const page: ScannedPdfOcrPage | undefined = result.pages[0];
  if (page) {
    const words: readonly string[] = page.words.map((word) => word.text);
    const claim: "caller-supplied-unverified" = page.provenance.sourceBinding;
    // @ts-expect-error Observed tokens are immutable.
    page.words[0]!.text = "invented fact";
    void words; void claim;
  }
  // @ts-expect-error This private result grants no accepted facts or permissions.
  observed.acceptedFacts;
  // @ts-expect-error This private result grants no provider usage receipt.
  observed.billableAttemptId;
  return { incomplete, unverified };
}
const originalDeadline = performance.now() + 1000;
void readScannedPdf(new Uint8Array(), { deadlineAtMs: originalDeadline });
void readLocalOcr({ bytes: new Uint8Array(4), width: 1, height: 1, format: "rgba8",
  source: { sha256: "0".repeat(64), derivativeSha256: "0".repeat(64), page: 1 } }, { deadlineAtMs: originalDeadline });
// @ts-expect-error Encoded/source URLs are not accepted.
void readScannedPdfOcr("https://example.invalid/document.pdf");
// @ts-expect-error OCR selection is fixed, not request-controlled.
void readScannedPdfOcr(new Uint8Array(), { language: "eng" });
// @ts-expect-error A wall-date timestamp string is not the monotonic deadline type.
void readScannedPdf(new Uint8Array(), { deadlineAtMs: "tomorrow" });
void inspect;
