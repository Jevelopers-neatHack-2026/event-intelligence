import { readLocalOcr, type LocalOcrInput, type LocalOcrResult, type OcrWordObservation } from "../../../src/extraction/local-ocr/index.mjs";
const pixels: LocalOcrInput = { bytes: new Uint8Array(4000), width: 100, height: 40, format: "gray8",
  source: { sha256: "a".repeat(64), page: 1, derivativeSha256: "b".repeat(64) } };
const response: Promise<LocalOcrResult> = readLocalOcr(pixels, { timeoutMs: 1000, maxWords: 20, signal: new AbortController().signal });
async function consume() {
  const result = await response;
  if (result.kind === "observed") {
    const review: true = result.requiresReview;
    const uncertain: "incomplete-unverified-ocr" = result.completeness;
    const word: OcrWordObservation | undefined = result.words[0];
    if (word) {
      const meaning: "uncalibrated-engine-score" = word.confidenceMeaning;
      const source: string = word.provenance.sourceSha256;
      const page: number = word.provenance.page;
      void [meaning, source, page];
      // @ts-expect-error the observation cannot be rewritten as a fact
      word.text = "verified";
    }
    // @ts-expect-error no accepted fact or permission is returned
    result.acceptedFacts;
    void [review, uncertain];
  } else {
    const code: string = result.code;
    // @ts-expect-error a refusal is not an empty recognized page
    result.words;
    void code;
  }
}
// @ts-expect-error URL acquisition is not part of this private reader
readLocalOcr("https://example.invalid/poster.png");
// @ts-expect-error no runtime model/language override
readLocalOcr(pixels, { language: "osd" });
// @ts-expect-error no encoded or unsupported media format
const unsupported: LocalOcrInput = { ...pixels, format: "image/jpeg" };
void [consume, unsupported];
