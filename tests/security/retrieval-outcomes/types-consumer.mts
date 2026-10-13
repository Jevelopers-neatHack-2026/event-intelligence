import { createLocalRetrievalOutcomes, type LocalRetrievalOutcome } from "../../../src/security/retrieval-outcomes/index.mjs";
import { SafeFetcher, type RetrievedDocument, type RetrievedSvgAssetDocument } from "../../../src/security/index.mjs";

const reader = createLocalRetrievalOutcomes();
const document: Promise<LocalRetrievalOutcome<RetrievedDocument>> = reader.fetch("https://example.org/", { signal: new AbortController().signal });
const svg: Promise<LocalRetrievalOutcome<RetrievedSvgAssetDocument>> = reader.fetchSvgAsset("https://example.org/asset.svg");
const legacy: Promise<RetrievedDocument> = new SafeFetcher().fetch("https://example.org/");
// @ts-expect-error private outcome factories never accept callbacks, credentials or policy.
createLocalRetrievalOutcomes({ fetch: () => undefined });
// @ts-expect-error headers are not supported.
reader.fetch("https://example.org/", { headers: { authorization: "synthetic" } });
// @ts-expect-error limits cannot be increased.
reader.fetch("https://example.org/", { totalMilliseconds: 60000 });
// @ts-expect-error method inputs must be URLs represented as strings.
reader.fetch(new URL("https://example.org/"));

function consume(outcome: LocalRetrievalOutcome<RetrievedDocument>): string {
  if (outcome.kind === "retrieved") {
    const complete: true = outcome.transportComplete;
    const bytes: Uint8Array = outcome.document.bytes;
    void complete; void bytes;
    // @ts-expect-error successful transport has no failure code.
    void outcome.code;
    return outcome.document.url;
  }
  const incomplete: false = outcome.transportComplete;
  void incomplete;
  // @ts-expect-error refusals cannot expose a partial document.
  void outcome.document;
  if (outcome.code === "DESTINATION_BLOCKED") {
    const reason: "POLICY_DENIED" = outcome.reason; return reason;
  }
  if (outcome.code === "DNS_FAILURE") {
    const reason: "DNS_FAILURE" = outcome.reason; return reason;
  }
  return outcome.reason;
}
void document; void svg; void legacy; void consume;
