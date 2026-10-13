import { composeSourceIdentity, SourceIdentityCompositionError } from "../../../src/discovery/identity/from-extraction.mjs";
import type {
  ComposeSourceIdentityInput,
  SourceIdentityCompositionResult,
  SourceIdentityCompositionErrorCode,
} from "../../../src/discovery/identity/from-extraction.mjs";
import type { EvidenceStore } from "../../../src/evidence/store.mjs";
import type { RetrievedDocument } from "../../../src/security/index.mjs";

declare const document: RetrievedDocument;
declare const evidenceStore: EvidenceStore<{ readonly principal: { readonly tenantId: string } }>;
declare const request: { readonly principal: { readonly tenantId: string } };
declare const retentionHandle: object;

const input: ComposeSourceIdentityInput<{ readonly principal: { readonly tenantId: string } }> = {
  sources: [{ document, retentionHandle }],
  request,
  evidenceStore,
  signal: new AbortController().signal,
};

const result: Promise<SourceIdentityCompositionResult> = composeSourceIdentity(input);
void result.then((composition) => {
  const schema: "ei-source-identity-composition-internal/v2" = composition.schema;
  const graphSchema: "ei-source-corroboration-internal/v1" = composition.corroboration.schema;
  const independence: "unknown" = composition.corroboration.independence;
  const declarationPosition: number | undefined = composition.corroboration.claims[0]?.sourceRef.locator.startByte;
  const authority: "not_evaluated" = composition.sourceAuthority;
  const hash: string | undefined = composition.sources[0]?.evidence?.contentHash;
  const storedAt: string | undefined = composition.sources[0]?.storedSource?.retrievedAt;
  const observedAt: string | undefined = composition.sources[0]?.observedRetrievedAt;
  const occurrenceCount: number = composition.occurrenceCandidates.length;
  const transitionCount: number = composition.transitionLinks.length;
  void [schema, graphSchema, independence, declarationPosition, authority, hash, storedAt, observedAt, occurrenceCount, transitionCount];
  // @ts-expect-error A declaration cluster never establishes independent authority.
  const independent: "independent" = composition.corroboration.independence;
  // @ts-expect-error The returned cluster collection is immutable.
  composition.corroboration.clusters.push({});
  void independent;
});

const refusalCodes: readonly SourceIdentityCompositionErrorCode[] = [
  "JS_REQUIRED", "ACCESS_RESTRICTED", "UNSUPPORTED_MEDIA", "UNSUPPORTED_ENCODING", "MALFORMED_ENCODING",
];
for (const code of refusalCodes) {
  const refusal: SourceIdentityCompositionErrorCode = new SourceIdentityCompositionError(code).code;
  void refusal;
}

// @ts-expect-error Untrusted extractor content cannot introduce an arbitrary error code.
new SourceIdentityCompositionError("SOURCE_TEXT_AS_ERROR");
