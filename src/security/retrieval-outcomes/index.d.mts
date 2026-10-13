import type { FetchOptions, RetrievedDocument, RetrievedSvgAssetDocument } from "../index.mjs";

export type LocalRetrievalFailure =
  | { readonly code: "DESTINATION_BLOCKED"; readonly reason: "POLICY_DENIED" }
  | { readonly code: "RESOURCE_LIMIT"; readonly reason:
      "RESOURCE_LIMIT" | "REDIRECT_LIMIT" | "REQUEST_LIMIT" | "UNSUPPORTED_MEDIA" | "DEADLINE_EXCEEDED" }
  | { readonly code: "DNS_FAILURE"; readonly reason: "DNS_FAILURE" }
  | { readonly code: "TRANSPORT_FAILURE"; readonly reason: "TRANSPORT_FAILURE" }
  | { readonly code: "CANCELED"; readonly reason: "CANCELED" }
  | { readonly code: "INVALID_INPUT"; readonly reason: "INVALID_INPUT" }
  | { readonly code: "INTERNAL_FAILURE"; readonly reason: "UNRECOGNIZED_FAILURE" | "UNRECOGNIZED_RESULT" };

export type LocalRetrievalOutcome<Document> =
  | Readonly<{ schema: "ei-private-retrieval-outcome/1"; kind: "retrieved"; transportComplete: true; document: Document }>
  | (Readonly<{ schema: "ei-private-retrieval-outcome/1"; kind: "refused"; transportComplete: false }> & LocalRetrievalFailure);

export interface LocalRetrievalOutcomes {
  /** One shared real SafeFetcher run; transport completion is not inspected or accepted evidence. */
  fetch(input: string, options?: FetchOptions): Promise<LocalRetrievalOutcome<RetrievedDocument>>;
  fetchSvgAsset(input: string, options?: FetchOptions): Promise<LocalRetrievalOutcome<RetrievedSvgAssetDocument>>;
}

/** Private relative-import entry point. Factory arguments and custom fetch callbacks are unsupported. */
export declare function createLocalRetrievalOutcomes(): Readonly<LocalRetrievalOutcomes>;
