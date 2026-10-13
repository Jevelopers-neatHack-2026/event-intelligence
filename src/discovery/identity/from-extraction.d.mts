import type {
  EvidenceStore,
  StoredEvidenceFactRecord,
} from "../../evidence/store.mjs";
import type { ExtractionResult } from "../../extraction/index.mjs";
import type { EntityIdentityDecision, EntityObservation } from "../entities/identity.mjs";
import type {
  OccurrenceIdentityDecision,
  OccurrenceObservation,
  OccurrenceTransition,
} from "../occurrences/identity.mjs";
import type { RetrievedDocument } from "../../security/index.mjs";
import type { SourceCorroboration, SourceCorroborationFactBinding } from "./corroboration.mjs";

export type SourceIdentityCompositionErrorCode =
  | "INVALID_INPUT"
  | "CANCELED"
  | "DEADLINE_EXCEEDED"
  | "RESOURCE_LIMIT"
  | "JS_REQUIRED"
  | "ACCESS_RESTRICTED"
  | "UNSUPPORTED_MEDIA"
  | "UNSUPPORTED_ENCODING"
  | "MALFORMED_ENCODING"
  | "EXTRACTION_UNUSABLE"
  | "SOURCE_BINDING_FAILED"
  | "NO_IDENTITY_CANDIDATES"
  | "EVIDENCE_POSITION_MISSING"
  | "EVIDENCE_POSITION_AMBIGUOUS"
  | "STORED_SOURCE_MISMATCH"
  | "EVIDENCE_EXPIRED"
  | "EVIDENCE_DENIED"
  | "EVIDENCE_UNAVAILABLE"
  | "COMPOSITION_FAILED";

export interface CompletedSourceInput {
  readonly document: RetrievedDocument & {
    /** Original URL passed to SafeFetcher; defaults to the returned URL for legacy callers. */
    readonly requestedUrl?: string;
    /** Exact SafeFetcher redirect targets in order; required when redirects is nonzero. */
    readonly redirectChain?: readonly string[];
  };
  /** Opaque capability checked by the host's existing evidence retention resolver. */
  readonly retentionHandle: object;
}

export interface ComposeSourceIdentityInput<Request = unknown> {
  readonly sources: readonly CompletedSourceInput[];
  readonly request: Request;
  readonly evidenceStore: EvidenceStore<Request>;
  readonly signal?: AbortSignal;
}

export interface SourceIdentityEvidenceSummary {
  readonly evidenceId: string;
  /** Full-source SHA-256 hex digest, distinct from every selected-position digest. */
  readonly contentHash: string;
  readonly duplicateGroupId: string;
  /** Original stored retrieval time; idempotent replay never refreshes it. */
  readonly retrievedAt: string;
  readonly expiresAt: string;
  readonly positionCount: number;
}

export interface StoredSourceSummary {
  readonly sourceUrl: string;
  readonly canonicalUrl: string;
  readonly redirectChain: readonly string[];
  readonly contentType: string;
  readonly sourceKind: "external";
  readonly retrievedAt: string;
  readonly retrievedAtMs: number;
  /** Full-source SHA-256, distinct from every selected-position digest. */
  readonly contentHash: string;
}

export interface ComposedSourceIdentitySource {
  readonly evidence: SourceIdentityEvidenceSummary | null;
  /** Stored descriptor after an aggregate check; null when this source had no eligible claims. */
  readonly storedSource: StoredSourceSummary | null;
  /** Timestamp on the current completed-retrieval input, separate from the stored descriptor. */
  readonly observedRetrievedAt: string;
  readonly extraction: ExtractionResult;
}

export interface ComposedSourceLinkCandidate {
  readonly url: string;
  readonly sourceRef: Readonly<{
    readonly evidenceId: string;
    readonly contentHash: string;
    readonly locator: Readonly<{ kind: "text-range"; startByte: number; endByte: number }>;
    readonly field: "canonical.url" | "openGraph.url";
    /** Exact normalized target used as the persisted frontier URL. */
    readonly value: string;
  }>;
}

export interface SourceIdentityCompositionLimits {
  readonly maxSources: 8;
  readonly maxBytesPerSource: 524288;
  readonly maxTotalBytes: 2097152;
  readonly maxIdentityCandidates: 23;
  readonly maxFacts: 128;
  readonly maxPositions: 128;
  readonly maxComparisons: 256;
  readonly deadlineMs: 12000;
}

export interface SourceIdentityCompositionFields {
  readonly sources: readonly ComposedSourceIdentitySource[];
  /** Private evidence facts preserve raw and normalized values separately. */
  readonly facts: readonly StoredEvidenceFactRecord[];
  readonly entityCandidates: readonly EntityObservation[];
  readonly occurrenceCandidates: readonly OccurrenceObservation[];
  readonly entityDecisions: readonly EntityIdentityDecision[];
  readonly occurrenceDecisions: readonly OccurrenceIdentityDecision[];
  /** No predecessor or successor is invented when the source does not encode the link. */
  readonly transitionLinks: readonly OccurrenceTransition[];
  readonly unresolvedTransitions: readonly Readonly<{
    candidateId: string;
    transition: "canceled" | "rescheduled";
    reason: "source_predecessor_successor_relation_not_extracted";
  }>[];
  /** Bounded, exact-position-bound navigation candidates; not authority or source verification. */
  readonly linkCandidates: readonly ComposedSourceLinkCandidate[];
  /** Number of unsupported, sensitive, malformed, or over-limit navigation candidates omitted. */
  readonly linkCandidatesOmitted: number;
  readonly sourceAuthority: "not_evaluated";
  readonly limits: SourceIdentityCompositionLimits;
}

/** Historical output has no retained attribution policy; independence is unknown. */
export interface LegacySourceIdentityCompositionResult extends SourceIdentityCompositionFields {
  readonly schema: "ei-source-identity-composition-internal/v1";
}

export interface SourceIdentityCompositionResult extends SourceIdentityCompositionFields {
  readonly schema: "ei-source-identity-composition-internal/v2";
  readonly corroboration: SourceCorroboration;
  readonly corroborationFactBindings: readonly SourceCorroborationFactBinding[];
}

export type SupportedSourceIdentityComposition = SourceIdentityCompositionResult | LegacySourceIdentityCompositionResult;

export declare class SourceIdentityCompositionError extends Error {
  readonly code: SourceIdentityCompositionErrorCode;
  constructor(code?: SourceIdentityCompositionErrorCode);
}

/**
 * Compose completed local retrieval bytes into private evidence-backed identity
 * observations. The helper performs deterministic extraction itself and makes
 * no network requests.
 */
export declare function composeSourceIdentity<Request = unknown>(
  input: ComposeSourceIdentityInput<Request>,
): Promise<SourceIdentityCompositionResult>;
