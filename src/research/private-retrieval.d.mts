import type {
  DiscoveryFrontierStore,
  FrontierLimits,
  FrontierSeedInput,
} from '../discovery/planner/frontier.mjs';
import type {
  EntityIdentityDecision,
  EntityObservation,
} from '../discovery/entities/identity.mjs';
import type {
  ControlledAssetAcquisitionBinding,
  ControlledAssetAcquisitionCompletion,
  ControlledAssetEvidenceStore,
  EvidenceSelectedEvidence,
  EvidenceStore,
  StoredEvidenceFactRecord,
} from '../evidence/store.mjs';
import type {
  OccurrenceIdentityDecision,
  OccurrenceObservation,
  OccurrenceTransition,
} from '../discovery/occurrences/identity.mjs';
import type { SafeFetcher } from '../security/index.mjs';
import type { PrivateAssetReleaseAuthorityController } from './private-asset-release.mjs';
import type { PrivateSourceAuthorityReview } from './source-authority-followup.mjs';

export type PrivateRetrievalAuthorizationStage = 'start' | 'candidate' | 'asset-acquisition' | 'release';

export interface PrivateRetrievalRetentionContext {
  readonly runId: string;
  /** Exact URL spelling stored on the corresponding frontier observation. */
  readonly sourceUrl: string;
  /** Final normalized transport URL reported by SafeFetcher. */
  readonly canonicalUrl: string;
  readonly representation?: 'asset-source-excerpt' | 'controlled-asset-bytes';
  readonly sourceEvidenceId?: string;
  readonly sourceEvidenceVersion?: number;
  readonly sourceContentHash?: string;
}

export interface PrivateRetrievalAssetAcquisitionPolicy {
  readonly schemaVersion: 1;
  readonly policyVersion: 'ei-private-svg-acquisition/1';
  readonly policyId: string;
  /** Explicit allowlist of exact URL origins. Unknown or omitted policies keep acquisition off. */
  readonly allowedOrigins: readonly string[];
}

export interface PrivateRetrievalInputBase<Request = unknown, Store extends EvidenceStore<Request> = EvidenceStore<Request>> {
  readonly frontier: DiscoveryFrontierStore<Request>;
  readonly evidenceStore: Store;
  readonly safeFetcher: SafeFetcher;
  readonly request: Request;
  readonly runId: string;
  readonly seeds: readonly FrontierSeedInput[];
  readonly limits?: FrontierLimits;
  readonly retentionHandleFor: (
    request: Request,
    context: Readonly<PrivateRetrievalRetentionContext>,
  ) => object | Promise<object>;
  /** Trusted host callback; it must rederive current tenant and authorization synchronously. */
  readonly authorizeCurrent: (
    request: Request,
    context: Readonly<{ runId: string; stage: PrivateRetrievalAuthorizationStage }>,
  ) => boolean;
  /** Trusted host policy callback. A returned policy is immutable for this run and receipt identity. */
  readonly assetAcquisitionPolicyFor?: (
    request: Request,
    context: Readonly<{ runId: string }>,
  ) => PrivateRetrievalAssetAcquisitionPolicy | null | Promise<PrivateRetrievalAssetAcquisitionPolicy | null>;
  /**
   * Opt-in host capability issuer. Its controller is bound to this logical run,
   * exact normalized policy digest, tenant, and monotonic deadline. Keep the
   * controller and revoke it synchronously when any bound authority changes.
   */
  readonly assetAcquisitionReleaseAuthorityFor?: (
    request: Request,
    context: Readonly<{
      runId: string;
      policy: PrivateRetrievalAssetAcquisitionPolicy;
      policyDigest: string;
      deadlineAtMonotonic: number;
    }>,
  ) => PrivateAssetReleaseAuthorityController | Promise<PrivateAssetReleaseAuthorityController>;
  readonly signal?: AbortSignal;
}

/**
 * Legacy adapters remain valid while acquisition is default-off. Supplying an
 * explicit acquisition policy requires the store's additive controlled-SVG
 * capability so enabled callers cannot accidentally type an incomplete port.
 */
export type PrivateRetrievalInput<Request = unknown> =
  | (PrivateRetrievalInputBase<Request, EvidenceStore<Request>> & {
      readonly assetAcquisitionPolicyFor?: undefined;
      readonly assetAcquisitionReleaseAuthorityFor?: undefined;
    })
  | (PrivateRetrievalInputBase<Request, ControlledAssetEvidenceStore<Request>> & {
      readonly assetAcquisitionPolicyFor: NonNullable<PrivateRetrievalInputBase<Request>['assetAcquisitionPolicyFor']>;
      readonly assetAcquisitionReleaseAuthorityFor: NonNullable<
        PrivateRetrievalInputBase<Request>['assetAcquisitionReleaseAuthorityFor']
      >;
    });

/** Issues the opaque host controller used by the opt-in release barrier. */
export declare function createPrivateAssetReleaseAuthority(input: Readonly<{
  tenantId: string;
  runId: string;
  policy: PrivateRetrievalAssetAcquisitionPolicy;
  expiresAtMonotonic: number;
}>): PrivateAssetReleaseAuthorityController;

export interface PrivateRetrievalProgress {
  readonly state: 'active' | 'halted' | 'exhausted';
  readonly stopReason: string | null;
  readonly stopReasons: readonly string[];
  readonly completedCandidates: number;
  readonly remainingCandidates: number;
  readonly transportAttemptAdmissions: number;
  /** Valid extracted suggestions omitted at the configured per-completion cap. */
  readonly truncatedSuggestionCount?: number;
  /** Exact count omitted earlier by source parsing or policy, without retained raw URLs. */
  readonly sourceLinkCandidateOmittedCount?: number | null;
  /** Proven minimum, including one per legacy positive marker with an unknown exact count. */
  readonly sourceLinkCandidateOmittedCountLowerBound?: number;
  /** False when a replayed legacy receipt reports omissions but did not persist their exact count. */
  readonly sourceLinkCandidateOmittedCountComplete?: boolean;
}

export interface PrivateRetrievalPdfProjection {
  readonly pageCount: number;
  readonly textPageCount: number;
  readonly textBoxCount: number;
  readonly completeness: 'incomplete';
  readonly requiresInspection: true;
}

export interface PrivateRetrievalAssetCandidate {
  readonly candidateId: string;
  readonly sourceForm: string;
  readonly field: string;
  readonly association: NonNullable<EvidenceSelectedEvidence['source']['assetSource']>['candidates'][number]['association'];
  readonly locator: Readonly<{ kind: 'text-range'; startByte: number; endByte: number }>;
  readonly excerptHash: string;
  readonly normalizedSuggestion: string | null;
  readonly fetchSuggestion: string | null;
  readonly quarantineReason: string | null;
  readonly role: 'unknown';
  readonly permission: 'unknown';
  readonly inspection: 'pending';
  readonly sourceRef: Readonly<{
    evidenceId: string;
    contentHash: string;
    locator: Readonly<{ kind: 'text-range'; startByte: number; endByte: number }>;
    field: string;
  }>;
}

export interface PrivateRetrievalSource {
  readonly evidenceId: string;
  readonly version: number;
  readonly representation: 'raw' | 'pdf-derived-text' | 'asset-source-excerpt';
  readonly sourceUrl: string;
  readonly canonicalUrl: string;
  readonly redirectChain: readonly string[];
  readonly contentType: string;
  readonly retrievedAt: string;
  readonly contentHash: string;
  readonly sourceAuthority: 'not_evaluated';
  readonly pdf?: PrivateRetrievalPdfProjection;
  readonly assetCandidates?: readonly PrivateRetrievalAssetCandidate[];
  readonly assetCompleteness?: string;
  readonly assetLimitations?: readonly string[];
}

export interface PrivateRetrievalLinkCandidate {
  readonly candidateId: string;
  readonly url: string;
  readonly depth: number;
  readonly sourceRefs: readonly Readonly<{
    readonly evidenceId: string;
    readonly contentHash: string;
    readonly locator: Readonly<{ kind: 'text-range'; startByte: number; endByte: number } | { kind: 'json-pointer'; pointer: string }>;
    readonly field: string;
    readonly value: string;
  }>[];
  readonly sourceAuthority: 'not_evaluated';
}

export interface PrivateRetrievalAssetAcquisition {
  readonly schemaVersion: 1;
  readonly status: 'blocked_local_inspection_only';
  readonly candidateBindingHash: string;
  readonly candidate: Readonly<{
    frontierCandidateId: string;
    assetSourceCandidateId: string;
    sourceEvidenceId: string;
    assetUrl: string;
    field: string;
    excerptHash: string;
  }>;
  readonly sourceEvidence: Readonly<{
    evidenceId: string;
    version: number;
    contentHash: string;
    derivationDigest: string;
  }>;
  readonly acquiredEvidence: Readonly<{
    fetchedSource: ControlledAssetAcquisitionCompletion['originalEvidence'];
    transformed: ControlledAssetAcquisitionCompletion['transformedEvidence'];
    sourceBytesHash: string;
    transformedBytesHash: string;
    inspectionPolicyVersion: 'svg-static-geometry/1';
    storedBytesReopenedAndVerified: true;
  }>;
  readonly acceptedExternalAssetVersion: null;
  readonly questionPlan: Readonly<{
    questionId: 'Q-EI-BRAND-ROLE:v1';
    status: 'blocked';
    candidateBindingHash: string;
    execution: 'not_dispatched';
    observerMetadata: null;
    observerMetadataProvenance: 'absent';
    rights: 'unknown';
    permission: 'unknown';
    roleClassification: null;
    reasonCodes: readonly string[];
  }>;
}

export interface PrivateRetrievalConflict {
  readonly kind: 'occurrence_identity' | 'entity_identity';
  readonly candidateIds: readonly string[];
  readonly reasonCodes: readonly string[];
  readonly fields?: readonly string[];
  readonly decision: OccurrenceIdentityDecision | EntityIdentityDecision;
}

export interface PrivateRetrievalDraft {
  readonly schema: 'ei-private-retrieval-draft/v1';
  readonly status: 'draft' | 'incomplete';
  readonly completeness: 'incomplete';
  readonly facts: readonly StoredEvidenceFactRecord[];
  readonly occurrenceCandidates: readonly OccurrenceObservation[];
  readonly entityCandidates: readonly EntityObservation[];
  readonly occurrenceDecisions: readonly OccurrenceIdentityDecision[];
  readonly entityDecisions: readonly EntityIdentityDecision[];
  readonly transitionLinks: readonly OccurrenceTransition[];
  readonly unresolvedTransitions: readonly Readonly<{
    candidateId: string;
    transition: 'canceled' | 'rescheduled';
    reason: 'source_predecessor_successor_relation_not_extracted';
  }>[];
  readonly sources: readonly PrivateRetrievalSource[];
  readonly linkCandidates: readonly PrivateRetrievalLinkCandidate[];
  readonly assetAcquisitions?: readonly PrivateRetrievalAssetAcquisition[];
  /** Valid extracted links retained with provenance but not queued because of the completion cap. */
  readonly omittedLinkCandidates: readonly Readonly<{
    readonly url: string;
    readonly sourceRefs: PrivateRetrievalLinkCandidate['sourceRefs'];
    readonly reason: 'completion_suggestion_limit';
  }>[];
  readonly conflicts: readonly PrivateRetrievalConflict[];
  readonly sourceAuthority: 'not_evaluated';
  /** Passive private input request, built only from the final authorized selection. */
  readonly sourceAuthorityReview?: PrivateSourceAuthorityReview;
  readonly rights: 'not_evaluated';
  readonly usage: 'unknown';
  readonly limitations: readonly string[];
  readonly progress: PrivateRetrievalProgress;
}

export interface PrivateRetrievalIncomplete {
  readonly schema: 'ei-private-retrieval-draft/v1';
  readonly runId: string;
  readonly status: 'incomplete' | 'cancelled' | 'denied';
  readonly completeness: 'incomplete';
  readonly draft: null;
  /** Present only for a settled eligible source refusal with current release authorization; references are empty. */
  readonly sourceAuthorityReview?: PrivateSourceAuthorityReview;
  readonly limitations: readonly string[];
  readonly progress?: PrivateRetrievalProgress;
}

export type PrivateRetrievalResult = PrivateRetrievalDraft | PrivateRetrievalIncomplete;

export type PrivateRetrievalErrorCode = 'INVALID_INPUT' | 'POLICY_DENIED';

export declare class PrivateRetrievalError extends Error {
  readonly code: PrivateRetrievalErrorCode;
  constructor(code: PrivateRetrievalErrorCode);
}

/**
 * Runs bounded private retrieval over the existing safe-fetch, extraction,
 * evidence, and source-identity components. It does not establish source
 * authority, public release, asset permission, or billable usage.
 */
export declare function runPrivateRetrieval<Request = unknown>(
  input: PrivateRetrievalInput<Request>,
): Promise<PrivateRetrievalResult>;
