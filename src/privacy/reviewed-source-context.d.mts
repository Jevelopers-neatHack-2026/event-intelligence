import type { EvidenceHandle, EvidenceStore, EvidenceStoreOptions } from '../evidence/store.mjs';
import type { ContentModality, PrivacyBoundary, SanitizedDerivative, TenantScope } from './boundary.mjs';

declare const contextBrand: unique symbol;
/** Process-local capability. A copied or serialized object is not a context. */
export type ReviewedSourceContextHandle = { readonly [contextBrand]: true };

export declare const REVIEWED_SOURCE_CONTEXT_SCHEMA: 'ei-private-reviewed-source-context/1';
export type ReviewedSourceContextErrorCode =
  | 'INVALID_INPUT' | 'SOURCE_BINDING_DENIED' | 'SOURCE_MISMATCH'
  | 'SOURCE_CONTEXT_INCOMPLETE' | 'UNSUPPORTED_SOURCE' | 'EXTRACTION_INCOMPLETE'
  | 'REVIEW_REQUIRED' | 'REVIEW_REJECTED' | 'REVIEW_INVALID' | 'CRITICAL_NOTICE_OMITTED'
  | 'AUTHORITY_DENIED' | 'EVIDENCE_DENIED' | 'EVIDENCE_EXPIRED' | 'EVIDENCE_UNAVAILABLE'
  | 'CONTEXT_REVOKED' | 'CANCELED' | 'DEADLINE_EXCEEDED' | 'BUSY';

export declare class ReviewedSourceContextError extends Error {
  readonly code: ReviewedSourceContextErrorCode;
  constructor(code?: ReviewedSourceContextErrorCode);
}

export interface ReviewedContextRange {
  readonly startByte: number;
  readonly endByte: number;
}

export interface ReviewedContextSegment extends ReviewedContextRange {
  /** Exact retained UTF-8 source slice; remains untrusted source content. */
  readonly text: string;
}

export interface ReviewedContextNotice extends ReviewedContextSegment {
  readonly kind: 'source-status-notice' | 'structured-event-status';
}

export interface SourceContextReviewInput {
  readonly schema: typeof REVIEWED_SOURCE_CONTEXT_SCHEMA;
  readonly purpose: string;
  readonly tenantId: string;
  readonly recordId: string;
  readonly sourceDigest: string;
  readonly evidenceId: string;
  readonly modality: ContentModality;
  readonly source: Readonly<{ sourceUrl: string; contentType: string }>;
  readonly criticalNotices: readonly ReviewedContextNotice[];
  readonly signal: AbortSignal;
  /** Private capability. Fails after the attempt, revocation, cancellation or retention expiry. */
  readSourceText(): string;
}

export type SourceContextReviewDecision = Readonly<{ status: 'rejected' }> | Readonly<{
  status: 'approved';
  schema: typeof REVIEWED_SOURCE_CONTEXT_SCHEMA;
  purpose: string;
  tenantId: string;
  recordId: string;
  sourceDigest: string;
  evidenceId: string;
  sourceUrl: string;
  /** Private reviewer policy reference, not canonical election or a provider grant. */
  reviewVersion: string;
  completeForPurpose: true;
  criticalNoticesReviewed: true;
  /** Sorted, nonoverlapping exact source ranges. Text replacement is not accepted. */
  ranges: readonly ReviewedContextRange[];
}>;

export interface ReviewedSourceContextAuthority<Request = unknown> {
  readonly tenantId: string;
  readonly request: Request;
  readonly action: 'review_source_context' | 'materialize_source_context';
  readonly purpose: string;
  readonly recordId: string;
  readonly sourceDigest: string;
  readonly evidenceId: string;
}

export interface ReviewedSourceContextOptions<Request = unknown> {
  readonly boundary: PrivacyBoundary<Request>;
  /** This adapter constructs the actual store and owns its private payload consumer. */
  readonly evidenceStoreOptions: Omit<EvidenceStoreOptions<Request>, 'consumePrivatePayload'>;
  /** Trusted composition-selected purpose. A browser/request cannot elect the review policy. */
  readonly purpose: string;
  /** Optional only to make missing review fail closed. No default classifier or approval exists. */
  readonly reviewContext?: (input: SourceContextReviewInput) => SourceContextReviewDecision | Promise<SourceContextReviewDecision>;
  /** Must synchronously re-derive the current authenticated tenant and exact ACL. Thenables refuse. */
  readonly authorizeContextCurrent?: (input: ReviewedSourceContextAuthority<Request>) => boolean;
  /** Original elapsed operation budget, 1..12000 ms. Does not preempt synchronous trusted callbacks. */
  readonly deadlineMs?: number;
}

export interface PrivateReviewedSourceContext {
  readonly schema: typeof REVIEWED_SOURCE_CONTEXT_SCHEMA;
  readonly visibility: 'tenant_private';
  readonly trust: 'untrusted_external';
  readonly purpose: string;
  readonly recordId: string;
  readonly evidenceId: string;
  readonly sourceDigest: string;
  readonly sourceUrl: string;
  readonly expiresAt: string;
  readonly reviewVersion: string;
  readonly segments: readonly ReviewedContextSegment[];
  readonly criticalNotices: readonly ReviewedContextNotice[];
  readonly canonicalAdoption: false;
  readonly dispatchStatus: 'not_dispatched';
}

export interface ReviewedSourceContextAdapter<Request = unknown> {
  /** The concrete store. Direct withPrivatePayload calls refuse: only the adapter owns that bridge. */
  readonly evidenceStore: EvidenceStore<Request>;
  review(input: Readonly<{
    scope: TenantScope;
    derivative: SanitizedDerivative;
    evidence: EvidenceHandle;
    request: Request;
    signal?: AbortSignal;
  }>): Promise<ReviewedSourceContextHandle>;
  /** Reopens retained evidence and rechecks current authority on every private materialization. */
  materialize(input: Readonly<{
    scope: TenantScope;
    context: ReviewedSourceContextHandle;
    request: Request;
    signal?: AbortSignal;
  }>): Promise<PrivateReviewedSourceContext>;
  revoke(scope: TenantScope, context: ReviewedSourceContextHandle): boolean;
}

export declare function createReviewedSourceContext<Request = unknown>(
  options: ReviewedSourceContextOptions<Request>,
): ReviewedSourceContextAdapter<Request>;
