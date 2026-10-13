import type { SafeFetcher, RetrievedDocument } from '../../security/index.mjs';
import type { CacheIdentity, ReusePins, ReuseStore, ScopedReuseScope } from './store.mjs';
export { CacheRevalidationError } from './revalidation.mjs';

export interface ReviewedPublicSourceBinding {
  readonly schema: 'ei-reviewed-public-conditional-source/v1';
  readonly scopeKind: 'public_profile';
  readonly tenantId: string;
  readonly actorId: string;
  readonly publicationLinkId: string;
  readonly sourceRecordId: string;
  readonly profileRef: string;
  readonly profileVersion: number;
  readonly identity: CacheIdentity;
  readonly pins: ReusePins;
  /** Local reviewed-publication key; never inferred to equal the HTTP body hash. */
  readonly profileContentHash: string;
  readonly profileHashDomain: 'scoped-reuse-reviewed-publication-content-key/v1';
  readonly sourceRef: string;
  readonly evidenceId: string;
  readonly evidenceVersion: number;
  readonly sourceUrl: string;
  readonly contentType: string;
  readonly originalBodyHash: string;
  readonly bodyHashDomain: 'safe-fetch-decoded-entity-bytes/v1';
  readonly originalRetrievedAt: string;
  readonly validator: Readonly<{ name: 'etag' | 'last-modified'; value: string }>;
  /** Fixed earliest public/link/evidence/source-permission deadline, never renewed. */
  readonly expiresAtMs: number;
}

/** Explicit trusted-host mapping from the actual publication record and stored
 * private link to the complete original EvidenceStore representation. A caller
 * echo, a hash match alone, or a public read grant is insufficient authority. */
export interface ReviewedPublicSourceMapping {
  readonly schema: 'ei-reviewed-public-source-mapping/v1';
  readonly publicationLinkId: string;
  readonly sourceRecordId: string;
  readonly profileRef: string;
  readonly profileVersion: number;
  readonly profileContentHash: string;
  readonly profileHashDomain: 'scoped-reuse-reviewed-publication-content-key/v1';
  readonly sourceRef: string;
  readonly evidenceId: string;
  readonly evidenceVersion: number;
  readonly originalBodyHash: string;
  readonly bodyHashDomain: 'safe-fetch-decoded-entity-bytes/v1';
}

export interface RetainedPublicSourceInput {
  readonly request: unknown;
  readonly binding: ReviewedPublicSourceBinding;
  readonly phase: 'bind' | 'prepare' | 'dispatch' | 'commit';
  readonly signal: AbortSignal;
}

export interface RetainedPublicSource {
  readonly binding: ReviewedPublicSourceBinding;
  readonly mapping: ReviewedPublicSourceMapping;
  readonly representation: 'full_original_response';
  readonly bytes: Uint8Array;
  readonly validUntilMs: number;
}

/** Exact host-attested private source-access revocation. It scrubs the private
 * source binding/response records without retracting independently reviewed facts.
 * Missing data, outages and arbitrary thrown errors are not revocation evidence. */
export interface RevokedPublicSourceAccess {
  readonly status: 'source_access_revoked';
  readonly binding: ReviewedPublicSourceBinding;
  readonly mapping: ReviewedPublicSourceMapping;
}

interface PublicResponseReceipt {
  readonly responseRef: string;
  readonly responseKind: 'not_modified' | 'body_unchanged' | 'body' | 'removed' | 'outage';
  readonly httpStatus: number;
  /** Historical completion fact, not a current retention/access assertion. */
  readonly responseRetainedAtCompletion: boolean;
  readonly duplicateObservation: false;
}

export type ReviewedPublicRefreshReceipt = PublicResponseReceipt & (
  | { readonly effectKind: 'observation'; readonly observationRef: string;
      readonly observationStatus: 'not_modified' | 'outage'; readonly invalidated: false }
  | { readonly effectKind: 'invalidation'; readonly reason: 'source_body_changed';
      readonly invalidationEventRefs: readonly string[]; readonly invalidated: true;
      readonly observationRef?: never; readonly observationStatus?: never }
  | { readonly effectKind: 'invalidation'; readonly reason: 'removed';
      readonly invalidationEventRefs: readonly string[]; readonly invalidated: true;
      readonly observationRef: string; readonly observationStatus: 'removed' }
);

interface ReviewedPublicResultBase {
  readonly scopeKind: 'public_profile';
  readonly admissionRef: string;
  readonly profileRef: string;
  readonly profileVersion: number;
  readonly localRefreshId: string;
  /** Tenant-private keyed binding digest, never a canonical source hash. */
  readonly bindingDigest: string;
  readonly replayed: boolean;
  readonly usage: 'unknown';
  readonly holdDisposition: 'finance_reconciliation_required';
}

export type ReviewedPublicRefreshResult =
  | (ReviewedPublicResultBase & { readonly status: 'completed'; readonly receipt: ReviewedPublicRefreshReceipt })
  | (ReviewedPublicResultBase & { readonly status: 'unknown'; readonly receipt?: never });

export interface ReviewedPublicCacheRevalidation {
  bindSource(scope: ScopedReuseScope, request: unknown, input: {
    readonly scopeKind: 'public_profile'; readonly profileRef: string;
    readonly sourceRef: string; readonly evidenceId: string; readonly evidenceVersion: number;
    readonly document: RetrievedDocument;
  }, options?: { readonly signal?: AbortSignal }): Promise<{
    readonly status: 'bound'; readonly scopeKind: 'public_profile'; readonly profileRef: string;
    readonly profileVersion: number; readonly replayed: boolean;
  }>;
  refresh(scope: ScopedReuseScope, request: unknown, input: {
    readonly scopeKind: 'public_profile'; readonly profileRef: string; readonly admissionRef: string;
  }, options?: { readonly signal?: AbortSignal }): Promise<ReviewedPublicRefreshResult>;
}

export function createReviewedPublicCacheRevalidation(options: {
  readonly store: ReuseStore;
  readonly safeFetcher: SafeFetcher;
  readonly readRetainedPublicSource: (input: RetainedPublicSourceInput) => RetainedPublicSource | RevokedPublicSourceAccess
    | Promise<RetainedPublicSource | RevokedPublicSourceAccess>;
  readonly timeoutMs?: number;
}): ReviewedPublicCacheRevalidation;
