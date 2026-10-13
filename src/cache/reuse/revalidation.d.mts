import type { SafeFetcher, RetrievedDocument } from '../../security/index.mjs';
import type { CacheIdentity, ReusePins, ReuseStore, ScopedReuseScope } from './store.mjs';

export interface RefreshSourceBinding {
  readonly schema: 'ei-private-conditional-source/v1';
  readonly scopeKind: 'tenant_private';
  readonly tenantId: string;
  readonly actorId: string;
  readonly profileRef: string;
  readonly profileVersion: number;
  readonly identity: CacheIdentity;
  readonly pins: ReusePins;
  readonly profileContentHash: string;
  readonly profileHashDomain: 'safe-fetch-decoded-entity-bytes/v1';
  readonly sourceRef: string;
  readonly evidenceId: string;
  readonly evidenceVersion: number;
  readonly sourceUrl: string;
  readonly contentType: string;
  readonly originalBodyHash: string;
  readonly bodyHashDomain: 'safe-fetch-decoded-entity-bytes/v1';
  readonly originalRetrievedAt: string;
  readonly validator: Readonly<{ name: 'etag' | 'last-modified'; value: string }>;
  readonly expiresAtMs: number;
}

export interface RetainedSourceInput {
  readonly request: unknown;
  readonly binding: RefreshSourceBinding;
  readonly phase: 'bind' | 'prepare' | 'dispatch' | 'commit';
  readonly signal: AbortSignal;
}

/** The trusted host must check the exact binding, evidence retention and current
 * authority, then reopen the complete original representation. Echoing a binding
 * or supplying caller bytes is not evidence/authorization for production. */
export interface RetainedSource {
  readonly binding: RefreshSourceBinding;
  readonly representation: 'full_original_response';
  readonly bytes: Uint8Array;
  /** Combined evidence/authority expiry, at or before the profile retention limit. */
  readonly validUntilMs: number;
}

export interface PrivateRefreshReceipt {
  readonly observationRef: string;
  readonly observationStatus: 'not_modified' | 'body_changed' | 'removed' | 'outage';
  readonly responseKind: 'not_modified' | 'body_unchanged' | 'body' | 'removed' | 'outage';
  readonly httpStatus: number;
  readonly invalidated: boolean;
  readonly duplicateObservation: boolean;
}

interface RefreshResultBase {
  readonly admissionRef: string;
  readonly profileRef: string;
  readonly profileVersion: number;
  readonly localRefreshId: string;
  /** Keyed digest in an EI-private binding domain, not a canonical source hash. */
  readonly bindingDigest: string;
  readonly replayed: boolean;
  readonly usage: 'unknown';
  readonly holdDisposition: 'finance_reconciliation_required';
}

export type PrivateRefreshResult =
  | (RefreshResultBase & { readonly status: 'completed'; readonly receipt: PrivateRefreshReceipt })
  | (RefreshResultBase & { readonly status: 'unknown'; readonly receipt?: never });

export interface PrivateCacheRevalidation {
  bindSource(scope: ScopedReuseScope, request: unknown, input: {
    readonly profileRef: string;
    readonly scopeKind: 'tenant_private';
    readonly sourceRef: string;
    readonly evidenceId: string;
    readonly evidenceVersion: number;
    readonly document: RetrievedDocument;
  }, options?: { readonly signal?: AbortSignal }): Promise<{
    readonly status: 'bound'; readonly profileRef: string; readonly profileVersion: number; readonly replayed: boolean;
  }>;
  refresh(scope: ScopedReuseScope, request: unknown, input: {
    readonly profileRef: string;
    readonly scopeKind: 'tenant_private';
    readonly admissionRef: string;
  }, options?: { readonly signal?: AbortSignal }): Promise<PrivateRefreshResult>;
}

export class CacheRevalidationError extends Error {
  readonly name: 'CacheRevalidationError';
  readonly code: 'REVALIDATION_INVALID' | 'REVALIDATION_UNSUPPORTED' | 'REVALIDATION_DENIED'
    | 'REVALIDATION_CANCELLED' | 'REVALIDATION_DEADLINE' | 'REVALIDATION_PROVENANCE';
}

export function createPrivateCacheRevalidation(options: {
  readonly store: ReuseStore;
  readonly safeFetcher: SafeFetcher;
  readonly readRetainedSource: (input: RetainedSourceInput) => RetainedSource | Promise<RetainedSource>;
  readonly timeoutMs?: number;
}): PrivateCacheRevalidation;
