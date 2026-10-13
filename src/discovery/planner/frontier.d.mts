declare const frontierTenantScopeBrand: unique symbol;

export type FrontierTenantScope = { readonly [frontierTenantScopeBrand]: true };

export type FrontierStopReason =
  | 'cancelled'
  | 'budget_denied'
  | 'access_restricted'
  | 'deadline'
  | 'attempt_limit'
  | 'frontier_exhausted'
  | 'depth_limit'
  | 'fanout_limit'
  | 'unresolved_work'
  | 'adequate_facts'
  | 'review_required';

export type FrontierErrorCode =
  | 'FRONTIER_INVALID_INPUT'
  | 'FRONTIER_DENIED'
  | 'FRONTIER_NOT_FOUND'
  | 'FRONTIER_CONFLICT'
  | 'FRONTIER_STOPPED'
  | 'FRONTIER_STALE_LEASE'
  | 'FRONTIER_BUSY'
  | 'FRONTIER_STORAGE_LIMIT'
  | 'FRONTIER_VERSION'
  | 'FRONTIER_STORAGE';

export type FrontierLocator =
  | { readonly kind: 'text-range'; readonly startByte: number; readonly endByte: number }
  | { readonly kind: 'json-pointer'; readonly pointer: string };

/** A caller-projected reference to an already validated private evidence position. */
export interface FrontierSourceReference {
  readonly evidenceId: string;
  readonly contentHash: string;
  readonly locator: FrontierLocator;
  readonly field: string;
  /** Must equal the exact supplied link value. */
  readonly value: string;
}

export interface FrontierSeedInput {
  readonly url: string;
  readonly sourceRefs?: readonly FrontierSourceReference[];
}

export interface FrontierSuggestionInput {
  readonly url: string;
  readonly label?: string;
  readonly sourceRefs: readonly FrontierSourceReference[];
}

export interface FrontierLimits {
  readonly maxDepth?: number;
  readonly maxTransportAttemptAdmissions?: number;
  readonly maxInFlightLeases?: number;
  readonly durationMs?: number;
  readonly maxSuggestionsPerCompletion?: number;
}

/** Trusted local policy, bound immutably to the tenant database on first use. */
export interface FrontierTenantLimits {
  /** Defaults to 4; includes leases retained by any uncertain transport exposure. */
  readonly maxInFlightLeases?: number;
  /** Defaults to 100 MiB; outstanding reservations only, not cumulative spend. */
  readonly maxReservedDecodedBytes?: number;
}

export interface FrontierTenantProgress {
  readonly limits: Required<FrontierTenantLimits>;
  readonly inFlightLeases: number;
  readonly reservedBytes: number;
  readonly availableInFlightLeases: number;
  readonly availableReservedBytes: number;
  readonly unsettledTransportHops: number;
  /** Admissions without transport rows, excluding v1 full-run reservations. */
  readonly untrackedAttempts: number;
  readonly legacyUnknownRuns: number;
}

export interface FrontierRunInput {
  readonly runId: string;
  readonly seeds: readonly FrontierSeedInput[];
  readonly limits?: FrontierLimits;
  /** Optional private retrieval policy binding; omission preserves the historical default-off config hash. */
  readonly privateRunConfigHash?: string;
}

export interface FrontierCandidate {
  readonly candidateId: string;
  readonly canonicalUrl: string;
  readonly depth: number;
  readonly state: 'queued' | 'leased' | 'completed' | 'unresolved' | 'depth_limited';
  readonly seed: boolean;
  readonly admittedAttemptCount: number;
  readonly completionOutcome?: 'links_observed' | 'no_links' | 'failed' | 'access_restricted';
  readonly activeLease?: { readonly claimKey: string; readonly workerId: string };
  readonly unresolvedReason?: 'worker_lost' | 'dispatch_state_unknown' | 'cancelled_before_dispatch';
  readonly sourceRefs: readonly FrontierSourceReference[];
  readonly sourceAuthority: 'not_evaluated';
}

export interface FrontierObservation {
  readonly kind: 'seed' | 'link';
  readonly parentCandidateId: string | null;
  readonly targetCandidateId: string;
  readonly suppliedUrl: string;
  readonly canonicalUrl: string;
  readonly depth: number;
  readonly untrustedLabel?: string;
  readonly sourceRefs: readonly FrontierSourceReference[];
  readonly disposition: 'seed' | 'duplicate' | 'cycle' | 'depth_limit' | 'queued' | 'retained_after_stop';
  readonly outcome?: 'links_observed' | 'no_links' | 'failed' | 'access_restricted';
  readonly sourceAuthority: 'not_evaluated';
}

export interface FrontierSnapshot {
  readonly schema: 'ei-private-bounded-frontier/v1';
  readonly runId: string;
  readonly createdAtMs: number;
  readonly deadlineAtMs: number;
  readonly lastObservedClockMs: number;
  readonly state: 'active' | 'halted' | 'exhausted';
  readonly stopReason: FrontierStopReason | null;
  readonly stopReasons: readonly { readonly reason: FrontierStopReason; readonly occurredAtMs: number }[];
  readonly limits: Required<FrontierLimits>;
  readonly counters: {
    readonly seedInputs: number;
    readonly uniqueCandidates: number;
    readonly transportAttemptAdmissions: number;
    readonly inFlightLeases: number;
  };
  readonly candidates: readonly FrontierCandidate[];
  readonly observations: readonly FrontierObservation[];
  readonly attempts: readonly {
    readonly attemptKey: string;
    readonly sequence: number;
    readonly candidateId: string;
    readonly kind: 'initial' | 'retry' | 'redirect';
    readonly previousAttemptKey: string | null;
    readonly canonicalUrl: string;
    readonly admittedAtMs: number;
  }[];
  readonly duplicateContentGroups: readonly {
    readonly contentHash: string;
    readonly evidenceIds: readonly string[];
    readonly independence: 'unknown';
  }[];
  readonly sourceAuthority: 'not_evaluated';
  readonly independentCorroboration: 'not_evaluated';
  readonly usageStatus: 'unknown';
  readonly budgetAuthority: 'not_evaluated';
  readonly transportDispatch: 'not_implemented';
  readonly readiness: 'blocked_no_transport_adapter';
}

export type FrontierClaimResult =
  | {
      readonly state: 'claimed' | 'completed' | 'unresolved';
      /** True when this is the original durable lease; it never authorizes redispatch. */
      readonly replayed: boolean;
      readonly claimKey: string;
      readonly leaseToken: string;
      readonly workerId: string;
      readonly candidate: Pick<FrontierCandidate, 'candidateId' | 'canonicalUrl' | 'depth' | 'admittedAttemptCount'>;
    }
  | { readonly state: 'stopped' | 'waiting' | 'empty'; readonly reason: string };

export interface FrontierClaimReceiptCandidate {
  readonly candidateId: string;
  readonly canonicalUrl: string;
  readonly depth: number;
  readonly seed: boolean;
  readonly sourceRefs: readonly FrontierSourceReference[];
  /** Stable representative observation selected from the claim-time prefix. */
  readonly suppliedUrl: string;
}

export interface FrontierCandidateReceiptBinding {
  readonly bindingVersion: 0 | 1;
  /** Null only for v1/v2 claims whose original observation cutoff was never stored. */
  readonly candidate: FrontierClaimReceiptCandidate | null;
  readonly claim: {
    readonly claimKey: string;
    readonly workerId: string;
    readonly leaseToken: string;
    readonly candidateId: string;
    readonly state: 'leased' | 'completed' | 'unresolved';
  };
  readonly completion: null | {
    readonly completionKey: string;
    readonly outcome: 'links_observed' | 'no_links' | 'failed' | 'access_restricted';
    /** SHA-256 of the exact normalized suggestions and truncation count committed by the completion. */
    readonly payloadHash: string;
  };
}

export type FrontierAttemptResult =
  | {
      readonly state: 'admitted';
      readonly attemptKey: string;
      readonly sequence: number;
      readonly admittedAtMs: number;
      readonly stopAfterThisAdmission: boolean;
    }
  /** Historical deduplication only; never authority for another real dispatch. */
  | { readonly state: 'already_admitted'; readonly attemptKey: string; readonly sequence: number; readonly admittedAtMs: number }
  | { readonly state: 'denied'; readonly reason: string };

export interface FrontierTransportProgress {
  readonly reservedBytes: number;
  readonly spentBytes: number;
  readonly availableBytes: number;
  readonly states: Readonly<Record<string, number>>;
  /** Runs migrated from v1 with unobservable transport exposure; their full budget remains reserved. */
  readonly legacyUnknownRuns: number;
}

export type FrontierTransportAdmissionResult =
  | {
      readonly state: 'admitted';
      readonly attemptKey: string;
      readonly sequence: number;
      readonly admittedAtMs: number;
      readonly stopAfterThisAdmission: boolean;
      readonly capacity: FrontierTransportProgress;
    }
  /** Historical status only; never authority to dispatch again after replay. */
  | { readonly state: 'already_admitted'; readonly transportState: string; readonly capacity: FrontierTransportProgress }
  | { readonly state: 'already_admitted_without_transport_state'; readonly capacity: FrontierTransportProgress }
  | { readonly state: 'denied'; readonly reason: string; readonly capacity: FrontierTransportProgress };

export interface DiscoveryFrontierOptions<Request = unknown> {
  /** Private local state root. The configured directory and its parent are trusted. */
  readonly directory: string;
  /** Must derive tenant identity from the authenticated server-side request. */
  readonly resolveTenant: (request: Request) => string | Promise<string>;
  /** Trusted clock injection for deterministic tests; persisted time never moves backward. */
  readonly now?: () => number;
  readonly lockTimeoutMs?: number;
  /** Every instance for a tenant database must supply the same normalized policy. */
  readonly tenantLimits?: FrontierTenantLimits;
}

export interface DiscoveryFrontierStore<Request = unknown> {
  scopeForAuthenticatedRequest(request: Request): Promise<FrontierTenantScope>;
  /** Saturates available capacity at zero without erasing migrated over-limit exposure. */
  getTenantProgress(scope: FrontierTenantScope, signal?: AbortSignal): Promise<FrontierTenantProgress>;
  createRun(scope: FrontierTenantScope, input: FrontierRunInput, signal?: AbortSignal): Promise<FrontierSnapshot>;
  claimNext(scope: FrontierTenantScope, runId: string, input: { readonly workerId: string; readonly claimKey: string }, signal?: AbortSignal): Promise<FrontierClaimResult>;
  /** Read the immutable claim-time candidate prefix and its durable claim/completion identity for private receipt replay. */
  getCandidateReceiptBinding(scope: FrontierTenantScope, runId: string, candidateId: string,
    signal?: AbortSignal): Promise<FrontierCandidateReceiptBinding | null>;
  /** Persist admission before a future adapter dispatches; replay only returns historical state. */
  admitAttempt(scope: FrontierTenantScope, runId: string, input: {
    readonly leaseToken: string;
    readonly attemptKey: string;
    readonly kind: 'initial' | 'retry' | 'redirect';
    readonly previousAttemptKey?: string;
    readonly url: string;
  }, signal?: AbortSignal): Promise<FrontierAttemptResult>;
  /** Atomically admits one actual hop and reserves the full 20MiB decoded ceiling before DNS/socket dispatch. */
  admitTransportHop(scope: FrontierTenantScope, runId: string, input: {
    readonly leaseToken: string;
    readonly attemptKey: string;
    readonly kind: 'initial' | 'retry' | 'redirect';
    readonly previousAttemptKey?: string;
    readonly url: string;
  }, signal?: AbortSignal): Promise<FrontierTransportAdmissionResult>;
  /** CAS transition. A replayed transition never authorizes another dispatch. */
  markTransportDispatchIntent(scope: FrontierTenantScope, runId: string, input: {
    readonly leaseToken: string; readonly attemptKey: string;
  }, signal?: AbortSignal): Promise<Readonly<Record<string, unknown>>>;
  markTransportResponseReceived(scope: FrontierTenantScope, runId: string, input: {
    readonly leaseToken: string; readonly attemptKey: string;
  }, signal?: AbortSignal): Promise<Readonly<Record<string, unknown>>>;
  /** Only use when local transport evidence proves body decoding never began. */
  settleTransportHopKnownZero(scope: FrontierTenantScope, runId: string, input: {
    readonly leaseToken: string; readonly attemptKey: string;
  }, signal?: AbortSignal): Promise<Readonly<Record<string, unknown>>>;
  /** EOF-only settlement; partial or ambiguous decodes retain the full reservation. */
  settleTransportHopBodyComplete(scope: FrontierTenantScope, runId: string, input: {
    readonly leaseToken: string; readonly attemptKey: string;
  }, decodedBytes: number, signal?: AbortSignal): Promise<Readonly<Record<string, unknown>>>;
  markTransportHopUnknown(scope: FrontierTenantScope, runId: string, input: {
    readonly leaseToken: string; readonly attemptKey: string;
  }, signal?: AbortSignal): Promise<Readonly<Record<string, unknown>>>;
  getTransportProgress(scope: FrontierTenantScope, runId: string, signal?: AbortSignal): Promise<FrontierTransportProgress>;
  completeCandidate(scope: FrontierTenantScope, runId: string, input: {
    readonly leaseToken: string;
    readonly completionKey: string;
    readonly outcome: 'links_observed' | 'no_links' | 'failed' | 'access_restricted';
    readonly suggestions: readonly FrontierSuggestionInput[];
    readonly truncatedCount?: number;
  }, signal?: AbortSignal): Promise<FrontierSnapshot>;
  markUnresolved(scope: FrontierTenantScope, runId: string, input: {
    readonly leaseToken: string;
    readonly reason: 'worker_lost' | 'dispatch_state_unknown' | 'cancelled_before_dispatch';
  }, signal?: AbortSignal): Promise<FrontierSnapshot>;
  stopRun(scope: FrontierTenantScope, runId: string,
    reason: 'cancelled' | 'budget_denied' | 'access_restricted' | 'adequate_facts' | 'review_required' | 'deadline', signal?: AbortSignal): Promise<FrontierSnapshot>;
  /** Atomic final-release/cancel race guard; an already sealed run cannot be canceled retroactively. */
  sealPrivateDraft(scope: FrontierTenantScope, runId: string, signal?: AbortSignal): Promise<Readonly<{
    state: 'sealed' | 'already_sealed' | 'denied'; reason?: string;
  }>>;
  getSnapshot(scope: FrontierTenantScope, runId: string, signal?: AbortSignal): Promise<FrontierSnapshot>;
  close(): void;
}

export declare class DiscoveryFrontierError extends Error {
  readonly code: FrontierErrorCode;
  constructor(code?: FrontierErrorCode);
}

/**
 * Private bounded candidate-frontier and checkpoint store. It does not perform
 * requests, attest transport, verify source authority, or authorize spending.
 */
export declare function createDiscoveryFrontierStore<Request = unknown>(
  options: DiscoveryFrontierOptions<Request>,
): DiscoveryFrontierStore<Request>;
