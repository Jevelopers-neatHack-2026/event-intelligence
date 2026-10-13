declare const tenantScopeBrand: unique symbol;
declare const sourceHandleBrand: unique symbol;
declare const sessionBrand: unique symbol;
declare const resultBrand: unique symbol;
declare const derivativeBrand: unique symbol;

export type TenantScope = { readonly [tenantScopeBrand]: true };
export type SourceHandle = { readonly [sourceHandleBrand]: true };
export type BoundarySession = { readonly [sessionBrand]: true };
export type BoundaryResult = { readonly [resultBrand]: true };
export type SanitizedDerivative = { readonly [derivativeBrand]: true };

export type ContentModality =
  | 'html'
  | 'ocr_text'
  | 'pdf_text'
  | 'pdf_metadata'
  | 'plain_text'
  | 'image_binary'
  | 'pdf_binary'
  | 'attendee_csv'
  | 'unknown_binary';

export type BoundaryState =
  | 'accepting'
  | 'preparing'
  | 'ready_for_publish'
  | 'published'
  | 'quarantined'
  | 'cancelled'
  | 'expired';

export type QuarantineReason =
  | 'unverified_public_facts'
  | 'review_unavailable'
  | 'unsupported_modality'
  | 'invalid_text'
  | 'invalid_candidate'
  | 'invalid_review_decision'
  | 'source_expired'
  | 'cancelled';

export type PublicFacts = Readonly<Partial<{
  event_name: string;
  event_date: string;
  venue: string;
}>>;

export interface SourceDocument {
  readonly modality: ContentModality;
  readonly content: string | Uint8Array;
}

export interface PublicFactReviewInput {
  readonly tenantId: string;
  readonly sourceDigest: string;
  readonly modality: ContentModality;
  readonly candidate: PublicFacts;
  readonly signal: { readonly aborted: boolean };
  /** Reads only while this prepare attempt is active and its original is retained. */
  readSourceText(): string;
}

export interface PublicFactReviewDecision {
  readonly status: 'approved' | 'rejected';
  readonly tenantId: string;
  readonly sourceDigest: string;
  readonly facts?: PublicFacts;
}

export interface SafeDiagnostics {
  readonly recordId: string;
  readonly state: BoundaryState;
  readonly modality: ContentModality;
  readonly trust: 'untrusted_external';
  readonly reasonCode: QuarantineReason | null;
  readonly redactionCategories: readonly string[];
}

export interface BoundaryStart {
  readonly source: SourceHandle;
  readonly session: BoundarySession;
}

export interface PrivateReviewInput {
  readonly tenantId: string;
  readonly modality: ContentModality;
  readonly sourceDigest: string;
  readonly content: string | Uint8Array;
  readonly request: unknown;
}

export interface PrivacyBoundaryOptions<Request = unknown> {
  /** Must read tenant scope only from an authenticated app-owned request contract. */
  resolveTenant?: (request: Request) => string;
  /** Trusted verifier port. With no verifier, every textual candidate is quarantined. */
  reviewPublicFacts?: (input: PublicFactReviewInput) => PublicFactReviewDecision | Promise<PublicFactReviewDecision>;
  /** Optional actor-level gate for explicit private review. */
  authorizePrivateReview?: (input: { readonly tenantId: string; readonly request: unknown }) => boolean | Promise<boolean>;
  /** Runs inside the trusted private-review adapter; raw content is never returned by the boundary itself. */
  consumePrivateOriginal?: (input: PrivateReviewInput) => unknown | Promise<unknown>;
  retentionMs?: number;
  maxSourceBytes?: number;
  now?: () => number;
}

export interface PrivacyBoundary<Request = unknown> {
  scopeForAuthenticatedRequest(request: Request): TenantScope;
  begin(scope: TenantScope, document: SourceDocument): BoundaryStart;
  restart(scope: TenantScope, source: SourceHandle): BoundarySession;
  prepare(scope: TenantScope, session: BoundarySession, candidate?: PublicFacts): Promise<BoundaryResult>;
  /** Synchronous commit point. Cancellation that commits first prevents publication. */
  publish(scope: TenantScope, session: BoundarySession): SanitizedDerivative;
  cancel(scope: TenantScope, session: BoundarySession): boolean;
  result(scope: TenantScope, session: BoundarySession): BoundaryResult;
  diagnostics(scope: TenantScope, result: BoundaryResult): SafeDiagnostics;
  exportDerivative(scope: TenantScope, derivative: SanitizedDerivative): Readonly<{
    recordId: string;
    modality: ContentModality;
    trust: 'untrusted_external';
    facts: PublicFacts;
  }>;
  /** Revokes only the private source association; public derivative serialization is unchanged. */
  revokeSourceAssociation(scope: TenantScope, derivative: SanitizedDerivative): boolean;
  withPrivateOriginal(scope: TenantScope, source: SourceHandle, request: unknown): Promise<unknown>;
  purgeExpired(): number;
  retainedOriginalCount(): number;
  sessionState(scope: TenantScope, session: BoundarySession): BoundaryState;
  /** Internal partition capability used by privacy flow adapters; it contains no tenant label. */
  scopePartition(scope: TenantScope): object;
}

export declare function createPrivacyBoundary<Request = unknown>(options?: PrivacyBoundaryOptions<Request>): PrivacyBoundary<Request>;
/** @internal Authenticity check used by the adjacent flow adapter. */
export declare function isPrivacyBoundary(value: unknown): value is PrivacyBoundary;
/** @internal Requires genuine issuer-backed handles; a digest is never a permission grant. */
export declare function readDerivativeSourceAssociation(
  boundary: PrivacyBoundary,
  scope: TenantScope,
  derivative: SanitizedDerivative,
): Readonly<{
  tenantId: string;
  recordId: string;
  modality: ContentModality;
  sourceDigest: string;
  signal: AbortSignal;
}>;
