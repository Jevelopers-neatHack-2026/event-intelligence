export declare const CORROBORATION_SCHEMA: 'ei-source-corroboration-internal/v1';
export declare const CORROBORATION_POLICY: 'explicit-source-declaration/v1';

export interface SourceCorroborationNode {
  readonly candidateId: string;
  readonly kind: 'event' | 'organization';
  readonly entityKey: string;
  readonly entityPointer: string;
  readonly sourceEntityCount: number;
  readonly evidenceId: string;
  readonly contentHash: string;
  /** Observed retrieval URLs only. This does not authorize a network request. */
  readonly sourceUrls: readonly string[];
  /** Stable hashes of the candidate's retained identity support references. */
  readonly identityKeys: readonly string[];
}

export interface SourceAttributionReference {
  readonly evidenceId: string;
  readonly contentHash: string;
  readonly locator: Readonly<{ kind: 'text-range'; startByte: number; endByte: number }>;
  readonly positionHash: string;
  readonly jsonPointer: string;
}

export interface SourceAttributionClaimInput {
  readonly candidateId: string;
  readonly form: 'direct_string' | 'unsupported_shape' | 'unsupported_value';
  readonly status: 'retained' | 'legacy_position_unavailable' | 'unsupported';
  readonly targetUrl: string | null;
  readonly sourceRef: SourceAttributionReference;
  readonly factKey: string | null;
}

export interface SourceAttributionClaim extends SourceAttributionClaimInput {
  readonly claimId: string;
}

/** Per-result stored fact identity; deliberately outside stable policy hashes. */
export interface SourceCorroborationFactBinding {
  readonly claimId: string;
  readonly factId: string;
}

export interface SourceCorroborationEdge {
  readonly basis: 'exact_content' | 'source_declared_derivation';
  readonly from: string;
  readonly to: string;
  readonly claimId: string | null;
}

export interface SourceCorroborationCluster {
  readonly clusterId: string;
  readonly members: readonly string[];
  readonly independence: 'unknown';
  readonly origin: 'not_established';
}

export interface SourceCorroboration {
  readonly schema: typeof CORROBORATION_SCHEMA;
  readonly policy: typeof CORROBORATION_POLICY;
  readonly method: Readonly<{ name: 'retained-source-declaration'; version: '1' }>;
  readonly sourceAuthority: 'not_evaluated';
  readonly independence: 'unknown';
  readonly nodes: readonly SourceCorroborationNode[];
  readonly claims: readonly SourceAttributionClaim[];
  readonly edges: readonly SourceCorroborationEdge[];
  readonly clusters: readonly SourceCorroborationCluster[];
  readonly unresolved: readonly Readonly<{
    claimId: string;
    reason: 'legacy_position_unavailable' | 'unsupported' | 'target_not_retained' | 'target_ambiguous' | 'self_reference';
  }>[];
  readonly limits: Readonly<{ maxNodes: 23; maxClaims: 128; maxEdges: 256; maxUtf8Bytes: 65536 }>;
  readonly digest: string;
}

export declare class CorroborationError extends Error {
  readonly code: 'INVALID' | 'LIMIT';
  constructor(code?: 'INVALID' | 'LIMIT');
}

/** Only use for already bounded plain data, never raw untrusted objects. */
export declare function stableCorroborationJson(value: unknown): string;
export declare function corroborationDigest(domain: string, value: unknown): string;
export declare function normalizedAttributionUrl(value: unknown): string | null;
export declare function buildSourceCorroboration(nodes: readonly SourceCorroborationNode[], claims: readonly SourceAttributionClaimInput[]): SourceCorroboration;
export declare function validateSourceCorroboration(value: unknown): SourceCorroboration;
