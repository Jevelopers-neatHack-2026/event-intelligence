import type { EvidenceStore, EvidenceStoreOptions, EvidenceHandle, TextRangeLocator } from '../../evidence/store.mjs';

export declare const DECLARATION_PROFILE: 'ei-private-html-brand-declarations/1';
export declare const DECLARATION_LIMITS: Readonly<{
  sourceBytes: number; positions: number; nodes: number; observations: number;
  attributeCodeUnits: number; declarationCodeUnits: number; families: number;
  outputBytes: number; deadlineMs: number;
}>;
export type BrandDeclarationErrorCode = 'INVALID_INPUT' | 'BUSY' | 'CANCELED' | 'DEADLINE_EXCEEDED'
  | 'EVIDENCE_DENIED' | 'EVIDENCE_EXPIRED' | 'EVIDENCE_UNAVAILABLE' | 'SOURCE_MISMATCH'
  | 'SOURCE_INCOMPLETE' | 'UNSUPPORTED_SOURCE' | 'MALFORMED_HTML' | 'PARSER_FAILURE' | 'RESOURCE_LIMIT';
export declare class BrandDeclarationError extends Error {
  readonly code: BrandDeclarationErrorCode;
  constructor(code?: BrandDeclarationErrorCode);
}
export interface BrandDeclaration {
  readonly property: 'color' | 'background-color' | 'font-family' | 'theme-color';
  readonly value: string | readonly Readonly<{ kind: 'declared-name' | 'generic-family'; name: string }>[];
  readonly rawDeclaration: string;
  readonly sourceForm: 'inline-style' | 'meta-theme-color';
  readonly tagName: string;
  readonly locator: TextRangeLocator;
  /** Exact containing HTML start-tag range; includes conditional metadata without evaluating it. */
  readonly elementLocator: TextRangeLocator;
  readonly excerptHash: string;
}
export interface BrandDeclarations {
  readonly profile: typeof DECLARATION_PROFILE;
  readonly visibility: 'tenant_private';
  readonly trust: 'untrusted_source_declarations';
  readonly completeness: 'incomplete-supported-subset';
  readonly status: 'declarations_observed' | 'no_supported_declarations';
  readonly canonicalAdoption: false;
  readonly dispatchStatus: 'not_dispatched';
  readonly officialBrand: 'unknown';
  readonly renderedAppearance: 'not_evaluated';
  readonly fontAvailability: 'unknown';
  readonly permission: 'unknown';
  readonly source: Readonly<{
    evidenceId: string; version: number; contentHash: string; sourceUrl: string;
    sourceKind: 'external' | 'customer_supplied'; contentType: string;
    retrievedAt: string; expiresAt: string;
  }>;
  readonly declarations: readonly BrandDeclaration[];
  readonly unsupported: readonly Readonly<{
    code: 'UNSUPPORTED_VALUE' | 'STYLESHEET_NOT_EVALUATED' | 'EXTERNAL_STYLESHEET_NOT_FETCHED'
      | 'RAW_ATTRIBUTE_UNSUPPORTED' | 'COMPLEX_STYLE_UNSUPPORTED' | 'DUPLICATE_DECLARATION' | 'MALFORMED_STYLE';
    locator: TextRangeLocator | null;
  }>[];
}
export interface BrandDeclarationReader<Request extends object> {
  readonly evidenceStore: EvidenceStore<Request>;
  read(input: Readonly<{ evidence: EvidenceHandle; request: Request; signal?: AbortSignal }>): Promise<BrandDeclarations>;
}
/** Trusted composition only. No public package, rights or rendered-style contract. */
export declare function createBrandDeclarationReader<Request extends object>(options: Readonly<{
  evidenceStoreOptions: Omit<EvidenceStoreOptions<Request>, 'consumePrivatePayload' | 'authorizePrivateAccess'> & {
    readonly authorizePrivateAccess: NonNullable<EvidenceStoreOptions<Request>['authorizePrivateAccess']>;
  };
  /** Lower-only original elapsed operation budget, including both store reads and parsing. */
  deadlineMs?: number;
}>): BrandDeclarationReader<Request>;
