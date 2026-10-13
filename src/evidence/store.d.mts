import type { PdfTextReaderErrorCode } from '../extraction/pdf/index.mjs';
import type { RetrievedDocument, RetrievedSvgAssetDocument } from '../security/index.mjs';
import type {
  PrivateAssetReleaseAuthorityController,
  PrivateAssetReleaseCheck,
} from '../research/private-asset-release.mjs';

declare const tenantScopeBrand: unique symbol;
declare const evidenceHandleBrand: unique symbol;
declare const evidencePositionBrand: unique symbol;
declare const factHandleBrand: unique symbol;

export type EvidenceTenantScope = { readonly [tenantScopeBrand]: true };
export type EvidenceHandle = { readonly [evidenceHandleBrand]: true };
export type EvidencePositionHandle = { readonly [evidencePositionBrand]: true };
export type EvidenceFactHandle = { readonly [factHandleBrand]: true };

export type EvidenceErrorCode =
  | 'EVIDENCE_DENIED'
  | 'EVIDENCE_INVALID'
  | 'EVIDENCE_NOT_FOUND'
  | 'EVIDENCE_EXPIRED'
  | 'EVIDENCE_BUSY'
  | 'EVIDENCE_INTEGRITY'
  | 'EVIDENCE_KEY_UNAVAILABLE'
  | 'EVIDENCE_CANCELLED'
  | 'EVIDENCE_STORAGE';

export declare class EvidenceStoreError extends Error {
  readonly code: EvidenceErrorCode;
  constructor(code: EvidenceErrorCode);
}

export interface EvidenceStoreKeyRequest {
  readonly tenantId: string;
  readonly purpose: 'payload' | 'fact' | 'source-index';
  readonly keyId?: string;
}

export interface EvidenceStoreKey {
  readonly keyId: string;
  /** A fresh 32-byte AES/HMAC key from the trusted application key resolver. */
  readonly key: Uint8Array;
}

export interface EvidenceRetentionRequest {
  readonly tenantId: string;
  readonly kind: 'evidence' | 'fact';
  readonly sourceKind?: 'external' | 'customer_supplied' | 'sourced' | 'inferred' | 'conflicting' | 'missing';
  readonly nowMs: number;
  /** Facts cannot outlive any evidence record that supports them. */
  readonly sourceExpiresAtMs?: number;
  /** An opaque, app-issued permit linked to the source's existing retention decision. */
  readonly retentionHandle?: object;
}

export interface EvidenceRetentionDecision {
  readonly expiresAtMs: number;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly accessPolicy: 'tenant_private';
}

export interface TextRangeLocator {
  readonly kind: 'text-range';
  /** UTF-8 byte positions in the complete fetched source. */
  readonly startByte: number;
  readonly endByte: number;
}

export interface JsonPointerLocator {
  readonly kind: 'json-pointer';
  /** RFC 6901 pointer into a JSON or JSON-LD source. */
  readonly pointer: string;
}

export interface EvidencePositionInput {
  readonly locator: TextRangeLocator | JsonPointerLocator;
  /** Exact bytes selected by locator; persisted only after it matches the source. */
  readonly content: string | Uint8Array;
}

export interface PdfTextBoxLocator {
  readonly kind: 'pdf-text-box';
  readonly pageIndex: number;
  readonly textIndex: number;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  readonly pageWidth: number;
  readonly pageHeight: number;
  readonly rotation: 0 | 90 | 180 | 270;
  readonly coordinateSystem: 'viewport-points-top-left';
  readonly geometry: 'approximate-text-item';
}

export type StoredEvidenceLocator = TextRangeLocator | JsonPointerLocator | PdfTextBoxLocator;

export interface StoredPdfDerivedPage {
  readonly pageIndex: number;
  readonly width: number;
  readonly height: number;
  readonly rotation: 0 | 90 | 180 | 270;
  readonly coordinateSystem: 'viewport-points-top-left';
  readonly textPresence: 'text-present' | 'no-embedded-text';
  readonly requiresInspection: true;
  readonly textBoxCount: number;
}

export interface PdfDerivedProvenance {
  readonly bindingVersion: 1;
  readonly decoder: Readonly<{ name: 'pdfjs-dist'; version: '6.4.299'; configVersion: 'ei-text-pdf/1' }>;
  readonly completeness: 'incomplete-text-only';
  readonly requiresInspection: true;
  readonly limits: Readonly<Record<string, number>>;
  readonly pages: readonly StoredPdfDerivedPage[];
  readonly textBoxCount: number;
  readonly derivationDigest: string;
}

export interface AvailableEvidenceMetadata {
  readonly evidenceId: string;
  readonly version: number;
  readonly previousEvidenceId: string | null;
  readonly contentHash: string;
  /** Exact-content duplicate cluster; it does not establish source independence or authority. */
  readonly duplicateGroupId: string;
  readonly retrievedAt: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly accessPolicy: 'tenant_private';
  readonly state: 'available';
  readonly positionCount: number;
  readonly representation?: 'pdf-derived-text' | 'asset-source-excerpt';
  readonly derivationDigest?: string;
}

/** A minimal tombstone with no content hash, URL key, timestamp, or source linkage. */
export interface ExpiredEvidenceMetadata {
  readonly evidenceId: string;
  readonly state: 'expired';
  readonly positionCount: 0;
}

export type EvidenceMetadata = AvailableEvidenceMetadata | ExpiredEvidenceMetadata;

export interface EvidenceIngestInput {
  readonly sourceUrl: string;
  readonly canonicalUrl?: string;
  readonly redirectChain?: readonly string[];
  readonly content: string | Uint8Array;
  readonly contentType: string;
  readonly retrievedAt: string;
  readonly sourceKind: 'external' | 'customer_supplied';
  readonly positions: readonly EvidencePositionInput[];
  /** Opaque app-issued retention capability. Caller tenant fields are never accepted. */
  readonly retentionHandle: object;
}

export interface EvidenceIngestResult {
  readonly evidence: EvidenceHandle;
  readonly positions: readonly EvidencePositionHandle[];
  readonly created: boolean;
  readonly metadata: AvailableEvidenceMetadata;
}

export interface ControlledAssetEvidenceIngestResult extends EvidenceIngestResult {
  readonly outcome: 'stored';
}

export interface ControlledAssetProvenance {
  readonly schemaVersion: 1;
  readonly policyVersion: 'ei-private-svg-acquisition/1';
  readonly policyId: string;
  readonly role: 'fetched-source' | 'transformed';
  readonly inspectionPolicyVersion: 'svg-static-geometry/1';
  readonly sourceEvidenceId: string;
  readonly sourceEvidenceVersion: number;
  readonly sourceContentHash: string;
  readonly sourceDerivationDigest: string;
  readonly sourceUrl: string;
  readonly candidateId: string;
  readonly positionIndex: number;
  readonly sourceForm: AssetSourceForm;
  readonly sourceLocator: TextRangeLocator;
  readonly excerptHash: string;
  readonly field: string;
  readonly value: string;
  readonly assetUrl: string;
  readonly sourceBytesHash: string;
  readonly transformedBytesHash: string;
}

export interface ControlledAssetEvidenceIngestInput {
  /** Original result object supplied by the trusted same-run composition; copied documents lack its process-local witness. */
  readonly document: RetrievedSvgAssetDocument;
  readonly retentionHandle: object;
  readonly retentionCeiling: Readonly<{
    evidence: EvidenceHandle;
    version: number;
    contentHash: string;
  }>;
  /** Opaque, one-process witness from the trusted private-retrieval composition. */
  readonly witness: object;
  readonly provenance: ControlledAssetProvenance;
}

export interface ControlledAssetAcquisitionBinding {
  readonly schemaVersion: 1;
  readonly policyVersion: 'ei-private-svg-acquisition/1';
  readonly policyId: string;
  readonly sourceEvidenceId: string;
  readonly sourceEvidenceVersion: number;
  readonly sourceContentHash: string;
  readonly sourceDerivationDigest: string;
  readonly sourceUrl: string;
  readonly candidateId: string;
  readonly positionIndex: number;
  readonly sourceForm: AssetSourceForm;
  readonly sourceLocator: TextRangeLocator;
  readonly excerptHash: string;
  readonly field: string;
  readonly value: string;
  readonly assetUrl: string;
}

export interface AssetSourceCandidateBindingRead {
  readonly evidenceId: string;
  readonly metadata: AvailableEvidenceMetadata & {
    readonly representation: 'asset-source-excerpt';
    readonly derivationDigest: string;
  };
  readonly source: EvidenceSelectedEvidence['source'];
  readonly candidate: Readonly<{
    readonly candidateId: string;
    readonly positionIndex: number;
    readonly sourceForm: AssetSourceForm;
    readonly locator: TextRangeLocator;
    readonly excerptHash: string;
    readonly field: string;
    readonly fetchSuggestion: string;
    readonly quarantineReason: null;
    /** Exact UTF-8 value copied from the encrypted source position. */
    readonly value: string;
  }>;
}

export interface ControlledAssetAcquisitionArtifact {
  readonly evidenceId: string;
  readonly version: number;
  readonly contentHash: string;
  readonly byteLength: number;
}

export interface ControlledAssetAcquisitionCompletion {
  readonly schemaVersion: 1;
  readonly policyVersion: 'ei-private-svg-acquisition/1';
  readonly inspectionPolicyVersion: 'svg-static-geometry/1';
  readonly binding: ControlledAssetAcquisitionBinding;
  readonly sourceBytesHash: string;
  readonly transformedBytesHash: string;
  readonly originalEvidence: ControlledAssetAcquisitionArtifact;
  readonly transformedEvidence: ControlledAssetAcquisitionArtifact;
}

export interface PdfDerivedReaderOptions {
  /** Lower than the reader's fixed maximum. Timeout is operational and excluded from derivation identity. */
  readonly timeoutMs?: number;
  /** Lower-only decoder caps; the effective values are persisted in provenance. */
  readonly maxTextCodeUnits?: number;
  readonly maxOutputBytes?: number;
}

export interface PdfDerivedEvidenceIngestInput {
  readonly sourceUrl: string;
  readonly canonicalUrl?: string;
  readonly redirectChain?: readonly string[];
  /** Exact copied bytes fetched from the source. Strings are rejected to avoid re-encoding the PDF. */
  readonly content: Uint8Array;
  readonly contentType: string;
  readonly retrievedAt: string;
  readonly sourceKind: 'external' | 'customer_supplied';
  /** Opaque app-issued retention capability; caller tenant fields are never accepted. */
  readonly retentionHandle: object;
  readonly readerOptions?: PdfDerivedReaderOptions;
}

export type AssetSourceForm = 'html-img-src' | 'html-icon-link' | 'open-graph-image' | 'jsonld-image' | 'jsonld-logo';
export type AssetSourceQuarantineReason =
  | 'invalid_or_empty'
  | 'unresolvable_url'
  | 'unsupported_scheme'
  | 'sensitive_query'
  | 'url_policy_denied';
export type AssetSourceAssociation =
  | Readonly<{ kind: 'unassigned-page' }>
  | Readonly<{
    kind: 'entity-source-claim';
    entityKind: 'event' | 'organization';
    entityId: string;
    blockIndex: number;
    entityPointer: string;
    assetPointer: string;
  }>
  | Readonly<{
    kind: 'nested-entity-source-claim';
    parentEntityKind: 'event';
    parentEntityId: string;
    roleHint: 'organizer';
    parentPointer: string;
    assetPointer: string;
  }>;

export interface StoredAssetSourceCandidate {
  readonly candidateId: string;
  readonly positionIndex: number;
  readonly sourceForm: AssetSourceForm;
  readonly field: string;
  readonly relationHint: string | null;
  /** A source claim only. It does not identify or verify an event or company. */
  readonly association: AssetSourceAssociation;
  readonly locator: TextRangeLocator;
  /** SHA-256 of the exact private source excerpt, not of fetched asset bytes. */
  readonly excerptHash: string;
  /** Present on selector-3 through selector-6 records; distinguishes URL value bytes from an empty/missing HTML attribute token. */
  readonly excerptKind?: 'url-value' | 'html-empty-attribute-token';
  readonly normalizedSuggestion: string | null;
  readonly fetchSuggestion: string | null;
  readonly quarantineReason: AssetSourceQuarantineReason | null;
  readonly role: 'unknown';
  readonly permission: 'unknown';
  readonly inspection: 'pending';
}

export interface AssetSourceProvenance {
  readonly bindingVersion: 1;
  readonly selectorVersion: 'ei-asset-source-selector/1' | 'ei-asset-source-selector/2' | 'ei-asset-source-selector/3' | 'ei-asset-source-selector/4' | 'ei-asset-source-selector/5' | 'ei-asset-source-selector/6';
  readonly extractorVersion: string;
  readonly sourceUrl: string;
  readonly sourceKind: 'external';
  readonly completeness: 'static-selected-forms-only';
  readonly limitations: readonly string[];
  readonly candidates: readonly StoredAssetSourceCandidate[];
  readonly derivationDigest: string;
}

export interface AssetSourceEvidenceIngestInput {
  /** Completed HTML/XHTML/JSON-LD bytes from the existing retrieval boundary; redirects must be zero. */
  readonly document: RetrievedDocument;
  /** Existing app-issued tenant-private source retention capability. */
  readonly retentionHandle: object;
}

export type AssetSourceEvidenceIngestResult =
  | (Omit<EvidenceIngestResult, 'metadata'> & {
    readonly outcome: 'stored';
    readonly metadata: AvailableEvidenceMetadata & {
      readonly representation: 'asset-source-excerpt';
      readonly derivationDigest: string;
    };
  })
  | { readonly outcome: 'no-candidates'; readonly code: 'NO_STATIC_ASSET_CANDIDATES' }
  | {
    readonly outcome: 'rejected';
    readonly code:
      | 'SOURCE_EXTRACTION_FAILURE'
      | 'SOURCE_EXTRACTION_INCOMPLETE'
      | 'SOURCE_URL_POLICY_DENIED'
      | 'SOURCE_ACCESS_RESTRICTED'
      | 'SOURCE_DYNAMIC_OR_INCOMPLETE'
      | 'SOURCE_UNSUPPORTED_OR_MALFORMED'
      | 'ASSET_CANDIDATE_LIMIT';
  };

export type PdfDerivedEvidenceIngestResult =
  | (Omit<EvidenceIngestResult, 'metadata'> & {
    readonly outcome: 'stored';
    readonly metadata: AvailableEvidenceMetadata & {
      readonly representation: 'pdf-derived-text';
      readonly derivationDigest: string;
    };
  })
  | { readonly outcome: 'no-text'; readonly code: 'NO_EMBEDDED_TEXT'; readonly requiresInspection: true }
  | { readonly outcome: 'rejected'; readonly code: PdfTextReaderErrorCode };

export interface EvidenceSupportInput {
  readonly evidence: EvidenceHandle;
  readonly position: EvidencePositionHandle;
  readonly contentHash: string;
}

export interface EvidenceFactValue {
  readonly rawValue: unknown;
  readonly normalizedValue: unknown;
  readonly precision?: 'date' | 'local_datetime' | 'instant' | 'unknown';
}

export interface EvidenceMethod {
  readonly name: string;
  readonly version: string;
}

export interface SourcedFactInput extends EvidenceFactValue {
  readonly field: string;
  readonly status: 'sourced' | 'customer_supplied';
  readonly supports: readonly EvidenceSupportInput[];
}

export interface InferredFactInput extends EvidenceFactValue {
  readonly field: string;
  readonly status: 'inferred';
  readonly supports: readonly EvidenceSupportInput[];
  readonly method: EvidenceMethod;
}

export interface MissingFactInput {
  readonly field: string;
  readonly status: 'missing';
  readonly reason?: string;
}

export interface ConflictingFactCandidate extends EvidenceFactValue {
  readonly originStatus: 'sourced' | 'inferred' | 'customer_supplied';
  readonly supports: readonly EvidenceSupportInput[];
  readonly method?: EvidenceMethod;
}

export interface ConflictingFactInput {
  readonly field: string;
  readonly status: 'conflicting';
  readonly candidates: readonly [ConflictingFactCandidate, ConflictingFactCandidate, ...ConflictingFactCandidate[]];
}

export type EvidenceFactInput = SourcedFactInput | InferredFactInput | MissingFactInput | ConflictingFactInput;

export interface EvidenceFactSupport extends EvidenceSupportInput {
  readonly duplicateGroupId: string;
  readonly independence: 'unknown';
}

export interface StoredEvidenceFact extends EvidenceFactValue {
  readonly factId: string;
  readonly field: string;
  readonly status: 'sourced' | 'inferred' | 'customer_supplied';
  readonly method?: EvidenceMethod;
  readonly supports: readonly EvidenceFactSupport[];
}

export interface StoredMissingFact {
  readonly factId: string;
  readonly field: string;
  readonly status: 'missing';
  readonly reason: string;
  readonly supports: readonly [];
}

export interface StoredConflictingFact {
  readonly factId: string;
  readonly field: string;
  readonly status: 'conflicting';
  readonly candidates: readonly (EvidenceFactValue & {
    readonly originStatus: 'sourced' | 'inferred' | 'customer_supplied';
    readonly method?: EvidenceMethod;
    readonly supports: readonly EvidenceFactSupport[];
  })[];
}

export type StoredEvidenceFactRecord = StoredEvidenceFact | StoredMissingFact | StoredConflictingFact;

export interface EvidencePrivatePayloadInput<Request = unknown> {
  readonly tenantId: string;
  readonly evidenceId: string;
  readonly metadata: AvailableEvidenceMetadata;
  readonly source: Readonly<{
    sourceUrl: string;
    canonicalUrl: string;
    redirectChain: readonly string[];
    contentType: string;
    sourceKind: 'external' | 'customer_supplied';
    retrievedAt: string;
    retrievedAtMs: number;
    contentHash: string;
    /** Present only for derived PDF text, and remains private provenance. */
    derivedPdf?: PdfDerivedProvenance;
    /** Present only for the encrypted asset source excerpt representation. */
    assetSource?: AssetSourceProvenance;
    /** Present only on encrypted controlled SVG acquisition evidence. */
    controlledAsset?: ControlledAssetProvenance;
  }>;
  readonly positions: readonly Readonly<{
    locator: StoredEvidenceLocator;
    contentHash: string;
    content: Uint8Array;
  }>[];
  readonly request: Request;
}

export type EvidencePrivatePayloadValue =
  | null
  | boolean
  | number
  | string
  | readonly EvidencePrivatePayloadValue[]
  | { readonly [key: string]: EvidencePrivatePayloadValue };
export type EvidencePrivatePayloadResult = EvidencePrivatePayloadValue | undefined;

export interface EvidenceSelectedEvidence {
  readonly handle: EvidenceHandle;
  readonly metadata: AvailableEvidenceMetadata;
  /** Stored private provenance; these values come from the encrypted bundle, not caller descriptors. */
  readonly source: Readonly<{
    sourceUrl: string;
    canonicalUrl: string;
    redirectChain: readonly string[];
    contentType: string;
    sourceKind: 'external' | 'customer_supplied';
    retrievedAt: string;
    retrievedAtMs: number;
    /** Full source SHA-256; each position carries its own selected-content hash. */
    contentHash: string;
    /** Present only for derived PDF text. Contains no text bytes or text strings. */
    derivedPdf?: PdfDerivedProvenance;
    /** Present only for asset source excerpts. Text remains behind the private payload capability. */
    assetSource?: AssetSourceProvenance;
    /** Present only on encrypted controlled SVG acquisition evidence. */
    controlledAsset?: ControlledAssetProvenance;
  }>;
  readonly positions: readonly Readonly<{
    handle: EvidencePositionHandle;
    locator: StoredEvidenceLocator;
    /** Digest of the exact selected position bytes, distinct from source.contentHash. */
    contentHash: string;
  }>[];
}

export interface EvidenceSelectedMaterialization {
  readonly evidence: readonly EvidenceSelectedEvidence[];
  readonly facts: readonly StoredEvidenceFactRecord[];
}

export interface EvidenceSelectedMaterializationInput {
  /** At most eight direct evidence handles; supporting evidence for selected facts is included automatically. */
  readonly evidence: readonly EvidenceHandle[];
  /** At most 128 selected fact handles. */
  readonly facts: readonly EvidenceFactHandle[];
}

export interface EvidenceStoreOptions<Request = unknown> {
  /** Trusted local storage path, configured by the application composition root. */
  readonly directory: string;
  /** Must derive tenant identity from the authenticated server-side request. */
  readonly resolveTenant: (request: Request) => string | Promise<string>;
  /** Trusted key manager. Never log or serialize returned key bytes. */
  readonly resolveKey: (request: EvidenceStoreKeyRequest) => EvidenceStoreKey | Promise<EvidenceStoreKey>;
  /** Must bind evidence retentionHandle to the source's existing privacy expiry. */
  readonly resolveRetention: (request: EvidenceRetentionRequest) => EvidenceRetentionDecision | Promise<EvidenceRetentionDecision>;
  readonly authorizePrivateAccess?: (request: Readonly<{
    tenantId: string;
    request: Request;
    action: string;
    evidenceIds: readonly string[];
    factIds: readonly string[];
  }>) => boolean | Promise<boolean>;
  /**
   * Required for any private result release. Must synchronously re-derive the
   * current authenticated tenant and current ACL for the exact action and IDs.
   * It receives the expected tenant from an opaque store scope and must compare
   * that with current host identity. Promise/thenable results fail closed.
   */
  readonly authorizePrivateAccessCurrent: (request: Readonly<{
    tenantId: string;
    request: Request;
    action: string;
    evidenceIds: readonly string[];
    factIds: readonly string[];
  }>) => boolean;
  /** Trusted synchronous consumer for explicitly authorized private evidence. Runtime-denies native Promise results. */
  readonly consumePrivatePayload?: (input: EvidencePrivatePayloadInput<Request>) => EvidencePrivatePayloadResult;
  readonly now?: () => number;
  readonly maxSourceBytes?: number;
  readonly maxPositionBytes?: number;
  readonly maxPositionCount?: number;
  readonly maxStoredPayloadBytes?: number;
  readonly maxRetentionMs?: number;
  /**
   * Original elapsed budget for each lock operation, including queue/open/retry
   * and transaction work. Expired boundaries fail EVIDENCE_BUSY. It does not
   * bound earlier key work or preempt synchronous host callbacks or SQLite.
   */
  readonly lockTimeoutMs?: number;
}

export interface EvidenceIntegritySnapshot {
  readonly availableEvidence: number;
  readonly expiredEvidence: number;
  readonly availableFacts: number;
  readonly expiredFacts: number;
  readonly encryptedPayloadRecords: number;
  readonly encryptedPrivateReceiptRecords: number;
}

export interface PrivateRetrievalReceiptCandidate {
  readonly candidateId: string;
  readonly canonicalUrl: string;
  /** Present on new v3 frontier claims; absent from historical v1/v2 receipt bindings. */
  readonly suppliedUrl?: string;
  readonly depth: number;
  readonly seed: boolean;
  readonly sourceRefs: readonly Readonly<{
    evidenceId: string;
    contentHash: string;
    locator: TextRangeLocator | JsonPointerLocator;
    field: string;
    value: string;
  }>[];
  readonly assetAcquisition?: ControlledAssetAcquisitionBinding;
}

export interface PrivateRetrievalReceiptClaim {
  readonly claimKey: string;
  readonly workerId: string;
  readonly leaseToken: string;
}

export interface PrivateRetrievalReceiptIdentity {
  readonly entityCandidates: readonly unknown[];
  readonly occurrenceCandidates: readonly unknown[];
  readonly transitionLinks: readonly unknown[];
  readonly unresolvedTransitions: readonly unknown[];
}

export interface PrivateRetrievalReceiptCompletion {
  readonly completionKey: string;
  readonly outcome: 'links_observed' | 'no_links' | 'failed' | 'access_restricted';
  readonly suggestions: readonly unknown[];
  readonly limitations: readonly string[];
  readonly identity: PrivateRetrievalReceiptIdentity;
  /** Omission fields are optional for callers writing historical v1 completion shapes. */
  readonly truncatedCount?: number;
  readonly omittedSuggestions?: readonly unknown[];
  readonly sourceLinkCandidatesOmittedCount?: number;
  readonly assetAcquisition?: ControlledAssetAcquisitionCompletion;
  readonly assetSuggestions?: readonly ControlledAssetAcquisitionBinding[];
}

export interface PrivateRetrievalReceiptBinding {
  readonly runId: string;
  readonly configHash: string;
  readonly candidate: PrivateRetrievalReceiptCandidate;
}

export type PrivateRetrievalReceiptRead =
  | { readonly state: 'missing' | 'expired' | 'mismatch' }
  | (PrivateRetrievalReceiptBinding & {
    readonly state: 'pending';
    readonly claim: PrivateRetrievalReceiptClaim;
  })
  | (PrivateRetrievalReceiptBinding & {
    readonly state: 'complete';
    readonly claim: PrivateRetrievalReceiptClaim;
    readonly completionKey: string;
    readonly outcome: 'links_observed' | 'no_links' | 'failed' | 'access_restricted';
    readonly suggestions: readonly unknown[];
    /** Zero identifies an authenticated historical v1 body without omission metadata. */
    readonly omissionMetadataVersion: 0 | 1;
    readonly truncatedCount: number;
    readonly omittedSuggestions: readonly unknown[];
    readonly sourceLinkCandidatesOmittedCount: number;
    readonly limitations: readonly string[];
    readonly identity: PrivateRetrievalReceiptIdentity;
    readonly assetAcquisition?: ControlledAssetAcquisitionCompletion;
    readonly assetSuggestions?: readonly ControlledAssetAcquisitionBinding[];
    readonly evidenceIds: readonly string[];
    readonly facts: readonly StoredEvidenceFactRecord[];
  });

export interface EvidenceStore<Request = unknown> {
  scopeForAuthenticatedRequest(request: Request): Promise<EvidenceTenantScope>;
  ingestEvidence(scope: EvidenceTenantScope, input: EvidenceIngestInput, signal?: AbortSignal): Promise<EvidenceIngestResult>;
  /** Runs the existing bounded HTML/XHTML/JSON-LD parser and stores only exact private source excerpts. */
  ingestAssetSourceEvidence(
    scope: EvidenceTenantScope,
    input: AssetSourceEvidenceIngestInput,
    request: Request,
    signal?: AbortSignal,
  ): Promise<AssetSourceEvidenceIngestResult>;
  /** Invokes the pinned isolated PDF reader itself; caller-supplied observations and geometry are rejected. */
  ingestDerivedPdfEvidence(
    scope: EvidenceTenantScope,
    input: PdfDerivedEvidenceIngestInput,
    request: Request,
    signal?: AbortSignal,
  ): Promise<PdfDerivedEvidenceIngestResult>;
  lookupEvidence(scope: EvidenceTenantScope, evidenceId: string, signal?: AbortSignal): Promise<EvidenceHandle>;
  getEvidenceMetadata(scope: EvidenceTenantScope, evidence: EvidenceHandle): Promise<EvidenceMetadata>;
  listEvidencePositions(scope: EvidenceTenantScope, evidence: EvidenceHandle, request: Request): Promise<readonly Readonly<{
    handle: EvidencePositionHandle;
    locator: StoredEvidenceLocator;
    contentHash: string;
  }>[] >;
  /** Bounded, all-or-error private snapshot; no raw source or position bytes are returned. */
  materializeSelected(
    scope: EvidenceTenantScope,
    selection: EvidenceSelectedMaterializationInput,
    request: Request,
    signal?: AbortSignal,
  ): Promise<EvidenceSelectedMaterialization>;
  withPrivatePayload(scope: EvidenceTenantScope, evidence: EvidenceHandle, request: Request): Promise<EvidencePrivatePayloadResult>;
  appendFact(scope: EvidenceTenantScope, fact: EvidenceFactInput, request: Request, signal?: AbortSignal): Promise<EvidenceFactHandle>;
  lookupFact(scope: EvidenceTenantScope, factId: string, signal?: AbortSignal): Promise<EvidenceFactHandle>;
  readFact(scope: EvidenceTenantScope, fact: EvidenceFactHandle, request: Request): Promise<StoredEvidenceFactRecord>;
  listFacts(scope: EvidenceTenantScope, request: Request): Promise<readonly StoredEvidenceFactRecord[]>;
  purgeExpired(scope: EvidenceTenantScope, signal?: AbortSignal): Promise<number>;
  integritySnapshot(scope: EvidenceTenantScope): Promise<EvidenceIntegritySnapshot>;
  /** Internal durable marker written before private retrieval can dispatch. */
  beginPrivateRunReceipt(
    scope: EvidenceTenantScope,
    input: PrivateRetrievalReceiptBinding & { readonly claim: PrivateRetrievalReceiptClaim },
    request: Request,
    signal?: AbortSignal,
  ): Promise<Readonly<{ state: 'pending' | 'complete' | 'expired'; created: boolean }>>;
  /** Stores an encrypted, bounded completion before the frontier completion CAS. */
  finalizePrivateRunReceipt(
    scope: EvidenceTenantScope,
    input: PrivateRetrievalReceiptBinding & {
      readonly claim: PrivateRetrievalReceiptClaim;
      readonly completion: PrivateRetrievalReceiptCompletion;
      readonly selection: EvidenceSelectedMaterializationInput;
    },
    request: Request,
    signal?: AbortSignal,
  ): Promise<Readonly<{ state: 'complete' | 'already_complete' }>>;
  /** Reopens exact evidence and facts under current key, retention, and authorization checks. */
  readPrivateRunReceipt(
    scope: EvidenceTenantScope,
    input: PrivateRetrievalReceiptBinding,
    request: Request,
    signal?: AbortSignal,
  ): Promise<PrivateRetrievalReceiptRead>;
}

export interface ControlledAssetReleaseEvidenceReference {
  readonly handle: EvidenceHandle;
  readonly metadata: AvailableEvidenceMetadata;
}

export interface ControlledAssetReleaseRoleGroup {
  readonly candidateId: string;
  readonly evidence: readonly [ControlledAssetReleaseEvidenceReference, ControlledAssetReleaseEvidenceReference];
}

export interface ControlledAssetReleaseRevalidationInput {
  readonly runId: string;
  readonly policyDigest: string;
  readonly releaseController: PrivateAssetReleaseAuthorityController;
  /** The same at-most-eight evidence records selected for the private draft, including fact support. */
  readonly evidence: readonly ControlledAssetReleaseEvidenceReference[];
  /** The same fact handles selected for the private draft. */
  readonly facts: readonly EvidenceFactHandle[];
  /** At most eight candidate-bound fetched/transformed role pairs. */
  readonly assetGroups: readonly ControlledAssetReleaseRoleGroup[];
  /** Last awaited policy re-read; returns only candidate IDs whose plans remain eligible. */
  readonly beforeFinalization: (context: Readonly<{ candidateIds: readonly string[] }>) => readonly string[] | Promise<readonly string[]>;
  /**
   * Synchronous trusted-composition preflight after the last awaited policy
   * check. The opaque release controller, not this boolean result, is the
   * final revocation authority at projection; thenables are rejected.
   */
  readonly finalizeHostAuthority: (context: Readonly<{ candidateIds: readonly string[] }>) => Readonly<{
    releaseAuthorized: boolean;
    candidateIds: readonly string[];
  }>;
}

export interface ControlledAssetReleaseRevalidationResult {
  readonly releaseCheck: PrivateAssetReleaseCheck;
  readonly candidateIds: readonly string[];
}

export interface ControlledAssetReleaseFinalizationInput<Result> {
  readonly releaseController: PrivateAssetReleaseAuthorityController;
  readonly runId: string;
  readonly policyDigest: string;
  readonly deadlineAtMonotonic: number;
  readonly candidateIds: readonly string[];
  /** Synchronous projection callback executed at the release linearization point. */
  readonly project: (current: Readonly<{
    currentEvidenceMetadata: readonly AvailableEvidenceMetadata[];
    candidateIds: readonly string[];
  }>) => Result;
}

/** Optional capability required only when private retrieval is explicitly opted into controlled SVG acquisition. */
export interface ControlledAssetEvidenceStore<Request = unknown> extends EvidenceStore<Request> {
  /** Internal same-run SVG path; supported callers must provide the trusted composition's original document and witness. */
  ingestControlledAssetEvidence(
    scope: EvidenceTenantScope,
    input: ControlledAssetEvidenceIngestInput,
    request: Request,
    signal?: AbortSignal,
  ): Promise<ControlledAssetEvidenceIngestResult>;
  /** Reopens one exact encrypted asset-source position, with current tenant/retention checks. */
  readAssetSourceCandidateBinding(
    scope: EvidenceTenantScope,
    evidence: EvidenceHandle,
    candidateId: string,
    request: Request,
    signal?: AbortSignal,
  ): Promise<AssetSourceCandidateBindingRead>;
  /** Reopens exact encrypted controlled asset bytes and reauthorizes their current source candidate. */
  readControlledAssetBytes(
    scope: EvidenceTenantScope,
    evidence: EvidenceHandle,
    request: Request,
    signal?: AbortSignal,
  ): Promise<Readonly<{
    evidenceId: string;
    metadata: AvailableEvidenceMetadata;
    source: EvidenceSelectedEvidence['source'];
    bytes: Uint8Array;
  }>>;
  /** Final same-run release barrier for the selected page/facts and active controlled asset role pairs. */
  revalidateControlledAssetRelease(
    scope: EvidenceTenantScope,
    input: ControlledAssetReleaseRevalidationInput,
    request: Request,
    signal?: AbortSignal,
  ): Promise<ControlledAssetReleaseRevalidationResult>;
  /** Synchronous one-shot current-state check and projection; implementations must not await or return a thenable. */
  finalizeControlledAssetRelease<Result>(
    scope: EvidenceTenantScope,
    releaseCheck: PrivateAssetReleaseCheck,
    request: Request,
    signal: AbortSignal | undefined,
    input: ControlledAssetReleaseFinalizationInput<Result>,
  ): Result;
  /** Discards an unused preflight and wipes its retained snapshot. */
  discardControlledAssetRelease(scope: EvidenceTenantScope, releaseCheck: PrivateAssetReleaseCheck): boolean;
}

export declare function createEvidenceStore<Request = unknown>(options: EvidenceStoreOptions<Request>): ControlledAssetEvidenceStore<Request>;
