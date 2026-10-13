import type { SupportedSourceIdentityComposition } from '../../discovery/identity/from-extraction.mjs';
import type { SourceCorroborationCluster, SourceCorroborationEdge, SourceCorroborationFactBinding } from '../../discovery/identity/corroboration.mjs';
import type { OccurrenceEvidenceLocator } from '../../discovery/occurrences/identity.mjs';
import type { QuestionPlan } from './index.mjs';

export type SourceIdentityQuestionPreparationErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_TARGET_BINDING'
  | 'UNKNOWN_TARGET_REFERENCE'
  | 'SOURCE_BINDING_FAILED'
  | 'VISIBLE_STATUS_REVIEW_REQUIRED'
  | 'UNSUPPORTED_ORIGIN'
  | 'RESOURCE_LIMIT_EXCEEDED'
  | 'SENSITIVE_CONTENT';

export interface SourceIdentityQuestionPreparationOptions {
  readonly candidateIds: readonly [string, string];
  /** Caller labels only. They are not source-language detection or authority evidence. */
  readonly languageByEvidenceId: Readonly<Record<string, string>>;
}

export interface SourceIdentityBindingSupport {
  readonly evidenceId: string;
  readonly contentHash: string;
  readonly duplicateGroupId: string;
  readonly locator: OccurrenceEvidenceLocator;
  readonly field: string;
  readonly value: string;
  readonly languageLabel: string;
  readonly languageLabelTrust: 'unverified_caller_metadata';
}

export interface SourceIdentityBindingClaim {
  readonly field: string;
  readonly value: string;
  readonly origin: 'sourced';
  readonly precision?: 'date' | 'local_datetime' | 'instant' | 'unknown';
  readonly retentionTags: readonly import('./index.mjs').RetentionTag[];
  readonly supports: readonly SourceIdentityBindingSupport[];
}

export interface SourceIdentityBindingObservationGroup {
  readonly candidateId: string;
  readonly evidenceId: string;
  readonly contentHash: string;
  readonly languageLabel: string;
  readonly claims: readonly Readonly<{
    field: string;
    value: string;
    origin: 'sourced';
    precision?: 'date' | 'local_datetime' | 'instant' | 'unknown';
    retentionTags: readonly import('./index.mjs').RetentionTag[];
  }>[];
  readonly duplicateGroupId: string;
  readonly languageLabelTrust: 'unverified_caller_metadata';
  readonly fieldRef: string;
  readonly observationRef: string;
  readonly text: string;
  readonly corroboration?: SourceCorroborationContext;
}

export interface SourceCorroborationContext {
  readonly schema: 'ei-source-corroboration-internal/v1';
  readonly policy: 'explicit-source-declaration/v1';
  readonly clusterId: string;
  readonly relation: 'shared_dependence_cluster' | 'no_retained_dependence_link';
  readonly independence: 'unknown';
  readonly origin: 'not_established';
  readonly sourceAuthority: 'not_evaluated';
  readonly bases: readonly ('exact_content' | 'source_declared_derivation')[];
  readonly unresolvedClaimCount: number;
}

export interface SourceIdentityBindingFields {
  readonly questionId: 'Q-EI-IDENTITY:v1';
  readonly candidateIds: readonly [string, string];
  readonly sourceAuthority: 'not_evaluated';
  readonly sourceEvidence: readonly Readonly<{
    evidenceId: string;
    contentHash: string;
    duplicateGroupId: string;
    retrievedAt: string;
    expiresAt: string;
    positionCount: number;
  }>[];
  readonly selectedCandidates: readonly Readonly<{
    candidateId: string;
    facts: readonly SourceIdentityBindingClaim[];
  }>[];
  readonly observationGroups: readonly SourceIdentityBindingObservationGroup[];
  readonly comparison: Readonly<{
    schema: 'ei-occurrence-identity-decision-internal/v1';
    candidateIds: readonly [string, string];
    relation: 'same_occurrence_candidate' | 'different_occurrence_candidate' | 'review' | 'unknown';
    reasonCodes: readonly string[];
    conflictFields: readonly string[];
    sourceAuthority: 'not_evaluated';
    duplicateContentHashes: readonly string[];
    provenanceReferences: readonly Readonly<{
      evidenceId: string;
      contentHash: string;
      locator: OccurrenceEvidenceLocator;
      field: string;
      value: string;
    }>[];
    transitionLinks: readonly Readonly<Record<string, unknown>>[];
  }>;
  readonly transitionLinks: readonly Readonly<Record<string, unknown>>[];
  readonly unresolvedTransitions: readonly Readonly<{
    candidateId: string;
    transition: 'canceled' | 'rescheduled';
    reason: string;
  }>[];
  readonly languageMetadataTrust: 'unverified_caller_metadata';
  readonly localReviewOnly: true;
  readonly bindingHashes: Readonly<{
    registryVersion: string;
    registryHash: string;
    questionDefinitionHash: string;
    sourceEvidenceHash: string;
    targetRef: string | null;
    targetBindingHash: string | null;
    targetStateHash: string | null;
    questionInstanceHash: string;
    planHash: string;
  }>;
  readonly limits: Readonly<{
    maxUtf8Bytes: 65_536;
    maxObservations: 32;
    maxTextBytesPerField: 4_096;
    maxTotalTextBytes: 10_000;
    /** Actual question-input bytes across both text and claimText fields. */
    observationTextBytes: number;
  }>;
  readonly digest: string;
  readonly utf8Bytes: number;
}

/** Historical v1 contains no declaration graph; independence remains unknown. */
export interface LegacySourceIdentityBinding extends SourceIdentityBindingFields {
  readonly schema: 'ei-source-identity-question-binding-internal/v1';
  readonly sourceCompositionSchema: 'ei-source-identity-composition-internal/v1';
}

export interface CurrentSourceIdentityBinding extends SourceIdentityBindingFields {
  readonly schema: 'ei-source-identity-question-binding-internal/v2';
  readonly sourceCompositionSchema: 'ei-source-identity-composition-internal/v2';
  readonly corroboration: Readonly<{
    schema: 'ei-source-corroboration-internal/v1';
    policy: 'explicit-source-declaration/v1';
    sourceGraphDigest: string;
    factBindings: readonly SourceCorroborationFactBinding[];
    sourceAuthority: 'not_evaluated';
    independence: 'unknown';
    selectedCandidates: readonly (SourceCorroborationContext & { readonly candidateId: string })[];
    clusters: readonly SourceCorroborationCluster[];
    edges: readonly SourceCorroborationEdge[];
  }>;
}

export type SourceIdentityBinding = LegacySourceIdentityBinding | CurrentSourceIdentityBinding;

export interface SourceIdentityQuestionPreparationResult {
  readonly plan: QuestionPlan;
  readonly sourceIdentityBinding: SourceIdentityBinding;
}

export declare class SourceIdentityQuestionPreparationError extends Error {
  readonly code: SourceIdentityQuestionPreparationErrorCode;
  constructor(code?: SourceIdentityQuestionPreparationErrorCode);
}

/**
 * Prepare the existing identity question for exactly two caller-selected source
 * identity candidates. The result is candidate-only and does not verify source
 * authority, current retention, tenant authorization, or a DecisionPort response.
 */
export declare function prepareIdentityQuestionFromComposition(
  composition: SupportedSourceIdentityComposition,
  options: SourceIdentityQuestionPreparationOptions
): SourceIdentityQuestionPreparationResult;
