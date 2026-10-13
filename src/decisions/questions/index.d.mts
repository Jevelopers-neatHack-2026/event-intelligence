export type QuestionId =
  | 'Q-EI-SOURCE-TYPE:v1'
  | 'Q-EI-RELEVANCE:v1'
  | 'Q-EI-INJECTION:v1'
  | 'Q-EI-IDENTITY:v1'
  | 'Q-EI-FACT-SUPPORT:v1'
  | 'Q-EI-CONFLICT:v1'
  | 'Q-EI-BRAND-ROLE:v1';

export type QuestionStage = 'independent' | 'identity-dependent';
export type QuestionPrimitive = 'choice' | 'score' | 'noul';
export type ObservationKind =
  | 'source_text'
  | 'passage_text'
  | 'claim_evidence_text'
  | 'structured_visual_observation'
  | 'completed_question_observation';
export type RetentionTag =
  | 'event_identity'
  | 'occurrence'
  | 'tour_city'
  | 'annual_edition'
  | 'date'
  | 'time_zone'
  | 'venue'
  | 'cancellation'
  | 'reschedule'
  | 'rights'
  | 'safety';

export type TypeSafeQuestion =
  | {
      readonly type: 'choice';
      readonly instructions: string;
      readonly criteria: Readonly<Record<string, string>>;
    }
  | {
      readonly type: 'score';
      readonly instructions: string;
      readonly criteria: readonly string[];
    }
  | {
      readonly type: 'noul';
      readonly instructions: string;
      readonly criteria: Readonly<{ true: string; false: string }>;
    };

export interface QuestionDefinition {
  readonly questionId: QuestionId;
  readonly stage: QuestionStage;
  readonly primitive: QuestionPrimitive;
  readonly question: TypeSafeQuestion;
  readonly outputLabels: readonly string[];
  readonly eligibleInputKinds: readonly ObservationKind[];
  readonly targetUnit: string;
  readonly eligibleCondition: string;
  readonly registryVersion: string;
  readonly schemaVersion: string;
  readonly rubricVersion: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyDocumentHash: string;
  readonly policyStatus: 'proposed_unapproved';
  readonly ownerRole: 'Agent and research';
  readonly modelCandidate: 'jev-1.13.0';
  readonly modelCandidateStatus: 'candidate_only_not_accepted_runtime_pin';
  readonly modelInputMode: 'text_only_structured_observations_no_raw_images';
  readonly supportedLanguagePolicy: Readonly<{
    primaryLanguage: 'en';
    primaryLanguageSource: string;
    otherKnownLanguages: string;
    unknownLanguage: string;
    languageTagTrust: string;
  }>;
  readonly labelSetRef: string;
  readonly labelSetSha256: string;
  readonly corpusRef: string;
  readonly corpusVersion: string;
  readonly corpusManifestSha256: string;
  readonly thresholds: Readonly<{
    sourceRef: string;
    candidateValues: Readonly<Record<string, number>>;
    status: string;
    applicability: string;
  }>;
  readonly policyLabelSet: Readonly<{
    classes: readonly string[];
    positiveClasses: readonly string[];
    negativeClasses: readonly string[];
    unknownClasses: readonly string[];
    requiredMetrics: readonly string[];
    requiredNegativeSlices: readonly string[];
    perSliceFloorMin: number;
    minimumSamplesPerClass: Readonly<Record<string, number>>;
    denominator: string;
    confidenceIntervalMethod: string;
    thresholdSelectionSplit: string;
    metricDefinitions: Readonly<Record<string, string>>;
    errorCostReference: string;
  }>;
  readonly labelReconciliation: Readonly<{
    status: 'blocked_pending_agent_and_research_owner_review';
    existingPolicyLabels: readonly string[];
    requiredQuestionLabels: readonly string[];
    existingPolicyMetrics: readonly string[];
    existingPolicyDenominator: string;
    semanticMismatch: string;
    affectedMetrics: readonly string[];
    affectedDenominator: string;
    ownerAction: string;
  }>;
  readonly requiredForV1: true;
  readonly requiredWhenApplicable: true;
  readonly canBeOmittedOnlyWhenIneligible: true;
  readonly approvalStatus: 'pending_owner_review';
  readonly ownerApprovalAuthenticated: false;
  readonly promotionStatus: 'unpromoted';
  readonly timeoutBehavior: string;
  readonly malformedBehavior: string;
  readonly abstentionBehavior: string;
  readonly outputIsRecommendationOnly: true;
  readonly grantsVerifiedFactStatus: false;
  readonly grantsOfficialSourceStatus: false;
  readonly grantsRightsOrPermission: false;
  readonly grantsCapabilitiesOrBudget: false;
  readonly grantsIndependentVerification: false;
  readonly definitionHash: string;
}

export interface VisualObservationMetadata {
  readonly observerRef: string;
  readonly observerModel: string;
  readonly regionRef: string;
  readonly assetHash: string;
  readonly uncertainty: 'low' | 'medium' | 'high' | 'unknown';
}

export interface CompletionObservationReference {
  readonly questionId: 'Q-EI-IDENTITY:v1';
  readonly predecessorPlanHash: string;
}

interface ObservationBase {
  readonly observationRef: string;
  readonly language: string;
  readonly text: string;
  readonly candidateRef?: string;
  readonly retentionTags?: readonly RetentionTag[];
}

export interface SourceTextObservation extends ObservationBase {
  readonly kind: 'source_text';
  readonly sourceRef: string;
  readonly fieldRef?: string;
}

export interface PassageTextObservation extends ObservationBase {
  readonly kind: 'passage_text';
  readonly sourceRef: string;
  readonly fieldRef?: string;
}

export interface ClaimEvidenceObservation extends ObservationBase {
  readonly kind: 'claim_evidence_text';
  readonly sourceRef: string;
  readonly fieldRef: string;
  readonly claimText: string;
}

export interface StructuredVisualObservation extends ObservationBase {
  readonly kind: 'structured_visual_observation';
  readonly sourceRef: string;
  readonly visual: VisualObservationMetadata;
}

export interface CompletedQuestionObservation extends ObservationBase {
  readonly kind: 'completed_question_observation';
  readonly completion: CompletionObservationReference;
}

export type QuestionObservation =
  | SourceTextObservation
  | PassageTextObservation
  | ClaimEvidenceObservation
  | StructuredVisualObservation
  | CompletedQuestionObservation;

export interface PreparedObservation {
  readonly observationRef: string;
  readonly sourceRef: string | null;
  readonly candidateRef: string | null;
  readonly fieldRef: string | null;
  readonly kind: ObservationKind;
  readonly language: string;
  readonly text: string;
  readonly textHash: string;
  readonly claimText: string | null;
  readonly claimTextHash: string | null;
  readonly retentionTags: readonly RetentionTag[];
  readonly visual: VisualObservationMetadata | null;
  readonly completion: CompletionObservationReference | null;
  readonly recordHash: string;
}

export interface PreparedQuestionState {
  readonly schema: 'ei-jev-prepared-state-internal/v1';
  readonly dataHandling: string;
  readonly observations: readonly PreparedObservation[];
  readonly predecessor: Readonly<{
    readonly questionId: 'Q-EI-IDENTITY:v1';
    readonly predecessorPlanHash: string;
    readonly predecessorStateHash: string;
    readonly completionObservationRef: string;
    readonly completionObservationHash: string;
    readonly completionAssertion: 'caller_asserted_for_preparation_only';
  }> | null;
}

export interface QuestionTargetBindingInput {
  readonly questionId: QuestionId;
  readonly targetRef: string;
  readonly observationRefs: readonly string[];
  readonly contextObservationRefs?: readonly string[];
  readonly fieldRef?: string;
  readonly candidateRefs?: readonly string[];
}

export interface PreparedQuestionTargetBinding {
  readonly questionId: QuestionId;
  readonly targetRef: string;
  readonly observationRefs: readonly string[];
  readonly contextObservationRefs: readonly string[];
  readonly fieldRef: string | null;
  readonly candidateRefs: readonly string[];
  readonly evidenceRecordHashes: readonly string[];
  readonly contextRecordHashes: readonly string[];
}

export interface PreparedQuestionTargetState {
  readonly schema: 'ei-jev-question-target-state-internal/v1';
  readonly questionId: QuestionId;
  readonly targetRef: string;
  readonly evidence: readonly Readonly<{
    observationRef: string;
    sourceRef: string | null;
    candidateRef: string | null;
    fieldRef: string | null;
    kind: ObservationKind;
    language: string;
    textHash: string;
    claimTextHash: string | null;
    recordHash: string;
  }>[];
  readonly context: readonly Readonly<{
    observationRef: string;
    sourceRef: string | null;
    candidateRef: string | null;
    fieldRef: string | null;
    kind: ObservationKind;
    language: string;
    textHash: string;
    claimTextHash: string | null;
    recordHash: string;
  }>[];
  readonly predecessor: PreparedQuestionState['predecessor'];
}

export interface PlannedQuestion {
  readonly questionId: QuestionId;
  readonly stage: QuestionStage;
  readonly requiredForV1: true;
  readonly eligible: boolean;
  readonly reasonCodes: readonly string[];
  readonly reviewRequired: boolean;
  readonly reviewReasons: readonly string[];
  readonly definitionHash: string;
  readonly targetBinding: PreparedQuestionTargetBinding | null;
  readonly targetBindingHash: string | null;
  readonly targetState: PreparedQuestionTargetState | null;
  readonly targetStateHash: string | null;
  readonly questionInstanceHash: string;
  readonly question?: TypeSafeQuestion;
}

export interface QuestionPlan {
  readonly schema: 'ei-jev-question-plan-internal/v2';
  readonly registryVersion: string;
  readonly registrySchemaVersion: string;
  readonly registryHash: string;
  readonly policy: Readonly<{
    readonly policyId: string;
    readonly policyVersion: string;
    readonly policyDocumentHash: string;
    readonly policyStatus: 'proposed_unapproved';
    readonly configuredRegistryVersion: string;
    readonly configuredRegistryVersionStatus: string;
  }>;
  readonly stage: QuestionStage;
  readonly sourceEvidenceHash: string;
  readonly stateHash: string;
  readonly state: PreparedQuestionState;
  readonly stateUtf8Bytes: number;
  readonly preparationStatus: 'prepared' | 'blocked';
  readonly readinessStatus: 'blocked';
  readonly readinessBlockers: readonly string[];
  readonly promotionStatus: 'unpromoted';
  readonly executionStatus: 'not_dispatched';
  readonly decisionPortContractStatus: 'unavailable';
  readonly candidateOnly: true;
  readonly questionsReviewRequired: boolean;
  readonly requiredQuestionIds: readonly QuestionId[];
  readonly allRequiredQuestionIds: readonly QuestionId[];
  readonly eligibleQuestionIds: readonly QuestionId[];
  readonly questions: readonly PlannedQuestion[];
  readonly preservedEvidence: readonly Readonly<Record<string, unknown>>[];
  readonly preservedCriticalEvidence: readonly Readonly<Record<string, unknown>>[];
  readonly authorityScope: Readonly<{
    readonly sourceOfficialnessGranted: false;
    readonly verifiedFactStatusGranted: false;
    readonly independentVerificationGranted: false;
    readonly rightsOrPermissionGranted: false;
    readonly capabilitiesGranted: false;
    readonly budgetGranted: false;
    readonly promotionGranted: false;
  }>;
  readonly limits: Readonly<{
    readonly maxObservations: number;
    readonly maxTargetBindingsPerQuestion: 1;
    readonly maxTargetReferences: number;
    readonly maxTargetBindings: number;
    readonly maxTextBytesPerField: number;
    readonly maxTotalTextBytes: number;
    readonly maxStateUtf8Bytes: number;
    readonly maxPlanUtf8Bytes: number;
    readonly stateUtf8Bytes: number;
    readonly byteCapsAreTokenizerGuarantee: false;
    readonly tokenCountProven: false;
  }>;
  readonly planHash: string;
}

export declare class QuestionPreparationError extends Error {
  readonly code:
    | 'INVALID_INPUT'
    | 'INVALID_TARGET_BINDING'
    | 'DUPLICATE_TARGET_BINDING'
    | 'UNKNOWN_TARGET_REFERENCE'
    | 'MISMATCHED_TARGET_REFERENCE'
    | 'RESOURCE_LIMIT_EXCEEDED'
    | 'SENSITIVE_CONTENT';
}

export type {
  SourceIdentityQuestionPreparationOptions,
  SourceIdentityQuestionPreparationResult,
  SourceIdentityQuestionPreparationErrorCode,
  SourceIdentityBinding,
  SourceIdentityBindingObservationGroup,
  SourceCorroborationContext,
  LegacySourceIdentityBinding,
  CurrentSourceIdentityBinding
} from './from-source-identity.mjs';
export {
  SourceIdentityQuestionPreparationError,
  prepareIdentityQuestionFromComposition
} from './from-source-identity.mjs';

export declare const QUESTION_IDS: readonly QuestionId[];
export declare const INDEPENDENT_QUESTION_IDS: readonly QuestionId[];
export declare const IDENTITY_DEPENDENT_QUESTION_IDS: readonly QuestionId[];
export declare const QUESTION_POLICY: Readonly<QuestionPlan['policy']>;
export declare const QUESTION_REGISTRY: readonly QuestionDefinition[];
export declare const QUESTION_REGISTRY_HASH: string;
export declare const QUESTION_REGISTRY_SCHEMA_VERSION: string;
export declare const QUESTION_REGISTRY_VERSION: string;

export declare function getQuestionDefinition(questionId: string): QuestionDefinition | null;
export declare function deriveQuestionTargetRef(
  questionId: QuestionId,
  observationRefs: readonly string[],
  options?: Readonly<{ fieldRef?: string; candidateRefs?: readonly string[] }>
): string;
export declare function prepareIndependentQuestions(
  observations: readonly QuestionObservation[],
  targetBindings?: readonly QuestionTargetBindingInput[]
): QuestionPlan;
/** Prepare a new fact-support/conflict state after the caller says the identity stage has completed. */
export declare function prepareDependentQuestions(
  observations: readonly QuestionObservation[],
  predecessorPlan: QuestionPlan | null | undefined,
  targetBindings?: readonly QuestionTargetBindingInput[]
): QuestionPlan;
