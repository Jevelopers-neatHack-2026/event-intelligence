import {
  prepareIdentityQuestionFromComposition,
  type SourceIdentityQuestionPreparationOptions,
  type SourceIdentityQuestionPreparationResult
} from '../../../src/decisions/questions/index.mjs';
import type { SourceIdentityCompositionResult, LegacySourceIdentityCompositionResult } from '../../../src/discovery/identity/from-extraction.mjs';

declare const composition: SourceIdentityCompositionResult;
const options: SourceIdentityQuestionPreparationOptions = {
  candidateIds: ['event-selected-left', 'event-selected-right'],
  languageByEvidenceId: { '00000000-0000-4000-8000-000000000001': 'en' }
};
const prepared: SourceIdentityQuestionPreparationResult = prepareIdentityQuestionFromComposition(composition, options);

const readiness: 'blocked' = prepared.plan.readinessStatus;
const execution: 'not_dispatched' = prepared.plan.executionStatus;
const promotion: 'unpromoted' = prepared.plan.promotionStatus;
const candidateOnly: true = prepared.plan.candidateOnly;
const decisionPort: 'unavailable' = prepared.plan.decisionPortContractStatus;
const questionId: 'Q-EI-IDENTITY:v1' = prepared.sourceIdentityBinding.questionId;
const localReviewOnly: true = prepared.sourceIdentityBinding.localReviewOnly;
const digest: string = prepared.sourceIdentityBinding.digest;
const observationGroupClaim: string | undefined = prepared.sourceIdentityBinding.observationGroups[0]?.claims[0]?.value;
const observationTextLimit: 4_096 = prepared.sourceIdentityBinding.limits.maxTextBytesPerField;
const hashes: string[] = [
  prepared.plan.sourceEvidenceHash,
  prepared.plan.planHash,
  prepared.sourceIdentityBinding.bindingHashes.targetBindingHash ?? '',
  prepared.sourceIdentityBinding.bindingHashes.targetStateHash ?? '',
  prepared.sourceIdentityBinding.bindingHashes.questionInstanceHash
];

void [readiness, execution, promotion, candidateOnly, decisionPort, questionId, localReviewOnly, digest, observationGroupClaim, observationTextLimit, hashes];

if (prepared.sourceIdentityBinding.schema === 'ei-source-identity-question-binding-internal/v2') {
  const sourceSchema: 'ei-source-identity-composition-internal/v2' = prepared.sourceIdentityBinding.sourceCompositionSchema;
  const graphDigest: string = prepared.sourceIdentityBinding.corroboration.sourceGraphDigest;
  const independence: 'unknown' = prepared.sourceIdentityBinding.corroboration.independence;
  void [sourceSchema, graphDigest, independence];
} else {
  const legacySchema: 'ei-source-identity-composition-internal/v1' = prepared.sourceIdentityBinding.sourceCompositionSchema;
  // @ts-expect-error Legacy output does not invent a retained attribution graph.
  prepared.sourceIdentityBinding.corroboration;
  void legacySchema;
}
declare const historical: LegacySourceIdentityCompositionResult;
const historicalPrepared: SourceIdentityQuestionPreparationResult = prepareIdentityQuestionFromComposition(historical, options);
void historicalPrepared;
