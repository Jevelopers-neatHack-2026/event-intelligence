import { deriveOcrCandidateFacts, validateOcrCandidateFacts, type OcrCandidateInput } from '../../../src/extraction/ocr-candidates/index.mjs';
import { prepareOcrCandidateQuestions } from '../../../src/decisions/questions/from-ocr-candidates.mjs';
declare const input: OcrCandidateInput;
const a = deriveOcrCandidateFacts(input);
validateOcrCandidateFacts(a.copyBytes(), a.sha256, input);
const p = prepareOcrCandidateQuestions({reportBytes: a.copyBytes(), expectedSha256: a.sha256, input}, {lineId:'explicit-selection'});
const review: true = p.requiresReview;
const authority: false = p.plan.authorityScope.verifiedFactStatusGranted;
const noDispatch: 'not_dispatched' = p.plan.executionStatus;
const incomplete: 'incomplete' = a.report.overall;
// @ts-expect-error no reader, fetch, model or authorization callback belongs to a pure input
const forbidden: OcrCandidateInput = {...input, readOcr: async () => ({})};
// @ts-expect-error source language or source authority cannot be elected by a selection
prepareOcrCandidateQuestions({reportBytes:a.copyBytes(),expectedSha256:a.sha256,input},{lineId:'x',language:'en'});
// @ts-expect-error a candidate is not an accepted canonical fact
const accepted: 'verified' = a.report.candidates[0].status;
// @ts-expect-error output provenance is immutable
p.binding.scope.page = 3;
void [review,authority,noDispatch,incomplete,forbidden,accepted];
