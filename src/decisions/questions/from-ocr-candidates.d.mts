import type { OcrCandidateInput, OcrCandidateScope, OcrCandidateWord, OcrCandidateFact } from "../../extraction/ocr-candidates/index.mjs";
import type { ByteIdentity } from "../../extraction/inspection-report/index.mjs";
import type { QuestionPlan } from "./index.mjs";
export interface OcrQuestionInput { readonly reportBytes: Uint8Array; readonly expectedSha256: string; readonly input: OcrCandidateInput; }
export interface OcrQuestionPreparation {
  readonly kind: "prepared";
  readonly requiresReview: true;
  readonly plan: QuestionPlan;
  readonly binding: Readonly<{ schemaVersion: "ei-private-ocr-question-binding/1"; candidateReportSha256: string;
    prerequisiteReport: ByteIdentity; planHash: string; stateHash: string; lineId: string; scope: OcrCandidateScope;
    words: readonly OcrCandidateWord[]; candidates: readonly OcrCandidateFact[]; languageAuthority: string;
    sourceAuthority: "unverified"; dispatch: "not_dispatched"; acceptedFacts: readonly never[]; ownerAcknowledgements: readonly never[] }>;
  readonly bindingSha256: string;
  readonly authority: string;
}
export function prepareOcrCandidateQuestions(input: OcrQuestionInput, selection: Readonly<{ lineId: string }>): OcrQuestionPreparation;
