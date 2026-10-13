import { OcrCandidateError, validateOcrCandidateFacts } from "../../extraction/ocr-candidates/index.mjs";
import { canonical, exactKeys, freeze, hash } from "../../extraction/inspection-report/media-data.mjs";
import { deriveQuestionTargetRef, prepareIndependentQuestions } from "./prepare.mjs";

/** Revalidate all original report inputs; prepare one untrusted OCR line, never dispatch it. */
export function prepareOcrCandidateQuestions(input, selection) {
  try {
    exactKeys(input, ["reportBytes", "expectedSha256", "input"]); exactKeys(selection, ["lineId"]);
    if (typeof selection.lineId !== "string") throw new OcrCandidateError();
    const artifact = validateOcrCandidateFacts(input.reportBytes, input.expectedSha256, input.input);
    const line = artifact.report.lines.find((value) => value.lineId === selection.lineId);
    if (!line) throw new OcrCandidateError("UNKNOWN_LINE");
    const candidates = artifact.report.candidates.filter((value) => value.lineId === line.lineId);
    const tags = new Set(["safety"]);
    for (const candidate of candidates) {
      const tag = { title: "event_identity", date: "date", start: "date", end: "date", venue: "venue", city: "tour_city" }[candidate.field];
      tags.add(tag);
    }
    const observation = { observationRef: line.lineId, kind: "passage_text", sourceRef: "ocr-source:" + line.scope.originalSource.sha256,
      language: "und", text: line.text, retentionTags: [...tags].sort() };
    const bindings = ["Q-EI-RELEVANCE:v1", "Q-EI-INJECTION:v1"].map((questionId) => ({ questionId,
      targetRef: deriveQuestionTargetRef(questionId, [line.lineId]), observationRefs: [line.lineId] }));
    let plan;
    try { plan = prepareIndependentQuestions([observation], bindings); }
    catch { throw new OcrCandidateError("QUESTION_PREPARATION_REFUSED"); }
    const binding = freeze({ schemaVersion: "ei-private-ocr-question-binding/1", candidateReportSha256: artifact.sha256,
      prerequisiteReport: artifact.report.prerequisite, planHash: plan.planHash, stateHash: plan.stateHash,
      lineId: line.lineId, scope: line.scope, words: line.words, candidates,
      languageAuthority: "unknown; the OCR model language is not detected source language",
      sourceAuthority: "unverified", dispatch: "not_dispatched", acceptedFacts: [], ownerAcknowledgements: [] });
    return freeze({ kind: "prepared", requiresReview: true, plan, binding,
      bindingSha256: hash(Buffer.from(canonical(binding))), authority: "local preparation only; no provider, rights, accepted fact, budget or canonical contract grant" });
  } catch (e) { if (e instanceof OcrCandidateError) throw e; throw new OcrCandidateError("INVALID_INPUT"); }
}
