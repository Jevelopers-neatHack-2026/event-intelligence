// Private interpretation of retained OCR tokens. No reader, model, URL or store runs here.
import { validateInspectionOcrReport } from "../inspection-report/ocr.mjs";
import { normalizeCandidateValue } from "../source.mjs";
import { bytes, canonical, data, exactKeys, freeze, hash, identity, isHash, parseJson } from "../inspection-report/media-data.mjs";

export const OCR_CANDIDATE_VERSION = "ei-private-ocr-candidate-facts/1";
export const OCR_CANDIDATE_PROFILE = "explicit-label-ordinal-line-unknown-dates/1";
export const OCR_CANDIDATE_LIMITS = Object.freeze({ maxLines: 256, maxCandidates: 128, maxWordsPerLine: 256,
  maxLineTextBytes: 4096, maxTotalTextBytes: 32768, maxReportBytes: 2 * 1024 * 1024 });
const LABELS = new Map([["event", "title"], ["title", "title"], ["date", "date"], ["start", "start"], ["end", "end"], ["venue", "venue"], ["city", "city"]]);
const TEMPORAL = new Set(["date", "start", "end"]);
const ERRORS = new Set(["INVALID_INPUT", "PREREQUISITE_INVALID", "RESOURCE_LIMIT", "REPORT_BYTES_MISMATCH", "UNSUPPORTED_VERSION", "UNKNOWN_LINE", "QUESTION_PREPARATION_REFUSED"]);
export class OcrCandidateError extends Error {
  constructor(code = "INVALID_INPUT") { super(ERRORS.has(code) ? code : "INVALID_INPUT"); this.name = "OcrCandidateError"; this.code = this.message; }
}
const check = (condition, code = "INVALID_INPUT") => { if (!condition) throw new OcrCandidateError(code); };
const digest = (value) => hash(Buffer.from(canonical(value)));

function labelAt(words, at) {
  const token = words[at]?.text;
  if (typeof token !== "string") return null;
  const attached = /^([A-Za-z]+):$/.exec(token);
  const name = (attached?.[1] ?? token).toLowerCase();
  const field = LABELS.get(name);
  if (!field) return null;
  if (attached) return { field, name, count: 1 };
  return words[at + 1]?.text === ":" ? { field, name, count: 2 } : null;
}

function pageScope(observation, page, reportHash) {
  const r = observation.observation, pdf = observation.component === "scanned-pdf-ocr";
  return {
    reportSha256: reportHash, observationId: observation.id, mediaObservationId: observation.mediaObservationId,
    executionId: observation.executionId, result: observation.result, originalSource: observation.originalSource,
    page: pdf ? page.page : 1, coordinateSystem: "top-left-pixels",
    rawRgbaSha256: pdf ? page.derivativeSha256 : r.image.rgbaSha256,
    normalizedPngSha256: pdf ? null : r.image.normalizedSha256,
    width: pdf ? page.width : r.image.width, height: pdf ? page.height : r.image.height,
    pageWidthPoints: pdf ? page.pageWidthPoints : null, pageHeightPoints: pdf ? page.pageHeightPoints : null,
    sourceAuthority: "unverified", wordSourceBinding: "caller-supplied-unverified",
    byteBinding: observation.binding, callerRecordBound: observation.callerRecordBound,
    issuerAuthority: "not established by supplied bytes or records",
  };
}

function derive(input) {
  exactKeys(input, ["reportBytes", "expectedSha256", "input"]);
  let artifact;
  try { artifact = validateInspectionOcrReport(input.reportBytes, input.expectedSha256, input.input); }
  catch { throw new OcrCandidateError("PREREQUISITE_INVALID"); }
  const prior = artifact.report, lines = [], candidates = [], outcomes = [];
  let textBytes = 0;
  for (const observation of prior.observations) {
    const r = observation.observation;
    const outcome = { observationId: observation.id, component: observation.component, result: observation.result,
      status: "unknown", reason: "no-text-observed", lineIds: [] };
    outcomes.push(outcome);
    if (r.kind === "rejected") { outcome.reason = "component-refused"; outcome.refusalCode = r.code; continue; }
    if (observation.binding !== "bound-supplied-byte-domains" || observation.callerRecordBound !== true) {
      outcome.reason = observation.binding !== "bound-supplied-byte-domains" ? "source-or-raw-bytes-unbound" : "caller-record-missing";
      continue;
    }
    const pages = observation.component === "scanned-pdf-ocr" ? r.pages : [r];
    for (const page of pages) {
      const scope = pageScope(observation, page, artifact.sha256), groups = [];
      for (const [index, word] of page.words.entries()) {
        const ordinal = [word.block, word.paragraph, word.line], key = ordinal.join(":");
        let group = groups.at(-1);
        if (!group || group.key !== key) { group = { key, ordinal, words: [] }; groups.push(group); }
        group.words.push({ index, word });
      }
      for (const group of groups) {
        check(lines.length < OCR_CANDIDATE_LIMITS.maxLines && group.words.length <= OCR_CANDIDATE_LIMITS.maxWordsPerLine, "RESOURCE_LIMIT");
        const words = group.words.map(({ index, word }) => ({ index, ordinal: [word.block, word.paragraph, word.line, word.word],
          text: word.text, box: word.box, confidence: word.confidence, confidenceMeaning: word.confidenceMeaning,
          requiresReview: true, wordSha256: digest(word) }));
        const text = words.map((word) => word.text).join(" ");
        const size = Buffer.byteLength(text); textBytes += size;
        check(size <= OCR_CANDIDATE_LIMITS.maxLineTextBytes && textBytes <= OCR_CANDIDATE_LIMITS.maxTotalTextBytes, "RESOURCE_LIMIT");
        const lineId = "ocr-line:" + digest({ scope, ordinal: group.ordinal, words });
        const line = { lineId, scope, ordinal: group.ordinal, text,
          textRendering: "ordinal OCR tokens joined by one space; not original source whitespace",
          words, candidateIds: [], status: "unknown", reason: "unsupported-or-unlabelled-text", requiresReview: true };
        lines.push(line); outcome.lineIds.push(lineId);
        const label = labelAt(words, 0);
        if (!label) continue;
        if (words.length === label.count) { line.reason = "empty-labelled-value"; continue; }
        if (words.some((_, at) => at >= label.count && labelAt(words, at))) { line.reason = "multiple-labels-on-line"; continue; }
        const selected = words.slice(label.count), rawValue = selected.map((word) => word.text).join(" ");
        const normalizedValue = normalizeCandidateValue(rawValue);
        if (!normalizedValue) { line.reason = "empty-labelled-value"; continue; }
        check(candidates.length < OCR_CANDIDATE_LIMITS.maxCandidates, "RESOURCE_LIMIT");
        const candidate = { candidateId: "ocr-candidate:" + digest({ lineId, field: label.field, words: selected.map((w) => w.index) }),
          lineId, field: label.field, rawValue, normalizedValue,
          precision: TEMPORAL.has(label.field) ? "unknown" : null,
          status: "tentative", requiresReview: true, valueVerified: false,
          derivation: "explicit OCR label; not a sourced or customer-supplied evidence fact",
          labelWordIndices: words.slice(0, label.count).map((word) => word.index),
          valueWordIndices: selected.map((word) => word.index),
          reasons: TEMPORAL.has(label.field) ? ["date-or-time-not-interpreted", "ocr-text-unverified"] : ["ocr-text-unverified"],
          entityAssociation: "unassigned; no lines, pages or observations merged" };
        candidates.push(candidate); line.candidateIds.push(candidate.candidateId);
        line.status = "tentative-field"; line.reason = TEMPORAL.has(label.field) ? "temporal-meaning-unknown" : "explicit-label-only";
      }
    }
    if (outcome.lineIds.length) { outcome.status = "review-required"; outcome.reason = "untrusted-ocr-lines-retained"; }
  }
  const report = freeze({ schemaVersion: OCR_CANDIDATE_VERSION, profile: OCR_CANDIDATE_PROFILE,
    prerequisite: identity(artifact.copyBytes(), "inspection-ocr-report-bytes"),
    overall: "incomplete", requiresReview: true, sourceAuthority: "unverified", financeAuthority: "none",
    acceptedFacts: [], acceptance: { evaluated: false, satisfiedIds: [], ownerAcknowledgements: [] },
    lines, candidates, outcomes, totalTextBytes: textBytes,
    reasons: [...new Set([...prior.reasons, "OCR_CANDIDATES_REQUIRE_REVIEW", "BOUNDED_LABEL_SUBSET_ONLY", "NO_LOGO_OR_PERMISSION_INFERENCE"])].sort(),
    limits: OCR_CANDIDATE_LIMITS });
  const encoded = Buffer.from(JSON.stringify(data(report, OCR_CANDIDATE_LIMITS.maxReportBytes)) + "\n");
  check(encoded.length <= OCR_CANDIDATE_LIMITS.maxReportBytes, "RESOURCE_LIMIT");
  return Object.freeze({ report, sha256: hash(encoded), byteLength: encoded.length, copyBytes: () => new Uint8Array(encoded) });
}

export function deriveOcrCandidateFacts(input) {
  try { return derive(input); } catch (e) { if (e instanceof OcrCandidateError) throw e; throw new OcrCandidateError("INVALID_INPUT"); }
}
export function validateOcrCandidateFacts(reportBytes, expectedSha256, input) {
  try {
    check(isHash(expectedSha256)); const supplied = bytes(reportBytes, OCR_CANDIDATE_LIMITS.maxReportBytes);
    check(hash(supplied) === expectedSha256, "REPORT_BYTES_MISMATCH");
    check(parseJson(supplied, OCR_CANDIDATE_LIMITS.maxReportBytes).schemaVersion === OCR_CANDIDATE_VERSION, "UNSUPPORTED_VERSION");
    const artifact = deriveOcrCandidateFacts(input);
    check(supplied.equals(Buffer.from(artifact.copyBytes())), "REPORT_BYTES_MISMATCH"); return artifact;
  } catch (e) { if (e instanceof OcrCandidateError) throw e; throw new OcrCandidateError("INVALID_INPUT"); }
}
