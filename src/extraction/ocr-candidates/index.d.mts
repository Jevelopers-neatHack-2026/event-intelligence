import type { InspectionOcrReportInput } from "../inspection-report/ocr.mjs";
import type { ByteIdentity } from "../inspection-report/index.mjs";
export interface OcrCandidateInput {
  readonly reportBytes: Uint8Array;
  readonly expectedSha256: string;
  readonly input: InspectionOcrReportInput;
}
export type OcrCandidateField = "title" | "date" | "start" | "end" | "venue" | "city";
export interface OcrCandidateWord {
  readonly index: number;
  readonly ordinal: readonly number[];
  readonly text: string;
  readonly box: Readonly<{ left: number; top: number; width: number; height: number }>;
  readonly confidence: number;
  readonly confidenceMeaning: "uncalibrated-engine-score";
  readonly requiresReview: true;
  readonly wordSha256: string;
}
export interface OcrCandidateScope {
  readonly reportSha256: string;
  readonly observationId: string;
  readonly mediaObservationId: string;
  readonly executionId: string;
  readonly result: ByteIdentity;
  readonly originalSource: ByteIdentity;
  readonly page: number;
  readonly coordinateSystem: "top-left-pixels";
  readonly rawRgbaSha256: string;
  readonly normalizedPngSha256: string | null;
  readonly width: number;
  readonly height: number;
  readonly pageWidthPoints: number | null;
  readonly pageHeightPoints: number | null;
  readonly sourceAuthority: "unverified";
  readonly wordSourceBinding: "caller-supplied-unverified";
  readonly byteBinding: "bound-supplied-byte-domains";
  readonly callerRecordBound: true;
  readonly issuerAuthority: string;
}
export interface OcrCandidateLine {
  readonly lineId: string;
  readonly scope: OcrCandidateScope;
  readonly ordinal: readonly number[];
  readonly text: string;
  readonly textRendering: string;
  readonly words: readonly OcrCandidateWord[];
  readonly candidateIds: readonly string[];
  readonly status: "unknown" | "tentative-field";
  readonly reason: string;
  readonly requiresReview: true;
}
export interface OcrCandidateFact {
  readonly candidateId: string;
  readonly lineId: string;
  readonly field: OcrCandidateField;
  readonly rawValue: string;
  readonly normalizedValue: string;
  readonly precision: "unknown" | null;
  readonly status: "tentative";
  readonly requiresReview: true;
  readonly valueVerified: false;
  readonly derivation: string;
  readonly labelWordIndices: readonly number[];
  readonly valueWordIndices: readonly number[];
  readonly reasons: readonly string[];
  readonly entityAssociation: string;
}
export interface OcrCandidateReport {
  readonly schemaVersion: "ei-private-ocr-candidate-facts/1";
  readonly profile: "explicit-label-ordinal-line-unknown-dates/1";
  readonly prerequisite: ByteIdentity;
  readonly overall: "incomplete";
  readonly requiresReview: true;
  readonly sourceAuthority: "unverified";
  readonly financeAuthority: "none";
  readonly acceptedFacts: readonly never[];
  readonly acceptance: Readonly<{ evaluated: false; satisfiedIds: readonly never[]; ownerAcknowledgements: readonly never[] }>;
  readonly lines: readonly OcrCandidateLine[];
  readonly candidates: readonly OcrCandidateFact[];
  readonly outcomes: readonly Readonly<{ observationId: string; component: string; result: ByteIdentity; status: "unknown" | "review-required"; reason: string; lineIds: readonly string[]; refusalCode?: string }>[];
  readonly totalTextBytes: number;
  readonly reasons: readonly string[];
  readonly limits: Readonly<Record<string, number>>;
}
export interface OcrCandidateArtifact { readonly report: OcrCandidateReport; readonly sha256: string; readonly byteLength: number; copyBytes(): Uint8Array; }
export const OCR_CANDIDATE_VERSION: "ei-private-ocr-candidate-facts/1";
export const OCR_CANDIDATE_PROFILE: "explicit-label-ordinal-line-unknown-dates/1";
export const OCR_CANDIDATE_LIMITS: Readonly<Record<string, number>>;
export class OcrCandidateError extends Error { readonly code: string; }
export function deriveOcrCandidateFacts(input: OcrCandidateInput): OcrCandidateArtifact;
export function validateOcrCandidateFacts(reportBytes: Uint8Array, expectedSha256: string, input: OcrCandidateInput): OcrCandidateArtifact;
