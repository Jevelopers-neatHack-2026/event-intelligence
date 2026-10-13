import type { ByteIdentity, JsonValue, SelectedInspectionPins, InspectionMode } from "./index.mjs";
import type { InspectionMediaReportInput, InspectionMediaReport } from "./media.mjs";
import type { StaticImageOcrResult } from "../static-image-ocr/index.mjs";
import type { ScannedPdfOcrObserved, ScannedPdfOcrRejected } from "../scanned-pdf-ocr/index.mjs";

export type InspectionOcrComponent = "static-image-ocr" | "scanned-pdf-ocr";
export interface InspectionOcrExecution {
  readonly id: string;
  readonly component: InspectionOcrComponent;
  readonly pins: SelectedInspectionPins;
  readonly mode: InspectionMode;
  readonly origin: "local-synthetic" | "recorded";
  /** Complete existing component-verifier wrapper stream, separately from caller records. */
  readonly stdoutBytes: Uint8Array;
  readonly stderrBytes: Uint8Array;
  readonly childStderrBytes: Uint8Array | null;
  readonly exitCode: number | null;
  readonly signal: "SIGTERM" | "SIGKILL" | "SIGABRT" | "SIGINT" | null;
  /** Caller-produced source/result/observation join; a supplied record is not an issuer signature. */
  readonly callerRecordBytes: Uint8Array | null;
  readonly expectedCallerRecordSha256: string | null;
}
export type InspectionOcrObservation = Readonly<{
  id: string; mediaObservationId: string; executionId: string;
  /** SHA256 of sorted compact JSON plus LF; declared absent refusal fields are omitted. */
  expectedResultSha256: string;
}> & (Readonly<{ component: "static-image-ocr"; result: StaticImageOcrResult }> |
  Readonly<{ component: "scanned-pdf-ocr"; result: ScannedPdfOcrObserved | ScannedPdfOcrRejected }>);
export interface InspectionOcrReportInput {
  readonly prerequisite: Readonly<{ input: InspectionMediaReportInput; reportBytes: Uint8Array; expectedSha256: string }>;
  readonly runtimeReceipt: Readonly<{ bytes: Uint8Array; expectedSha256: string }> | null;
  /** Required OCR formats, separately selected from prior non-OCR component coverage. */
  readonly requiredFormats: readonly ("png" | "jpeg" | "webp" | "scanned-pdf")[];
  readonly executions: readonly InspectionOcrExecution[];
  readonly observations: readonly InspectionOcrObservation[];
}
export interface InspectionOcrReport {
  readonly schemaVersion: "ei-local-inspection-ocr-report/1";
  readonly pins: SelectedInspectionPins;
  readonly pinAuthority: "checked-host-selection-only";
  readonly overall: "incomplete";
  readonly acceptance: Readonly<{ evaluated: false; satisfiedIds: readonly never[]; ownerAcknowledgements: readonly never[] }>;
  readonly financeAuthority: "none";
  readonly factInference: "none";
  readonly prerequisite: ByteIdentity & Readonly<{ report: InspectionMediaReport }>;
  readonly runtimeReceipt: ByteIdentity | null;
  readonly runtimeAuthority: string;
  readonly requiredFormats: readonly string[];
  readonly missingFormats: readonly string[];
  readonly executions: readonly Readonly<Record<string, JsonValue>>[];
  readonly observations: readonly Readonly<Record<string, JsonValue>>[];
  readonly totalResultBytes: number;
  readonly reasons: readonly string[];
  readonly authority: string;
}
export interface InspectionOcrReportArtifact {
  readonly report: InspectionOcrReport;
  readonly sha256: string;
  readonly byteLength: number;
  copyBytes(): Uint8Array;
}
export const INSPECTION_OCR_REPORT_VERSION: "ei-local-inspection-ocr-report/1";
export const INSPECTION_OCR_REPORT_LIMITS: Readonly<Record<string, number>>;
export function composeInspectionOcrReport(input: InspectionOcrReportInput): InspectionOcrReportArtifact;
export function validateInspectionOcrReport(reportBytes: Uint8Array, expectedSha256: string, input: InspectionOcrReportInput): InspectionOcrReportArtifact;
