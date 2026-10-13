import type { ExtractionLimits, ExtractionResult } from "../index.mjs";
import type { PdfTextReadResult } from "../pdf/index.mjs";

export type InspectionMode = "mock" | "recorded" | "sandbox" | "live";
export type InspectionFormat = "html" | "xhtml" | "plain-text" | "json-ld" | "text-pdf" | "scanned-pdf" | "png" | "jpeg" | "webp";
export type InspectionComponent = "deterministic-extraction" | "text-pdf";
export type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export interface SelectedInspectionPins {
  /** Exact selected repository revision; checked for equality, not attested. */
  readonly sourceRevision: string;
  readonly package: Readonly<{ version: string; sha256: string }>;
  /** JSON Pointer selects the schema's existing version value; no alias mapping. */
  readonly evidenceSchema: Readonly<{ id: string; version: string; versionPointer: string; sha256: string }>;
  readonly supportMatrix: Readonly<{ version: string; sha256: string }>;
}

export interface InspectionExecution {
  readonly id: string;
  readonly component: InspectionComponent;
  readonly pins: SelectedInspectionPins;
  readonly mode: InspectionMode;
  readonly origin: "local-synthetic" | "recorded";
  /** Existing deterministic runner or existing text-PDF Node TAP output. */
  readonly format: "verify-summary" | "node-tap";
  readonly summaryBytes: Uint8Array;
  readonly expectedCases: number;
  readonly exitCode: number | null;
  readonly signal: "SIGTERM" | "SIGKILL" | "SIGABRT" | "SIGINT" | null;
}

interface ObservationBase {
  readonly id: string;
  readonly pins: SelectedInspectionPins;
  readonly executionId: string;
  readonly sourceBytes: Uint8Array;
  /** Unprefixed SHA-256 of original source bytes, checked independently. */
  readonly expectedSourceSha256: string;
}
export interface DeterministicInspectionObservation extends ObservationBase {
  readonly component: "deterministic-extraction";
  readonly format: "html" | "xhtml" | "plain-text" | "json-ld";
  readonly result: ExtractionResult;
  readonly sourceMetadata: Readonly<{ url: string; fetchedAt: string; contentType: string }>;
  /** Full lower-only declared limits. The current extractor does not echo them. */
  readonly declaredLimits: ExtractionLimits;
}
export interface PdfInspectionObservation extends ObservationBase {
  readonly component: "text-pdf";
  readonly format: "text-pdf";
  readonly result: PdfTextReadResult;
}

export interface InspectionReportInput {
  readonly expectedPins: SelectedInspectionPins;
  readonly artifacts: Readonly<{ package: Uint8Array; evidenceSchema: Uint8Array; supportMatrix: Uint8Array }>;
  readonly requiredMode: InspectionMode;
  /** There is deliberately no accepted/granted state in this local format. */
  readonly mappingState: "missing" | "held" | "selected-unaccepted";
  readonly executions: readonly InspectionExecution[];
  readonly observations: readonly (DeterministicInspectionObservation | PdfInspectionObservation)[];
}

export interface ByteIdentity {
  readonly domain: string;
  readonly sha256: string;
  readonly bytes: number;
}
export interface InspectionExecutionView {
  readonly id: string;
  readonly component: InspectionComponent;
  readonly mode: InspectionMode;
  readonly origin: "local-synthetic" | "recorded";
  readonly format: "verify-summary" | "node-tap";
  readonly summary: ByteIdentity;
  readonly expectedCases: number;
  readonly counts: Readonly<{ total: number; passed: number; failed: number; skipped: number; todo: number; cancelled: number }>;
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly complete: boolean;
}
export interface InspectionReport {
  readonly schemaVersion: "ei-local-inspection-report/1";
  readonly pins: SelectedInspectionPins;
  readonly pinAuthority: "checked-host-selection-only";
  readonly requiredMode: InspectionMode;
  readonly mappingState: InspectionReportInput["mappingState"];
  readonly overall: "incomplete";
  readonly acceptance: Readonly<{ evaluated: false; satisfiedIds: readonly never[]; ownerAcknowledgements: readonly never[] }>;
  readonly providerActivity: "not established by report validation";
  readonly financeAuthority: "none";
  readonly requiredFormats: readonly InspectionFormat[];
  readonly missingFormats: readonly InspectionFormat[];
  /** Completeness only of the selected inventory and declared checks. */
  readonly declaredCoverage: "complete" | "incomplete";
  readonly prerequisiteDeterministicReport: ByteIdentity | null;
  readonly executions: readonly InspectionExecutionView[];
  readonly observations: readonly Readonly<{ id: string; component: InspectionComponent; format: InspectionFormat; executionId: string; source: ByteIdentity; result: ByteIdentity; view: Readonly<Record<string, JsonValue>> }>[];
  readonly reasons: readonly string[];
}
export interface InspectionReportArtifact {
  readonly report: InspectionReport;
  readonly sha256: string;
  readonly byteLength: number;
  /** A fresh owned copy; mutating it cannot change the artifact or another copy. */
  copyBytes(): Uint8Array;
}

export declare const INSPECTION_REPORT_VERSION: "ei-local-inspection-report/1";
export declare const INSPECTION_MATRIX_SCHEMA: "ei-local-inspection-support-matrix/1";
export declare const INSPECTION_REPORT_LIMITS: Readonly<{
  maxObservations: number; maxExecutions: number; maxSourceBytes: number;
  maxTotalSourceBytes: number; maxArtifactBytes: number; maxSummaryBytes: number;
  maxResultBytes: number; maxReportBytes: number; maxJsonDepth: number;
  maxJsonNodes: number; maxCases: number;
}>;
export declare class InspectionReportError extends Error { readonly code: string; }
export declare function composeInspectionReport(input: InspectionReportInput): InspectionReportArtifact;
export declare function validateInspectionReport(bytes: Uint8Array, expectedSha256: string, input: InspectionReportInput): InspectionReportArtifact;
