import type { InspectionMode, InspectionReport, InspectionReportInput, SelectedInspectionPins, JsonValue, ByteIdentity } from "./index.mjs";
import type { StaticPngDecoded, StaticPngRejected } from "../png/index.mjs";
import type { StaticJpegWebpDecoded, StaticJpegWebpRejected } from "../jpeg-webp/index.mjs";
import type { ScannedPdfDecoded, ScannedPdfRejected, RasterPageObservation } from "../scanned-pdf/index.mjs";

export type InspectionMediaComponent = "static-png" | "static-jpeg-webp" | "scanned-pdf";
/** Explicit data projection: callers copy derivatives outside the pure composer.
 * An absent native source hash becomes null, never a fabricated hash. */
type Projected<T> = Omit<T, "sourceSha256" | "copyNormalizedBytes" | "copyRgbaBytes"> & { readonly sourceSha256: string | null; readonly copyNormalizedBytes?: never; readonly copyRgbaBytes?: never };
export type PngDataProjection = Readonly<{ schemaVersion: "ei-native-media-data-projection/1"; component: "static-png"; result: Projected<StaticPngDecoded> | Projected<StaticPngRejected> }>;
export type JpegWebpDataProjection = Readonly<{ schemaVersion: "ei-native-media-data-projection/1"; component: "static-jpeg-webp"; result: Projected<StaticJpegWebpDecoded> | Projected<StaticJpegWebpRejected> }>;
export type ScannedPdfDataProjection = Readonly<{ schemaVersion: "ei-native-media-data-projection/1"; component: "scanned-pdf"; result:
  (Omit<ScannedPdfDecoded, "pages"> & { readonly pages: readonly (Omit<RasterPageObservation, "copyRgbaBytes"> & { readonly copyRgbaBytes?: never })[] }) | Projected<ScannedPdfRejected> }>;
export type MediaDataProjection = PngDataProjection | JpegWebpDataProjection | ScannedPdfDataProjection;

export interface InspectionSourceSnapshot {
  readonly schemaVersion: "ei-inspection-source-snapshot/1";
  readonly revision: string;
  readonly tree: string;
  readonly dirty: boolean;
  /** Exact sorted physical source inventory; this is supplied evidence, not trust. */
  readonly files: readonly Readonly<{ path: string; mode: number; bytes: number; sha256: string }>[];
}
export interface InspectionSourceBindingInput {
  readonly selectedTree: string;
  readonly beforeBytes: Uint8Array;
  readonly expectedBeforeSha256: string;
  readonly afterBytes: Uint8Array;
  readonly expectedAfterSha256: string;
}
export interface InspectionRuntimeReceipt {
  readonly component: "static-jpeg-webp" | "scanned-pdf";
  readonly bytes: Uint8Array;
  readonly expectedSha256: string;
}
export interface InspectionMediaExecution {
  readonly id: string;
  readonly component: InspectionMediaComponent;
  readonly pins: SelectedInspectionPins;
  readonly mode: InspectionMode;
  readonly origin: "local-synthetic" | "recorded";
  /** Entire existing dedicated wrapper output, including its terminal JSON. */
  readonly stdoutBytes: Uint8Array;
  readonly stderrBytes: Uint8Array;
  /** Separate child stderr bytes only when available; never assume wrapper equivalence. */
  readonly childStderrBytes: Uint8Array | null;
  readonly exitCode: number | null;
  readonly signal: "SIGTERM" | "SIGKILL" | "SIGABRT" | "SIGINT" | null;
}
export interface InspectionPngDerivative {
  readonly role: "normalized-png";
  readonly page: null;
  readonly bytes: Uint8Array;
  readonly expectedSha256: string;
}
/** Raw static-image samples; distinct from encoded PNG and scanned-page RGBA. */
export interface InspectionImageRgbaDerivative {
  readonly role: "image-rgba8";
  readonly page: null;
  readonly bytes: Uint8Array;
  readonly expectedSha256: string;
}
export interface InspectionRgbaDerivative {
  readonly role: "page-rgba8";
  readonly page: number;
  readonly bytes: Uint8Array;
  readonly expectedSha256: string;
}
type OriginalSource = Readonly<{ sourceBytes: Uint8Array; expectedSourceSha256: string }> | Readonly<{ sourceBytes: null; expectedSourceSha256: null }>;
interface ObservationBase { readonly id: string; readonly pins: SelectedInspectionPins; readonly executionId: string; }
export type InspectionMediaObservation = ObservationBase & OriginalSource & (
  Readonly<{ component: "static-png"; format: "png"; projection: PngDataProjection; derivatives: readonly (InspectionPngDerivative | InspectionImageRgbaDerivative)[] }> |
  Readonly<{ component: "static-jpeg-webp"; format: "jpeg" | "webp"; projection: JpegWebpDataProjection; derivatives: readonly (InspectionPngDerivative | InspectionImageRgbaDerivative)[] }> |
  Readonly<{ component: "scanned-pdf"; format: "scanned-pdf"; projection: ScannedPdfDataProjection; derivatives: readonly InspectionRgbaDerivative[] }>
);
export interface InspectionMediaReportInput {
  /** The existing v1 report is revalidated against its complete original input. */
  readonly prerequisite: Readonly<{ input: InspectionReportInput; reportBytes: Uint8Array; expectedSha256: string }>;
  readonly source: InspectionSourceBindingInput;
  readonly runtimeReceipts: readonly InspectionRuntimeReceipt[];
  readonly executions: readonly InspectionMediaExecution[];
  readonly observations: readonly InspectionMediaObservation[];
}
export interface InspectionMediaReport {
  readonly schemaVersion: "ei-local-inspection-media-report/2";
  readonly pins: SelectedInspectionPins;
  readonly pinAuthority: "checked-host-selection-only";
  readonly mappingState: InspectionReportInput["mappingState"];
  readonly requiredMode: InspectionMode;
  readonly overall: "incomplete";
  readonly acceptance: Readonly<{ evaluated: false; satisfiedIds: readonly never[]; ownerAcknowledgements: readonly never[] }>;
  readonly financeAuthority: "none";
  readonly ocrOrFactInference: "none";
  readonly providerActivity: "not established by report validation";
  readonly prerequisite: ByteIdentity & Readonly<{ report: InspectionReport }>;
  readonly source: Readonly<Record<string, JsonValue>>;
  readonly runtimeReceipts: readonly Readonly<Record<string, JsonValue>>[];
  readonly requiredFormats: readonly string[];
  readonly missingFormats: readonly string[];
  /** Selected inventory/check completeness only; never accepted research or inspection. */
  readonly declaredCoverage: "complete" | "incomplete";
  readonly executions: readonly Readonly<Record<string, JsonValue>>[];
  readonly observations: readonly Readonly<Record<string, JsonValue>>[];
  readonly totalProvidedSourceBytes: number;
  readonly totalDerivativeBytes: number;
  readonly reasons: readonly string[];
  readonly authority: string;
}
export interface InspectionMediaReportArtifact {
  readonly report: InspectionMediaReport;
  readonly sha256: string;
  readonly byteLength: number;
  copyBytes(): Uint8Array;
}
export const INSPECTION_MEDIA_REPORT_VERSION: "ei-local-inspection-media-report/2";
export const INSPECTION_MEDIA_PROJECTION_VERSION: "ei-native-media-data-projection/1";
export const INSPECTION_SOURCE_SNAPSHOT_VERSION: "ei-inspection-source-snapshot/1";
export const INSPECTION_MEDIA_REPORT_LIMITS: Readonly<Record<string, number>>;
export function composeInspectionMediaReport(input: InspectionMediaReportInput): InspectionMediaReportArtifact;
export function validateInspectionMediaReport(reportBytes: Uint8Array, expectedSha256: string, input: InspectionMediaReportInput): InspectionMediaReportArtifact;
