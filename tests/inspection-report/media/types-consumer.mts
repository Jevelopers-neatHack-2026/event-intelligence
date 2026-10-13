import { composeInspectionMediaReport, validateInspectionMediaReport, type InspectionMediaReportInput, type InspectionMediaObservation, type PngDataProjection, type ScannedPdfDataProjection } from "../../../src/extraction/inspection-report/media.mjs";
import type { InspectionReportInput, SelectedInspectionPins } from "../../../src/extraction/inspection-report/index.mjs";
import { readStaticPng, type StaticPngDecoded } from "../../../src/extraction/png/index.mjs";
import { readScannedPdf, type ScannedPdfDecoded } from "../../../src/extraction/scanned-pdf/index.mjs";

declare const prerequisite: InspectionReportInput;
declare const pins: SelectedInspectionPins;
declare const reportInput: InspectionMediaReportInput;
declare const pngNative: StaticPngDecoded;
declare const scannedNative: ScannedPdfDecoded;

const png = await readStaticPng(new Uint8Array([1]));
if (png.kind === "decoded") {
  const { copyNormalizedBytes, ...metadata } = png;
  const projection: PngDataProjection = { schemaVersion: "ei-native-media-data-projection/1", component: "static-png", result: metadata };
  const observation: InspectionMediaObservation = { id: "native-png", component: "static-png", format: "png", pins, executionId: "png-native-checks",
    sourceBytes: new Uint8Array([1]), expectedSourceSha256: png.sourceSha256, projection,
    derivatives: [{ role: "normalized-png", page: null, bytes: copyNormalizedBytes(), expectedSha256: png.normalizedSha256 }] };
  void observation;
}
const scanned = await readScannedPdf(new Uint8Array([1]));
if (scanned.kind === "decoded") {
  const projection: ScannedPdfDataProjection = { schemaVersion: "ei-native-media-data-projection/1", component: "scanned-pdf",
    result: { ...scanned, pages: scanned.pages.map(({ copyRgbaBytes, ...metadata }) => metadata) } };
  const observation: InspectionMediaObservation = { id: "native-pdf", component: "scanned-pdf", format: "scanned-pdf", pins, executionId: "pdf-native-checks",
    sourceBytes: new Uint8Array([1]), expectedSourceSha256: scanned.sourceSha256, projection,
    derivatives: scanned.pages.map((p) => ({ role: "page-rgba8", page: p.page, bytes: p.copyRgbaBytes(), expectedSha256: p.sha256 })) };
  void observation;
}
const artifact = composeInspectionMediaReport(reportInput);
const validated = validateInspectionMediaReport(artifact.copyBytes(), artifact.sha256, reportInput);
const incomplete: "incomplete" = validated.report.overall;
const noAcceptance: false = validated.report.acceptance.evaluated;
void incomplete; void noAcceptance; void prerequisite;

// Methods belong to the trusted native caller; the pure report only receives data.
// @ts-expect-error actual decoded PNG still has a callable byte-copy capability
const unprojectedPng: PngDataProjection = { schemaVersion: "ei-native-media-data-projection/1", component: "static-png", result: pngNative };
// @ts-expect-error actual native PDF pages still have callable copy capabilities
const unprojectedPdf: ScannedPdfDataProjection = { schemaVersion: "ei-native-media-data-projection/1", component: "scanned-pdf", result: scannedNative };
// @ts-expect-error the original text-only input has none of the required media/source joins
composeInspectionMediaReport(prerequisite);
// @ts-expect-error source absence must pair with an absent expected digest
const inventedSource: InspectionMediaObservation = { id: "x", component: "static-png", format: "png", pins, executionId: "x", sourceBytes: null, expectedSourceSha256: "a", projection: unprojectedPng, derivatives: [] };
// @ts-expect-error aggregate validation cannot grant inspection acceptance
const complete: true = validated.report.acceptance.evaluated;
// @ts-expect-error report inventory and retained data are immutable
validated.report.observations.push({});
void unprojectedPng; void unprojectedPdf; void inventedSource; void complete;
