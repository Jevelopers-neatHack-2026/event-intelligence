import { composeInspectionOcrReport, validateInspectionOcrReport, type InspectionOcrReportInput, type InspectionOcrObservation } from "../../../src/extraction/inspection-report/ocr.mjs";
import type { StaticImageOcrResult } from "../../../src/extraction/static-image-ocr/index.mjs";
import type { ScannedPdfOcrObserved } from "../../../src/extraction/scanned-pdf-ocr/index.mjs";
declare const input: InspectionOcrReportInput;
declare const image: StaticImageOcrResult;
declare const pdf: ScannedPdfOcrObserved;
const observations: readonly InspectionOcrObservation[] = [
  { id: "image", mediaObservationId: "pixels", executionId: "image-suite", component: "static-image-ocr", result: image, expectedResultSha256: "selected" },
  { id: "pdf", mediaObservationId: "pages", executionId: "pdf-suite", component: "scanned-pdf-ocr", result: pdf, expectedResultSha256: "selected" },
];
const a = composeInspectionOcrReport({ ...input, observations });
validateInspectionOcrReport(a.copyBytes(), a.sha256, input);
const incomplete: "incomplete" = a.report.overall;
const noGrant: "none" = a.report.financeAuthority;
const unaccepted: false = a.report.acceptance.evaluated;
// @ts-expect-error Report validation cannot grant accepted facts.
const accepted: "complete" = a.report.overall;
// @ts-expect-error Native OCR is not a callback the pure report can dispatch.
composeInspectionOcrReport({ ...input, readOcr: async () => image });
// @ts-expect-error A static-image result cannot impersonate a PDF result.
const wrong: InspectionOcrObservation = { id: "wrong", mediaObservationId: "pages", executionId: "pdf-suite", component: "scanned-pdf-ocr", result: image, expectedResultSha256: "selected" };
void [incomplete, noGrant, unaccepted, accepted, wrong];
