import { extractDeterministically, EXTRACTION_LIMITS } from "../../src/extraction/index.mjs";
import { readTextPdf } from "../../src/extraction/pdf/index.mjs";
import { composeInspectionReport, validateInspectionReport, type InspectionReportInput, type SelectedInspectionPins } from "../../src/extraction/inspection-report/index.mjs";
import type { RetrievedDocument } from "../../src/security/index.mjs";

declare const pins: SelectedInspectionPins;
declare const input: InspectionReportInput;
declare const source: Uint8Array;
const metadata = { url: "https://events.example.test/", contentType: "text/html", fetchedAt: "2026-10-12T00:00:00Z" } satisfies Pick<RetrievedDocument, "url" | "contentType" | "fetchedAt">;
const result = await extractDeterministically({ ...metadata, bytes: source, redirects: 0 });
const pdf = await readTextPdf(source);
const composed = composeInspectionReport({ ...input, observations: [
  { id: "html", pins, component: "deterministic-extraction", format: "html", executionId: "text", expectedSourceSha256: "a".repeat(64), sourceBytes: source, sourceMetadata: metadata, declaredLimits: EXTRACTION_LIMITS, result },
  { id: "pdf", pins, component: "text-pdf", format: "text-pdf", executionId: "pdf", expectedSourceSha256: "b".repeat(64), sourceBytes: source, result: pdf },
] });
validateInspectionReport(composed.copyBytes(), composed.sha256, input);
const incomplete: "incomplete" = composed.report.overall;
const notAccepted: false = composed.report.acceptance.evaluated;
void incomplete; void notAccepted;
// @ts-expect-error No accepted migration or provider grant can be assigned.
composeInspectionReport({ ...input, mappingState: "accepted" });
// @ts-expect-error Paths/URLs are not source bytes.
validateInspectionReport("file:///private/report", composed.sha256, input);
// @ts-expect-error Native PDF result is not deterministic byte-range evidence.
composeInspectionReport({ ...input, observations: [{ id: "wrong", pins, component: "deterministic-extraction", format: "html", executionId: "text", expectedSourceSha256: "c".repeat(64), sourceBytes: source, sourceMetadata: metadata, declaredLimits: EXTRACTION_LIMITS, result: pdf }] });
// @ts-expect-error Report validity cannot become public research-package acceptance.
const accepted: true = composed.report.acceptance.evaluated;
void accepted;
