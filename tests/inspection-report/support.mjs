import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { extractDeterministically, EXTRACTION_LIMITS } from "../../src/extraction/index.mjs";
import { readTextPdf } from "../../src/extraction/pdf/index.mjs";
import { INSPECTION_MATRIX_SCHEMA } from "../../src/extraction/inspection-report/index.mjs";

export const ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const jsonBytes = (v) => Buffer.from(JSON.stringify(v));
export const copy = (value) => structuredClone(value);

function command(args) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, args, { cwd: ROOT, env, encoding: "buffer", timeout: 60_000, maxBuffer: 512 * 1024 });
  assert.equal(child.error, undefined, child.error?.message);
  assert.equal(child.status, 0, JSON.stringify({ args, status: child.status, signal: child.signal, stdout: child.stdout?.toString(), stderr: child.stderr?.toString() }));
  assert.equal(child.signal, null);
  return child.stdout;
}

export async function actualFixture() {
  const packageBytes = readFileSync(new URL("../../package.json", import.meta.url));
  // Existing pinned candidate schema is consumed as bytes only. No adapter,
  // canonical acceptance or migration is established by this diagnostic.
  const schemaBytes = readFileSync(new URL("../contracts/research-contract-v1/candidate-upstream/schemas/EventIntelligencePackage/1.0.0.json", import.meta.url));
  const matrixBytes = jsonBytes({ schemaVersion: INSPECTION_MATRIX_SCHEMA, version: "synthetic-selected-matrix/1", requiredFormats: ["html", "plain-text", "text-pdf", "png", "jpeg", "webp", "scanned-pdf"] });
  const pins = {
    sourceRevision: "dc97a96d07abd5d7b66c0c18f46021e85fd60cea",
    package: { version: "0.1.0", sha256: hash(packageBytes) },
    evidenceSchema: { id: "https://schemas.jevelopers.org/EventIntelligencePackage/1.0.0", version: "1.0.0", versionPointer: "/properties/schema_version/const", sha256: hash(schemaBytes) },
    supportMatrix: { version: "synthetic-selected-matrix/1", sha256: hash(matrixBytes) },
  };
  const htmlBytes = readFileSync(new URL("../extraction/fixtures/multi-event.html", import.meta.url));
  const sourceMetadata = { url: "https://events.example.test/calendar", fetchedAt: "2026-10-10T12:00:00.000Z", contentType: "text/html; charset=utf-8" };
  const extraction = await extractDeterministically({ ...sourceMetadata, bytes: htmlBytes, redirects: 0 });
  assert.equal(extraction.status, "PARTIAL");
  const plainBytes = Buffer.from("Community night. Doors at 7 PM. Dates require review.");
  const plainMetadata = { ...sourceMetadata, contentType: "text/plain; charset=utf-8" };
  const plain = await extractDeterministically({ ...plainMetadata, bytes: plainBytes, redirects: 0 });
  const pdfBytes = readFileSync(new URL("../extraction/pdf/fixtures/text-multipage.pdf", import.meta.url));
  const pdf = await readTextPdf(pdfBytes);
  assert.equal(pdf.kind, "observation", "required real Linux reader must execute; unavailable isolation is not a skip");
  const deterministicStdout = command(["tools/verify.mjs", "--case", "deterministic-extraction", "--mode", "mock"]);
  const summaryLine = deterministicStdout.toString().split("\n").find((x) => x.startsWith("VERIFY_SUMMARY_JSON="));
  const summary = JSON.parse(summaryLine.slice("VERIFY_SUMMARY_JSON=".length));
  assert.equal(summary.expected_cases, 56, "the existing full deterministic route must retain its expected case inventory");
  const pdfStdout = command(["--test", "--test-reporter=tap", "tests/extraction/pdf/reader.test.mjs"]);
  const pdfCount = Number(/^# tests (\d+)$/m.exec(pdfStdout.toString())[1]);
  assert.equal(pdfCount, 20, "the existing full native PDF route must retain its expected case inventory");
  return {
    expectedPins: pins,
    artifacts: { package: packageBytes, evidenceSchema: schemaBytes, supportMatrix: matrixBytes },
    requiredMode: "mock",
    mappingState: "held",
    executions: [
      { id: "deterministic", component: "deterministic-extraction", pins, mode: "mock", origin: "local-synthetic", format: "verify-summary", summaryBytes: deterministicStdout, expectedCases: summary.expected_cases, exitCode: 0, signal: null },
      { id: "pdf", component: "text-pdf", pins, mode: "mock", origin: "local-synthetic", format: "node-tap", summaryBytes: pdfStdout, expectedCases: pdfCount, exitCode: 0, signal: null },
    ],
    observations: [
      { id: "html-source", component: "deterministic-extraction", format: "html", pins, executionId: "deterministic", sourceBytes: htmlBytes, expectedSourceSha256: hash(htmlBytes), sourceMetadata, declaredLimits: EXTRACTION_LIMITS, result: extraction },
      { id: "text-source", component: "deterministic-extraction", format: "plain-text", pins, executionId: "deterministic", sourceBytes: plainBytes, expectedSourceSha256: hash(plainBytes), sourceMetadata: plainMetadata, declaredLimits: EXTRACTION_LIMITS, result: plain },
      { id: "pdf-source", component: "text-pdf", format: "text-pdf", pins, executionId: "pdf", sourceBytes: pdfBytes, expectedSourceSha256: hash(pdfBytes), result: pdf },
    ],
  };
}

export function replaceSummary(input, changes) {
  const e = input.executions[0];
  const prefix = "VERIFY_SUMMARY_JSON=";
  const lines = Buffer.from(e.summaryBytes).toString().split("\n");
  e.summaryBytes = Buffer.from(lines.map((line) => line.startsWith(prefix) ? prefix + JSON.stringify({ ...JSON.parse(line.slice(prefix.length)), ...changes }) : line).join("\n"));
}
