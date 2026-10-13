import path from "node:path";
import process from "node:process";
import { lstat, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { run } from "node:test";
import { spec } from "node:test/reporters";
import { finished } from "node:stream/promises";

import { evaluateInspectionCompletion } from "./verify-inspection-report.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
export const OCR_CANDIDATE_TEST_FILES = Object.freeze([
  "tests/extraction/ocr-candidates/candidates.test.mjs",
]);
export const OCR_CANDIDATE_EXPECTED_CASES = 41;

export async function verifyOcrCandidates(args) {
  const mode = args.length === 0 ? "mock" : args.length === 2 && args[0] === "--mode" ? args[1] : null;
  const common = { schemaVersion: "ei-ocr-candidate-check/1", case: "ocr-candidate-facts", mode, expectedCases: OCR_CANDIDATE_EXPECTED_CASES, fullInspectionAdaptersAcceptance: false, providerActivity: "none", fixtureScope: "fresh synthetic PNG/scanned-PDF native calls; explicitly labeled structural word mutations; no upstream suite pass inferred" };
  const emit = (value) => process.stdout.write(`OCR_CANDIDATE_VERIFY_JSON=${JSON.stringify({ ...common, ...value })}\n`);
  if (mode !== "mock") {
    emit({ status: mode === "live" ? "blocked" : "failed", exitCode: 1, testFiles: 0, terminalCases: 0, reason: mode === "live" ? "live inspection is not implemented by this local integrity checker" : "only --mode mock is supported" });
    return 1;
  }
  if (process.platform !== "linux" || process.versions.node !== "22.23.3") {
    emit({ status: "failed", exitCode: 1, testFiles: 0, terminalCases: 0, reason: "required actual Linux/Node22.23.3 consumer runtime unavailable; no skipped pass" });
    return 1;
  }
  try {
    const root = await realpath(ROOT);
    const files = [];
    for (const relative of OCR_CANDIDATE_TEST_FILES) {
      const filename = path.join(root, relative);
      const info = await lstat(filename);
      if (!info.isFile() || info.isSymbolicLink() || await realpath(filename) !== filename) throw new Error("required test file is not an ordinary source file");
      files.push(filename);
    }
    const stream = run({ files, concurrency: 1, isolation: "process", cwd: root });
    const summaries = [];
    let enqueued = 0;
    stream.on("test:enqueue", (value) => { if (value.type === "test") enqueued += 1; });
    stream.on("test:summary", (value) => { summaries.push(value); });
    const reporter = stream.compose(spec);
    const done = finished(reporter);
    reporter.pipe(process.stdout, { end: false });
    await done;
    const result = evaluateInspectionCompletion(summaries, enqueued, OCR_CANDIDATE_EXPECTED_CASES);
    emit({ status: result.complete ? "passed" : "failed", exitCode: result.complete ? 0 : 1, testFiles: files.length, enqueuedCases: enqueued, terminalCases: result.terminal, counts: result.counts, rootSummaries: result.rootSummaries, reason: result.complete ? "all required local OCR candidate checks completed" : "missing, extra, failed, skipped, cancelled, TODO or ambiguous terminal evidence" });
    return result.complete ? 0 : 1;
  } catch {
    emit({ status: "failed", exitCode: 1, testFiles: 0, terminalCases: 0, reason: "required local OCR candidate checker failed before trustworthy completion" });
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await verifyOcrCandidates(process.argv.slice(2));
}
