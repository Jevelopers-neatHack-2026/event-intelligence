import path from "node:path";
import process from "node:process";
import { lstat, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { run } from "node:test";
import { spec } from "node:test/reporters";
import { finished } from "node:stream/promises";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
export const INSPECTION_REPORT_TEST_FILES = Object.freeze([
  "tests/inspection-report/report.test.mjs",
  "tests/inspection-report/runner.test.mjs",
]);
export const INSPECTION_REPORT_EXPECTED_CASES = 65;

export function evaluateInspectionCompletion(summaries, enqueued, expectedCases) {
  const roots = summaries.filter((summary) => summary.file === undefined);
  const aggregate = roots.length === 1 ? roots[0] : null;
  const counts = aggregate?.counts;
  const keys = ["passed", "failed", "skipped", "todo", "cancelled"];
  const valid = counts && keys.every((key) => Number.isSafeInteger(counts[key]) && counts[key] >= 0)
    && Number.isSafeInteger(enqueued) && enqueued > 0 && Number.isSafeInteger(expectedCases) && expectedCases > 0;
  const terminal = valid ? keys.reduce((total, key) => total + counts[key], 0) : 0;
  const complete = Boolean(valid && aggregate.success === true && enqueued === expectedCases && terminal === expectedCases
    && counts.passed === expectedCases && keys.slice(1).every((key) => counts[key] === 0));
  return Object.freeze({ complete, terminal, counts: valid ? Object.freeze(Object.fromEntries(keys.map((key) => [key, counts[key]]))) : null, rootSummaries: roots.length });
}

export async function verifyInspectionReport(args) {
  const mode = args.length === 0 ? "mock" : args.length === 2 && args[0] === "--mode" ? args[1] : null;
  const common = { schemaVersion: "ei-inspection-report-check/1", case: "inspection-report-integrity", mode, expectedCases: INSPECTION_REPORT_EXPECTED_CASES, fullInspectionAdaptersAcceptance: false, providerActivity: "none", fixtureScope: "synthetic sources; actual local deterministic/native Linux PDF components" };
  const emit = (value) => process.stdout.write(`INSPECTION_REPORT_VERIFY_JSON=${JSON.stringify({ ...common, ...value })}\n`);
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
    for (const relative of INSPECTION_REPORT_TEST_FILES) {
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
    const result = evaluateInspectionCompletion(summaries, enqueued, INSPECTION_REPORT_EXPECTED_CASES);
    emit({ status: result.complete ? "passed" : "failed", exitCode: result.complete ? 0 : 1, testFiles: files.length, enqueuedCases: enqueued, terminalCases: result.terminal, counts: result.counts, rootSummaries: result.rootSummaries, reason: result.complete ? "all required local report checks completed" : "missing, extra, failed, skipped, cancelled, TODO or ambiguous terminal evidence" });
    return result.complete ? 0 : 1;
  } catch {
    emit({ status: "failed", exitCode: 1, testFiles: 0, terminalCases: 0, reason: "required local report checker failed before trustworthy completion" });
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await verifyInspectionReport(process.argv.slice(2));
}
