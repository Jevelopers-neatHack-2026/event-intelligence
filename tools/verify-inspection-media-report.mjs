import path from "node:path";
import process from "node:process";
import { lstat, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { run } from "node:test";
import { spec } from "node:test/reporters";
import { finished } from "node:stream/promises";
import { evaluateInspectionCompletion } from "./verify-inspection-report.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
export const INSPECTION_MEDIA_REPORT_TEST_FILES = Object.freeze([
  "tests/inspection-report/media/media.test.mjs",
  "tests/inspection-report/media/runner.test.mjs",
]);
export const INSPECTION_MEDIA_REPORT_EXPECTED_CASES = 148;

async function ordinary(filename, directory = false) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) throw new Error("required runtime or source file unavailable");
  const selected = path.resolve(filename), info = await lstat(selected);
  if (info.isSymbolicLink() || (directory ? !info.isDirectory() : !info.isFile()) || await realpath(selected) !== selected) throw new Error("required ordinary runtime or source file unavailable");
  return selected;
}

export async function verifyInspectionMediaReport(args) {
  const mode = args.length === 0 ? "mock" : args.length === 2 && args[0] === "--mode" ? args[1] : null;
  const common = { schemaVersion: "ei-inspection-media-report-check/1", case: "inspection-media-report-integrity", mode,
    expectedCases: INSPECTION_MEDIA_REPORT_EXPECTED_CASES, fullInspectionAdaptersAcceptance: false, providerActivity: "none", ocrActivity: "none",
    fixtureScope: "synthetic sources; actual deterministic, native text-PDF, PNG, pinned JPEG/WebP and scanned-PDF components" };
  const emit = (value) => process.stdout.write(`INSPECTION_MEDIA_REPORT_VERIFY_JSON=${JSON.stringify({ ...common, ...value })}\n`);
  if (mode !== "mock") {
    emit({ status: mode === "live" ? "blocked" : "failed", exitCode: 1, testFiles: 0, terminalCases: 0,
      reason: mode === "live" ? "live inspection is not implemented by this local media report checker" : "only --mode mock is supported" });
    return 1;
  }
  if (process.platform !== "linux" || process.arch !== "x64" || process.versions.node !== "22.23.3") {
    emit({ status: "failed", exitCode: 1, testFiles: 0, terminalCases: 0, reason: "the required Linux x86_64 / Node22.23.3 native consumer cannot be skipped" });
    return 1;
  }
  try {
    const root = await realpath(ROOT);
    const raster = await ordinary(process.env.EI_JPEG_WEBP_TEST_RUNTIME, true);
    await ordinary(path.join(raster, "runtime.json"));
    await ordinary(process.env.EI_JPEG_WEBP_TEST_WHEEL);
    await ordinary(path.join(root, "tools/scanned-pdf/runtime/manifest.json"));
    // Actual component readers and their complete native test routes perform
    // version, archive, closure and isolation verification. Existence is only
    // an early prerequisite check, never a substitute for those checks.
    const files = [];
    for (const relative of INSPECTION_MEDIA_REPORT_TEST_FILES) files.push(await ordinary(path.join(root, relative)));
    const stream = run({ files, concurrency: 1, isolation: "process", cwd: root });
    const summaries = [];
    let enqueued = 0;
    stream.on("test:enqueue", (value) => { if (value.type === "test") enqueued += 1; });
    stream.on("test:summary", (value) => { summaries.push(value); });
    const reporter = stream.compose(spec), done = finished(reporter);
    reporter.pipe(process.stdout, { end: false });
    await done;
    const result = evaluateInspectionCompletion(summaries, enqueued, INSPECTION_MEDIA_REPORT_EXPECTED_CASES);
    emit({ status: result.complete ? "passed" : "failed", exitCode: result.complete ? 0 : 1,
      testFiles: files.length, enqueuedCases: enqueued, terminalCases: result.terminal, counts: result.counts, rootSummaries: result.rootSummaries,
      reason: result.complete ? "all required local media report and actual component-consumer controls completed" : "missing, extra, failed, skipped, cancelled, TODO or ambiguous terminal evidence" });
    return result.complete ? 0 : 1;
  } catch {
    emit({ status: "failed", exitCode: 1, testFiles: 0, terminalCases: 0, reason: "required pinned runtime, native consumer or local checker unavailable before trustworthy completion" });
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await verifyInspectionMediaReport(process.argv.slice(2));
