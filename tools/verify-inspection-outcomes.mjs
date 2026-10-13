import path from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "node:test";
import { spec } from "node:test/reporters";
import { finished } from "node:stream/promises";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const files = [path.join(root, "tests/extraction/inspection-outcomes/reader.test.mjs")];
// Maintained inventory; never lower this to whichever cases happened to enqueue.
const requiredCases = 73;
const args = process.argv.slice(2);
const selected = args.length === 0 || (args.length === 2 && args[0] === "--mode" && args[1] === "mock");
const common = {
  schemaVersion: "ei-inspection-outcomes-check/1", case: "private-inspection-outcomes",
  mode: "mock", fixture_origin: "synthetic byte fixtures; maintained tests call actual pinned native readers",
  expected_cases: requiredCases, provider_activity: "none", canonical_adoption: false, consumer_ack: null,
};
const emit = (value) => process.stdout.write("INSPECTION_OUTCOMES_VERIFY_JSON=" + JSON.stringify({ ...common, ...value }) + "\n");
if (!selected || process.platform !== "linux" || process.arch !== "x64" ||
    process.versions.node !== "22.23.3" || process.versions.zlib !== "1.3.1-e00f703") {
  emit({ status: "failed", test_files: 0, observed_cases: 0, terminal_cases: 0,
    reason: "required local Linux x64 Node/zlib mode unavailable; no skipped pass" });
  process.exitCode = 1;
} else {
  try {
    const summaries = []; let enqueued = 0;
    const stream = run({ files, cwd: root, concurrency: 1, isolation: "process" });
    stream.on("test:enqueue", (event) => { if (event.type === "test") enqueued += 1; });
    stream.on("test:summary", (event) => { if (event.file === undefined) summaries.push(event); });
    const report = stream.compose(spec); const completion = finished(report);
    report.pipe(process.stdout, { end: false }); await completion;
    const summary = summaries.length === 1 ? summaries[0] : null;
    const counts = summary?.counts;
    const keys = ["passed", "failed", "skipped", "cancelled", "todo"];
    const valid = counts && keys.every((key) => Number.isSafeInteger(counts[key]) && counts[key] >= 0);
    const terminal = valid ? keys.reduce((sum, key) => sum + counts[key], 0) : 0;
    const passed = valid && summary.success === true && enqueued === requiredCases && terminal === requiredCases
      && counts.passed === requiredCases && keys.slice(1).every((key) => counts[key] === 0);
    emit({ status: passed ? "passed" : "failed", test_files: files.length, observed_cases: enqueued,
      terminal_cases: terminal, root_summaries: summaries.length, passed_cases: counts?.passed ?? 0,
      failed_cases: counts?.failed ?? 0, skipped_cases: counts?.skipped ?? 0,
      cancelled_cases: counts?.cancelled ?? 0, todo_cases: counts?.todo ?? 0,
      runtime: { node: process.versions.node, zlib: process.versions.zlib },
      reason: passed ? "all required native outcome cases completed" : "missing, reduced, failed, skipped, cancelled, TODO or ambiguous cases" });
    process.exitCode = passed ? 0 : 1;
  } catch {
    emit({ status: "failed", test_files: files.length, observed_cases: 0, terminal_cases: 0,
      reason: "required verifier did not produce trustworthy completion" });
    process.exitCode = 1;
  }
}
