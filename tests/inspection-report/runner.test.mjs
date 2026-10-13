import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { evaluateInspectionCompletion, INSPECTION_REPORT_TEST_FILES } from "../../tools/verify-inspection-report.mjs";
import { ROOT } from "./support.mjs";

const root = () => ({ success: true, counts: { passed: 3, failed: 0, skipped: 0, todo: 0, cancelled: 0 } });

test("required completion checks actual single root, expected and collected counts", () => {
  assert.equal(evaluateInspectionCompletion([root()], 3, 3).complete, true);
  assert.equal(evaluateInspectionCompletion([root()], 4, 3).complete, false);
  assert.equal(evaluateInspectionCompletion([root()], 3, 4).complete, false);
  assert.equal(evaluateInspectionCompletion([], 0, 0).complete, false);
});
test("duplicate root summaries cannot let the last successful result win", () => {
  assert.equal(evaluateInspectionCompletion([root(), root()], 3, 3).complete, false);
  const failed = root(); failed.success = false;
  assert.equal(evaluateInspectionCompletion([failed, root()], 3, 3).complete, false);
});
for (const key of ["failed", "skipped", "todo", "cancelled"]) test(`runner refuses required ${key} case completion`, () => {
  const result = root(); result.counts.passed = 2; result.counts[key] = 1;
  assert.equal(evaluateInspectionCompletion([result], 3, 3).complete, false);
});
test("counts cannot be strings, negative, nonfinite or child-only summaries", () => {
  for (const bad of ["3", -1, NaN, Infinity]) {
    const r = root(); r.counts.passed = bad;
    assert.equal(evaluateInspectionCompletion([r], 3, 3).complete, false);
  }
  assert.equal(evaluateInspectionCompletion([{ ...root(), file: "child.mjs" }], 3, 3).complete, false);
});
test("test selection is explicit and cannot absorb other media owner's recursive tests", () => {
  assert.deepEqual(INSPECTION_REPORT_TEST_FILES, ["tests/inspection-report/report.test.mjs", "tests/inspection-report/runner.test.mjs"]);
  assert.ok(Object.isFrozen(INSPECTION_REPORT_TEST_FILES));
});
test("live and arbitrary path CLI options refuse before any child or source read", () => {
  for (const args of [["--mode", "live"], ["--files", "../../private"], ["--mode", "mock", "--mode", "live"]]) {
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
    const r = spawnSync(process.execPath, ["tools/verify-inspection-report.mjs", ...args], { cwd: ROOT, env, encoding: "utf8", timeout: 5000, maxBuffer: 16384 });
    assert.equal(r.status, 1); assert.equal(r.signal, null);
    const lines = r.stdout.trim().split("\n"); assert.equal(lines.length, 1);
    const summary = JSON.parse(lines[0].slice("INSPECTION_REPORT_VERIFY_JSON=".length));
    assert.equal(summary.testFiles, 0); assert.equal(summary.terminalCases, 0);
    assert.equal(summary.fullInspectionAdaptersAcceptance, false);
  }
});
