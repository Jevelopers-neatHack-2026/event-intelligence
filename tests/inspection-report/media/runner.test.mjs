import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { evaluateInspectionCompletion } from "../../../tools/verify-inspection-report.mjs";
import { INSPECTION_MEDIA_REPORT_TEST_FILES, INSPECTION_MEDIA_REPORT_EXPECTED_CASES } from "../../../tools/verify-inspection-media-report.mjs";
import { ROOT } from "./support.mjs";

function refused(args, omit = null) {
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  if (omit) delete env[omit];
  const result = spawnSync(process.execPath, ["tools/verify-inspection-media-report.mjs", ...args], { cwd: ROOT, env, encoding: "utf8", timeout: 5000, maxBuffer: 16384 });
  assert.equal(result.status, 1); assert.equal(result.signal, null); assert.equal(result.error, undefined);
  const lines = result.stdout.trim().split("\n"); assert.equal(lines.length, 1);
  const prefix = "INSPECTION_MEDIA_REPORT_VERIFY_JSON="; assert.ok(lines[0].startsWith(prefix));
  const summary = JSON.parse(lines[0].slice(prefix.length));
  assert.equal(summary.testFiles, 0); assert.equal(summary.terminalCases, 0);
  assert.equal(summary.fullInspectionAdaptersAcceptance, false); assert.equal(summary.providerActivity, "none"); assert.equal(summary.ocrActivity, "none");
  return summary;
}
test("media report selection is explicit and cannot absorb a media owner's growing test tree", () => {
  assert.deepEqual(INSPECTION_MEDIA_REPORT_TEST_FILES, ["tests/inspection-report/media/media.test.mjs", "tests/inspection-report/media/runner.test.mjs"]);
  assert.ok(Object.isFrozen(INSPECTION_MEDIA_REPORT_TEST_FILES));
});
test("aggregate completion cannot borrow a component summary or ignore an uncollected required case", () => {
  const count = INSPECTION_MEDIA_REPORT_EXPECTED_CASES;
  const root = { success: true, counts: { passed: count, failed: 0, skipped: 0, todo: 0, cancelled: 0 } };
  assert.equal(evaluateInspectionCompletion([root], count, count).complete, true);
  assert.equal(evaluateInspectionCompletion([{ ...root, file: "component" }], count, count).complete, false);
  assert.equal(evaluateInspectionCompletion([root, root], count, count).complete, false);
  assert.equal(evaluateInspectionCompletion([root], count - 1, count).complete, false);
  const failed = structuredClone(root); failed.counts.passed--; failed.counts.failed++;
  assert.equal(evaluateInspectionCompletion([failed], count, count).complete, false);
});
test("live and arbitrary path options cannot start native work or change the report inventory", () => {
  assert.equal(refused(["--mode", "live"]).status, "blocked");
  for (const args of [["--files", "../../private"], ["--mode", "mock", "--mode", "live"], ["--mode", "recorded"]]) assert.equal(refused(args).status, "failed");
});
test("a missing pinned JPEG/WebP runtime is a required failure with no skipped pass", () => {
  assert.equal(refused(["--mode", "mock"], "EI_JPEG_WEBP_TEST_RUNTIME").status, "failed");
});
test("a missing pinned archive required by native recovery controls cannot be counted as coverage", () => {
  assert.equal(refused(["--mode", "mock"], "EI_JPEG_WEBP_TEST_WHEEL").status, "failed");
});
