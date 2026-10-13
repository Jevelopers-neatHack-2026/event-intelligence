import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { evaluateCompletion } from "../../tools/verify.mjs";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));

function runVerifier(args, env = {}) {
  const childEnv = { ...process.env, ...env };
  // The standalone verifier starts its own node:test run; do not inherit this runner's child marker.
  delete childEnv.NODE_TEST_CONTEXT;
  return spawnSync(process.execPath, [path.join(ROOT, "tools/verify.mjs"), ...args], {
    cwd: ROOT,
    encoding: "utf8",
    env: childEnv,
  });
}

function summaryFrom(output) {
  const line = output.split(/\r?\n/).find((entry) => entry.startsWith("VERIFY_SUMMARY_JSON="));
  assert.ok(line, output);
  return JSON.parse(line.slice("VERIFY_SUMMARY_JSON=".length));
}

test("completion gate requires a nonempty all-pass run with no skipped or unreported cases", () => {
  const pass = { success: true, counts: { passed: 2, failed: 0, skipped: 0, todo: 0, cancelled: 0 } };
  assert.deepEqual(evaluateCompletion(pass, 2), { complete: true, terminal: 2, counts: pass.counts });
  assert.equal(evaluateCompletion(pass, 0).complete, false);
  assert.equal(evaluateCompletion({ ...pass, counts: { ...pass.counts, skipped: 1 } }, 3).complete, false);
  assert.equal(evaluateCompletion(pass, 3).complete, false);
  assert.equal(evaluateCompletion(undefined, 2).complete, false);
});

test("unimplemented reserved case fails when it collects zero test files", () => {
  const result = runVerifier(["--case=evals", "--mode=mock"]);
  const summary = summaryFrom(result.stdout);
  assert.equal(result.status, 1);
  assert.equal(summary.test_files, 0);
  assert.equal(summary.expected_cases, 0);
  assert.equal(summary.status, "failed");
});

test("evidence-facts mock case runs only local durable-store and provenance fixtures", () => {
  const result = runVerifier(["--case=evidence-facts", "--mode=mock"]);
  const summary = summaryFrom(result.stdout);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(summary.case, "evidence-facts");
  assert.equal(summary.mode, "mock");
  assert.equal(summary.status, "passed");
  assert.equal(summary.test_files, 4);
  assert.ok(summary.expected_cases > 0);
  assert.equal(summary.expected_cases, summary.terminal_cases);
  assert.equal(summary.failed_cases, 0);
  assert.equal(summary.skipped_cases, 0);
  assert.equal(summary.provider_activity, "none");
  assert.equal(summary.fixture_scope, "local controlled fixtures only");
});

test("evidence remains a compatibility alias for the canonical evidence-facts case", () => {
  const canonical = summaryFrom(runVerifier(["--case=evidence-facts", "--mode=mock"]).stdout);
  const aliasResult = runVerifier(["--case=evidence", "--mode=mock"]);
  const alias = summaryFrom(aliasResult.stdout);
  assert.equal(aliasResult.status, 0, aliasResult.stderr);
  assert.equal(alias.case, "evidence-facts");
  assert.equal(alias.expected_cases, canonical.expected_cases);
  assert.equal(alias.test_files, canonical.test_files);
});

test("deterministic extraction mock route runs only local fixtures with complete counts", () => {
  const result = runVerifier(["--case=deterministic-extraction", "--mode=mock"]);
  const summary = summaryFrom(result.stdout);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(summary.case, "deterministic-extraction");
  assert.equal(summary.mode, "mock");
  assert.equal(summary.status, "passed");
  assert.equal(summary.test_files, 3);
  assert.ok(summary.expected_cases > 0);
  assert.equal(summary.expected_cases, summary.terminal_cases);
  assert.equal(summary.passed_cases, summary.expected_cases);
  assert.equal(summary.failed_cases, 0);
  assert.equal(summary.skipped_cases, 0);
  assert.equal(summary.fixture_scope, "local controlled fixtures only");
  assert.equal(summary.external_egress, "not measured");
  assert.equal(summary.provider_activity, "none");
});

test("Python policy checks have a separate unit-only route with faithful unittest counts", () => {
  const result = runVerifier(["--case=eval-policy-unit", "--mode=unit"]);
  const summary = summaryFrom(result.stdout);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(summary.case, "eval-policy-unit");
  assert.equal(summary.mode, "unit");
  assert.equal(summary.status, "passed");
  assert.ok(summary.expected_cases > 0);
  assert.equal(summary.expected_cases, summary.executed_cases + summary.skipped_cases);
  assert.equal(summary.executed_cases, summary.passed_cases);
  assert.equal(summary.failed_cases, 0);
  assert.equal(summary.skipped_cases, 0);
  assert.equal(summary.expected_failure_cases, 0);
  assert.equal(summary.unexpected_success_cases, 0);
  assert.equal(summary.provider_activity, "none");
});

test("Python policy checks reject mock, recorded, sandbox, and live mode labels", () => {
  for (const mode of ["mock", "recorded", "sandbox", "live"]) {
    const result = runVerifier(["--case=eval-policy-unit", `--mode=${mode}`]);
    const summary = summaryFrom(result.stdout);
    assert.equal(result.status, 1, mode);
    assert.equal(summary.status, "failed", mode);
    assert.equal(summary.reason, "unknown case or mode", mode);
  }
});

test("Python launcher ignores PYTHONPATH startup injection", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "ei-pythonpath-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(path.join(directory, "sitecustomize.py"), "raise RuntimeError('PYTHONPATH was executed')\n");

  const result = runVerifier(
    ["--case=eval-policy-unit", "--mode=unit"],
    { PYTHONPATH: directory },
  );
  const summary = summaryFrom(result.stdout);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(summary.status, "passed");
  assert.equal(summary.provider_activity, "none");
});

test("live mode remains blocked even when a config-shaped file is present", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "ei-verify-config-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const configPath = path.join(directory, "release.json");
  await writeFile(configPath, JSON.stringify({
    release_manifest: "manifest-reference",
    budget_authorization: "budget-reference",
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  }));
  for (const caseName of ["safe-retrieval", "cache-invalidation"]) {
    const result = runVerifier([`--case=${caseName}`, "--mode=live"], { EVENT_INTELLIGENCE_LIVE_CONFIG: configPath });
    const summary = summaryFrom(result.stdout);
    assert.equal(result.status, 1);
    assert.equal(summary.status, "blocked");
    assert.equal(summary.release_config_shape_present, true);
    assert.equal(summary.provider_activity, "none");
    assert.match(summary.reason, /not authenticated authorization/);
  }
});

test("prototype property names are not valid case selectors", () => {
  const result = runVerifier(["--case=constructor", "--mode=mock"]);
  assert.equal(result.status, 1);
  assert.equal(summaryFrom(result.stdout).reason, "unknown case or mode");
});
