import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
const execute = promisify(execFile);
const required = 73;

// Synthetic verifier-only inventories. No native product result is represented
// by these controls. The actual verifier includes reader.test.mjs only.
for (const mode of ["complete", "missing", "reduced", "skipped", "failed"]) {
  test("dedicated native outcome verifier " + mode + " inventory", async (t) => {
    const root = await mkdtemp(path.join(os.tmpdir(), "ei-native-outcome-verifier-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    await mkdir(path.join(root, "tools"), { recursive: true });
    await mkdir(path.join(root, "tests/extraction/inspection-outcomes"), { recursive: true });
    await writeFile(path.join(root, "tools/verify-inspection-outcomes.mjs"),
      await readFile(new URL("../../../tools/verify-inspection-outcomes.mjs", import.meta.url)));
    if (mode !== "missing") {
      const count = mode === "reduced" ? 1 : required;
      const lines = ["import test from 'node:test';"];
      for (let i = 0; i < count; i++) lines.push("test" + (mode === "skipped" && i === 0 ? ".skip" : "") +
        "('synthetic inventory " + i + "', () => {" + (mode === "failed" && i === 0 ? "throw new Error('expected synthetic verifier failure');" : "") + "});");
      await writeFile(path.join(root, "tests/extraction/inspection-outcomes/reader.test.mjs"), lines.join("\n"));
    }
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
    let result;
    try {
      result = { ...await execute(process.execPath, ["tools/verify-inspection-outcomes.mjs", "--mode", "mock"], {
        cwd: root, timeout: 10000, maxBuffer: 1024 * 1024, env,
      }), code: 0 };
    } catch (error) { result = error; }
    t.diagnostic("SYNTHETIC_VERIFIER_CONTROL=" + mode);
    t.diagnostic(result.stdout ?? "no stdout"); t.diagnostic(result.stderr ?? "no stderr");
    assert.equal(result.signal ?? null, null); assert.equal(result.killed ?? false, false);
    assert.equal(result.code, mode === "complete" ? 0 : 1);
    const summaries = result.stdout.split("\n").filter((line) => line.startsWith("INSPECTION_OUTCOMES_VERIFY_JSON="));
    assert.equal(summaries.length, 1);
    const summary = JSON.parse(summaries[0].slice("INSPECTION_OUTCOMES_VERIFY_JSON=".length));
    assert.equal(summary.expected_cases, required);
    assert.equal(summary.status, mode === "complete" ? "passed" : "failed");
    if (mode === "complete") assert.equal(summary.passed_cases, required);
    if (mode === "missing" || mode === "failed") assert.ok(summary.failed_cases > 0);
    if (mode === "reduced") assert.equal(summary.observed_cases, 1);
    if (mode === "skipped") assert.equal(summary.skipped_cases, 1);
  });
}
