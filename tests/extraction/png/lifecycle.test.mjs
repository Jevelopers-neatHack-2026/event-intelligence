import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const fixture = fileURLToPath(new URL("./lifecycle-fixture.mjs", import.meta.url));
for (const mode of ["profile", "cancel", "timeout", "queued-cancel", "saturation",
  "queued-deadline", "late-return", "cancel-delayed-close", "raw-copy-timeout", "raw-copy-cancel"]) {
  test("actual child lifecycle: " + mode, () => {
    assert.equal(process.platform, "linux", "Required Linux process cases may not be skipped.");
    const result = spawnSync(process.execPath, [fixture, mode], {
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
      encoding: "utf8", timeout: 20000, maxBuffer: 1024 * 1024,
    });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(result.signal, null, result.stderr);
    const evidence = JSON.parse(result.stdout);
    assert.equal(evidence.outcome, "pass");
    assert.equal(evidence.mode, mode);
    assert.ok(evidence.records.every((record) => record.closed));
    // The phase, exact launch profile and actual kernel/closure results stay in CI logs.
    console.log(JSON.stringify(evidence));
  });
}
