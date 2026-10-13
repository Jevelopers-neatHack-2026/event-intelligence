import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

test("fixed worker JS network APIs deny before malformed calls and Node denies filesystem/child/worker/addon operations", () => {
  const source = fileURLToPath(new URL("../../../src/extraction/png/", import.meta.url));
  const tests = fileURLToPath(new URL("./", import.meta.url));
  const probe = fileURLToPath(new URL("./network-permission-probe.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [
    "--permission", "--allow-fs-read=" + source, "--allow-fs-read=" + tests, probe,
  ], {
    env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
    encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const evidence = JSON.parse(result.stdout);
  assert.equal(evidence.networkApiAttemptCount, 22);
  assert.equal(evidence.exercised.length, 27);
  assert.equal(evidence.nativeEgressOrHostContainmentAttested, false);
  console.log(JSON.stringify(evidence));
});
