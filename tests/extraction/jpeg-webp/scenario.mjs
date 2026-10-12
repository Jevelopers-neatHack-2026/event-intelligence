import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export function scenario(mode, t) {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("./supervision-fixture.mjs", import.meta.url)), mode], {
    encoding: "utf8", timeout: 16000, maxBuffer: 512 * 1024,
  });
  if (result.stderr) t.diagnostic(result.stderr);
  assert.equal(result.error, undefined, result.stderr);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const data = JSON.parse(result.stdout);
  t.diagnostic(JSON.stringify(data));
  return data;
}
