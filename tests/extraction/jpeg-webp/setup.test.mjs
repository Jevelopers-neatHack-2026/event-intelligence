import assert from "node:assert/strict";
import test, { after } from "node:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hash, runtimeDirectory } from "./fixtures.mjs";

const setup = fileURLToPath(new URL("../../../tools/static-raster/install.py", import.meta.url));
const root = mkdtempSync(path.join(tmpdir(), "ei-static-raster-setup-"));
const python = path.join(runtimeDirectory(), "bin", "python");
const wheel = process.env.EI_JPEG_WEBP_TEST_WHEEL;
assert.ok(wheel, "EI_JPEG_WEBP_TEST_WHEEL must name the exact development wheel; missing input is a failure");
const wheelHash = "78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91";
assert.equal(hash(readFileSync(wheel)), wheelHash);
after(() => { assert.equal(hash(readFileSync(wheel)), wheelHash); rmSync(root, { recursive: true }); });

function refused(args, t, prefix = []) {
  const argv = ["-I", "-S", "-B", ...(prefix.length ? prefix : [setup]), ...args];
  const result = spawnSync(python, argv, { encoding: "utf8", timeout: 5000, maxBuffer: 256 * 1024 });
  t.diagnostic(JSON.stringify({ executable: python, argv, status: result.status, signal: result.signal, stdout: result.stdout, stderr: result.stderr }));
  assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 2);
  assert.equal(result.stdout, "");
  return result.stderr;
}

test("offline installer refuses a same-name same-length wheel with the wrong digest before creating an environment", (t) => {
  const bad = path.join(root, path.basename(wheel));
  writeFileSync(bad, Buffer.alloc(6940830));
  const destination = path.join(root, "bad-wheel-runtime");
  assert.match(refused(["--wheel", bad, "--destination", destination], t), /exact pinned Pillow wheel/);
  assert.equal(existsSync(destination), false);
});

test("offline installer refuses an existing empty destination without replacing it", (t) => {
  const destination = path.join(root, "existing"); mkdirSync(destination);
  assert.match(refused(["--wheel", wheel, "--destination", destination], t), /new canonical absolute path/);
  assert.equal(existsSync(path.join(destination, "runtime.json")), false);
});

test("offline installer refuses a relative destination before installation", (t) => {
  assert.match(refused(["--wheel", wheel, "--destination", "relative-runtime"], t), /new canonical absolute path/);
  assert.equal(existsSync("relative-runtime"), false);
});

test("synthetic wrong-patch runtime control exercises the installer ABI admission before setup", (t) => {
  const destination = path.join(root, "wrong-python");
  const script = "import platform,runpy,sys;platform.python_version=lambda:'3.12.0';p=sys.argv.pop(1);sys.argv[0]=p;runpy.run_path(p,run_name='__main__')";
  assert.match(refused(["--wheel", wheel, "--destination", destination], t, ["-c", script, setup]), /CPython 3.12.14 on Linux x86-64/);
  assert.equal(existsSync(destination), false);
});
