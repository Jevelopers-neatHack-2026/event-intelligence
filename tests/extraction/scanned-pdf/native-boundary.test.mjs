import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { imagePdf, RGBA_2X2 } from "./fixtures.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
test("native PDFium file loading and native filesystem/network calls are denied while byte rasterization recovers", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "ei-scan-own-native-"));
  const marker = path.join(directory, "synthetic-owned-scan.pdf");
  const input = imagePdf();
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  writeFileSync(marker, input);
  try {
    const manifest = JSON.parse(readFileSync(path.join(root, "tools/scanned-pdf/runtime/manifest.json")));
    const result = spawnSync("/usr/bin/prlimit", [
      "--as=1073741824:1073741824", "--cpu=5:5", "--nofile=64:64", "--core=0:0", "--",
      manifest.descriptor.python, "-I", "-S", "-B", path.join(root, "tests/extraction/scanned-pdf/native-boundary-probe.py"), root, marker,
    ], { input, encoding: "utf8", timeout: 10000, maxBuffer: 16384,
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" } });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    const observed = JSON.parse(result.stdout);
    assert.equal(observed.beforeSealPathLoad, true);
    assert.equal(observed.afterSealPathLoad, false);
    assert.equal(observed.extraDescriptorClosed, true);
    assert.equal(observed.enforcementControlsPassed, 8);
    assert.equal(observed.pixelsExact, true);
    assert.equal(observed.sourceSha256, digest(input));
    assert.equal(observed.pageSha256, digest(RGBA_2X2));
    for (const value of Object.values(observed.attempts)) assert.deepEqual(value, { value: -1, errno: 1 });
    assert.equal(digest(readFileSync(marker)), digest(input), "the denied unlink/open attempt leaves owned bytes unchanged");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
