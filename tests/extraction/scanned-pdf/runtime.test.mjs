import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { imagePdf } from "./fixtures.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const originalManifest = JSON.parse(readFileSync(path.join(root, "tools/scanned-pdf/runtime/manifest.json")));
function copyProject() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "ei-scan-owned-runtime-"));
  cpSync(path.join(root, "src/extraction/scanned-pdf"), path.join(directory, "src/extraction/scanned-pdf"), { recursive: true });
  cpSync(path.join(root, "tools/scanned-pdf"), path.join(directory, "tools/scanned-pdf"), { recursive: true,
    filter: (source) => !source.includes(path.sep + "wheels") });
  return directory;
}
async function readIn(directory) {
  const reader = await import(pathToFileURL(path.join(directory, "src/extraction/scanned-pdf/index.mjs")).href);
  return reader.readScannedPdf(imagePdf());
}

test("the reproducible installer checks the current exact dependency and loaded runtime closure", () => {
  const result = spawnSync(originalManifest.descriptor.python,
    [path.join(root, "tools/scanned-pdf/install.py"), "--check"],
    { encoding: "utf8", timeout: 10000, maxBuffer: 16384 });
  assert.equal(result.status, 0, result.stderr);
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.checked, true);
  assert.equal(receipt.wheelMembers, 71);
  assert.equal(receipt.closureSha256, originalManifest.closureSha256);
});

for (const [name, alter] of [
  ["package byte drift", (directory) => {
    const file = path.join(directory, "tools/scanned-pdf/runtime/site/pypdfium2_raw/version.json");
    chmodSync(file, 0o644); writeFileSync(file, "{}\n"); chmodSync(file, 0o444);
  }],
  ["writable package mode", (directory) => chmodSync(path.join(directory, "tools/scanned-pdf/runtime/site/pypdfium2_raw/version.json"), 0o644)],
  ["extra unreviewed package file", (directory) => writeFileSync(path.join(directory, "tools/scanned-pdf/runtime/site/unreviewed.py"), "raise RuntimeError('must never import')\n")],
  ["symlinked package member", (directory) => {
    const member = path.join(directory, "tools/scanned-pdf/runtime/site/pypdfium2_raw/version.json");
    rmSync(member); symlinkSync(path.join(root, "tools/scanned-pdf/runtime/site/pypdfium2_raw/version.json"), member);
  }],
  ["wrong native build claim", (directory) => {
    const manifest = structuredClone(originalManifest);
    manifest.descriptor.pdfiumVersion = "unreviewed";
    writeFileSync(path.join(directory, "tools/scanned-pdf/runtime/manifest.json"), JSON.stringify(manifest));
  }],
  ["loaded runtime hash drift", (directory) => {
    const manifest = structuredClone(originalManifest);
    manifest.descriptor.files.find((file) => file.path !== manifest.descriptor.python).sha256 = "0".repeat(64);
    writeFileSync(path.join(directory, "tools/scanned-pdf/runtime/manifest.json"), JSON.stringify(manifest));
  }],
]) {
  test("an isolated copy refuses " + name + " before source parsing", async () => {
    const directory = copyProject();
    try {
      alter(directory);
      const result = await readIn(directory);
      assert.equal(result.kind, "rejected");
      assert.equal(result.code, "RUNTIME_MISMATCH", JSON.stringify(result));
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
}

test("missing installation returns a local prerequisite refusal and never downloads", async () => {
  const directory = copyProject();
  try {
    rmSync(path.join(directory, "tools/scanned-pdf/runtime"), { recursive: true, force: true });
    assert.equal((await readIn(directory)).code, "DECODER_UNAVAILABLE");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("a wrong wheel is refused before extracting any runtime or invoking setup code", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "ei-scan-owned-install-"));
  try {
    const tools = path.join(directory, "tools/scanned-pdf"); mkdirSync(tools, { recursive: true });
    for (const name of ["install.py", "lock.json", "requirements.txt"]) cpSync(path.join(root, "tools/scanned-pdf", name), path.join(tools, name));
    const wheel = path.join(directory, "wrong.whl"); writeFileSync(wheel, "synthetic wrong wheel");
    const result = spawnSync(originalManifest.descriptor.python, [path.join(tools, "install.py"), "--wheel", wheel],
      { encoding: "utf8", timeout: 10000, maxBuffer: 16384 });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Exact wheel bytes\/digest mismatch/);
    assert.throws(() => readFileSync(path.join(tools, "runtime/manifest.json")), { code: "ENOENT" });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
