import assert from "node:assert/strict";
import test, { after } from "node:test";
import { constants, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createStaticJpegWebpReader } from "../../../src/extraction/jpeg-webp/index.mjs";
import { fixture, hash, runtimeDirectory } from "./fixtures.mjs";

// A private copy of every installed package byte; no hardlinks or mutations of
// the actual configured runtime. This deliberately models trusted setup drift.
const original = runtimeDirectory();
const manifestBytes = readFileSync(path.join(original, "runtime.json"));
const manifest = JSON.parse(manifestBytes);
const directory = mkdtempSync(path.join(tmpdir(), "ei-static-raster-integrity-"));
const site = path.join(directory, manifest.sitePackages);
mkdirSync(path.join(directory, "bin"), { recursive: true });
symlinkSync(manifest.pythonExecutable, path.join(directory, "bin", "python"));
for (const entry of manifest.files) {
  const destination = path.join(site, entry.path);
  mkdirSync(path.dirname(destination), { recursive: true });
  copyFileSync(path.join(original, manifest.sitePackages, entry.path), destination, constants.COPYFILE_FICLONE);
}
const marker = path.join(directory, "runtime.json");
writeFileSync(marker, manifestBytes);
const reader = createStaticJpegWebpReader({ runtimeDirectory: directory });
const bytes = fixture("jpeg-gray-baseline").bytes;
const changedPath = path.join(site, "PIL", "JpegImagePlugin.py");
const originalChanged = readFileSync(changedPath);
after(() => {
  // The independent configured environment remains exactly as installed.
  assert.equal(hash(readFileSync(path.join(original, "runtime.json"))), hash(manifestBytes));
  for (const entry of manifest.files) {
    const actual = readFileSync(path.join(original, manifest.sitePackages, entry.path));
    assert.equal(actual.length, entry.bytes); assert.equal(hash(actual), entry.sha256);
  }
  rmSync(directory, { recursive: true });
});

test("complete copied pinned runtime decodes real pixels before integrity controls", async () => {
  const result = await reader.read(bytes);
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.equal(result.rgbaSha256, fixture("jpeg-gray-baseline").expected.expectedRgbaSha256);
});

const cases = [
  ["malformed marker JSON", () => writeFileSync(marker, "{unfinished")],
  ["marker exceeding its byte bound", () => writeFileSync(marker, Buffer.alloc(256 * 1024 + 1))],
  ["symlinked marker", () => { rmSync(marker); symlinkSync(path.join(original, "runtime.json"), marker); }],
  ["wrong Python patch version", (value) => { value.pythonVersion = "3.12.0"; }],
  ["different wheel hash", (value) => { value.wheelSha256 = "0".repeat(64); }],
  ["wrong interpreter binary hash", (value) => { value.pythonSha256 = "0".repeat(64); }],
  ["changed installed source byte", () => writeFileSync(changedPath, Buffer.concat([originalChanged, Buffer.from("\n# drift\n")]))],
  ["missing installed source", () => rmSync(changedPath)],
  ["installed package symlink", () => { rmSync(changedPath); symlinkSync(path.join(original, manifest.sitePackages, "PIL/JpegImagePlugin.py"), changedPath); }],
  ["unrecorded package source", () => writeFileSync(path.join(site, "PIL", "unrecorded.py"), "raise RuntimeError('not an admitted dependency')\n")],
  ["incomplete package inventory", (value) => { value.files = value.files.slice(1); }],
  ["duplicate inventory entry", (value) => { value.files.push({ ...value.files[0] }); }],
  ["path outside permitted package roots", (value) => { value.files[0].path = "../outside.py"; }],
  ["coerced inventory length", (value) => { value.files[0].bytes = String(value.files[0].bytes); }],
];
for (const [name, alter] of cases) {
  test("installed runtime integrity refuses " + name + " and recovers", async () => {
    const value = structuredClone(manifest);
    // Metadata mutations are distinguished from literal file/marker mutations.
    if (alter.length === 1) { alter(value); writeFileSync(marker, JSON.stringify(value)); }
    else alter();
    try {
      const result = await reader.read(bytes);
      assert.equal(result.kind, "rejected", JSON.stringify(result));
      assert.equal(result.code, "DECODER_UNAVAILABLE");
      assert.equal(result.copyNormalizedBytes, undefined); assert.equal(result.rgbaSha256, undefined);
    } finally {
      rmSync(marker, { force: true }); writeFileSync(marker, manifestBytes);
      rmSync(changedPath, { force: true }); writeFileSync(changedPath, originalChanged);
      rmSync(path.join(site, "PIL", "unrecorded.py"), { force: true });
    }
    assert.equal((await reader.read(bytes)).kind, "decoded", "clean restored runtime must recover");
  });
}

test("isolated no-site startup does not execute an unrelated .pth or sitecustomize file", async () => {
  const canary = path.join(directory, "must-not-exist");
  const payload = "import pathlib; pathlib.Path(" + JSON.stringify(canary) + ").write_text('unexpected startup execution')\n";
  writeFileSync(path.join(site, "unrelated.pth"), payload);
  writeFileSync(path.join(site, "sitecustomize.py"), payload);
  const result = await reader.read(bytes);
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.throws(() => readFileSync(canary), { code: "ENOENT" });
});
