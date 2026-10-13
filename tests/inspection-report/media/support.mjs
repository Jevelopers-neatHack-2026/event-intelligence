import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync, readlinkSync, mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { actualFixture as textFixture } from "../support.mjs";
import { composeInspectionReport } from "../../../src/extraction/inspection-report/index.mjs";
import { INSPECTION_MEDIA_PROJECTION_VERSION, INSPECTION_SOURCE_SNAPSHOT_VERSION } from "../../../src/extraction/inspection-report/media.mjs";
import { readStaticPng } from "../../../src/extraction/png/index.mjs";
import { createStaticJpegWebpReader } from "../../../src/extraction/jpeg-webp/index.mjs";
import { readScannedPdf } from "../../../src/extraction/scanned-pdf/index.mjs";
import { png } from "../../extraction/png/fixtures.mjs";
import { fixture } from "../../extraction/jpeg-webp/fixtures.mjs";
import { imagePdf } from "../../extraction/scanned-pdf/fixtures.mjs";

export const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
export const hash = (value) => createHash("sha256").update(value).digest("hex");
export const copy = (value) => structuredClone(value);
export const jsonBytes = (value) => Buffer.from(JSON.stringify(value));
export function git(...args) {
  const child = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
  assert.equal(child.status, 0, child.stderr); return child.stdout.trim();
}
export function sourceSnapshot() {
  const names = [...new Set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0").filter(Boolean))].sort();
  const files = names.map((name) => {
    const file = path.join(ROOT, name), info = lstatSync(file);
    const bytes = info.isSymbolicLink() ? Buffer.from(readlinkSync(file)) : readFileSync(file);
    return { path: name, mode: info.mode & 0o777, bytes: bytes.length, sha256: hash(bytes) };
  });
  return { schemaVersion: INSPECTION_SOURCE_SNAPSHOT_VERSION, revision: git("rev-parse", "HEAD"), tree: git("rev-parse", "HEAD^{tree}"), dirty: git("status", "--porcelain").length > 0, files };
}
const captureDirectory = process.env.EI_INSPECTION_MEDIA_REPORT_CAPTURE;
function capture(name, bytes) {
  if (!captureDirectory) return;
  assert.ok(path.isAbsolute(captureDirectory));
  const relative = path.relative(ROOT, captureDirectory);
  assert.ok(relative.startsWith(".." + path.sep) || path.isAbsolute(relative), "evidence must stay outside the tested source tree");
  mkdirSync(captureDirectory, { recursive: true });
  writeFileSync(path.join(captureDirectory, name), bytes, { flag: "wx" });
}
function command(component, script) {
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const args = [script];
  const child = spawnSync(process.execPath, args, { cwd: ROOT, env, encoding: "buffer", timeout: 180_000, maxBuffer: 2 * 1024 * 1024 });
  capture(component + ".stdout", child.stdout ?? Buffer.alloc(0));
  capture(component + ".stderr", child.stderr ?? Buffer.alloc(0));
  capture(component + ".command.json", jsonBytes({ executable: process.execPath, args, cwd: ROOT, exitCode: child.status, signal: child.signal, error: child.error?.code ?? null, mode: "actual existing local native component checks over synthetic fixtures; no provider requests" }));
  assert.equal(child.error, undefined, child.error?.message);
  assert.equal(child.status, 0, JSON.stringify({ component, exit: child.status, signal: child.signal, stdout: child.stdout?.toString(), stderr: child.stderr?.toString() }));
  assert.equal(child.signal, null);
  return child;
}

/** This helper consumes actual trusted native reader output. The production
 * composer never calls the removed methods or reads the filesystem. */
export function projectedObservation(component, format, id, native, sourceBytes, pins) {
  const result = { ...native, sourceSha256: native.sourceSha256 ?? null };
  delete result.copyNormalizedBytes;
  let derivatives = [];
  if (native.kind === "decoded" && component === "scanned-pdf") {
    result.pages = native.pages.map(({ copyRgbaBytes, ...metadata }) => metadata);
    derivatives = native.pages.map((p) => ({ role: "page-rgba8", page: p.page, bytes: p.copyRgbaBytes(), expectedSha256: p.sha256 }));
  } else if (native.kind === "decoded") {
    derivatives = [{ role: "normalized-png", page: null, bytes: native.copyNormalizedBytes(), expectedSha256: native.normalizedSha256 }];
  }
  return { id, component, format, pins, executionId: component, sourceBytes,
    expectedSourceSha256: sourceBytes === null ? null : hash(sourceBytes),
    projection: { schemaVersion: INSPECTION_MEDIA_PROJECTION_VERSION, component, result }, derivatives };
}
export function refreshPrerequisite(input, change) {
  change(input.prerequisite.input);
  const artifact = composeInspectionReport(input.prerequisite.input);
  input.prerequisite.reportBytes = artifact.copyBytes(); input.prerequisite.expectedSha256 = artifact.sha256;
}
export function changeSnapshot(input, key, change) {
  const field = key === "before" ? "beforeBytes" : "afterBytes";
  const value = JSON.parse(Buffer.from(input.source[field]).toString()); change(value);
  input.source[field] = jsonBytes(value); input.source[key === "before" ? "expectedBeforeSha256" : "expectedAfterSha256"] = hash(input.source[field]);
}
export function changeNativeSummary(input, component, change, alterTap = (x) => x) {
  const e = input.executions.find((e) => e.component === component);
  const text = Buffer.from(e.stdoutBytes).toString(), start = text.lastIndexOf("\n{") + 1;
  assert.ok(start > 0);
  const native = JSON.parse(text.slice(start)); const tap = alterTap(text.slice(0, start));
  change(native); if (component === "scanned-pdf") native.stdoutSha256 = hash(tap);
  e.stdoutBytes = Buffer.from(tap + JSON.stringify(native) + "\n");
}

export async function actualMediaFixture() {
  assert.equal(process.platform, "linux"); assert.equal(process.versions.node, "22.23.3");
  const runtimeDirectory = process.env.EI_JPEG_WEBP_TEST_RUNTIME;
  assert.ok(runtimeDirectory, "actual pinned JPEG/WebP runtime is required, never skipped");
  const before = sourceSnapshot(); capture("source-before.json", jsonBytes(before));
  const text = await textFixture();
  const pins = { ...text.expectedPins, sourceRevision: before.revision };
  text.expectedPins = pins;
  text.executions = text.executions.map((e) => ({ ...e, pins }));
  text.observations = text.observations.map((o) => ({ ...o, pins }));
  const prerequisite = composeInspectionReport(text);
  const raster = createStaticJpegWebpReader({ runtimeDirectory });
  const observations = [];
  for (const [id, source] of [
    ["png-rgba", png()], ["png-rgb", png({ colorType: 2, scanlines: Buffer.from([0, 255, 100, 10]) })],
  ]) {
    const native = await readStaticPng(source); assert.equal(native.kind, "decoded", JSON.stringify(native));
    observations.push(projectedObservation("static-png", "png", id, native, source, pins));
  }
  for (const name of ["jpeg-gray-baseline", "jpeg-rgb-baseline", "jpeg-rgb-progressive", "webp-rgb-lossy", "webp-rgb-lossless", "webp-rgba-lossless", "webp-rgba-compressed-alpha"]) {
    const source = fixture(name).bytes; const native = await raster.read(source);
    assert.equal(native.kind, "decoded", JSON.stringify(native));
    observations.push(projectedObservation("static-jpeg-webp", native.sourceFormat, name, native, source, pins));
  }
  for (const [id, source] of [["pdf-scan-one", imagePdf()], ["pdf-scan-two", imagePdf([{ points: [72, 36] }, { points: [36, 72] }])]]) {
    const native = await readScannedPdf(source); assert.equal(native.kind, "decoded", JSON.stringify(native));
    observations.push(projectedObservation("scanned-pdf", "scanned-pdf", id, native, source, pins));
  }
  const executions = [];
  for (const component of ["static-png", "static-jpeg-webp", "scanned-pdf"]) {
    const child = command(component, "tools/verify-" + component + ".mjs");
    // Empty wrapper stderr proves that no distinct child stderr bytes were lost.
    // Otherwise retain unknown instead of assigning the whole wrapper stream.
    executions.push({ id: component, component, pins, mode: "mock", origin: "local-synthetic", stdoutBytes: child.stdout,
      stderrBytes: child.stderr, childStderrBytes: child.stderr.length === 0 ? Buffer.alloc(0) : null, exitCode: child.status, signal: child.signal });
  }
  const runtimeReceipts = [
    { component: "static-jpeg-webp", bytes: readFileSync(path.join(runtimeDirectory, "runtime.json")) },
    { component: "scanned-pdf", bytes: readFileSync(path.join(ROOT, "tools/scanned-pdf/runtime/manifest.json")) },
  ].map((item) => ({ ...item, expectedSha256: hash(item.bytes) }));
  const after = sourceSnapshot(); capture("source-after.json", jsonBytes(after));
  assert.deepEqual(after, before, "actual component checks must preserve the complete selected source");
  const first = jsonBytes(before), last = jsonBytes(after);
  const input = { prerequisite: { input: text, reportBytes: prerequisite.copyBytes(), expectedSha256: prerequisite.sha256 },
    source: { selectedTree: before.tree, beforeBytes: first, expectedBeforeSha256: hash(first), afterBytes: last, expectedAfterSha256: hash(last) },
    runtimeReceipts, executions, observations };
  capture("actual-fixture-origins.json", jsonBytes({ selectedSource: { revision: before.revision, tree: before.tree, dirty: before.dirty, files: before.files.length },
    pins: "selected existing package/schema bytes and explicitly synthetic unaccepted support matrix", observations: observations.map((o) => ({ id: o.id, sourceSha256: o.expectedSourceSha256, projection: o.projection, derivatives: o.derivatives.map((d) => ({ role: d.role, page: d.page, bytes: d.bytes.length, sha256: hash(d.bytes) })) })),
    runtimeReceipts: runtimeReceipts.map((r) => ({ component: r.component, bytes: r.bytes.length, sha256: r.expectedSha256 })), ocrOrProviderCalls: false }));
  return { input, readStaticPng, raster, readScannedPdf, png, imagePdf, fixture, capture };
}
