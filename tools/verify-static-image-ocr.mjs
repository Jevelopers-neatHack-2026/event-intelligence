// Dedicated private composition route; no shared selector or release gate changes.
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstatSync, readFileSync, readlinkSync, writeFileSync, mkdirSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PNG_DECODER, RASTER_DECODER, OCR_PROFILE } from "../src/extraction/static-image-ocr/profile.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const syntheticFiles = ["admission", "protocol", "lifecycle"].map((name) => `tests/extraction/static-image-ocr/${name}.test.mjs`);
const nativeFiles = ["deadline-overlay", "reader"].map((name) => `tests/extraction/static-image-ocr/${name}.test.mjs`);
const files = [...syntheticFiles, ...nativeFiles];
const expectedTests = 137;
const sha = (value) => createHash("sha256").update(value).digest("hex");
const git = (...args) => {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error("Source identity unavailable");
  return result.stdout;
};
function sourceMap() {
  const names = [...new Set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0").filter(Boolean))].sort();
  return names.map((name) => {
    const file = path.join(root, name), stat = lstatSync(file);
    const bytes = stat.isSymbolicLink() ? Buffer.from(readlinkSync(file)) : readFileSync(file);
    return { path: name, mode: stat.mode & 0o777, bytes: bytes.length, sha256: sha(bytes) };
  });
}
function markerIdentity(name, file) {
  try {
    const bytes = readFileSync(file);
    return { name, path: file, bytes: bytes.length, sha256: sha(bytes) };
  } catch { return { name, path: file, unavailable: true }; }
}
if (process.platform !== "linux" || process.arch !== "x64" ||
    process.versions.node !== PNG_DECODER.nodeVersion || process.versions.node !== RASTER_DECODER.nodeVersion ||
    process.versions.node !== OCR_PROFILE.nodeVersion) {
  throw new Error("Required native composition verification needs Linux x86_64 / Node22.23.3; unsupported hosts cannot skip required cases.");
}
const raster = process.env.EI_STATIC_IMAGE_OCR_RASTER_RUNTIME;
if (!raster || !path.isAbsolute(raster) || path.resolve(raster) !== raster || realpathSync(raster) !== raster) {
  throw new Error("An explicit canonical EI_STATIC_IMAGE_OCR_RASTER_RUNTIME with the reviewed offline installation is required.");
}
const before = sourceMap();
const source = { revision: git("rev-parse", "HEAD").trim(), tree: git("rev-parse", "HEAD^{tree}").trim(),
  dirty: git("status", "--porcelain").length > 0, files: before.length, sha256: sha(JSON.stringify(before)) };
const runtime = [markerIdentity("static-raster", path.join(raster, "runtime.json")),
  markerIdentity("local-ocr", path.join(root, "tools/local-ocr/runtime/manifest.json"))];
const command = ["--test", "--test-reporter=tap", "--test-concurrency=1", ...files];
const startedAt = new Date().toISOString();
const result = spawnSync(process.execPath, command, {
  cwd: root, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120000,
});
process.stdout.write(result.stdout ?? ""); process.stderr.write(result.stderr ?? "");
const counts = {};
for (const name of ["tests", "pass", "fail", "cancelled", "skipped", "todo"]) {
  const matches = [...(result.stdout ?? "").matchAll(new RegExp("^# " + name + " (\\d+)$", "gm"))];
  counts[name] = matches.length === 1 ? Number(matches[0][1]) : null;
}
const unchanged = JSON.stringify(before) === JSON.stringify(sourceMap());
const runtimeUnchanged = JSON.stringify(runtime) === JSON.stringify(runtime.map(({ name, path: file }) => markerIdentity(name, file)));
const complete = !result.error && result.status === 0 && result.signal === null && unchanged && runtimeUnchanged &&
  runtime.every((item) => !item.unavailable) && counts.tests === expectedTests && counts.pass === expectedTests &&
  ["fail", "cancelled", "skipped", "todo"].every((name) => counts[name] === 0);
const attempt = new Date().toISOString().replaceAll(":", "-") + "-" + randomUUID();
const directory = path.join(root, "tools/static-image-ocr/runtime/verification", attempt);
mkdirSync(directory, { recursive: true });
const summary = {
  mode: "synthetic sources; actual PNG/JPEG/WebP-to-Tesseract native composition, child-close and recovery; separately simulated stage/protocol/admission cases; no provider calls",
  startedAt, finishedAt: new Date().toISOString(), source, sourceUnchanged: unchanged,
  runtimeMarkers: runtime, runtimeMarkersUnchanged: runtimeUnchanged, node: process.versions.node,
  command: [process.execPath, ...command], files, expectedTests, counts,
  groups: { syntheticStageBoundary: { files: syntheticFiles, expectedTests: 95 },
    actualNativeCompositionAndDeadline: { files: nativeFiles, expectedTests: 42 } },
  complete, exitCode: result.status, signal: result.signal, executionError: result.error?.code ?? null,
  stdoutSha256: sha(result.stdout ?? ""), stderrSha256: sha(result.stderr ?? ""),
};
writeFileSync(path.join(directory, "source-map.json"), JSON.stringify(before, null, 2) + "\n");
writeFileSync(path.join(directory, "stdout.tap"), result.stdout ?? "");
writeFileSync(path.join(directory, "stderr.txt"), result.stderr ?? "");
writeFileSync(path.join(directory, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
// This pointer never replaces the distinct directory for any passed or failed attempt.
writeFileSync(path.join(root, "tools/static-image-ocr/runtime/verification.json"), JSON.stringify({ attempt, ...summary }, null, 2) + "\n");
process.stdout.write(JSON.stringify(summary) + "\n");
if (!complete) { process.stderr.write("Required composition failed, drifted, or omitted a required case.\n"); process.exitCode = 1; }
