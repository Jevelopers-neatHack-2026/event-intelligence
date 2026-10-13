// Dedicated private composition route; shared application/evaluation runners stay unchanged.
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstatSync, readFileSync, readlinkSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PDF_PROFILE, OCR_PROFILE } from "../src/extraction/scanned-pdf-ocr/profile.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const files = ["tests/extraction/scanned-pdf-ocr/admission.test.mjs", "tests/extraction/scanned-pdf-ocr/protocol.test.mjs",
  "tests/extraction/scanned-pdf-ocr/lifecycle.test.mjs", "tests/extraction/scanned-pdf-ocr/deadline-overlay.test.mjs",
  "tests/extraction/scanned-pdf-ocr/reader.test.mjs"];
const expectedTests = 143;
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
function runtimeIdentity(name) {
  try {
    const bytes = readFileSync(path.join(root, name));
    return { path: name, bytes: bytes.length, sha256: sha(bytes) };
  } catch { return { path: name, unavailable: true }; }
}
if (process.platform !== "linux" || process.arch !== "x64" ||
    process.versions.node !== PDF_PROFILE.nodeVersion || process.versions.node !== OCR_PROFILE.nodeVersion) {
  throw new Error("Required composed native verification needs Linux x86_64 / Node22.23.3; unsupported hosts cannot skip required tests.");
}
const before = sourceMap();
const source = { revision: git("rev-parse", "HEAD").trim(), tree: git("rev-parse", "HEAD^{tree}").trim(),
  dirty: git("status", "--porcelain").length > 0, files: before.length, sha256: sha(JSON.stringify(before)) };
const runtime = ["tools/scanned-pdf/runtime/manifest.json", "tools/local-ocr/runtime/manifest.json"].map(runtimeIdentity);
const command = ["--test", "--test-reporter=tap", "--test-concurrency=1", ...files];
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
const runtimeUnchanged = JSON.stringify(runtime) === JSON.stringify(runtime.map(({ path: name }) => runtimeIdentity(name)));
const complete = !result.error && result.status === 0 && result.signal === null && unchanged && runtimeUnchanged &&
  runtime.every((item) => !item.unavailable) && counts.tests === expectedTests && counts.pass === expectedTests &&
  ["fail", "cancelled", "skipped", "todo"].every((name) => counts[name] === 0);
const attempt = new Date().toISOString().replaceAll(":", "-") + "-" + randomUUID();
const directory = path.join(root, "tools/scanned-pdf-ocr/runtime/verification", attempt);
mkdirSync(directory, { recursive: true });
const summary = {
  mode: "synthetic PDF/raster sources; real PDFium-to-Tesseract composition and native child recovery; separately simulated stage/protocol/queue cases; no provider calls",
  source, sourceUnchanged: unchanged, runtime, runtimeUnchanged, node: process.versions.node,
  command: [process.execPath, ...command], files, expectedTests, counts,
  groups: { admission: 27, protocol: 69, lifecycle: 13, actualDeadlineOverlay: 16, actualNativeCaller: 18 },
  complete, exitCode: result.status, signal: result.signal, executionError: result.error?.code ?? null,
  stdoutSha256: sha(result.stdout ?? ""), stderrSha256: sha(result.stderr ?? ""),
};
writeFileSync(path.join(directory, "source-map.json"), JSON.stringify(before, null, 2) + "\n");
writeFileSync(path.join(directory, "stdout.tap"), result.stdout ?? "");
writeFileSync(path.join(directory, "stderr.txt"), result.stderr ?? "");
writeFileSync(path.join(directory, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
// The mutable pointer does not replace any retained attempt, including failed attempts.
writeFileSync(path.join(root, "tools/scanned-pdf-ocr/runtime/verification.json"), JSON.stringify({ attempt, ...summary }, null, 2) + "\n");
process.stdout.write(JSON.stringify(summary) + "\n");
if (!complete) { process.stderr.write("Required composed verification failed, drifted, or omitted a required case.\n"); process.exitCode = 1; }
