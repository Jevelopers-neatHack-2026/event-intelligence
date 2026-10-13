// Dedicated private-reader route. Shared application/evaluation runners are untouched.
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstatSync, readFileSync, readlinkSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import profile from "../src/extraction/local-ocr/profile.json" with { type: "json" };
const root = fileURLToPath(new URL("../", import.meta.url));
const files = ["tests/extraction/local-ocr/reader.test.mjs", "tests/extraction/local-ocr/lifecycle.test.mjs",
  "tests/extraction/local-ocr/protocol.test.mjs", "tests/extraction/local-ocr/native.test.mjs",
  "tests/extraction/local-ocr/runtime.test.mjs", "tests/extraction/local-ocr/initializer.test.mjs",
  "tests/extraction/local-ocr/loader-diagnostic.test.mjs"];
const expectedTests = 178;
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
if (process.platform !== "linux" || process.arch !== "x64" || process.versions.node !== profile.nodeVersion) {
  throw new Error("Required local OCR verification needs Linux x86_64 / Node22.23.3; unsupported platforms do not skip required tests.");
}
const before = sourceMap();
const source = { revision: git("rev-parse", "HEAD").trim(), tree: git("rev-parse", "HEAD^{tree}").trim(),
  dirty: git("status", "--porcelain").length > 0, files: before.length, sha256: sha(JSON.stringify(before)) };
const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", "--test-concurrency=1", ...files], {
  cwd: root, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120000,
});
process.stdout.write(result.stdout ?? ""); process.stderr.write(result.stderr ?? "");
const counts = {};
for (const name of ["tests", "pass", "fail", "cancelled", "skipped", "todo"]) {
  const matches = [...(result.stdout ?? "").matchAll(new RegExp("^# " + name + " (\\d+)$", "gm"))];
  counts[name] = matches.length === 1 ? Number(matches[0][1]) : null;
}
const unchanged = JSON.stringify(before) === JSON.stringify(sourceMap());
const complete = !result.error && result.status === 0 && result.signal === null && unchanged &&
  counts.tests === expectedTests && counts.pass === expectedTests &&
  ["fail", "cancelled", "skipped", "todo"].every((name) => counts[name] === 0);
const attempt = new Date().toISOString().replaceAll(":", "-") + "-" + randomUUID();
const directory = path.join(root, "tools/local-ocr/runtime/verification", attempt);
mkdirSync(directory, { recursive: true });
const summary = {
  mode: "synthetic raster fixtures; real Tesseract/model/native restrictions and recovery; separately simulated worker protocols/lifecycle; no provider requests",
  source, sourceUnchanged: unchanged, node: process.versions.node, files, expectedTests, counts,
  nestedNativeTsvVectors: { expected: 26, requiredBy: "native.test.mjs" }, complete,
  exitCode: result.status, signal: result.signal, executionError: result.error?.code ?? null,
  stdoutSha256: sha(result.stdout ?? ""), stderrSha256: sha(result.stderr ?? ""),
};
writeFileSync(path.join(directory, "source-map.json"), JSON.stringify(before, null, 2) + "\n");
writeFileSync(path.join(directory, "stdout.tap"), result.stdout ?? "");
writeFileSync(path.join(directory, "stderr.txt"), result.stderr ?? "");
writeFileSync(path.join(directory, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
// This latest pointer can change; immutable attempt directories preserve earlier failures.
writeFileSync(path.join(root, "tools/local-ocr/runtime/verification.json"), JSON.stringify({ attempt, ...summary }, null, 2) + "\n");
process.stdout.write(JSON.stringify(summary) + "\n");
if (!complete) { process.stderr.write("Required OCR verification failed, changed source, or omitted a required case.\n"); process.exitCode = 1; }
