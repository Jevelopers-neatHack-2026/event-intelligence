// Dedicated private-reader verification; does not change another owner's shared runner.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import profile from "../src/extraction/scanned-pdf/profile.json" with { type: "json" };

const root = fileURLToPath(new URL("../", import.meta.url));
const files = [
  "tests/extraction/scanned-pdf/reader.test.mjs",
  "tests/extraction/scanned-pdf/lifecycle.test.mjs",
  "tests/extraction/scanned-pdf/protocol.test.mjs",
  "tests/extraction/scanned-pdf/native-boundary.test.mjs",
  "tests/extraction/scanned-pdf/runtime.test.mjs",
];
const expectedTests = 99;
const sha = (value) => createHash("sha256").update(value).digest("hex");
const git = (...args) => {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error("source identity unavailable");
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
  throw new Error("Required scanned-PDF verification needs the declared Linux x86_64 / Node22.23.3 runtime.");
}
const before = sourceMap();
const source = { revision: git("rev-parse", "HEAD").trim(), tree: git("rev-parse", "HEAD^{tree}").trim(),
  dirty: git("status", "--porcelain").length > 0, files: before.length, sha256: sha(JSON.stringify(before)) };
const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", "--test-concurrency=1", ...files], {
  cwd: root, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120000,
});
process.stdout.write(result.stdout ?? "");
process.stderr.write(result.stderr ?? "");
const counts = {};
for (const name of ["tests", "pass", "fail", "cancelled", "skipped", "todo"]) {
  const matches = [...(result.stdout ?? "").matchAll(new RegExp("^# " + name + " (\\d+)$", "gm"))];
  counts[name] = matches.length === 1 ? Number(matches[0][1]) : null;
}
const unchanged = JSON.stringify(before) === JSON.stringify(sourceMap());
const complete = !result.error && result.status === 0 && result.signal === null && unchanged &&
  counts.tests === expectedTests && counts.pass === expectedTests &&
  ["fail", "cancelled", "skipped", "todo"].every((name) => counts[name] === 0);
const summary = {
  mode: "synthetic PDF/pixel fixtures; real PDFium and native syscall/process controls; separately synthetic protocol producers; no provider requests",
  source, sourceUnchanged: unchanged, node: process.versions.node,
  files, expectedTests, counts, complete,
  stdoutSha256: sha(result.stdout ?? ""), stderrSha256: sha(result.stderr ?? ""),
};
writeFileSync(path.join(root, "tools/scanned-pdf/runtime/verification.json"), JSON.stringify(summary, null, 2) + "\n");
process.stdout.write(JSON.stringify(summary) + "\n");
if (!complete) {
  process.stderr.write("Required scanned-PDF verification failed, changed source, or omitted a required case.\n");
  process.exitCode = 1;
}
