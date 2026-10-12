// Dedicated route: do not alter another owner's shared verification runner.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { PNG_NODE_VERSION, PNG_ZLIB_VERSION } from "../src/extraction/png/constants.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const files = [
  "tests/extraction/png/core.test.mjs",
  "tests/extraction/png/reader.test.mjs",
  "tests/extraction/png/lifecycle.test.mjs",
  "tests/extraction/png/network.test.mjs",
  "tests/extraction/png/protocol.test.mjs",
];
const expectedTests = 84;
if (process.platform !== "linux" || process.versions.node !== PNG_NODE_VERSION ||
    process.versions.zlib !== PNG_ZLIB_VERSION) {
  process.stderr.write("Required static PNG checks need Linux and the exact documented Node/zlib runtime.\n");
  process.exit(1);
}
const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", ...files], {
  cwd: root, encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 60000,
});
process.stdout.write(result.stdout ?? "");
process.stderr.write(result.stderr ?? "");
const counts = {};
for (const label of ["tests", "pass", "fail", "cancelled", "skipped", "todo"]) {
  const matches = [...(result.stdout ?? "").matchAll(new RegExp("^# " + label + " (\\d+)$", "gm"))];
  counts[label] = matches.length === 1 ? Number(matches[0][1]) : null;
}
const complete = !result.error && result.status === 0 && result.signal === null &&
  counts.tests === expectedTests && counts.pass === expectedTests &&
  ["fail", "cancelled", "skipped", "todo"].every((label) => counts[label] === 0);
process.stdout.write(JSON.stringify({
  mode: "local synthetic PNG bytes; actual Linux children; no provider calls",
  runtime: { node: process.versions.node, zlib: process.versions.zlib },
  files, expectedTests, counts, complete,
}) + "\n");
if (!complete) {
  process.stderr.write("Static PNG verification failed or omitted a required case.\n");
  process.exitCode = 1;
}
