// Dedicated private format route; existing runners and acceptance selectors stay separate.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { RASTER_NODE_VERSION, RASTER_DECODER } from "../src/extraction/jpeg-webp/constants.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const files = [
  "tests/extraction/jpeg-webp/reader.test.mjs",
  "tests/extraction/jpeg-webp/profile.test.mjs",
  "tests/extraction/jpeg-webp/native-validation.test.mjs",
  "tests/extraction/jpeg-webp/webp-native.test.mjs",
  "tests/extraction/jpeg-webp/normalization.test.mjs",
  "tests/extraction/jpeg-webp/lifecycle.test.mjs",
  "tests/extraction/jpeg-webp/protocol.test.mjs",
  "tests/extraction/jpeg-webp/network.test.mjs",
  "tests/extraction/jpeg-webp/runtime.test.mjs",
  "tests/extraction/jpeg-webp/setup.test.mjs",
];
const expectedTests = 160;
if (process.platform !== "linux" || process.arch !== "x64" || process.versions.node !== RASTER_NODE_VERSION ||
    !process.env.EI_JPEG_WEBP_TEST_RUNTIME || !process.env.EI_JPEG_WEBP_TEST_WHEEL) {
  process.stderr.write("Required JPEG/WebP checks need Linux x86-64, Node 22.23.3, and the explicit pinned runtime/wheel paths.\n");
  process.exit(1);
}
const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", "--test-concurrency=1", ...files], {
  cwd: root, encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 120000,
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
  mode: "synthetic JPEG/WebP fixtures; actual pinned native decodes and Linux child resource/lifecycle controls; local loopback canary; no provider calls",
  runtime: RASTER_DECODER, files, expectedTests, counts, complete,
  childStatus: result.status, childSignal: result.signal, childError: result.error?.code ?? null,
}) + "\n");
if (!complete) {
  process.stderr.write("Static JPEG/WebP verification failed or omitted a required case.\n");
  process.exitCode = 1;
}
