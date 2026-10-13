import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const python = JSON.parse(readFileSync(path.join(root, "tools/local-ocr/runtime/manifest.json"))).descriptor.python;
const env = { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", OMP_THREAD_LIMIT: "1", OMP_NUM_THREADS: "1" };
const script = "tests/extraction/local-ocr/loader-diagnostic-fixture.py";
function probe(family, mode) {
  const result = spawnSync(python, ["-I", "-S", "-B", script, "--probe", root, family, mode],
    { cwd: root, env, timeout: 20000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr?.toString());
  const value = JSON.parse(result.stdout);
  assert.equal(value.raised, true);
  assert.equal(value.summary.outcome, "worker_rejection");
  assert.equal(value.summary.workerCode, "OCR_FAILURE");
  assert.equal(value.summary.exitCode, 0);
  assert.equal(value.summary.reaped, true);
  assert.equal(value.summary.timedOut, false);
  assert.equal(value.summary.sourceUnchanged, true);
  assert.equal(value.summary.source.mapSha256, value.files["source-before.json"].sha256);
  assert.equal(JSON.stringify(value).includes("SYNTHETIC_LOADER_PRIVATE"), false);
  assert.equal(JSON.parse(value.streams.stdout).enforcementControlsPassed, 0);
  return value;
}

for (const mode of ["leptonica_missing", "tesseract_missing", "permission", "private_prefix", "private_suffix", "oversized",
  "unknown_dependency", "foreign_dependency", "multi_args", "non_string_args", "string_subclass", "subclass_args_getter",
  "dict_subclass", "recognition", "real_missing_file"]) {
  test(`startup loader ${mode} retains only recognized fixed values and never arbitrary error text`, () => {
    const value = probe("worker", mode);
    if (mode === "recognition") {
      assert.equal(value.streams.stderr, "");
      return;
    }
    const diagnostic = JSON.parse(value.streams.stderr).initializationDiagnostic;
    assert.equal(diagnostic.phase, "initialize");
    assert.equal(diagnostic.classification, "operating_system_error");
    if (["subclass_args_getter", "dict_subclass"].includes(mode)) {
      assert.equal(diagnostic.schema, 2);
      assert.equal("loader" in diagnostic, false);
      return;
    }
    assert.equal(diagnostic.schema, 3);
    assert.equal(diagnostic.exceptionType, "OSError");
    assert.deepEqual(Object.keys(diagnostic.loader).sort(), ["dependency", "reason", "target"]);
    if (["leptonica_missing", "tesseract_missing", "permission"].includes(mode)) {
      assert.deepEqual(diagnostic.loader, {
        target: mode === "tesseract_missing" ? "tesseract" : "leptonica",
        reason: mode === "permission" ? "dependency_permission_denied" : "dependency_not_found",
        dependency: mode === "tesseract_missing" ? "libarchive.so.13" : "libgif.so.7",
      });
    } else {
      assert.deepEqual(diagnostic.loader, { target: "leptonica", reason: "unclassified", dependency: null });
    }
    assert.equal(value.summary.streams.stderr.projectionReason, "validated_fixed_fields");
  });
}

for (const mode of ["valid", "extra", "unknown_target", "unknown_dependency", "unknown_reason", "foreign_dependency",
  "unclassified_nonnull", "old_schema_extra", "malformed", "duplicate"]) {
  test(`collector loader ${mode} validates complete schema and every value independently`, () => {
    const value = probe("collector", mode);
    const diagnostic = JSON.parse(value.streams.stderr);
    if (mode === "valid") {
      assert.deepEqual(diagnostic.initializationDiagnostic.loader,
        { target: "leptonica", reason: "dependency_not_found", dependency: "libgif.so.7" });
      assert.equal(value.summary.streams.stderr.projectionReason, "validated_fixed_fields");
    } else {
      assert.equal(diagnostic.diagnosticTextOmitted, true);
      assert.notEqual(value.summary.streams.stderr.projectionReason, "validated_fixed_fields");
    }
  });
}

test("both worker and collector loader labels equal independently decoded pinned ELF DT_NEEDED inventories", () => {
  const result = spawnSync(python, ["-I", "-S", "-B", script, "--elf-inventory", root],
    { cwd: root, env, timeout: 10000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr?.toString());
  const value = JSON.parse(result.stdout);
  assert.equal(value.needed.leptonica.length, 10);
  assert.equal(value.needed.tesseract.length, 8);
});
