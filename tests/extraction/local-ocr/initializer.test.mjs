import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const manifest = JSON.parse(readFileSync(path.join(root, "tools/local-ocr/runtime/manifest.json")));
const python = manifest.descriptor.python;
const env = { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", OMP_THREAD_LIMIT: "1", OMP_NUM_THREADS: "1" };
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const cases = [
  ["malformed", "invalid_json"], ["empty", "empty_stdout"], ["rejected", "worker_rejection"],
  ["nonzero", "nonzero_exit"], ["timeout", "timeout"], ["stdout_limit", "output_limit"],
  ["stderr_limit", "output_limit"], ["signal", "nonzero_exit"], ["invalid_utf8", "invalid_json"],
  ["redaction", "worker_rejection"], ["invalid_manifest", "invalid_manifest"],
  ["spawn_failure", "spawn_or_capture_failure"], ["source_changed", "source_changed"], ["valid", "initialized"],
  ["redaction_quoted", "worker_rejection"], ["redaction_truncated_url", "output_limit"],
  ["redaction_json", "worker_rejection"], ["structured_diagnostic", "worker_rejection"],
  ["diagnostic_extra", "worker_rejection"], ["diagnostic_unknown_value", "worker_rejection"],
  ["diagnostic_duplicate", "worker_rejection"], ["unknown_code", "worker_rejection"],
  ["error_extra", "worker_rejection"], ["model_unavailable", "worker_rejection"],
];
for (const [mode, expected] of cases) {
  test(`initializer evidence retains ${mode} actual subprocess outcome with bounded immutable records`, () => {
    const result = spawnSync(python, ["-I", "-S", "-B", "tests/extraction/local-ocr/initializer-fixture.py", "--probe", root, mode],
      { cwd: root, env, timeout: 20000, maxBuffer: 1024 * 1024 });
    assert.equal(result.status, 0, result.stderr?.toString());
    const output = JSON.parse(result.stdout);
    assert.equal(output.mode, "explicit synthetic initializer subprocess");
    assert.equal(output.records.length, 1);
    const { summary, streams, files } = output.records[0];
    assert.equal(summary.outcome, expected);
    assert.equal(summary.stage, "finished");
    assert.ok(Number.isFinite(Date.parse(summary.startedAt)));
    assert.ok(Number.isFinite(Date.parse(summary.finishedAt)));
    assert.equal(summary.sourceUnchanged, mode !== "source_changed");
    assert.match(summary.source.revision, /^[0-9a-f]{40}$/);
    assert.match(summary.source.tree, /^[0-9a-f]{40}$/);
    assert.equal(summary.source.mapSha256, files["source-before.json"].sha256);
    assert.ok(summary.elapsedSeconds < 5, "bounded actual subprocess and evidence capture must finish");
    assert.equal("env" in summary, false);
    assert.equal("input" in summary, false);
    if (expected === "initialized") {
      assert.equal(output.result.returned.descriptor.syntheticStartupFixture, true);
      assert.equal(summary.failureStage, null);
    } else {
      assert.equal(output.result.raised, "InitializationFailure");
      assert.ok(summary.failureStage);
    }
    if (mode === "timeout") {
      assert.equal(summary.streams.stdout.capturedSha256, hash(Buffer.from("entered actual synthetic child\n")));
      assert.equal(summary.streams.stdout.capturedBytes, Buffer.byteLength("entered actual synthetic child\n"));
      assert.equal(JSON.parse(streams.stdout).diagnosticTextOmitted, true);
      assert.equal(summary.timedOut, true);
      assert.equal(summary.killed, true);
      assert.equal(summary.reaped, true);
      assert.equal(summary.signal, 9);
    }
    if (mode === "nonzero") assert.equal(summary.exitCode, 7);
    if (mode === "signal") assert.equal(summary.signal, 15);
    if (mode === "spawn_failure") {
      assert.equal(summary.pid, null);
      assert.equal(summary.reaped, false);
      assert.equal(summary.exceptionType, "FileNotFoundError");
    }
    if (mode.endsWith("_limit") || mode === "redaction_truncated_url") {
      const stream = summary.streams[mode === "stdout_limit" ? "stdout" : "stderr"];
      assert.equal(stream.capturedBytes, 4096);
      assert.equal(stream.captureTruncated, true);
      assert.ok(stream.observedBytes > stream.capturedBytes);
      assert.equal(summary.killed, true);
      assert.equal(summary.reaped, true);
    }
    if (mode === "rejected" || mode === "redaction") assert.equal(summary.workerCode, "RUNTIME_MISMATCH");
    if (mode === "model_unavailable") {
      assert.equal(summary.workerCode, "MODEL_UNAVAILABLE");
      assert.equal(JSON.parse(streams.stdout).code, "MODEL_UNAVAILABLE");
      assert.equal(summary.exitCode, 0);
      assert.equal(summary.reaped, true);
      const value = JSON.parse(streams.stderr).initializationDiagnostic;
      assert.equal(value.schema, 2);
      assert.equal(value.phase, "initialize");
      assert.equal(value.exceptionType, "Rejection");
      assert.equal(value.classification, "fixed_policy_rejection");
      assert.equal(summary.streams.stdout.projectionReason, "validated_fixed_fields");
      assert.equal(summary.streams.stderr.projectionReason, "validated_fixed_fields");
    }
    if (mode === "redaction") {
      assert.equal(summary.streams.stderr.sanitized, true);
      assert.equal(JSON.parse(streams.stderr).diagnosticTextOmitted, true);
      for (const canary of ["SYNTHETIC_AUTH_CANARY", "SYNTHETIC_PASSWORD_CANARY", "SYNTHETIC_URL_CANARY", "synthetic-user", "synthetic-password", "\x1b", "\x00", "\x90"]) {
        assert.equal(streams.stderr.includes(canary), false, "synthetic sensitive/control canary escaped sanitation");
      }
    }
    assert.equal(summary.streams.stdout.evidencePolicy, "validated-fixed-fields-v2");
    assert.equal(summary.streams.stderr.evidencePolicy, "validated-fixed-fields-v2");
    for (const canary of ["SYNTHETIC_QUOTED_SECRET_TAIL", "SYNTHETIC_URI_SECRET", "SYNTHETIC_STRUCTURED_SECRET",
      "SYNTHETIC_CODE_SECRET", "SYNTHETIC_DUPLICATE_SECRET", "SYNTHETIC_STDOUT_SECRET"]) {
      assert.equal(JSON.stringify({ summary, streams }).includes(canary), false);
    }
    if (["redaction_quoted", "redaction_truncated_url", "redaction_json", "diagnostic_extra", "diagnostic_unknown_value", "diagnostic_duplicate"].includes(mode)) {
      assert.equal(JSON.parse(streams.stderr).diagnosticTextOmitted, true);
      assert.notEqual(summary.streams.stderr.projectionReason, "validated_fixed_fields");
    }
    if (mode === "structured_diagnostic") {
      const value = JSON.parse(streams.stderr).initializationDiagnostic;
      assert.deepEqual(value, { schema: 2, phase: "initialize", exceptionType: "OSError", classification: "operating_system_error",
        errno: 2, frames: [{ file: "native.py", function: "__init__", line: 10 }] });
      assert.equal(summary.streams.stderr.projectionReason, "validated_fixed_fields");
    }
    if (mode === "unknown_code") {
      assert.equal(summary.workerCode, null);
      assert.equal(JSON.parse(streams.stdout).diagnosticTextOmitted, true);
    }
    if (mode === "error_extra") {
      assert.equal(summary.workerCode, "RUNTIME_MISMATCH");
      assert.equal(JSON.parse(streams.stdout).diagnosticTextOmitted, true);
    }
  });
}

test("real pre-input native refusal is retained unchanged through a successful installer check", () => {
  const directory = path.join(root, "tools/local-ocr/runtime/initialization-attempts");
  const before = new Set(readdirSync(directory));
  const model = path.join(root, "tools/local-ocr/runtime/site/usr/share/tesseract-ocr/5/tessdata/eng.traineddata");
  const mode = statSync(model).mode & 0o777;
  assert.equal(mode, 0o444);
  let failed;
  try {
    chmodSync(model, 0o644);
    failed = spawnSync(python, ["tools/local-ocr/install.py", "--check"], { cwd: root, env, timeout: 30000, maxBuffer: 1024 * 1024 });
  } finally { chmodSync(model, mode); }
  assert.equal(failed.status, 1);
  const attempts = readdirSync(directory).filter((name) => !before.has(name));
  assert.equal(attempts.length, 1);
  const attempt = path.join(directory, attempts[0]);
  const receipt = JSON.parse(readFileSync(path.join(attempt, "summary.json")));
  assert.equal(receipt.outcome, "worker_rejection");
  assert.equal(receipt.workerCode, "RUNTIME_MISMATCH");
  assert.equal(receipt.sourceUnchanged, true);
  assert.equal(receipt.reaped, true);
  const map = () => Object.fromEntries(readdirSync(attempt).map((name) => [name, hash(readFileSync(path.join(attempt, name)))]));
  const frozen = map();
  const recovery = spawnSync(python, ["tools/local-ocr/install.py", "--check"], { cwd: root, env, timeout: 30000, maxBuffer: 1024 * 1024 });
  assert.equal(recovery.status, 0, recovery.stderr?.toString());
  assert.equal(JSON.parse(recovery.stdout).closureSha256, manifest.closureSha256);
  assert.deepEqual(map(), frozen);
  assert.equal(readdirSync(directory).filter((name) => !before.has(name)).length, 2);
});

for (const [option, mode] of [["--describe-runtime", "default"], ["--recognize", "default"],
  ["--describe-runtime", "quoted_space"], ["--describe-runtime", "truncated_userinfo"], ["--describe-runtime", "stringification_trap"]]) {
  test(`worker ${option} preserves its structured diagnostic/privacy boundary under ${mode} startup exception`, () => {
    const result = spawnSync(python, ["-I", "-S", "-B", "tests/extraction/local-ocr/initializer-fixture.py", "--worker-fault", root, option, mode],
      { cwd: root, env, timeout: 20000, maxBuffer: 1024 * 1024 });
    assert.equal(result.status, 0, result.stderr?.toString());
    const refusal = JSON.parse(result.stdout);
    assert.equal(refusal.kind, "rejected");
    assert.equal(refusal.code, "OCR_FAILURE");
    assert.equal(refusal.rasterSha256, null);
    assert.equal(refusal.closureSha256, null);
    assert.equal(refusal.enforcementControlsPassed, 0);
    if (option === "--recognize") {
      assert.equal(result.stderr.length, 0, "recognition must not expose startup diagnostics");
      assert.equal(result.stdout.includes("synthetic loader"), false);
    } else {
      assert.ok(result.stderr.length <= 8193);
      const diagnostic = JSON.parse(result.stderr).initializationDiagnostic;
      assert.deepEqual(Object.keys(diagnostic).sort(), ["classification", "errno", "exceptionType", "frames", "phase", "schema"]);
      assert.equal(diagnostic.schema, 2);
      assert.equal(diagnostic.phase, "initialize");
      assert.equal(diagnostic.exceptionType, mode === "stringification_trap" ? "Exception" : "OSError");
      assert.equal(diagnostic.classification, "operating_system_error");
      assert.equal(diagnostic.errno, mode === "stringification_trap" ? 13 : null);
      assert.equal("message" in diagnostic, false);
      assert.ok(diagnostic.frames.length >= 1 && diagnostic.frames.length <= 8);
      assert.ok(diagnostic.frames.every((frame) => Object.keys(frame).sort().join(",") === "file,function,line"));
      for (const secret of ["SYNTHETIC_STAGE_CANARY", "SYNTHETIC_STAGE_URL", "user:password", "\x1b",
        "SYNTHETIC_QUOTED_SECRET_TAIL", "SYNTHETIC_URI_SECRET", "SYNTHETIC_STRINGIFICATION_SECRET"]) {
        assert.equal(result.stderr.includes(secret), false);
      }
    }
  });
}
