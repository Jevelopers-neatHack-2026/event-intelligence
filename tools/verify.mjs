import { open, readdir, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { run } from "node:test";
import { spec } from "node:test/reporters";
import { finished } from "node:stream/promises";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CASES = Object.freeze({
  "safe-retrieval": ["tests/security"],
  "content-privacy": ["tests/privacy", "tests/security/injection"],
  "evidence-facts": ["tests/evidence"],
  "pdf-derived-evidence": ["tests/evidence", "tests/extraction/pdf", "tests/integration/pdf-evidence"],
  "asset-source-discovery": ["tests/brand-research", "tests/integration/asset-source/core"],
  "asset-source-discovery-linux": ["tests/integration/asset-source/linux"],
  // Raster readers have dedicated platform/profile gates; keep this text route scoped.
  "deterministic-extraction": [
    Object.freeze({ directory: "tests/extraction", recursive: false }),
    "tests/extraction/pdf",
  ],
  evals: ["tests/evals"],
  "research-api": ["tests/api"],
  "question-preparation": ["tests/decisions/questions", "tests/discovery/source-identity"],
  "cache-invalidation": ["tests/cache/reuse", "tests/review/history", "tests/integration/review-cache-binding"],
  "verify-runner": ["tests/runner"],
  "eval-policy-unit": [],
});
const PYTHON_SUMMARY_PREFIX = "PYTHON_VERIFY_SUMMARY_JSON=";

function optionsFromCli(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    const match = current.match(/^--(case|mode)=(.+)$/);
    if (match) parsed[match[1]] = match[2];
    else if (current === "--case" || current === "--mode") parsed[current.slice(2)] = args[++index];
    else throw new Error("Unknown verification option");
  }
  const requestedCase = parsed.case ?? process.env.CASE;
  return {
    caseName: requestedCase === "evidence" ? "evidence-facts" : requestedCase,
    mode: parsed.mode ?? process.env.MODE,
  };
}

async function collectTestFiles(relativeDirectories) {
  const files = [];
  async function visit(directory, recursive = true) {
    let entries;
    try { entries = await readdir(directory, { withFileTypes: true }); }
    catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory() && recursive) await visit(full);
      else if (entry.isFile() && entry.name.endsWith(".test.mjs")) files.push(full);
    }
  }
  for (const selection of relativeDirectories) {
    const directory = typeof selection === "string" ? selection : selection.directory;
    const recursive = typeof selection === "string" || selection.recursive;
    await visit(path.join(ROOT, directory), recursive);
  }
  return [...new Set(files)].sort();
}

function safeConfigString(value) {
  return typeof value === "string" && value.trim().length > 0 && value.length <= 1_024;
}

async function hasReleaseConfigShape() {
  const configuredPath = process.env.EVENT_INTELLIGENCE_LIVE_CONFIG;
  if (!configuredPath) return false;
  const resolvedPath = path.resolve(configuredPath);
  let configuration;
  try {
    const metadata = await stat(resolvedPath);
    if (!metadata.isFile() || metadata.size > 8_192) return false;
    const handle = await open(resolvedPath, "r");
    try {
      const bytes = Buffer.alloc(8_193);
      const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
      if (bytesRead !== metadata.size || bytesRead > 8_192) return false;
      configuration = JSON.parse(bytes.subarray(0, bytesRead).toString("utf8"));
    } finally {
      await handle.close();
    }
  } catch {
    return false;
  }
  if (!configuration || typeof configuration !== "object" || Array.isArray(configuration)) return false;
  const expiry = typeof configuration.expires_at === "string" ? Date.parse(configuration.expires_at) : NaN;
  return safeConfigString(configuration.release_manifest)
    && safeConfigString(configuration.budget_authorization)
    && Number.isFinite(expiry)
    && expiry > Date.now();
}

export function evaluateCompletion(aggregate, enqueued) {
  const counts = aggregate?.counts;
  const terminal = counts
    ? counts.passed + counts.failed + counts.skipped + counts.todo + counts.cancelled
    : 0;
  const complete = Boolean(counts)
    && aggregate.success === true
    && enqueued > 0
    && enqueued === terminal
    && counts.failed === 0
    && counts.skipped === 0
    && counts.todo === 0
    && counts.cancelled === 0;
  return Object.freeze({ complete, terminal, counts });
}

function printSummary(summary) {
  process.stdout.write(`VERIFY_SUMMARY_JSON=${JSON.stringify(summary)}\n`);
  process.exitCode = summary.exit_code;
}

async function executeMock(caseName, directories, mode = "mock", fixtureScope = "local controlled fixtures only") {
  const files = await collectTestFiles(directories);
  if (files.length === 0) {
    printSummary({
      case: caseName,
      mode,
      status: "failed",
      exit_code: 1,
      test_files: 0,
      expected_cases: 0,
      terminal_cases: 0,
      passed_cases: 0,
      failed_cases: 0,
      skipped_cases: 0,
      todo_cases: 0,
      cancelled_cases: 0,
      fixture_scope: fixtureScope,
      external_egress: "not measured",
      provider_activity: "none",
      reason: "no test files were collected",
    });
    return;
  }

  const testStream = run({ files, concurrency: 1, isolation: "process", cwd: ROOT });
  let aggregate;
  let enqueued = 0;
  testStream.on("test:enqueue", (data) => {
    if (data.type === "test") enqueued += 1;
  });
  testStream.on("test:summary", (data) => {
    if (data.file === undefined) aggregate = data;
  });
  const report = testStream.compose(spec);
  const reportFinished = finished(report);
  report.pipe(process.stdout, { end: false });
  await reportFinished;
  const { complete, terminal, counts } = evaluateCompletion(aggregate, enqueued);
  printSummary({
    case: caseName,
    mode,
    status: complete ? "passed" : "failed",
    exit_code: complete ? 0 : 1,
    test_files: files.length,
    expected_cases: enqueued,
    terminal_cases: terminal,
    passed_cases: counts?.passed ?? 0,
    failed_cases: counts?.failed ?? 0,
    skipped_cases: counts?.skipped ?? 0,
    todo_cases: counts?.todo ?? 0,
    cancelled_cases: counts?.cancelled ?? 0,
    fixture_scope: fixtureScope,
    external_egress: "not measured",
    provider_activity: "none",
    reason: complete ? null : "tests did not complete as an all-pass, non-skipped run",
  });
}

function pythonRouteFailure(reason) {
  printSummary({
    case: "eval-policy-unit",
    mode: "unit",
    status: "failed",
    exit_code: 1,
    runtime: null,
    expected_cases: 0,
    executed_cases: 0,
    passed_cases: 0,
    failed_cases: 0,
    error_cases: 0,
    runner_errors: 0,
    runner_skips: 0,
    skipped_cases: 0,
    skip_events: 0,
    subtest_skip_events: 0,
    subtest_failure_events: 0,
    subtest_error_events: 0,
    incomplete_cases: 0,
    expected_failure_cases: 0,
    unexpected_success_cases: 0,
    fixture_scope: "local policy and runner unit tests only",
    provider_activity: "none",
    reason,
  });
}

async function executePythonUnit() {
  await new Promise((resolve) => {
    let child;
    let outputBuffer = "";
    let pythonSummary;
    let settled = false;

    function finishWithFallback(reason) {
      if (settled) return;
      settled = true;
      pythonRouteFailure(reason);
      resolve();
    }

    function consumeLine(line) {
      if (line.startsWith(PYTHON_SUMMARY_PREFIX)) {
        try { pythonSummary = JSON.parse(line.slice(PYTHON_SUMMARY_PREFIX.length)); }
        catch { pythonSummary = undefined; }
      } else {
        process.stdout.write(line);
      }
    }

    try {
      child = spawn("python3", ["-I", "tools/run_python_tests.py", "--suite", "eval-policy-unit"], {
        cwd: ROOT,
        shell: false,
        timeout: 120_000,
        stdio: ["ignore", "pipe", "inherit"],
      });
    } catch {
      finishWithFallback("Python test process could not start");
      return;
    }

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      outputBuffer += chunk;
      let boundary;
      while ((boundary = outputBuffer.indexOf("\n")) >= 0) {
        consumeLine(outputBuffer.slice(0, boundary + 1));
        outputBuffer = outputBuffer.slice(boundary + 1);
      }
    });
    child.once("error", () => finishWithFallback("Python test process could not start"));
    child.once("close", (code, signal) => {
      if (settled) return;
      if (outputBuffer) consumeLine(outputBuffer);
      if (!pythonSummary || typeof pythonSummary !== "object") {
        finishWithFallback("Python test process exited without a structured summary");
        return;
      }

      settled = true;
      const processPassed = code === 0 && signal === null;
      const summaryPassed = pythonSummary.status === "passed" && pythonSummary.exit_code === 0;
      const consistent = processPassed === summaryPassed;
      printSummary({
        ...pythonSummary,
        status: processPassed && summaryPassed && consistent ? "passed" : "failed",
        exit_code: processPassed && summaryPassed && consistent ? 0 : 1,
        reason: consistent
          ? pythonSummary.reason
          : "Python process exit did not match its structured summary",
      });
      resolve();
    });
  });
}

async function main() {
  let selected;
  try { selected = optionsFromCli(process.argv.slice(2)); }
  catch {
    printSummary({ case: null, mode: null, status: "failed", exit_code: 1, reason: "invalid verification arguments" });
    return;
  }
  const { caseName, mode } = selected;
  const modeAllowed = caseName === "eval-policy-unit"
    ? mode === "unit"
    : caseName === "pdf-derived-evidence" || caseName === "asset-source-discovery-linux"
      ? mode === "linux-integration"
      : ["mock", "live"].includes(mode);
  if (!caseName || !Object.hasOwn(CASES, caseName) || !modeAllowed) {
    printSummary({ case: caseName ?? null, mode: mode ?? null, status: "failed", exit_code: 1, reason: "unknown case or mode" });
    return;
  }
  if (Number(process.versions.node.split(".")[0]) !== 22) {
    printSummary({
      case: caseName,
      mode,
      status: "failed",
      exit_code: 1,
      runtime: process.versions.node,
      required_runtime: "Node 22.x",
      reason: "verification must run on the supported Node 22 runtime",
    });
    return;
  }
  if (["pdf-derived-evidence", "asset-source-discovery-linux"].includes(caseName) && process.platform !== "linux") {
    printSummary({
      case: caseName,
      mode,
      status: "failed",
      exit_code: 1,
      runtime: process.versions.node,
      platform: process.platform,
      test_files: 0,
      expected_cases: 0,
      terminal_cases: 0,
      skipped_cases: 0,
      provider_activity: "none",
      reason: "this actual legacy SQLite/PDF compatibility integration requires Linux and cannot be counted as passed on another platform",
    });
    return;
  }
  if (mode === "live") {
    const configShapePresent = await hasReleaseConfigShape();
    printSummary({
      case: caseName,
      mode,
      status: "blocked",
      exit_code: 1,
      test_files: 0,
      expected_cases: 0,
      terminal_cases: 0,
      release_config_shape_present: configShapePresent,
      external_egress: "not measured",
      provider_activity: "none",
      reason: "live mode is disabled until an adapter and accepted EI-01/EI-09 integration exist; configuration presence or shape is not authenticated authorization; no request was attempted",
    });
    return;
  }
  if (caseName === "eval-policy-unit") {
    await executePythonUnit();
    return;
  }
  if (caseName === "pdf-derived-evidence") {
    await executeMock(caseName, CASES[caseName], mode, "local PDF fixtures through the actual isolated reader and synthetic store adapters");
    return;
  }
  if (caseName === "asset-source-discovery-linux") {
    await executeMock(caseName, CASES[caseName], mode, "pinned merged-v2 evidence-store binary with real PDF bytes and the actual v3 SQLite migration path");
    return;
  }
  if (caseName === "cache-invalidation") {
    await executeMock(caseName, CASES[caseName], mode,
      "local cache/history/invalidations, real controlled loopback conditional HTTP and encrypted retained evidence; synthetic host/permission/Finance authority only");
    return;
  }
  await executeMock(caseName, CASES[caseName]);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    printSummary({ case: null, mode: null, status: "failed", exit_code: 1, reason: "verification runner failed" });
  });
}
