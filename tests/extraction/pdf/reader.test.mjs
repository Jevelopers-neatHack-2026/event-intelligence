import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runInNewContext } from "node:vm";

import { decodePdfBytesForWorker } from "../../../src/extraction/pdf/core.mjs";
import {
  PDF_TEXT_READER_LIMITS,
  readTextPdf,
} from "../../../src/extraction/pdf/index.mjs";

const FIXTURES = new URL("./fixtures/", import.meta.url);
const REPO_ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const ADDRESS_SPACE_BYTES = 6 * 1024 * 1024 * 1024;

async function fixture(name) {
  return readFile(fileURLToPath(new URL(name, FIXTURES)));
}

function expectedHash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function safeChildDiagnostic(child) {
  const messages = [];
  for (const line of child.stdout.split("\n")) {
    if (line.length === 0) continue;
    try {
      const message = JSON.parse(line);
      if (message?.kind === "progress" && Number.isInteger(message.pageIndex)) {
        messages.push({ kind: "progress", pageIndex: message.pageIndex });
      } else if (message?.kind === "result" && Array.isArray(message.pages)) {
        messages.push({ kind: "result", pageCount: message.pages.length });
      } else if (message?.kind === "error" && typeof message.code === "string" && /^[a-z_]{1,64}$/.test(message.code)) {
        messages.push({ kind: "error", code: message.code });
      } else {
        messages.push({ kind: "unknown" });
      }
    } catch {
      messages.push({ kind: "invalid-line" });
    }
  }

  const stderr = child.stderr.toLowerCase();
  let stderrClass = "empty";
  if (stderr.length > 0) {
    stderrClass = /failed to reserve|out of memory|allocation failed/.test(stderr)
      ? "v8-memory"
      : /dommatrix|path2d|canvas/.test(stderr)
        ? "optional-canvas-warning"
        : "redacted-nonempty";
  }
  const allowedSpawnCodes = new Set(["ETIMEDOUT", "ENOENT", "EACCES", "ENOMEM", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"]);
  return {
    status: child.status,
    signal: child.signal,
    spawnError: allowedSpawnCodes.has(child.error?.code) ? child.error.code : child.error ? "OTHER" : null,
    stdoutBytes: Buffer.byteLength(child.stdout),
    stderrClass,
    messages,
  };
}

async function expectReject(name, code, options) {
  const bytes = await fixture(name);
  const result = await readTextPdf(bytes, options);
  if (process.platform !== "linux") {
    assert.equal(result.kind, "rejected");
    assert.equal(result.code, "ISOLATION_UNAVAILABLE");
  } else {
    assert.equal(result.kind, "rejected", `${name} must not produce an observation`);
    assert.equal(result.code, code, name);
  }
  assert.equal(result.documentSha256, expectedHash(bytes));
  return result;
}

test("decodes known synthetic multipage and rotated Unicode text deterministically", async () => {
  const bytes = await fixture("text-multipage.pdf");
  const first = await decodePdfBytesForWorker(bytes);
  const second = await decodePdfBytesForWorker(bytes);
  assert.deepEqual(second, first);
  assert.equal(first.kind, "observation");
  assert.equal(first.completeness, "incomplete-text-only");
  assert.deepEqual(first.pages.map((page) => page.pageIndex), [0, 1]);
  assert.equal(first.pages[0].textBoxes[0].text, "Community Night - Doors at 7 PM");
  assert.equal(first.pages[1].textBoxes[0].text, "Saturday, October 17, 2026");
  assert.equal(first.pages[1].rotation, 90);
  assert.deepEqual([first.pages[1].width, first.pages[1].height], [792, 612]);
  assert.equal(first.pages[0].textBoxes[0].x, 48);
  assert.equal(first.pages[0].textBoxes[0].y, 54);
  assert.equal(first.pages[1].textBoxes[0].geometry, "approximate-text-item");
  for (const page of first.pages) {
    assert.equal(page.requiresInspection, true);
    for (const box of page.textBoxes) {
      assert.ok(Number.isFinite(box.x) && Number.isFinite(box.y));
      assert.ok(box.x >= 0 && box.y >= 0);
      assert.ok(box.x + box.width <= page.width + 0.01);
      assert.ok(box.y + box.height <= page.height + 0.01);
    }
  }

  const unicode = await decodePdfBytesForWorker(await fixture("text-rotated-unicode.pdf"));
  assert.equal(unicode.kind, "observation");
  assert.equal(unicode.pages[0].rotation, 90);
  assert.equal(unicode.pages[0].textBoxes[0].text, "Festival 東京 2027");
  assert.equal(unicode.pages[0].requiresInspection, true);
});

test("empty, scanned, and mixed pages stay explicitly incomplete and require inspection", async () => {
  for (const name of ["empty.pdf", "scanned.pdf"]) {
    const result = await decodePdfBytesForWorker(await fixture(name));
    assert.equal(result.kind, "no-text", name);
    assert.equal(result.completeness, "incomplete-text-only");
    assert.equal(result.pages.length, 1);
    assert.equal(result.pages[0].textPresence, "no-embedded-text");
    assert.equal(result.pages[0].requiresInspection, true);
    assert.deepEqual(result.pages[0].textBoxes, []);
  }

  const mixed = await decodePdfBytesForWorker(await fixture("mixed.pdf"));
  assert.equal(mixed.kind, "observation");
  assert.equal(mixed.completeness, "incomplete-text-only");
  assert.equal(mixed.pages[0].textPresence, "text-present");
  assert.equal(mixed.pages[0].requiresInspection, true);
  const mixedTexts = mixed.pages[0].textBoxes.map((box) => box.text);
  assert.deepEqual(mixedTexts, ["Text layer is partial"]);
  assert.equal(
    mixedTexts.some((text) => text.includes("RASTER-ONLY EVENT POSTER")),
    false,
  );
  assert.equal(mixedTexts.some((text) => text.includes("Doors: 19:30 / River Hall")), false);
});

test("compressed text expansion above the declared text ceiling is rejected atomically", async () => {
  const expandedTextCodeUnits = 1_500 * 74;
  assert.ok(expandedTextCodeUnits > PDF_TEXT_READER_LIMITS.maxTextCodeUnits);
  const bytes = await fixture("compressed-expansion.pdf");
  assert.ok(bytes.byteLength < 20_000, "the checked-in Flate fixture stays small");
  await assert.rejects(
    () => decodePdfBytesForWorker(bytes),
    (error) => error.code === "text_limit",
  );
});

test("bounded name preflight decodes PDF escape spellings and rejects object streams", async () => {
  const base = await fixture("text-multipage.pdf");
  const escapedOpenAction = Buffer.concat([base, Buffer.from("\n/Open#41ction\n")]);
  const objectStream = Buffer.concat([base, Buffer.from("\n/ObjStm\n")]);
  await assert.rejects(
    () => decodePdfBytesForWorker(escapedOpenAction),
    (error) => error.code === "active_or_unsupported_feature",
  );
  await assert.rejects(
    () => decodePdfBytesForWorker(objectStream),
    (error) => error.code === "unsupported_pdf_feature",
  );
});

test("public reader binds a copied input snapshot to a frozen private observation", async () => {
  const bytes = await fixture("text-multipage.pdf");
  const digest = expectedHash(bytes);
  const pending = readTextPdf(bytes);
  bytes.fill(0);
  const result = await pending;
  if (process.platform !== "linux") {
    assert.equal(result.kind, "rejected");
    assert.equal(result.code, "ISOLATION_UNAVAILABLE");
    assert.equal(result.documentSha256, digest);
    return;
  }

  assert.equal(result.kind, "observation");
  assert.equal(result.documentSha256, digest);
  assert.deepEqual(result.decoder, {
    name: "pdfjs-dist",
    version: "6.4.299",
    configVersion: "ei-text-pdf/1",
  });
  assert.equal(result.networkAttemptCount, 0);
  assert.equal(result.completeness, "incomplete-text-only");
  assert.equal(result.requiresInspection, true);
  assert.equal(result.limits.addressSpaceBytes, ADDRESS_SPACE_BYTES);
  assert.equal(result.pages[1].textBoxes[0].text, "Saturday, October 17, 2026");
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.pages), true);
  assert.equal(Object.isFrozen(result.pages[1].textBoxes[0]), true);
  assert.equal("verified" in result, false);
  assert.equal("sourceUrl" in result, false);
});

test("public reader returns no-text for scanned pages and keeps mixed pages incomplete", async () => {
  for (const name of ["scanned.pdf", "mixed.pdf"]) {
    const bytes = await fixture(name);
    const result = await readTextPdf(bytes);
    if (process.platform !== "linux") {
      assert.equal(result.code, "ISOLATION_UNAVAILABLE");
      continue;
    }
    assert.equal(result.kind, name === "scanned.pdf" ? "no-text" : "observation");
    assert.equal(result.pages[0].requiresInspection, true);
    assert.equal(result.completeness, "incomplete-text-only");
  }
});

test("malformed, encrypted, active, remote, dimension, page, and text limits reject without leaking input", async () => {
  const cases = [
    ["malformed.pdf", "MALFORMED_PDF", "synthetic malformed"],
    ["encrypted.pdf", "ENCRYPTED_PDF", "synthetic-fixture-password"],
    ["javascript-open-action.pdf", "ACTIVE_PDF_FEATURE", "app.alert"],
    ["launch-open-action.pdf", "ACTIVE_PDF_FEATURE", "synthetic-never-run"],
    ["embedded-file.pdf", "ACTIVE_PDF_FEATURE", "synthetic attachment"],
    ["uri-link.pdf", "REMOTE_REFERENCE", "https://example.invalid/remote"],
    ["remote-goto-action.pdf", "REMOTE_REFERENCE", "remote.pdf"],
    ["giant-dimensions.pdf", "DIMENSION_LIMIT", "Oversized page"],
    ["over-pages.pdf", "PAGE_LIMIT", "Synthetic fixture"],
  ];
  for (const [name, code, secret] of cases) {
    const result = await expectReject(name, code);
    assert.equal(JSON.stringify(result).includes(secret), false, name);
  }

  await expectReject("text-overflow.pdf", "TEXT_LIMIT", { maxTextCodeUnits: 1_000 });
});

test("compressed expansion and output overflow never become partial text observations", async () => {
  const expansion = await fixture("compressed-expansion.pdf");
  const expansionResult = await readTextPdf(expansion, { timeoutMs: 20_000 });
  if (process.platform !== "linux") {
    assert.equal(expansionResult.code, "ISOLATION_UNAVAILABLE");
  } else {
    assert.equal(expansionResult.kind, "rejected");
    assert.equal(expansionResult.code, "TEXT_LIMIT");
    assert.equal("pages" in expansionResult, false);
  }

  await expectReject("text-overflow.pdf", "OUTPUT_LIMIT", { maxOutputBytes: 4_096 });
});

test("invalid input, unsupported options, and oversize input fail before PDF parsing", async () => {
  assert.equal((await readTextPdf("not bytes")).code, "INVALID_INPUT");
  const getterThrows = Object.defineProperty({}, "timeoutMs", {
    get() { throw new Error("must be converted to a typed input error"); },
  });
  assert.equal((await readTextPdf(new Uint8Array([1]), getterThrows)).code, "INVALID_OPTIONS");
  assert.equal((await readTextPdf(new Uint8Array([1]), { timeoutMs: 20_001 })).code, "INVALID_LIMIT");

  const oversized = Buffer.alloc(PDF_TEXT_READER_LIMITS.maxInputBytes + 1);
  Buffer.from("%PDF-1.7").copy(oversized);
  Buffer.from("%%EOF").copy(oversized, oversized.length - 5);
  assert.equal((await readTextPdf(oversized)).code, "INPUT_TOO_LARGE");
});

test("preflight, active cancellation, deadline, output, and queue failures never return partial pages", async () => {
  const bytes = await fixture("text-multipage.pdf");
  const preAborted = new AbortController();
  preAborted.abort();
  const cancelledBeforeQueue = await readTextPdf(bytes, { signal: preAborted.signal });
  assert.equal(cancelledBeforeQueue.code, "CANCELLED");

  if (process.platform !== "linux") return;

  const controller = new AbortController();
  const progress = [];
  const cancelled = await readTextPdf(bytes, {
    signal: controller.signal,
    onPageComplete(pageIndex) {
      progress.push(pageIndex);
      controller.abort();
    },
  });
  assert.equal(cancelled.code, "CANCELLED");
  assert.equal("pages" in cancelled, false);
  assert.deepEqual(progress, [0]);
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.deepEqual(progress, [0]);

  const timedOut = await readTextPdf(bytes, { timeoutMs: 1 });
  assert.equal(timedOut.code, "TIMEOUT");
  assert.equal("pages" in timedOut, false);

  const jobs = Array.from({ length: PDF_TEXT_READER_LIMITS.maxQueued + 1 }, () => readTextPdf(bytes));
  const queueFull = await readTextPdf(bytes);
  assert.equal(queueFull.code, "QUEUE_FULL");
  const completed = await Promise.all(jobs);
  assert.ok(completed.every((result) => result.kind === "observation"));
});

test("synthetic fragmented stdout after terminal events is ignored and queue resumes after close", () => {
  const probePath = fileURLToPath(new URL("./fragmented-stream-probe.mjs", import.meta.url));
  const probe = spawnSync(process.execPath, ["--experimental-vm-modules", probePath, REPO_ROOT], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
    maxBuffer: 20_000,
    timeout: 10_000,
  });
  assert.equal(probe.status, 0, `${probe.stdout}\n${probe.stderr}`);
  const summary = JSON.parse(probe.stdout.trim().split("\n").at(-1));
  assert.equal(summary.mode, "synthetic-fragmented-stream-lifecycle");
  assert.deepEqual(summary.cancellation, {
    cancelledCode: "CANCELLED",
    queuedKind: "observation",
    progress: [0],
  });
  assert.deepEqual(summary.callbackFailure, { code: "CALLBACK_FAILED", progress: [0] });
  assert.equal(summary.childCount, 3);
  assert.ok(summary.killAttemptCount >= 2);
});

test("known synthetic fixture reaches the decoder through the production Linux limits", async (t) => {
  if (process.platform !== "linux") return t.skip("Linux prlimit containment is required");
  const bytes = await fixture("text-multipage.pdf");
  const worker = fileURLToPath(new URL("../../../src/extraction/pdf/decode-worker.mjs", import.meta.url));
  const child = spawnSync("/usr/bin/prlimit", [
    `--as=${ADDRESS_SPACE_BYTES}:${ADDRESS_SPACE_BYTES}`,
    "--cpu=15:15",
    "--core=0:0",
    "--nofile=64:64",
    "--",
    process.execPath,
    "--disable-wasm-trap-handler",
    "--max-old-space-size=512",
    worker,
    "100000",
    String(PDF_TEXT_READER_LIMITS.maxOutputBytes),
  ], {
    cwd: path.dirname(worker),
    input: bytes,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
    maxBuffer: PDF_TEXT_READER_LIMITS.maxOutputBytes + 1,
    timeout: 20_000,
  });
  const diagnostic = safeChildDiagnostic(child);
  assert.equal(child.status, 0, JSON.stringify(diagnostic));
  assert.equal(diagnostic.signal, null, JSON.stringify(diagnostic));
  assert.deepEqual(diagnostic.messages.map(({ kind, pageIndex }) => [kind, pageIndex]), [
    ["progress", 0],
    ["progress", 1],
    ["result", undefined],
  ], JSON.stringify(diagnostic));
});

test("Linux child receives real kernel resource limits; unsupported hosts fail closed", () => {
  if (process.platform !== "linux") {
    assert.equal(PDF_TEXT_READER_LIMITS.maxAddressSpaceBytes, ADDRESS_SPACE_BYTES);
    return;
  }

  const temporaryDirectory = mkdtempSync(path.join(tmpdir(), "ei-pdf-rlimit-"));
  const executable = path.join(temporaryDirectory, "probe");
  try {
    const sourcePath = fileURLToPath(new URL("./rlimit-probe.c", import.meta.url));
    const compile = spawnSync("cc", ["-std=c11", "-O2", sourcePath, "-o", executable], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
      maxBuffer: 10_000,
    });
    assert.equal(compile.status, 0, compile.stderr);

    const probe = spawnSync("/usr/bin/prlimit", [
      `--as=${ADDRESS_SPACE_BYTES}:${ADDRESS_SPACE_BYTES}`,
      "--cpu=15:15",
      "--core=0:0",
      "--nofile=64:64",
      "--",
      executable,
    ], {
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
      maxBuffer: 10_000,
    });
    assert.equal(probe.status, 0, `status=${probe.status} stdout=${probe.stdout}`);
    assert.match(probe.stdout, /as=1 nofile=1 cpu=1 core=1 as_map_blocked=1 fd_blocked=1/);
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test("network guard measures and blocks Node resource attempts without dialing", () => {
  const script = String.raw`
    import { createRequire } from "node:module";
    import { installPdfNetworkGuard } from "./src/extraction/pdf/network-guard.mjs";
    const require = createRequire(import.meta.url);
    const https = require("node:https");
    const net = require("node:net");
    const dns = require("node:dns/promises");
    const guard = installPdfNetworkGuard();
    const attempts = [
      () => fetch("https://must-not-resolve.invalid/"),
      () => https.get("https://must-not-resolve.invalid/"),
      () => net.connect(443, "must-not-resolve.invalid"),
      () => dns.lookup("must-not-resolve.invalid"),
    ];
    for (const attempt of attempts) {
      try { attempt(); process.exitCode = 2; }
      catch (error) { if (error.code !== "PDF_EXTERNAL_RESOURCE_DENIED") process.exitCode = 3; }
    }
    process.stdout.write(String(guard.attemptCount));
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
    maxBuffer: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "4");
  assert.equal(result.stderr, "");
});

// These byte-boundary probes stop before decoder launch and preserve the
// production isolation prerequisite. All payloads derive from a synthetic fixture.
const INPUT_BOUNDARY_PDF = await fixture("text-multipage.pdf");

test("rejects an oversized native PDF view before copy, hashing, or isolation checks", async () => {
  const bytes = new Uint8Array(PDF_TEXT_READER_LIMITS.maxInputBytes + 1);
  bytes.set(INPUT_BOUNDARY_PDF);
  const calls = [];
  Object.defineProperty(bytes, "byteLength", {
    get() { calls.push("byteLength"); return 1; },
  });
  bytes.valueOf = () => { calls.push("valueOf"); return INPUT_BOUNDARY_PDF; };

  const result = await readTextPdf(bytes);
  assert.equal(result.kind, "rejected");
  assert.equal(result.code, "INPUT_TOO_LARGE");
  assert.equal(result.documentSha256, undefined);
  assert.deepEqual(calls, []);
});

test("ignores a false oversized property on an eligible native PDF view", async () => {
  const bytes = new Uint8Array(INPUT_BOUNDARY_PDF);
  const calls = [];
  Object.defineProperty(bytes, "byteLength", {
    get() { calls.push("byteLength"); return PDF_TEXT_READER_LIMITS.maxInputBytes + 1; },
  });
  const result = await readTextPdf(bytes, { signal: AbortSignal.abort() });
  assert.equal(result.kind, "rejected");
  assert.equal(result.code, "CANCELLED");
  assert.equal(result.documentSha256, expectedHash(INPUT_BOUNDARY_PDF));
  assert.deepEqual(calls, []);
});

test("binds the canceled PDF snapshot to native view bytes without caller conversions", async () => {
  const prefix = Buffer.from("ignored prefix:");
  const backing = Buffer.concat([prefix, INPUT_BOUNDARY_PDF, Buffer.from(":ignored suffix")]);
  const resizable = new ArrayBuffer(INPUT_BOUNDARY_PDF.length + 16, { maxByteLength: INPUT_BOUNDARY_PDF.length + 32 });
  new Uint8Array(resizable, 8, INPUT_BOUNDARY_PDF.length).set(INPUT_BOUNDARY_PDF);
  const views = [
    new Uint8Array(backing.buffer, backing.byteOffset + prefix.length, INPUT_BOUNDARY_PDF.length),
    backing.subarray(prefix.length, prefix.length + INPUT_BOUNDARY_PDF.length),
    new (class RetrievedPdfBytes extends Uint8Array {})(INPUT_BOUNDARY_PDF),
    runInNewContext("new Uint8Array(bytes)", { bytes: [...INPUT_BOUNDARY_PDF] }),
    new Uint8Array(resizable, 8, INPUT_BOUNDARY_PDF.length),
  ];
  for (const [index, bytes] of views.entries()) {
    const original = Array.from(bytes);
    const calls = [];
    for (const key of ["byteLength", "byteOffset", "buffer", "length", "constructor", Symbol.toStringTag]) {
      Object.defineProperty(bytes, key, {
        get() { calls.push(String(key)); throw new Error("byte property executed"); },
      });
    }
    for (const key of ["valueOf", Symbol.toPrimitive, Symbol.iterator]) {
      Object.defineProperty(bytes, key, {
        value() { calls.push(String(key)); throw new Error("byte conversion executed"); },
      });
    }
    const result = await readTextPdf(bytes, { signal: AbortSignal.abort() });
    assert.equal(result.kind, "rejected", `view ${index}`);
    assert.equal(result.code, "CANCELLED", `view ${index}`);
    assert.equal(result.documentSha256, expectedHash(INPUT_BOUNDARY_PDF), `view ${index}`);
    assert.deepEqual(calls, []);
    assert.deepEqual(original.map((_, offset) => bytes[offset]), original);
  }
});

test("does not let valueOf replace the PDF bytes or their source hash", async () => {
  const bytes = new Uint8Array(INPUT_BOUNDARY_PDF);
  let conversions = 0;
  const replacement = Buffer.concat([INPUT_BOUNDARY_PDF, Buffer.from("\n% substituted document\n")]);
  assert.notEqual(expectedHash(replacement), expectedHash(INPUT_BOUNDARY_PDF));
  bytes.valueOf = () => { conversions++; return replacement; };

  const pending = readTextPdf(bytes, { signal: AbortSignal.abort() });
  bytes.fill(0);
  const result = await pending;
  assert.equal(result.code, "CANCELLED");
  assert.equal(result.documentSha256, expectedHash(INPUT_BOUNDARY_PDF));
  assert.equal(conversions, 0);
});

test("rejects detached, out-of-bounds, shared, and non-Uint8 PDF inputs without proxy traps", async () => {
  const detached = new Uint8Array(INPUT_BOUNDARY_PDF);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  const resizable = new ArrayBuffer(8, { maxByteLength: 16 });
  const outOfBounds = new Uint8Array(resizable, 4, 4);
  const trackingOutOfBounds = new Uint8Array(resizable, 4);
  resizable.resize(2);
  const shared = new Uint8Array(new SharedArrayBuffer(INPUT_BOUNDARY_PDF.length));
  shared.set(INPUT_BOUNDARY_PDF);
  const calls = [];
  const proxied = new Proxy(new Uint8Array(INPUT_BOUNDARY_PDF), {
    get() { calls.push("get"); throw new Error("proxy get executed"); },
    getPrototypeOf() { calls.push("getPrototypeOf"); throw new Error("proxy prototype executed"); },
  });
  const revoked = Proxy.revocable(new Uint8Array(INPUT_BOUNDARY_PDF), {});
  revoked.revoke();
  const invalid = [
    detached, outOfBounds, trackingOutOfBounds, shared, proxied, revoked.proxy,
    new Uint8ClampedArray(INPUT_BOUNDARY_PDF), new Uint16Array([65]), new DataView(new ArrayBuffer(1)),
    INPUT_BOUNDARY_PDF.buffer, Object.create(Uint8Array.prototype),
  ];
  for (const [index, bytes] of invalid.entries()) {
    const result = await readTextPdf(bytes, { signal: AbortSignal.abort() });
    assert.equal(result.kind, "rejected", `invalid input ${index}`);
    assert.equal(result.code, "INVALID_INPUT", `invalid input ${index}`);
    assert.equal(result.documentSha256, undefined);
  }
  assert.deepEqual(calls, []);
});

test("keeps empty byte views invalid and malformed PDF bytes bound to their exact hash", async () => {
  for (const bytes of [Buffer.alloc(0), new Uint8Array(0), new Uint8Array(new ArrayBuffer(8), 8, 0)]) {
    const result = await readTextPdf(bytes, { signal: AbortSignal.abort() });
    assert.equal(result.code, "INVALID_INPUT");
    assert.equal(result.documentSha256, undefined);
  }
  const bytes = Buffer.from("synthetic non-PDF data");
  const result = await readTextPdf(bytes, { signal: AbortSignal.abort() });
  assert.equal(result.code, "MALFORMED_PDF");
  assert.equal(result.documentSha256, expectedHash(bytes));
});
