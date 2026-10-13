import test from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import { readScannedPdfOcr } from "../../../src/extraction/scanned-pdf-ocr/index.mjs";
import { createScannedPdfOcrReader } from "../../../src/extraction/scanned-pdf-ocr/reader.mjs";
import { readScannedPdf } from "../../../src/extraction/scanned-pdf/index.mjs";
import { readLocalOcr } from "../../../src/extraction/local-ocr/index.mjs";
import { textPdf, blankPdf, expectedText, imagePdf } from "./fixtures.mjs";
import { hash } from "./fake-stages.mjs";

test("actual two-page synthetic PDF → native raster → native OCR retains exact source, page, pixels and literal boxes", async () => {
  const bytes = textPdf(2);
  assert.equal(hash(bytes), "ec4da70a4fa3a92c0fb3672c4575797a4c0d700bd5473dd798ce1f1594e483cf");
  const result = await readScannedPdfOcr(bytes);
  assert.equal(result.kind, "observed");
  assert.equal(result.totalPages, 2); assert.equal(result.totalWords, 16); assert.equal(result.totalPixels, 440000);
  assert.equal(result.tokenUtf8Bytes, 56); assert.equal(result.sourceSha256, hash(bytes));
  assert.equal(result.sourceAuthority, "unverified"); assert.equal(result.completeness, "incomplete-unverified-ocr");
  assert.equal(result.decoder.enforcementControlsPassed, 8); assert.equal(result.observer.enforcementControlsPassed, 8);
  for (const [index, page] of result.pages.entries()) {
    assert.equal(page.page, index + 1);
    assert.equal(page.derivativeSha256, "7e83e22bde559dd5de6afd3764a223db475f4cbf2ae9e9e2e924cd25fef9e54c");
    assert.equal(page.words.map((word) => word.text).join(" "), expectedText);
    assert.equal(page.pageWidthPoints, 1000); assert.equal(page.pageHeightPoints, 220);
    for (const word of page.words) {
      assert.equal(word.provenance.sourceSha256, hash(bytes)); assert.equal(word.provenance.page, index + 1);
      assert.equal(word.provenance.derivativeSha256, page.derivativeSha256);
      assert.equal(word.provenance.sourceBinding, "caller-supplied-unverified");
      assert.equal(word.confidenceMeaning, "uncalibrated-engine-score"); assert.equal(word.requiresReview, true);
      assert.ok(word.box.left >= 0 && word.box.left + word.box.width <= page.width);
      assert.ok(word.box.top >= 0 && word.box.top + word.box.height <= page.height);
      assert.ok(Object.isFrozen(word) && Object.isFrozen(word.box) && Object.isFrozen(word.provenance));
    }
    assert.ok(Object.isFrozen(page) && Object.isFrozen(page.words));
  }
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.pages) && Object.isFrozen(result.limits));
  assert.throws(() => { result.pages[0].words[0].text = "invented"; }, TypeError);
});

test("actual four-page blank profile remains no-text-observed and unverified, not a complete empty document claim", async () => {
  const result = await readScannedPdfOcr(blankPdf(4));
  assert.equal(result.kind, "observed"); assert.equal(result.totalPages, 4); assert.equal(result.totalWords, 0);
  assert.equal(result.requiresReview, true);
  assert.ok(result.pages.every((page) => page.status === "no-text-observed" && page.words.length === 0));
});

test("actual source snapshot survives caller mutation and a genuine input subarray preserves exact original hash", async () => {
  const pdf = textPdf(); const expected = hash(pdf);
  const container = Buffer.concat([Buffer.from("prefix"), pdf, Buffer.from("suffix")]);
  const view = container.subarray(6, 6 + pdf.length);
  const pending = readScannedPdfOcr(view); view.fill(0);
  const result = await pending;
  assert.equal(result.kind, "observed"); assert.equal(result.sourceSha256, expected);
  assert.equal(result.pages[0].words.map((word) => word.text).join(" "), expectedText);
});

for (const [name, bytes, expected] of [
  ["unsupported header", () => Buffer.from("not a PDF"), "UNSUPPORTED_PDF_FEATURE"],
  ["malformed duplicate dictionary key", () => imagePdf([{ imageExtra: "/Width 2" }]), "MALFORMED_PDF"],
  ["encryption", () => imagePdf([{}], { trailerExtra: "/Encrypt 99 0 R" }), "ENCRYPTED_PDF"],
  ["active action", () => imagePdf([{}], { catalogExtra: "/OpenAction << /S /JavaScript /JS (do not run) >>" }), "ACTIVE_CONTENT"],
  ["remote resource", () => imagePdf([{ imageExtra: "/F (https://example.invalid/never-fetch)" }]), "REMOTE_RESOURCE"],
  ["unsupported image color", () => imagePdf([{ colorSpace: "DeviceCMYK" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["over-page source", () => blankPdf(5), "PAGE_LIMIT"],
]) test("actual " + name + " is refused by the PDF stage before any OCR dispatch, then a new operation recovers", async () => {
  let calls = 0;
  const reader = createScannedPdfOcrReader({ readPdf: readScannedPdf, readOcr: (...args) => { calls += 1; return readLocalOcr(...args); } });
  const result = await reader(bytes());
  assert.equal(result.kind, "rejected"); assert.equal(result.code, "PDF_REJECTED"); assert.equal(result.componentCode, expected);
  assert.equal(calls, 0); assert.equal("pages" in result, false);
  assert.equal((await reader(blankPdf())).kind, "observed"); assert.equal(calls, 1);
});

test("actual aggregate exhausted word allowance stops the next page without dispatch or partial promotion", async () => {
  let calls = 0;
  const reader = createScannedPdfOcrReader({ readPdf: readScannedPdf, readOcr: (...args) => { calls += 1; return readLocalOcr(...args); } });
  const result = await reader(textPdf(2), { maxWords: 8 });
  assert.equal(result.code, "OUTPUT_LIMIT"); assert.equal(result.page, 2); assert.equal(calls, 1);
  assert.equal("pages" in result, false); assert.equal((await reader(blankPdf())).kind, "observed");
});

for (const limits of [{ maxWords: 9 }, { maxTextBytes: 30 }]) test("actual lowered aggregate OCR budget is passed to the second native page: " + JSON.stringify(limits), async () => {
  const result = await readScannedPdfOcr(textPdf(2), limits);
  assert.equal(result.code, "OCR_REJECTED"); assert.equal(result.componentCode, "OUTPUT_LIMIT"); assert.equal(result.page, 2);
  assert.equal("pages" in result, false); assert.equal((await readScannedPdfOcr(blankPdf())).kind, "observed");
});

test("actual final report byte limit refuses the full observation without exposing a partial page collection", async () => {
  const result = await readScannedPdfOcr(textPdf(), { maxOutputBytes: 256 });
  assert.equal(result.code, "OUTPUT_LIMIT"); assert.equal(result.stage, "aggregate"); assert.equal("pages" in result, false);
  assert.equal((await readScannedPdfOcr(blankPdf())).kind, "observed");
});

function observeChildren(t, onSpawn = () => {}) {
  const original = childProcess.spawn;
  const counts = { spawned: 0, closed: 0 };
  t.mock.method(childProcess, "spawn", function (...args) {
    const child = original.apply(this, args); counts.spawned += 1;
    child.once("close", () => { counts.closed += 1; });
    onSpawn(child, args);
    return child;
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return counts;
}

test("actual cancellation between completed native pages starts no second OCR and awaits all child closes before recovery", async (t) => {
  const controller = new AbortController(); let calls = 0;
  const counts = observeChildren(t);
  const reader = createScannedPdfOcrReader({ readPdf: readScannedPdf, readOcr: async (...args) => {
    calls += 1; const result = await readLocalOcr(...args); controller.abort(); return result;
  } });
  const result = await reader(textPdf(2), { signal: controller.signal });
  assert.equal(result.code, "CANCELLED"); assert.equal(calls, 1);
  assert.equal(counts.spawned, 2); assert.equal(counts.closed, 2); assert.equal("pages" in result, false);
  assert.equal((await readScannedPdfOcr(blankPdf())).kind, "observed"); assert.equal(counts.closed, counts.spawned);
});

test("actual cancellation after the OCR child drains input kills and closes it before returning, then recovers", async (t) => {
  const controller = new AbortController(); let entered = 0;
  const counts = observeChildren(t, (child, args) => {
    if (args[1].some((part) => typeof part === "string" && part.includes("/local-ocr/worker.py")) && entered === 0) {
      child.stdin.once("finish", () => { entered += 1; controller.abort(); });
    }
  });
  const result = await readScannedPdfOcr(textPdf(), { signal: controller.signal });
  assert.equal(entered, 1); assert.equal(result.code, "CANCELLED");
  assert.equal(counts.spawned, 2); assert.equal(counts.closed, 2);
  assert.equal((await readScannedPdfOcr(blankPdf())).kind, "observed"); assert.equal(counts.closed, counts.spawned);
});

test("actual final synchronous report freezing stays inside the original monotonic deadline", async (t) => {
  const original = Object.freeze; let entered = 0;
  const bytes = textPdf(); const allowance = 2500;
  let originalDeadline;
  const counts = observeChildren(t);
  const reader = createScannedPdfOcrReader({ readPdf: (input, options) => {
    originalDeadline = options.deadlineAtMs;
    return readScannedPdf(input, options);
  }, readOcr: readLocalOcr });
  t.mock.method(Object, "freeze", function (value) {
    if (value?.kind === "observed" && value.profile === "ei-private-scanned-pdf-ocr/1") {
      entered += 1;
      assert.ok(Number.isFinite(originalDeadline));
      assert.ok(performance.now() < originalDeadline, "the native stages entered this final boundary before expiry");
      while (performance.now() < originalDeadline + 10) {}
    }
    return original(value);
  });
  const result = await reader(bytes, { timeoutMs: allowance });
  assert.equal(entered, 1, "native page and OCR must reach the final report before the controlled final stall");
  assert.equal(result.code, "TIMEOUT"); assert.equal("pages" in result, false);
  assert.equal(counts.spawned, 2); assert.equal(counts.closed, 2);
  t.mock.restoreAll(); syncBuiltinESMExports();
  assert.equal((await reader(blankPdf())).kind, "observed");
});

test("actual abort during final report freezing cannot escape as observed text", async (t) => {
  const original = Object.freeze; const controller = new AbortController(); let entered = 0;
  t.mock.method(Object, "freeze", function (value) {
    if (value?.kind === "observed" && value.profile === "ei-private-scanned-pdf-ocr/1") { entered += 1; controller.abort(); }
    return original(value);
  });
  const result = await readScannedPdfOcr(textPdf(), { signal: controller.signal });
  assert.equal(entered, 1); assert.equal(result.code, "CANCELLED"); assert.equal("pages" in result, false);
  t.mock.restoreAll();
  assert.equal((await readScannedPdfOcr(blankPdf())).kind, "observed");
});
