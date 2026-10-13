import test from "node:test";
import assert from "node:assert/strict";
import { createScannedPdfOcrReader } from "../../../src/extraction/scanned-pdf-ocr/reader.mjs";
import { SCANNED_PDF_OCR_LIMITS, SCANNED_PDF_OCR_ERRORS } from "../../../src/extraction/scanned-pdf-ocr/index.mjs";
import { fakePdf, fakeOcr, source } from "./fake-stages.mjs";

for (const [name, input, expected] of [
  ["URL", () => "https://example.invalid/private", "INVALID_INPUT"], ["path", () => "/private/file.pdf", "INVALID_INPUT"],
  ["null", () => null, "INVALID_INPUT"], ["array", () => [1, 2], "INVALID_INPUT"], ["empty", () => Buffer.alloc(0), "INVALID_INPUT"],
  ["DataView", () => new DataView(new ArrayBuffer(10)), "INVALID_INPUT"], ["Uint16Array", () => new Uint16Array(10), "INVALID_INPUT"],
  ["shared backing", () => new Uint8Array(new SharedArrayBuffer(10)), "INVALID_INPUT"],
  ["over byte cap", () => Buffer.alloc(SCANNED_PDF_OCR_LIMITS.maxInputBytes + 1), "INPUT_TOO_LARGE"],
]) test("admission refuses " + name + " before either reader runs", async () => {
  let calls = 0;
  const reader = createScannedPdfOcrReader({ readPdf: async () => { calls += 1; }, readOcr: async () => { calls += 1; } });
  assert.equal((await reader(input())).code, expected); assert.equal(calls, 0);
});

for (const [name, options, expected] of [
  ["null", null, "INVALID_OPTIONS"], ["array", [], "INVALID_OPTIONS"], ["provider", { provider: "private" }, "INVALID_OPTIONS"],
  ["language", { language: "eng" }, "INVALID_OPTIONS"], ["fake signal", { signal: { aborted: false } }, "INVALID_OPTIONS"],
  ["zero timeout", { timeoutMs: 0 }, "INVALID_LIMIT"], ["null timeout", { timeoutMs: null }, "INVALID_LIMIT"],
  ["large timeout", { timeoutMs: 30001 }, "INVALID_LIMIT"], ["fractional timeout", { timeoutMs: 1.5 }, "INVALID_LIMIT"],
  ["zero words", { maxWords: 0 }, "INVALID_LIMIT"], ["large words", { maxWords: 2049 }, "INVALID_LIMIT"],
  ["zero text bytes", { maxTextBytes: 0 }, "INVALID_LIMIT"], ["large text bytes", { maxTextBytes: 32769 }, "INVALID_LIMIT"],
  ["zero output bytes", { maxOutputBytes: 0 }, "INVALID_LIMIT"], ["large output bytes", { maxOutputBytes: 1048577 }, "INVALID_LIMIT"],
]) test("admission refuses options: " + name, async () => {
  let calls = 0;
  const reader = createScannedPdfOcrReader({ readPdf: async () => { calls += 1; }, readOcr: async () => { calls += 1; } });
  assert.equal((await reader(source(), options)).code, expected); assert.equal(calls, 0);
});

test("input and option accessors/proxies are not invoked", async () => {
  const reader = createScannedPdfOcrReader({ readPdf: async (...args) => fakePdf(...args), readOcr: async (...args) => fakeOcr(...args) });
  let invoked = 0;
  const proxy = new Proxy(source(), { getPrototypeOf() { invoked += 1; throw new Error("private"); } });
  assert.equal((await reader(proxy)).code, "INVALID_INPUT");
  assert.equal((await reader(source(), { get timeoutMs() { invoked += 1; return 100; } })).code, "INVALID_OPTIONS");
  assert.equal(invoked, 0);
});

test("pre-aborted admission starts no stage and does not return the private abort reason", async () => {
  const controller = new AbortController(); controller.abort("private reason"); let calls = 0;
  const reader = createScannedPdfOcrReader({ readPdf: async () => { calls += 1; }, readOcr: async () => { calls += 1; } });
  const result = await reader(source(), { signal: controller.signal });
  assert.equal(result.code, "CANCELLED"); assert.equal(calls, 0); assert.equal(JSON.stringify(result).includes("private reason"), false);
});

test("catalogs are immutable and the trusted internal factory refuses foreign hooks", () => {
  assert.ok(Object.isFrozen(SCANNED_PDF_OCR_LIMITS) && Object.isFrozen(SCANNED_PDF_OCR_ERRORS));
  assert.throws(() => createScannedPdfOcrReader({ readPdf() {}, readOcr() {}, provider() {} }), TypeError);
  assert.throws(() => createScannedPdfOcrReader({ get readPdf() { throw new Error("getter ran"); }, readOcr() {} }), TypeError);
});
