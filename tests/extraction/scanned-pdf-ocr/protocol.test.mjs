import test from "node:test";
import assert from "node:assert/strict";
import { createScannedPdfOcrReader } from "../../../src/extraction/scanned-pdf-ocr/reader.mjs";
import { fakePdf, fakeOcr, source, hash } from "./fake-stages.mjs";

const pdfCases = [
  ["unknown property", (v) => { v.secret = "private transcript marker"; }],
  ["original source mismatch", (v) => { v.sourceSha256 = "0".repeat(64); }],
  ["wrong engine", (v) => { v.engine.version = "foreign"; }],
  ["wrong profile", (v) => { v.profile = "accept-every-pdf"; }],
  ["complete promotion", (v) => { v.completeness = "complete"; }],
  ["inspection disabled", (v) => { v.requiresInspection = false; }],
  ["wrong native policy", (v) => { v.syscallPolicy = "none"; }],
  ["missing enforcement", (v) => { v.enforcementControlsPassed = 0; }],
  ["changed requested limit", (v) => { v.limits.maxOutputBytes -= 1; }],
  ["wrong byte total", (v) => { v.totalRgbaBytes += 1; }],
  ["zero pages", (v) => { v.pages = []; v.totalRgbaBytes = 0; }],
  ["over page count", (v) => { v.pages = Array(5).fill(v.pages[0]); }],
  ["out of order page", (v) => { v.pages[0].page = 2; }],
  ["duplicate page", (v) => { v.pages[1].page = 1; }],
  ["page source mismatch", (v) => { v.pages[0].sourceSha256 = "0".repeat(64); }],
  ["malformed pixel hash", (v) => { v.pages[0].sha256 = "bad"; }],
  ["zero dimension", (v) => { v.pages[0].width = 0; }],
  ["fractional dimension", (v) => { v.pages[0].height = 2.5; }],
  ["dimension ceiling", (v) => { v.pages[0].width = 4097; }],
  ["aggregate pixel ceiling", (v) => { const p = v.pages[0]; p.width = 4096; p.height = 4096; p.stride = 16384; p.byteLength = 4096 * 4096 * 4; }],
  ["infinite point geometry", (v) => { v.pages[0].pageWidthPoints = Infinity; }],
  ["wrong stride", (v) => { v.pages[0].stride -= 1; }],
  ["wrong format", (v) => { v.pages[0].format = "gray8"; }],
  ["wrong color space", (v) => { v.pages[0].colorSpace = "cmyk"; }],
  ["wrong coordinate system", (v) => { v.pages[0].coordinateSystem = "pdf-points"; }],
  ["pixel copy differs from stated hash", (v) => { v.pages[0].copyRgbaBytes = () => Buffer.alloc(3200, 0); }, "pixels"],
  ["transparent pixels despite matching hash", (v) => { const b = Buffer.alloc(3200, 255); b[3] = 0; v.pages[0].sha256 = hash(b); v.pages[0].copyRgbaBytes = () => b; }, "pixels"],
  ["shared pixel backing", (v) => { v.pages[0].copyRgbaBytes = () => new Uint8Array(new SharedArrayBuffer(3200)); }, "pixels"],
  ["pixel method failure", (v) => { v.pages[0].copyRgbaBytes = () => { throw new Error("private path"); }; }, "pixels"],
  ["page getter", (v, flag) => { Object.defineProperty(v.pages[0], "sha256", { enumerable: true, get() { flag.calls += 1; throw new Error("getter ran"); } }); }],
  ["array getter", (v, flag) => { Object.defineProperty(v.pages, "0", { enumerable: true, get() { flag.calls += 1; throw new Error("getter ran"); } }); }],
  ["proxy result", (v, flag) => new Proxy(v, { getPrototypeOf() { flag.calls += 1; throw new Error("proxy ran"); } })],
];

for (const [name, mutate, stage = "render"] of pdfCases) test("synthetic PDF stage rejects " + name + " and the next operation recovers", async () => {
  let turn = 0, ocrCalls = 0; const flag = { calls: 0 };
  const reader = createScannedPdfOcrReader({ readPdf: async (bytes, options) => {
    const result = fakePdf(bytes, options);
    if (turn++ === 0) { const changed = mutate(result, flag); return changed === undefined ? result : changed; }
    return result;
  }, readOcr: async (...args) => { ocrCalls += 1; return fakeOcr(...args); } });
  const result = await reader(source());
  assert.equal(result.code, "STAGE_PROTOCOL_ERROR"); assert.equal(result.stage, stage); assert.equal("pages" in result, false);
  assert.equal(flag.calls, 0); assert.equal(ocrCalls, 0); assert.equal(JSON.stringify(result).includes("private transcript marker"), false);
  assert.equal((await reader(source())).kind, "observed"); assert.equal(ocrCalls, 2);
});

const ocrCases = [
  ["unknown property", (v) => { v.secret = "private transcript marker"; }],
  ["engine version", (v) => { v.engine.version = "wrong"; }],
  ["model pin", (v) => { v.engine.modelSha256 = "0".repeat(64); }],
  ["language", (v) => { v.engine.language = "deu"; }],
  ["profile", (v) => { v.profile = "foreign"; }],
  ["native policy", (v) => { v.syscallPolicy = "none"; }],
  ["enforcement", (v) => { v.enforcementControlsPassed = 0; }],
  ["completion claim", (v) => { v.completeness = "complete"; }],
  ["review disabled", (v) => { v.requiresReview = false; }],
  ["false empty status", (v) => { v.status = "no-text-observed"; }],
  ["source origin", (v) => { v.provenance.sourceSha256 = "0".repeat(64); }],
  ["pixel digest", (v) => { v.provenance.derivativeSha256 = "0".repeat(64); }],
  ["page linkage", (v) => { v.provenance.page = 2; }],
  ["dimensions", (v) => { v.provenance.width -= 1; }],
  ["authority promotion", (v) => { v.provenance.sourceBinding = "accepted"; }],
  ["word source linkage", (v) => { v.words[0].provenance.sourceSha256 = "0".repeat(64); }],
  ["word page linkage", (v) => { v.words[0].provenance.page = 2; }],
  ["NaN confidence", (v) => { v.words[0].confidence = NaN; }],
  ["negative confidence", (v) => { v.words[0].confidence = -1; }],
  ["overrange confidence", (v) => { v.words[0].confidence = 101; }],
  ["probability claim", (v) => { v.words[0].confidenceMeaning = "verified-probability"; }],
  ["word review disabled", (v) => { v.words[0].requiresReview = false; }],
  ["empty word", (v) => { v.words[0].text = ""; }],
  ["carriage return", (v) => { v.words[0].text = "UNKNOWN\r"; }],
  ["bidi control", (v) => { v.words[0].text = "UNKNOWN\u202e"; }],
  ["unpaired surrogate", (v) => { v.words[0].text = "\ud800"; }],
  ["out of bounds box", (v) => { v.words[0].box.width = 100; }],
  ["negative box", (v) => { v.words[0].box.top = -1; }],
  ["fractional box", (v) => { v.words[0].box.left = 1.5; }],
  ["duplicate word identity", (v) => { v.words.push({ ...v.words[0] }); v.tokenUtf8Bytes *= 2; }],
  ["zero word identity", (v) => { v.words[0].word = 0; }],
  ["wrong token bytes", (v) => { v.tokenUtf8Bytes += 1; }],
  ["changed word budget", (v) => { v.limits.maxWords -= 1; }],
  ["word cap", (v) => { v.words = Array(2049).fill(v.words[0]); }],
  ["word getter", (v, flag) => { Object.defineProperty(v.words[0], "text", { enumerable: true, get() { flag.calls += 1; throw new Error("getter ran"); } }); }],
  ["proxy words", (v, flag) => { v.words = new Proxy(v.words, { get() { flag.calls += 1; throw new Error("proxy ran"); } }); }],
];

for (const [name, mutate] of ocrCases) test("synthetic OCR stage rejects " + name + " and the next operation recovers", async () => {
  let turn = 0; const flag = { calls: 0 };
  const reader = createScannedPdfOcrReader({ readPdf: async (...args) => fakePdf(...args), readOcr: async (...args) => {
    const result = fakeOcr(...args);
    if (turn++ === 0) { const changed = mutate(result, flag); return changed === undefined ? result : changed; }
    return result;
  } });
  const result = await reader(source());
  assert.equal(result.code, "STAGE_PROTOCOL_ERROR"); assert.equal(result.stage, "ocr"); assert.equal("pages" in result, false);
  assert.equal(flag.calls, 0); assert.equal(JSON.stringify(result).includes("private transcript marker"), false);
  assert.equal((await reader(source())).kind, "observed");
});

test("synthetic zero-confidence ambiguous word stays literal and unverified at the consumer boundary", async () => {
  const reader = createScannedPdfOcrReader({ readPdf: async (...args) => fakePdf(...args), readOcr: async (...args) => fakeOcr(...args) });
  const result = await reader(source());
  assert.equal(result.kind, "observed");
  for (const page of result.pages) {
    assert.equal(page.words[0].text, "UNKNOWN"); assert.equal(page.words[0].confidence, 0);
    assert.equal(page.words[0].requiresReview, true); assert.equal(page.provenance.sourceBinding, "caller-supplied-unverified");
  }
  assert.equal(result.sourceAuthority, "unverified");
});
