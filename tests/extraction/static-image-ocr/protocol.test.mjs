import test from "node:test";
import assert from "node:assert/strict";
import { createStaticImageOcrReaderWithPorts } from "../../../src/extraction/static-image-ocr/reader.mjs";
import { source, fakeImage, fakeOcr, hash } from "./fake-stages.mjs";

const imageMutations = [
  ["extra authority", (r) => { r.authorized = true; }], ["source hash", (r) => { r.sourceSha256 = "f".repeat(64); }],
  ["engine", (r) => { r.decoder.configVersion = "invented"; }], ["limit", (r) => { r.limits.maxPixels += 1; }],
  ["complete claim", (r) => { r.completeness = "complete"; }], ["inspection", (r) => { r.requiresInspection = false; }],
  ["width", (r) => { r.width = 4097; }], ["height", (r) => { r.height = 0; }],
  ["pixel length", (r) => { r.decodedRgbaBytes -= 1; }], ["output color", (r) => { r.outputColorType = 2; }],
  ["source color", (r) => { r.sourceColorType = 3; }], ["normalized hash", (r) => { r.normalizedSha256 = "bad"; }],
  ["normalized length", (r) => { r.normalizedByteLength = 20 * 1024 * 1024 + 1; }],
  ["network guard", (r) => { r.networkApiAttemptCount = 1; }], ["pixel hash", (r) => { r.rgbaSha256 = "e".repeat(64); }],
  ["truncated owned copy", (r) => { r.copyRgbaBytes = () => new Uint8Array(1); }],
  ["shared owned copy", (r) => { r.copyRgbaBytes = () => new Uint8Array(new SharedArrayBuffer(3200)); }],
  ["throwing copy", (r) => { r.copyRgbaBytes = () => { throw new Error("SYNTHETIC_PRIVATE_STAGE_CANARY"); }; }],
  ["proxy copy", (r) => { r.copyRgbaBytes = new Proxy(r.copyRgbaBytes, {}); }],
  ["async copy", (r) => { r.copyRgbaBytes = async () => new Uint8Array(3200); }],
];
for (const [label, mutate] of imageMutations) test("synthetic image boundary refuses " + label + " before OCR and recovers", async () => {
  let failing = true, ocrCalls = 0;
  const read = createStaticImageOcrReaderWithPorts({ readPng: async (...args) => { const r = fakeImage(...args); if (failing) mutate(r); return r; },
    readJpegWebp: async (...args) => fakeImage(...args, "jpeg"), readOcr: async (...args) => { ocrCalls += 1; return fakeOcr(...args); } });
  const result = await read(source());
  assert.equal(result.code, "STAGE_PROTOCOL_ERROR"); assert.equal(ocrCalls, 0); assert.equal("words" in result, false);
  assert.equal(JSON.stringify(result).includes("CANARY"), false);
  failing = false; assert.equal((await read(source())).kind, "observed"); assert.equal(ocrCalls, 1);
});
test("a pixel copy getter is never invoked", async () => {
  let calls = 0;
  const read = createStaticImageOcrReaderWithPorts({ readPng: async (...args) => {
    const r = fakeImage(...args); Object.defineProperty(r, "copyRgbaBytes", { get() { calls += 1; throw new Error(); } }); return r;
  }, readJpegWebp: async (...args) => fakeImage(...args, "jpeg"), readOcr: async (...args) => fakeOcr(...args) });
  assert.equal((await read(source())).code, "STAGE_PROTOCOL_ERROR"); assert.equal(calls, 0);
});
test("matching hash of transparent pixels still refuses before OCR; opacity is not inferred from metadata", async () => {
  let calls = 0;
  const read = createStaticImageOcrReaderWithPorts({ readPng: async (...args) => {
    const r = fakeImage(...args); const raw = Buffer.from(r.copyRgbaBytes()); raw[3] = 0;
    r.rgbaSha256 = hash(raw); r.copyRgbaBytes = () => new Uint8Array(raw); return r;
  }, readJpegWebp: async (...args) => fakeImage(...args, "jpeg"), readOcr: async (...args) => { calls += 1; return fakeOcr(...args); } });
  assert.equal((await read(source())).code, "NON_OPAQUE_IMAGE"); assert.equal(calls, 0);
});
const ocrMutations = [
  ["replacement source", (r) => { r.provenance.sourceSha256 = "f".repeat(64); }],
  ["replacement pixels", (r) => { r.provenance.derivativeSha256 = "f".repeat(64); }],
  ["wrong page", (r) => { r.provenance.page = 2; }], ["source authority", (r) => { r.provenance.sourceBinding = "verified"; }],
  ["wrong dimensions", (r) => { r.provenance.width += 1; }], ["model", (r) => { r.engine.modelSha256 = "f".repeat(64); }],
  ["no review", (r) => { r.requiresReview = false; }], ["complete claim", (r) => { r.completeness = "complete"; }],
  ["process policy", (r) => { r.syscallPolicy = "unconfined"; }], ["control count", (r) => { r.enforcementControlsPassed = 7; }],
  ["runtime limit", (r) => { r.limits.maxInputBytes += 1; }], ["invented field", (r) => { r.facts = []; }],
  ["status", (r) => { r.status = "no-text-observed"; }], ["word bytes", (r) => { r.tokenUtf8Bytes += 1; }],
  ["word source", (r) => { r.words[0].provenance.sourceSha256 = "f".repeat(64); }],
  ["word geometry", (r) => { r.words[0].box.left = 10000; }], ["word noninteger geometry", (r) => { r.words[0].box.top = 0.1; }],
  ["word confidence", (r) => { r.words[0].confidence = NaN; }], ["word certainty", (r) => { r.words[0].confidenceMeaning = "probability"; }],
  ["word review", (r) => { r.words[0].requiresReview = false; }], ["word identity", (r) => { r.words[0].word = 0; }],
  ["duplicate identity", (r) => { r.words.push({ ...r.words[0] }); r.tokenUtf8Bytes *= 2; }],
  ["extra array field", (r) => { r.words.secret = "SYNTHETIC_CANARY"; }],
  ["sparse array", (r) => { r.words.length = 2; }], ["text control", (r) => { r.words[0].text = "A\u0000B"; }],
  ["text surrogate", (r) => { r.words[0].text = "\ud800"; }], ["bidi control", (r) => { r.words[0].text = "A\u202eB"; }],
];
for (const [label, mutate] of ocrMutations) test("synthetic OCR boundary refuses " + label + " without partial output and recovers", async () => {
  let failing = true;
  const read = createStaticImageOcrReaderWithPorts({ readPng: async (...args) => fakeImage(...args), readJpegWebp: async (...args) => fakeImage(...args, "jpeg"),
    readOcr: async (...args) => { const result = fakeOcr(...args); if (failing) mutate(result); return result; } });
  const result = await read(source()); assert.equal(result.code, "STAGE_PROTOCOL_ERROR"); assert.equal("words" in result, false);
  failing = false; assert.equal((await read(source())).kind, "observed");
});
test("literal zero-confidence words are retained uncorrected and frozen; empty observations stay incomplete", async () => {
  let empty = false;
  const read = createStaticImageOcrReaderWithPorts({ readPng: async (...args) => fakeImage(...args), readJpegWebp: async (...args) => fakeImage(...args, "jpeg"),
    readOcr: async (...args) => fakeOcr(...args, empty ? null : "UNCERTAIN") });
  const observed = await read(source()); assert.equal(observed.kind, "observed"); assert.equal(observed.words[0].confidence, 0);
  assert.equal(observed.words[0].text, "UNCERTAIN"); assert.ok(Object.isFrozen(observed.words[0].box));
  assert.throws(() => { observed.words[0].text = "corrected"; }, TypeError);
  empty = true; const blank = await read(source()); assert.equal(blank.status, "no-text-observed"); assert.equal(blank.completeness, "incomplete-unverified-ocr");
});
test("composition report limit does not silently change either decoder normalized-image limit", async () => {
  let allowance;
  const read = createStaticImageOcrReaderWithPorts({ readPng: async (bytes, options) => { allowance = options.maxOutputBytes; return fakeImage(bytes, options); },
    readJpegWebp: async (...args) => fakeImage(...args, "jpeg"), readOcr: async (...args) => fakeOcr(...args) });
  const result = await read(source(), { maxOutputBytes: 100 });
  assert.equal(allowance, 20 * 1024 * 1024); assert.equal(result.code, "OUTPUT_LIMIT"); assert.equal(result.stage, "aggregate");
});
