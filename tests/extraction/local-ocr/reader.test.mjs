import test from "node:test";
import assert from "node:assert/strict";
import { readLocalOcr, LOCAL_OCR_LIMITS, LOCAL_OCR_ERRORS } from "../../../src/extraction/local-ocr/index.mjs";
import { fixture, asRgba, input, hash, expectedText } from "./helpers.mjs";

for (const [name, source] of [["gray8", fixture], ["opaque RGBA8", asRgba]]) test(`actual native OCR after seal recognizes synthetic ${name}`, async () => {
  const pixels = source();
  const result = await readLocalOcr(pixels);
  assert.equal(result.kind, "observed");
  assert.equal(result.words.map((word) => word.text).join(" "), expectedText);
  assert.equal(result.completeness, "incomplete-unverified-ocr");
  assert.equal(result.requiresReview, true);
  assert.equal(result.status, "text-observations");
  assert.equal(result.enforcementControlsPassed, 8);
  assert.equal(result.provenance.sourceSha256, pixels.source.sha256);
  assert.equal(result.provenance.derivativeSha256, hash(pixels.bytes));
  assert.equal(result.provenance.page, 3);
  assert.equal(result.provenance.sourceBinding, "caller-supplied-unverified");
  assert.equal(result.tokenUtf8Bytes, result.words.reduce((count, word) => count + Buffer.byteLength(word.text), 0));
  for (const word of result.words) {
    assert.equal(word.provenance, result.provenance);
    assert.equal(word.confidenceMeaning, "uncalibrated-engine-score");
    assert.equal(word.requiresReview, true);
    assert.ok(word.confidence >= 0 && word.confidence <= 100);
    assert.ok(word.box.left + word.box.width <= pixels.width && word.box.top + word.box.height <= pixels.height);
  }
  assert.deepEqual([...new Set(result.words.map((word) => word.line))], [1, 2]);
});

test("actual blank raster is explicit no-text observation, never evidence that a document lacks text", async () => {
  const result = await readLocalOcr(input());
  assert.equal(result.kind, "observed");
  assert.equal(result.status, "no-text-observed");
  assert.deepEqual(result.words, []);
  assert.equal(result.requiresReview, true);
  assert.equal(result.completeness, "incomplete-unverified-ocr");
});

test("actual observations and nested provenance/boxes are immutable", async () => {
  const result = await readLocalOcr(fixture());
  assert.equal(result.kind, "observed");
  for (const object of [result, result.engine, result.provenance, result.words, result.words[0], result.words[0].box, result.limits]) assert.ok(Object.isFrozen(object));
  assert.throws(() => { result.words[0].text = "APPROVED"; }, TypeError);
});

test("supplied bytes and source descriptors are snapshotted before awaiting OCR", async () => {
  const pixels = fixture();
  const pending = readLocalOcr(pixels);
  pixels.bytes.fill(255); pixels.source.page = 99; pixels.source.sha256 = "2".repeat(64);
  const result = await pending;
  assert.equal(result.kind, "observed");
  assert.equal(result.words.map((word) => word.text).join(" "), expectedText);
  assert.equal(result.provenance.page, 3);
  assert.equal(result.provenance.sourceSha256, "1".repeat(64));
});

test("genuine uint8 subarray respects byte offset and length", async () => {
  const original = fixture();
  const backing = Buffer.concat([Buffer.from([0, 1, 2]), original.bytes, Buffer.from([3])]);
  const source = { ...original, bytes: new Uint8Array(backing.buffer, backing.byteOffset + 3, original.bytes.length) };
  assert.equal((await readLocalOcr(source)).kind, "observed");
});

for (const [name, mutate, code] of [
  ["URL input", () => "https://example.invalid/secret", "INVALID_INPUT"],
  ["null input", () => null, "INVALID_INPUT"],
  ["array input", () => [], "INVALID_INPUT"],
  ["missing shape field", (p) => { delete p.width; return p; }, "INVALID_INPUT"],
  ["extra path option", (p) => ({ ...p, path: "/private/example" }), "INVALID_INPUT"],
  ["fractional width", (p) => ({ ...p, width: 1.5 }), "INVALID_INPUT"],
  ["zero height", (p) => ({ ...p, height: 0 }), "INVALID_INPUT"],
  ["NaN dimension", (p) => ({ ...p, height: NaN }), "INVALID_INPUT"],
  ["infinite dimension", (p) => ({ ...p, width: Infinity }), "INVALID_INPUT"],
  ["oversize dimension", (p) => ({ ...p, width: 4097 }), "DIMENSION_LIMIT"],
  ["pixel ceiling", (p) => ({ ...p, width: 4096, height: 1025 }), "PIXEL_LIMIT"],
  ["encoded PNG format", (p) => ({ ...p, format: "image/png" }), "UNSUPPORTED_RASTER"],
  ["RGB24 unsupported profile", (p) => ({ ...p, format: "rgb8" }), "UNSUPPORTED_RASTER"],
  ["string pixels", (p) => ({ ...p, bytes: "pixels" }), "INVALID_INPUT"],
  ["Uint16 pixels", (p) => ({ ...p, bytes: new Uint16Array(4000) }), "INVALID_INPUT"],
  ["DataView pixels", (p) => ({ ...p, bytes: new DataView(new ArrayBuffer(4000)) }), "INVALID_INPUT"],
  ["mismatched stride bytes", (p) => ({ ...p, bytes: Buffer.alloc(4001) }), "INVALID_INPUT"],
  ["input byte ceiling", (p) => ({ ...p, bytes: Buffer.alloc(LOCAL_OCR_LIMITS.maxInputBytes + 1) }), "INPUT_TOO_LARGE"],
  ["shared backing", (p) => ({ ...p, bytes: new Uint8Array(new SharedArrayBuffer(4000)) }), "INVALID_INPUT"],
  ["source URL", (p) => ({ ...p, source: "https://example.invalid/" }), "INVALID_PROVENANCE"],
  ["source hash uppercase", (p) => ({ ...p, source: { ...p.source, sha256: "A".repeat(64) } }), "INVALID_PROVENANCE"],
  ["wrong derivative hash", (p) => ({ ...p, source: { ...p.source, derivativeSha256: "0".repeat(64) } }), "INVALID_PROVENANCE"],
  ["zero page", (p) => ({ ...p, source: { ...p.source, page: 0 } }), "INVALID_PROVENANCE"],
  ["too large page", (p) => ({ ...p, source: { ...p.source, page: 10001 } }), "INVALID_PROVENANCE"],
  ["source authority field", (p) => ({ ...p, source: { ...p.source, approved: true } }), "INVALID_PROVENANCE"],
]) test(`rejects ${name} without pretending OCR ran`, async () => {
  const result = await readLocalOcr(mutate(input()));
  assert.equal(result.kind, "rejected"); assert.equal(result.code, code);
  assert.equal(result.words, undefined);
  assert.equal(result.enforcementControlsPassed, undefined);
});

test("transparent RGBA is refused instead of silently changing the image", async () => {
  const pixels = asRgba(input()); pixels.bytes[3] = 0; pixels.source.derivativeSha256 = hash(pixels.bytes);
  assert.equal((await readLocalOcr(pixels)).code, "UNSUPPORTED_RASTER");
});

test("untrusted object getters and proxies never execute", async () => {
  let calls = 0;
  const accessor = input(); Object.defineProperty(accessor, "width", { get() { calls += 1; return 100; } });
  assert.equal((await readLocalOcr(accessor)).code, "INVALID_INPUT");
  const proxy = new Proxy(input(), { get() { calls += 1; throw new Error("private"); }, ownKeys() { calls += 1; return []; } });
  assert.equal((await readLocalOcr(proxy)).code, "INVALID_INPUT");
  const nested = input(); Object.defineProperty(nested.source, "page", { get() { calls += 1; return 3; } });
  assert.equal((await readLocalOcr(nested)).code, "INVALID_PROVENANCE");
  assert.equal(calls, 0);
});

for (const [name, options, code] of [
  ["null options", null, "INVALID_OPTIONS"], ["unknown provider", { provider: "remote" }, "INVALID_OPTIONS"],
  ["language override", { language: "osd" }, "INVALID_OPTIONS"], ["model override", { model: "/private/model" }, "INVALID_OPTIONS"],
  ["zero timeout", { timeoutMs: 0 }, "INVALID_LIMIT"], ["null timeout", { timeoutMs: null }, "INVALID_LIMIT"],
  ["oversize timeout", { timeoutMs: 30001 }, "INVALID_LIMIT"], ["fractional timeout", { timeoutMs: 1.5 }, "INVALID_LIMIT"],
  ["zero text budget", { maxTextBytes: 0 }, "INVALID_LIMIT"], ["over ceiling text budget", { maxTextBytes: 32769 }, "INVALID_LIMIT"],
  ["zero word budget", { maxWords: 0 }, "INVALID_LIMIT"], ["over ceiling words", { maxWords: 2049 }, "INVALID_LIMIT"],
  ["fake signal", { signal: { aborted: false } }, "INVALID_OPTIONS"],
]) test(`rejects ${name}`, async () => assert.equal((await readLocalOcr(input(), options)).code, code));

test("option getters are refused without invocation", async () => {
  let calls = 0;
  const options = Object.defineProperty({}, "timeoutMs", { get() { calls += 1; return 10; } });
  assert.equal((await readLocalOcr(input(), options)).code, "INVALID_OPTIONS");
  assert.equal(calls, 0);
});

test("preaborted input does not start recognition and ignores private abort reasons", async () => {
  const controller = new AbortController(); controller.abort(new Error("PRIVATE ABORT TRANSCRIPT"));
  const result = await readLocalOcr(fixture(), { signal: controller.signal });
  assert.equal(result.code, "CANCELLED");
  assert.ok(!JSON.stringify(result).includes("PRIVATE"));
});

for (const options of [{ maxWords: 1 }, { maxTextBytes: 2 }]) test(`actual OCR refuses exceeded output budget ${JSON.stringify(options)} and recovers`, async () => {
  const refusal = await readLocalOcr(fixture(), options);
  assert.equal(refusal.kind, "rejected"); assert.equal(refusal.code, "OUTPUT_LIMIT");
  assert.equal(refusal.words, undefined);
  assert.equal((await readLocalOcr(input())).kind, "observed");
});

test("error and ceiling catalogs are immutable", () => {
  assert.ok(Object.isFrozen(LOCAL_OCR_ERRORS)); assert.ok(Object.isFrozen(LOCAL_OCR_LIMITS));
  assert.equal(LOCAL_OCR_LIMITS.maxConcurrency, 1); assert.equal(LOCAL_OCR_LIMITS.maxQueued, 4);
});
