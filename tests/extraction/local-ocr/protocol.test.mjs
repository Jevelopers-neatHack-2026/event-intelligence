import test from "node:test";
import assert from "node:assert/strict";
import { readLocalOcr } from "../../../src/extraction/local-ocr/index.mjs";
import { input } from "./helpers.mjs";
import { fakeWorkers } from "./fake-worker.mjs";

test("synthetic valid zero-confidence token remains uncertain, source-bound and review-required", async (t) => {
  fakeWorkers(t);
  const result = await readLocalOcr(input());
  assert.equal(result.kind, "observed");
  assert.equal(result.words[0].text, "TOKEN"); assert.equal(result.words[0].confidence, 0);
  assert.equal(result.words[0].requiresReview, true);
  assert.equal(result.words[0].confidenceMeaning, "uncalibrated-engine-score");
  assert.equal(result.words[0].provenance.derivativeSha256, input().source.derivativeSha256);
});

for (const [name, mutate] of [
  ["unknown result shape", (v) => ({ ...v, accepted: true })],
  ["foreign protocol", (v) => ({ ...v, protocol: "shared-contract" })],
  ["foreign profile", (v) => ({ ...v, profile: "arbitrary-model" })],
  ["foreign engine version", (v) => ({ ...v, tesseractVersion: "6" })],
  ["foreign model", (v) => ({ ...v, modelSha256: "0".repeat(64) })],
  ["foreign runtime closure", (v) => ({ ...v, closureSha256: "0".repeat(64) })],
  ["missing native controls", (v) => ({ ...v, enforcementControlsPassed: 0 })],
  ["foreign syscall policy", (v) => ({ ...v, syscallPolicy: "none" })],
  ["foreign source derivative", (v) => ({ ...v, rasterSha256: "0".repeat(64) })],
  ["foreign page dimensions", (v) => ({ ...v, width: 101 })],
  ["foreign raster format", (v) => ({ ...v, format: "rgba8" })],
  ["changed request word limit", (v) => ({ ...v, maxWords: 1 })],
  ["changed request text limit", (v) => ({ ...v, maxTextBytes: 1 })],
  ["wrong token byte total", (v) => ({ ...v, tokenUtf8Bytes: 0 })],
  ["non-array words", (v) => ({ ...v, words: {} })],
  ["unknown word property", (v) => { v.words[0].approved = true; return v; }],
  ["invalid confidence", (v) => { v.words[0].confidence = null; return v; }],
  ["negative confidence", (v) => { v.words[0].confidence = -1; return v; }],
  ["overrange confidence", (v) => { v.words[0].confidence = 101; return v; }],
  ["empty token", (v) => { v.words[0].text = ""; return v; }],
  ["control token", (v) => { v.words[0].text = "TO\nKEN"; return v; }],
  ["bidi token", (v) => { v.words[0].text = "TO\u202eKEN"; return v; }],
  ["paragraph separator token", (v) => { v.words[0].text = "TO\u2029KEN"; return v; }],
  ["unpaired surrogate token", (v) => { v.words[0].text = "\ud800"; return v; }],
  ["zero word identity", (v) => { v.words[0].word = 0; return v; }],
  ["fractional line", (v) => { v.words[0].line = 1.5; return v; }],
  ["duplicate word identity", (v) => { v.words.push(structuredClone(v.words[0])); v.tokenUtf8Bytes *= 2; return v; }],
  ["out-of-bounds box", (v) => { v.words[0].box.width = 1000; return v; }],
  ["negative box origin", (v) => { v.words[0].box.left = -1; return v; }],
  ["empty box", (v) => { v.words[0].box.width = 0; return v; }],
  ["foreign box coordinate", (v) => { v.words[0].box.coordinateSystem = "points"; return v; }],
  ["trailing second record", (v) => Buffer.from(JSON.stringify(v) + "{}")],
  ["invalid UTF8", () => Buffer.from([0xff, 0xfe])],
]) test(`synthetic worker response rejects ${name}`, async (t) => {
  fakeWorkers(t, (child) => child.reply(mutate));
  const result = await readLocalOcr(input());
  assert.equal(result.kind, "rejected"); assert.equal(result.code, "PROTOCOL_ERROR");
  assert.equal(result.words, undefined);
});

test("synthetic native refusal is sanitized and cannot attach arbitrary text", async (t) => {
  fakeWorkers(t, (child) => child.reply((value) => ({ kind: "rejected", protocol: value.protocol, profile: value.profile,
    code: "PRIVATE CUSTOMER DATA", rasterSha256: null, closureSha256: null, enforcementControlsPassed: 0 })));
  const result = await readLocalOcr(input());
  assert.equal(result.code, "PROTOCOL_ERROR"); assert.ok(!JSON.stringify(result).includes("PRIVATE"));
});
