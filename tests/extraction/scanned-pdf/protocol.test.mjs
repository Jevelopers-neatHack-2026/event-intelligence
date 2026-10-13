import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { readScannedPdf } from "../../../src/extraction/scanned-pdf/index.mjs";
import { imagePdf, RGBA_2X2 } from "./fixtures.mjs";
import { framed, interceptSpawns, protocolChild, validHeader } from "./process-helpers.mjs";

const input = imagePdf();
const cases = [
  ["wrong protocol", (h) => { h.protocol = "other"; }],
  ["wrong source hash", (h) => { h.sourceSha256 = "0".repeat(64); }],
  ["wrong closure hash", (h) => { h.closureSha256 = "0".repeat(64); }],
  ["missing enforcement", (h) => { h.enforcementControlsPassed = 0; }],
  ["wrong build", (h) => { h.pdfiumVersion = "unreviewed"; }],
  ["extra metadata", (h) => { h.transcript = "synthetic forbidden output"; }],
  ["empty page set", (h) => { h.pages = []; }],
  ["wrong page index", (h) => { h.pages[0].page = 0; }],
  ["zero width", (h) => { h.pages[0].width = 0; }],
  ["fractional width", (h) => { h.pages[0].width = 2.1; }],
  ["oversized pixel claim", (h) => { h.pages[0].width = 4096; h.pages[0].height = 4096; }],
  ["nonpositive point geometry", (h) => { h.pages[0].pageWidthPoints = 0; }],
  ["missing bytes", (h) => { h.pages[0].byteLength = 0; }],
  ["wrong derivative hash", (h) => { h.pages[0].sha256 = "0".repeat(64); }],
  ["extra page field", (h) => { h.pages[0].sourceUrl = "https://invalid.example"; }],
  ["output negotiation mismatch", (h) => { h.maxOutputBytes -= 1; }],
];
for (const [name, mutate] of cases) {
  test("synthetic protocol rejects " + name + " after actual producer close", async () => {
    const header = validHeader(input); mutate(header);
    let closed = false;
    const restore = interceptSpawns((real, _command, _args, options) => {
      const child = protocolChild(real, framed(header, RGBA_2X2), options);
      child.once("close", () => { closed = true; });
      return child;
    });
    try {
      assert.equal((await readScannedPdf(input)).code, "PROTOCOL_ERROR");
      assert.equal(closed, true);
    } finally { restore(); }
  });
}

test("synthetic valid protocol control carries exact opaque payload", async () => {
  const restore = interceptSpawns((real, _command, _args, options) =>
    protocolChild(real, framed(validHeader(input), RGBA_2X2), options));
  try {
    const result = await readScannedPdf(input);
    assert.equal(result.kind, "decoded");
    assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
  } finally { restore(); }
});

test("hash-consistent transparent pixels violate the elected opaque profile", async () => {
  const header = validHeader(input), pixels = Buffer.from(RGBA_2X2);
  pixels[3] = 0;
  header.pages[0].sha256 = createHash("sha256").update(pixels).digest("hex");
  const restore = interceptSpawns((real, _command, _args, options) => protocolChild(real, framed(header, pixels), options));
  try { assert.equal((await readScannedPdf(input)).code, "PROTOCOL_ERROR"); }
  finally { restore(); }
});

test("trailing payload bytes cannot be assigned to an omitted page", async () => {
  const restore = interceptSpawns((real, _command, _args, options) =>
    protocolChild(real, framed(validHeader(input), Buffer.concat([RGBA_2X2, Buffer.from([0])])), options));
  try { assert.equal((await readScannedPdf(input)).code, "PROTOCOL_ERROR"); }
  finally { restore(); }
});

test("invalid UTF-8 and incomplete frame headers fail closed", async () => {
  for (const frame of [Buffer.from([0, 0, 0, 2, 0xc0, 0xaf]), Buffer.from([0, 0, 0]), Buffer.alloc(4)]) {
    const restore = interceptSpawns((real, _command, _args, options) => protocolChild(real, frame, options));
    try { assert.equal((await readScannedPdf(input)).code, "PROTOCOL_ERROR"); }
    finally { restore(); }
  }
});

test("pre-input isolation refusal is typed without invented source or control evidence", async () => {
  const header = validHeader(input);
  delete header.pages;
  Object.assign(header, { kind: "rejected", code: "ISOLATION_UNAVAILABLE", sourceSha256: null,
    closureSha256: null, enforcementControlsPassed: 0 });
  const restore = interceptSpawns((real, _command, _args, options) => protocolChild(real, framed(header), options));
  try {
    const result = await readScannedPdf(input);
    assert.equal(result.code, "ISOLATION_UNAVAILABLE");
    assert.equal(result.sourceSha256, validHeader(input).sourceSha256);
  } finally { restore(); }
});

test("an unknown worker refusal cannot inject diagnostic text into the response", async () => {
  const header = validHeader(input); delete header.pages;
  Object.assign(header, { kind: "rejected", code: "synthetic private diagnostic" });
  const restore = interceptSpawns((real, _command, _args, options) => protocolChild(real, framed(header), options));
  try {
    const result = await readScannedPdf(input);
    assert.equal(result.code, "PROTOCOL_ERROR");
    assert.ok(!JSON.stringify(result).includes("synthetic private"));
  } finally { restore(); }
});

test("oversized stdout is killed and reaped before a following real decode", async () => {
  let closed = false;
  const restore = interceptSpawns((real, _command, _args, options) => {
    const child = protocolChild(real, Buffer.alloc(65536), options);
    child.once("close", () => { closed = true; }); return child;
  });
  try {
    assert.equal((await readScannedPdf(input, { maxOutputBytes: 16 })).code, "OUTPUT_LIMIT");
    assert.equal(closed, true);
  } finally { restore(); }
  assert.equal((await readScannedPdf(input)).kind, "decoded");
});

test("a nonzero producer exit never returns an otherwise valid derivative", async () => {
  const restore = interceptSpawns((real, _command, _args, options) =>
    protocolChild(real, framed(validHeader(input), RGBA_2X2), options, { exitCode: 2 }));
  try { assert.equal((await readScannedPdf(input)).code, "DECODER_FAILURE"); }
  finally { restore(); }
});
