import test from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import { readScannedPdf } from "../../../src/extraction/scanned-pdf/index.mjs";
import { readLocalOcr } from "../../../src/extraction/local-ocr/index.mjs";
import { input } from "../local-ocr/helpers.mjs";
import { blankPdf } from "./fixtures.mjs";

for (const [name, read, source, accepted] of [["PDF", readScannedPdf, blankPdf, "decoded"], ["OCR", readLocalOcr, input, "observed"]]) {
  test(name + " lower-only absolute deadline refuses an expired handoff before any child starts", async (t) => {
    let spawned = 0;
    t.mock.method(childProcess, "spawn", () => { spawned += 1; throw new Error("must not spawn"); });
    syncBuiltinESMExports(); t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
    const result = await read(source(), { timeoutMs: 10000, deadlineAtMs: performance.now() - 1 });
    assert.equal(result.code, "TIMEOUT"); assert.equal(spawned, 0);
  });
  test(name + " future absolute deadline cannot raise a shorter standalone timeout", async () => {
    const result = await read(source(), { timeoutMs: 1, deadlineAtMs: performance.now() + 100000 });
    assert.equal(result.code, "TIMEOUT");
    assert.equal((await read(source(), { deadlineAtMs: performance.now() + 10000 })).kind, accepted);
  });
  for (const value of [null, -1, NaN, Infinity, "1000", Number.MAX_SAFE_INTEGER + 1]) test(name + " refuses invalid absolute deadline " + String(value), async () => {
    assert.equal((await read(source(), { deadlineAtMs: value })).code, "INVALID_LIMIT");
  });
}
