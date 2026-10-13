import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fixture, asRgba, expectedText } from "../local-ocr/helpers.mjs";
import { png } from "../png/fixtures.mjs";
export { expectedText };
export const hash = (value) => createHash("sha256").update(value).digest("hex");
export const rasterRuntime = process.env.EI_STATIC_IMAGE_OCR_RASTER_RUNTIME;
export function image(name) {
  const manifest = JSON.parse(readFileSync(new URL("./fixtures/provenance.json", import.meta.url)));
  const entry = manifest.fixtures.find((item) => item.file === name);
  if (!entry) throw new Error("Unknown synthetic encoding fixture");
  const bytes = readFileSync(new URL("./fixtures/" + name, import.meta.url));
  if (hash(bytes) !== entry.sha256 || bytes.length !== entry.bytes) throw new Error("Synthetic encoding fixture hash mismatch");
  return { ...entry, bytes };
}
export function encodedPng({ transparent = false, blank = false } = {}) {
  const source = blank ? { width: 40, height: 20, bytes: Buffer.alloc(40 * 20 * 4, 255) } : asRgba(fixture());
  if (transparent) source.bytes[3] = 0;
  const rows = [];
  for (let row = 0; row < source.height; row += 1) rows.push(Buffer.from([0]), source.bytes.subarray(row * source.width * 4, (row + 1) * source.width * 4));
  return { bytes: png({ width: source.width, height: source.height, scanlines: Buffer.concat(rows) }),
    width: source.width, height: source.height, rgbaSha256: hash(source.bytes), pixelBytes: source.bytes };
}
