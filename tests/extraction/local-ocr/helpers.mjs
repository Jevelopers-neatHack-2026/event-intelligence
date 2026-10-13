import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
export const hash = (value) => createHash("sha256").update(value).digest("hex");
export function fixture() {
  const bytes = gunzipSync(readFileSync(new URL("./fixtures/english-gray8.raw.gz", import.meta.url)), { maxOutputLength: 220000 });
  if (bytes.length !== 220000 || hash(bytes) !== "50f86c14d6b77e84ffb70a933a80ab9a0cb0226d2301f1044b024414ee43d168") throw new Error("Pinned synthetic fixture mismatch");
  return input(bytes, 1000, 220);
}
export function input(bytes = Buffer.alloc(100 * 40, 255), width = 100, height = 40, format = "gray8") {
  return { bytes, width, height, format, source: { sha256: "1".repeat(64), page: 3, derivativeSha256: hash(bytes) } };
}
export function asRgba(source = fixture()) {
  const bytes = Buffer.alloc(source.bytes.length * 4);
  for (let index = 0; index < source.bytes.length; index += 1) {
    bytes[index * 4] = source.bytes[index]; bytes[index * 4 + 1] = source.bytes[index];
    bytes[index * 4 + 2] = source.bytes[index]; bytes[index * 4 + 3] = 255;
  }
  return input(bytes, source.width, source.height, "rgba8");
}
export const expectedText = "TICKET STUB 2026 DOORS OPEN AT 7 PM";
