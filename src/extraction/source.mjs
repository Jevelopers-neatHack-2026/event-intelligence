import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

const INVALID_OFFSET = 0xffff_ffff;
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "buffer").get;
const TYPED_ARRAY_BYTE_OFFSET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteOffset").get;
const TYPED_ARRAY_BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteLength").get;
const TYPED_ARRAY_VALUES = Uint8Array.prototype.values;

export function readRetrievedDocument(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  try {
    const url = readOwnDataProperty(value, "url");
    const contentType = readOwnDataProperty(value, "contentType");
    const bytes = readOwnDataProperty(value, "bytes");
    const fetchedAt = readOwnDataProperty(value, "fetchedAt");
    if (typeof url !== "string" || typeof contentType !== "string"
      || !utilTypes.isUint8Array(bytes) || typeof fetchedAt !== "string") return null;
    // Native validation distinguishes an empty view from a detached or
    // out-of-bounds view without reading any caller-defined properties.
    Reflect.apply(TYPED_ARRAY_VALUES, bytes, []);
    // Keep quota checks and the later owned copy on the same native byte view.
    // Caller-owned properties such as byteLength or valueOf must not replace it.
    const byteView = new Uint8Array(
      Reflect.apply(TYPED_ARRAY_BUFFER, bytes, []),
      Reflect.apply(TYPED_ARRAY_BYTE_OFFSET, bytes, []),
      Reflect.apply(TYPED_ARRAY_BYTE_LENGTH, bytes, []),
    );
    return Object.freeze({
      url,
      contentType,
      fetchedAt,
      bytes: byteView,
    });
  } catch {
    return null;
  }
}

function readOwnDataProperty(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && "value" in descriptor ? descriptor.value : undefined;
}

export function sha256(bytes) {
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

export function decodeUtf8(bytes) {
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    return { ok: true, text: decoder.decode(bytes) };
  } catch {
    return { ok: false, reason: "invalid_utf8" };
  }
}

export function declaredCharset(contentType) {
  const parameter = /(?:^|;)\s*charset\s*=\s*["']?([^;"'\s]+)/i.exec(contentType)?.[1];
  return parameter?.trim().toLowerCase() ?? null;
}

export function createByteOffsetMap(text, expectedByteLength) {
  const map = new Uint32Array(text.length + 1);
  let codeUnitOffset = 0;
  let byteOffset = 0;
  map[0] = 0;

  while (codeUnitOffset < text.length) {
    const codePoint = text.codePointAt(codeUnitOffset);
    const codeUnits = codePoint > 0xffff ? 2 : 1;
    const byteLength = utf8Length(codePoint);
    if (codeUnits === 2) map[codeUnitOffset + 1] = INVALID_OFFSET;
    byteOffset += byteLength;
    codeUnitOffset += codeUnits;
    map[codeUnitOffset] = byteOffset;
  }

  if (byteOffset !== expectedByteLength) return null;
  return map;
}

function utf8Length(codePoint) {
  if (codePoint <= 0x7f) return 1;
  if (codePoint <= 0x7ff) return 2;
  if (codePoint <= 0xffff) return 3;
  return 4;
}

export function exactRange(text, bytes, byteOffsetMap, startOffset, endOffset) {
  if (!Number.isInteger(startOffset) || !Number.isInteger(endOffset)
    || startOffset < 0 || endOffset < startOffset || endOffset > text.length) return null;
  const startByte = byteOffsetMap[startOffset];
  const endByte = byteOffsetMap[endOffset];
  if (startByte === undefined || endByte === undefined
    || startByte === INVALID_OFFSET || endByte === INVALID_OFFSET
    || endByte > bytes.length) return null;

  const rawValue = text.slice(startOffset, endOffset);
  const originalBytes = bytes.subarray(startByte, endByte);
  if (!Buffer.from(rawValue, "utf8").equals(originalBytes)) return null;
  return Object.freeze({
    rawValue,
    locator: Object.freeze({ kind: "text-range", startByte, endByte }),
  });
}

export function normalizeCandidateValue(value) {
  if (typeof value !== "string") return value;
  return value.replace(/\s+/gu, " ").trim();
}

export function resolveUrlSuggestion(rawValue, baseUrl) {
  if (typeof rawValue !== "string" || rawValue.trim() === "") return null;
  try {
    const resolved = new URL(rawValue.trim(), baseUrl);
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") return null;
    return resolved.href;
  } catch {
    return null;
  }
}

export function textCandidate({
  field,
  kind,
  text,
  bytes,
  byteOffsetMap,
  startOffset,
  endOffset,
  normalizedValue,
  jsonPointer,
  property,
  suggestionOnly,
}) {
  const exact = exactRange(text, bytes, byteOffsetMap, startOffset, endOffset);
  if (!exact) return null;
  const source = {
    kind,
    locator: exact.locator,
  };
  if (jsonPointer !== undefined) source.jsonPointer = jsonPointer;
  if (property !== undefined) source.property = property;
  const candidate = {
    field,
    rawValue: exact.rawValue,
    normalizedValue: normalizeCandidateValue(normalizedValue),
    source: Object.freeze(source),
  };
  if (suggestionOnly === true) candidate.suggestionOnly = true;
  return Object.freeze(candidate);
}

export function sourceFromDocument(document, sourceHash) {
  return Object.freeze({
    url: document.url,
    fetchedAt: document.fetchedAt,
    contentType: document.contentType,
    contentHash: sourceHash,
  });
}

export function isHttpDocumentUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}
