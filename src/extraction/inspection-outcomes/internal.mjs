// EI-private helpers. The supported index binds real readers, never caller decoders.
import { types } from "node:util";

export const OUTCOME_SCHEMA = "ei-private-inspection-outcome/1";
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted").get;
const add = EventTarget.prototype.addEventListener;
const remove = EventTarget.prototype.removeEventListener;
const typed = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(typed, "byteLength").get;
const byteOffset = Object.getOwnPropertyDescriptor(typed, "byteOffset").get;
const backing = Object.getOwnPropertyDescriptor(typed, "buffer").get;
const arrayBufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;

const COMMON = ["INVALID_INPUT", "INVALID_OPTIONS", "INVALID_LIMIT", "INPUT_TOO_LARGE",
  "OUTPUT_LIMIT", "CANCELLED", "TIMEOUT", "QUEUE_FULL", "ISOLATION_UNAVAILABLE",
  "DECODER_UNAVAILABLE", "DECODER_FAILURE", "PROTOCOL_ERROR"];
const CODES = Object.freeze({
  png: Object.freeze([...COMMON, "MALFORMED_PNG", "UNSUPPORTED_PNG_FEATURE", "DIMENSION_LIMIT",
    "RESOURCE_LIMIT", "REMOTE_RESOURCE_ATTEMPT"]),
  "jpeg-webp": Object.freeze([...COMMON, "UNSUPPORTED_FORMAT", "UNSUPPORTED_FEATURE",
    "MALFORMED_IMAGE", "DIMENSION_LIMIT", "RESOURCE_LIMIT", "REMOTE_RESOURCE_ATTEMPT"]),
  "scanned-pdf": Object.freeze([...COMMON, "RUNTIME_MISMATCH", "PAGE_LIMIT", "DIMENSION_LIMIT",
    "PIXEL_LIMIT", "STRUCTURE_LIMIT", "MALFORMED_PDF", "UNSUPPORTED_PDF_FEATURE",
    "ENCRYPTED_PDF", "ACTIVE_CONTENT", "REMOTE_RESOURCE", "DAMAGED_IMAGE", "INCOMPLETE_RENDER"]),
  "text-pdf": Object.freeze([...COMMON, "MALFORMED_PDF", "ENCRYPTED_PDF", "ACTIVE_PDF_FEATURE",
    "REMOTE_REFERENCE", "REMOTE_RESOURCE_ATTEMPT", "UNSUPPORTED_PDF_FEATURE",
    "PAGE_LIMIT", "DIMENSION_LIMIT", "TEXT_LIMIT", "RESOURCE_LIMIT", "NO_EMBEDDED_TEXT", "CALLBACK_FAILED"]),
});
const RESOURCES = Object.freeze({
  png: Object.freeze(["INPUT_TOO_LARGE", "DIMENSION_LIMIT", "RESOURCE_LIMIT", "OUTPUT_LIMIT"]),
  "jpeg-webp": Object.freeze(["INPUT_TOO_LARGE", "DIMENSION_LIMIT", "RESOURCE_LIMIT", "OUTPUT_LIMIT"]),
  "scanned-pdf": Object.freeze(["INPUT_TOO_LARGE", "PAGE_LIMIT", "DIMENSION_LIMIT", "PIXEL_LIMIT", "STRUCTURE_LIMIT", "OUTPUT_LIMIT"]),
  "text-pdf": Object.freeze(["INPUT_TOO_LARGE", "PAGE_LIMIT", "DIMENSION_LIMIT", "TEXT_LIMIT", "RESOURCE_LIMIT", "OUTPUT_LIMIT"]),
});

export function boundaryFailure(reader, reason) {
  return Object.freeze({ schemaVersion: OUTCOME_SCHEMA, kind: "boundary-failure", reader,
    category: reason === "INVALID_INPUT" || reason === "INVALID_OPTIONS" || reason === "INVALID_CONFIGURATION"
      ? reason : "INTERNAL_FAILURE",
    reason: ["INVALID_INPUT", "INVALID_OPTIONS", "INVALID_CONFIGURATION"].includes(reason) ? reason : "UNEXPECTED_READER_FAILURE" });
}

export function dataRecord(value, allowed) {
  if (!value || typeof value !== "object" || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((key) => !allowed.includes(key) || !Object.hasOwn(descriptors[key], "value"))) return null;
  return descriptors;
}

export function prepare(reader, input, options) {
  let bytes;
  try {
    if (!input || typeof input !== "object" || types.isProxy(input) ||
        ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(input))) return { failure: boundaryFailure(reader, "INVALID_INPUT") };
    const buffer = backing.call(input);
    arrayBufferLength.call(buffer); // Refuse SharedArrayBuffer and detached backing.
    // A canonical view avoids caller byte getters, iterators and Buffer.from hooks.
    // The bound reader synchronously copies it before its first asynchronous work.
    bytes = new Uint8Array(buffer, byteOffset.call(input), byteLength.call(input));
  } catch { return { failure: boundaryFailure(reader, "INVALID_INPUT") }; }
  try {
    const text = reader === "text-pdf";
    const allowed = ["signal", "timeoutMs", "maxOutputBytes", text ? "maxTextCodeUnits" : "deadlineAtMs"];
    const record = dataRecord(options === undefined ? {} : options, allowed);
    if (!record) return { failure: boundaryFailure(reader, "INVALID_OPTIONS") };
    const normalized = Object.create(null);
    for (const key of allowed.filter((key) => key !== "signal")) {
      if (!Object.hasOwn(record, key)) continue;
      const value = record[key].value;
      if (value !== undefined && typeof value !== "number") return { failure: boundaryFailure(reader, "INVALID_OPTIONS") };
      normalized[key] = value; // Numeric range validation remains in the real reader.
    }
    const signal = record.signal?.value;
    if (signal !== undefined) {
      if (!signal || typeof signal !== "object" || types.isProxy(signal)) return { failure: boundaryFailure(reader, "INVALID_OPTIONS") };
      aborted.call(signal); // Native brand, without caller property access.
      normalized.signal = text ? Object.freeze({
        get aborted() { return aborted.call(signal); },
        addEventListener(type, listener, settings) { return add.call(signal, type, listener, settings); },
        removeEventListener(type, listener, settings) { return remove.call(signal, type, listener, settings); },
      }) : signal;
    }
    return { bytes, options: normalized };
  } catch { return { failure: boundaryFailure(reader, "INVALID_OPTIONS") }; }
}

export function wrapReaderResult(reader, result) {
  try {
    if (!Object.hasOwn(CODES, reader) || !result || typeof result !== "object" ||
        types.isProxy(result) || !Object.isFrozen(result)) return boundaryFailure(reader, "UNEXPECTED_READER_FAILURE");
    const descriptor = Object.getOwnPropertyDescriptors(result);
    const value = (key) => descriptor[key] && Object.hasOwn(descriptor[key], "value") ? descriptor[key].value : undefined;
    const kind = value("kind");
    if (kind === "rejected") {
      const code = value("code");
      if (!CODES[reader].includes(code)) return boundaryFailure(reader, "UNEXPECTED_READER_FAILURE");
      return Object.freeze({ schemaVersion: OUTCOME_SCHEMA, kind: "reader-result", reader,
        category: RESOURCES[reader].includes(code) ? "RESOURCE_LIMIT" : code, reason: code, result });
    }
    const text = reader === "text-pdf";
    if (value("requiresInspection") !== true ||
        value("completeness") !== (text ? "incomplete-text-only" : "incomplete-pixels-only") ||
        (text ? !["observation", "no-text"].includes(kind) : kind !== "decoded") ||
        (kind === "no-text" && value("code") !== "NO_EMBEDDED_TEXT")) return boundaryFailure(reader, "UNEXPECTED_READER_FAILURE");
    // Keep the exact native object, including page/hash/box metadata and fresh-copy accessors.
    return Object.freeze({ schemaVersion: OUTCOME_SCHEMA, kind: "reader-result", reader,
      category: "OBSERVATION", reason: null, result });
  } catch { return boundaryFailure(reader, "UNEXPECTED_READER_FAILURE"); }
}
