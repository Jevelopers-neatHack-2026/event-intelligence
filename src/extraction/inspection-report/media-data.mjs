// Private data-only boundary shared by the versioned media report and its readers.
// No source URL, decoder, runtime installer or caller callback is invoked here.
import { createHash } from "node:crypto";
import { types } from "node:util";
import { InspectionReportError } from "./index.mjs";

export const MEDIA_DATA_LIMITS = Object.freeze({ maxDepth: 64, maxNodes: 100_000, maxJsonBytes: 4 * 1024 * 1024 });
const slots = Object.getOwnPropertyDescriptors(Object.getPrototypeOf(Uint8Array.prototype));
const overrides = ["buffer", "byteLength", "byteOffset", "length", "valueOf", "toString", "toJSON", Symbol.toPrimitive, Symbol.iterator];
export const isHash = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
export const isRevision = (value) => typeof value === "string" && /^[a-f0-9]{40}$/.test(value);
export const isId = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);
export const integer = (value, max, minimum = 0) => Number.isSafeInteger(value) && value >= minimum && value <= max;
export const hash = (value) => createHash("sha256").update(value).digest("hex");
export function check(ok, code = "INVALID_INPUT") { if (!ok) throw new InspectionReportError(code); }
export function record(value) {
  check(value !== null && typeof value === "object" && !types.isProxy(value) && !Array.isArray(value));
  check([Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const descriptors = Object.getOwnPropertyDescriptors(value);
  check(Reflect.ownKeys(descriptors).every((key) => typeof key === "string" && "value" in descriptors[key] && descriptors[key].enumerable));
  return value;
}
export function array(value, maximum) {
  check(!types.isProxy(value) && Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype);
  const size = Object.getOwnPropertyDescriptor(value, "length")?.value;
  check(Number.isSafeInteger(size) && size >= 0);
  check(size <= maximum, "RESOURCE_LIMIT");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  check(Reflect.ownKeys(descriptors).length === size + 1);
  const result = [];
  for (let index = 0; index < size; index += 1) {
    const descriptor = descriptors[index];
    check(descriptor && "value" in descriptor && descriptor.enumerable);
    result.push(descriptor.value);
  }
  return result;
}
export function bytes(value, maximum, allowEmpty = false) {
  check(!types.isProxy(value) && types.isUint8Array(value));
  check([Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(value)));
  check(overrides.every((key) => !Object.hasOwn(value, key)));
  const length = Reflect.apply(slots.byteLength.get, value, []);
  check(length >= (allowEmpty ? 0 : 1) && length <= maximum, "RESOURCE_LIMIT");
  const buffer = Reflect.apply(slots.buffer.get, value, []);
  check(!types.isSharedArrayBuffer(buffer));
  const offset = Reflect.apply(slots.byteOffset.get, value, []);
  try { return Buffer.from(new Uint8Array(buffer, offset, length)); }
  catch { throw new InspectionReportError("INVALID_INPUT"); }
}
export function data(input, maximum = MEDIA_DATA_LIMITS.maxJsonBytes) {
  let nodes = 0, used = 0;
  const parents = new Set();
  function visit(value, depth) {
    check(++nodes <= MEDIA_DATA_LIMITS.maxNodes && depth <= MEDIA_DATA_LIMITS.maxDepth, "RESOURCE_LIMIT");
    if (value === null || typeof value === "boolean") { used += 5; return value; }
    if (typeof value === "number") { check(Number.isFinite(value) && !Object.is(value, -0)); used += 32; return value; }
    if (typeof value === "string") { used += Buffer.byteLength(value) + 2; check(used <= maximum, "RESOURCE_LIMIT"); return value; }
    check(value !== null && typeof value === "object" && !types.isProxy(value) && !parents.has(value));
    parents.add(value);
    let output;
    if (Array.isArray(value)) output = array(value, MEDIA_DATA_LIMITS.maxNodes).map((child) => visit(child, depth + 1));
    else {
      record(value); output = {};
      for (const key of Object.keys(value).sort()) {
        used += Buffer.byteLength(key) + 4; check(used <= maximum, "RESOURCE_LIMIT");
        Object.defineProperty(output, key, { value: visit(Object.getOwnPropertyDescriptor(value, key).value, depth + 1), enumerable: true });
      }
    }
    parents.delete(value);
    return output;
  }
  const output = visit(input, 0);
  check(Buffer.byteLength(JSON.stringify(output)) <= maximum, "RESOURCE_LIMIT");
  return output;
}
export const canonical = (value) => JSON.stringify(data(value)) + "\n";
export const same = (left, right) => canonical(left) === canonical(right);
export function exactKeys(value, keys) { record(value); check(same(Object.keys(value).sort(), [...keys].sort())); }
export function freeze(value) {
  if (value !== null && typeof value === "object") { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
export const identity = (value, domain) => ({ domain, sha256: hash(value), bytes: value.length });

// Bounded duplicate-key-rejecting JSON parser. Escaped spellings cannot replace
// an earlier pin, count, runtime field or source member through JSON.parse.
export function parseJson(input, maximum) {
  const owned = bytes(input, maximum);
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(owned); }
  catch { throw new InspectionReportError("INVALID_JSON"); }
  let position = 0, nodes = 0;
  const space = () => { while (/[\t\n\r ]/.test(text[position] ?? "x")) position += 1; };
  function string() {
    const start = position++;
    while (position < text.length) {
      const c = text[position++];
      if (c === "\\") position += 1;
      else if (c === '"') { try { return JSON.parse(text.slice(start, position)); } catch { break; } }
    }
    throw new InspectionReportError("INVALID_JSON");
  }
  function read(depth) {
    space(); check(++nodes <= MEDIA_DATA_LIMITS.maxNodes && depth <= MEDIA_DATA_LIMITS.maxDepth, "RESOURCE_LIMIT");
    if (text[position] === '"') return string();
    if (text[position] === "{" || text[position] === "[") {
      const object = text[position++] === "{", end = object ? "}" : "]", output = object ? Object.create(null) : [], keys = new Set();
      space(); if (text[position] === end) { position += 1; return output; }
      while (position < text.length) {
        let key;
        if (object) { space(); check(text[position] === '"', "INVALID_JSON"); key = string(); check(!keys.has(key), "DUPLICATE_KEY"); keys.add(key); space(); check(text[position++] === ":", "INVALID_JSON"); }
        const child = read(depth + 1);
        if (object) output[key] = child; else output.push(child);
        space(); if (text[position] === end) { position += 1; return output; }
        check(text[position++] === ",", "INVALID_JSON");
      }
      throw new InspectionReportError("INVALID_JSON");
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(position))?.[0];
    check(token !== undefined, "INVALID_JSON"); position += token.length;
    const output = JSON.parse(token); check(typeof output !== "number" || (Number.isFinite(output) && !Object.is(output, -0)), "INVALID_JSON"); return output;
  }
  const output = read(0); space(); check(position === text.length, "INVALID_JSON"); return output;
}
