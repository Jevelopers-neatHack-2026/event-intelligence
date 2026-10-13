import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { createHash } from "node:crypto";
import { isPublicAddress, parseAndValidateUrl, sameAddress, validateHostname } from "./url-policy.mjs";
import { resolveSystemHost } from "./dns-resolver.mjs";
import { RetrievalError } from "./errors.mjs";
import { getTestSeam } from "./internal/test-seams.mjs";
import { recordSafeFetchProvenance, safeFetchLifecycleFor } from "./internal/fetch-lifecycle.mjs";
import { monotonicNow } from "./internal/monotonic-clock.mjs";
import {
  conditionalFetchFor, conditionalRequestHeaders, conditionalValidatorFromResponse, recordConditionalResponse,
} from "./internal/conditional-fetch.mjs";

export { RetrievalError };

export const DEFAULT_RUN_LIMITS = Object.freeze({
  requests: 30,
  redirectsPerFetch: 5,
  concurrentFetches: 4,
  connectMilliseconds: 10_000,
  totalMilliseconds: 30_000,
  wireBytesPerRequest: 10 * 1024 * 1024,
  decodedTextBytesPerRequest: 20 * 1024 * 1024,
  decodedMediaBytesPerRequest: 10 * 1024 * 1024,
  decodedBytesPerRun: 100 * 1024 * 1024,
  imageMaximumDimension: 10_000,
  imageMaximumPixels: 20_000_000,
});

const ACCEPT = [
  "text/html", "application/xhtml+xml", "text/plain", "application/json",
  "application/ld+json", "application/pdf", "image/png", "image/jpeg", "image/webp", "image/gif",
].join(", ");
const SVG_ASSET_ACCEPT = "image/svg+xml";
const SVG_ASSET_MAX_BYTES = 128 * 1024;
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
const SUPPORTED_MIME = new Set([...ACCEPT.split(", "), SVG_ASSET_ACCEPT]);
const TEXTUAL_MIME = new Set([
  "text/html", "application/xhtml+xml", "text/plain", "application/json", "application/ld+json", SVG_ASSET_ACCEPT,
]);
const MIME_PARAMETER_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+/;
const ABORTED_GETTER = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
const ADD_EVENT_LISTENER = EventTarget.prototype.addEventListener;
const REMOVE_EVENT_LISTENER = EventTarget.prototype.removeEventListener;

function signalIsAborted(signal) {
  return Reflect.apply(ABORTED_GETTER, signal, []);
}

function addSignalListener(signal, listener) {
  Reflect.apply(ADD_EVENT_LISTENER, signal, ["abort", listener, { once: true }]);
}

function removeSignalListener(signal, listener) {
  try { Reflect.apply(REMOVE_EVENT_LISTENER, signal, ["abort", listener]); }
  catch { /* Caller-owned signal cleanup must never replace the retrieval result. */ }
}

function throwIfStopped(context) {
  if (context.deadlineReached) throw new RetrievalError("DEADLINE_EXCEEDED");
  if (signalIsAborted(context.signal)) throw new RetrievalError("CANCELED");
  if (monotonicNow() >= context.deadline) throw new RetrievalError("DEADLINE_EXCEEDED");
}

function validateFetchOptions(options) {
  try {
    if (options === null || typeof options !== "object" || Array.isArray(options)) {
      throw new RetrievalError("POLICY_DENIED");
    }
    const prototype = Object.getPrototypeOf(options);
    if (prototype !== Object.prototype && prototype !== null) throw new RetrievalError("POLICY_DENIED");
    const keys = Reflect.ownKeys(options);
    if (keys.some((key) => key !== "signal")) throw new RetrievalError("POLICY_DENIED");
    const descriptor = Object.getOwnPropertyDescriptor(options, "signal");
    if (descriptor && !("value" in descriptor)) throw new RetrievalError("POLICY_DENIED");
    const signal = descriptor?.value;
    if (signal !== undefined && (typeof ABORTED_GETTER !== "function"
      || typeof ADD_EVENT_LISTENER !== "function" || typeof REMOVE_EVENT_LISTENER !== "function"
      || typeof signalIsAborted(signal) !== "boolean")) {
      throw new RetrievalError("POLICY_DENIED");
    }
    return signal;
  } catch {
    throw new RetrievalError("POLICY_DENIED");
  }
}

function assertAllowedAddress(address, seam) {
  if (isPublicAddress(address)) return;
  if (seam?.isFixtureAddress?.(address) === true) return;
  throw new RetrievalError("POLICY_DENIED");
}

class FetchSemaphore {
  #active = 0;
  #queue = [];

  acquire(context) {
    throwIfStopped(context);
    if (this.#active < DEFAULT_RUN_LIMITS.concurrentFetches) {
      this.#active += 1;
      return Promise.resolve(() => this.#release());
    }
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, context, timer: undefined, abort: undefined };
      const remove = () => {
        const index = this.#queue.indexOf(entry);
        if (index >= 0) this.#queue.splice(index, 1);
        clearTimeout(entry.timer);
        removeSignalListener(context.signal, entry.abort);
      };
      entry.abort = () => {
        remove();
        reject(context.deadlineReached ? new RetrievalError("DEADLINE_EXCEEDED") : new RetrievalError("CANCELED"));
      };
      entry.timer = setTimeout(() => {
        remove();
        reject(new RetrievalError("DEADLINE_EXCEEDED"));
      }, Math.max(1, Math.ceil(context.deadline - monotonicNow())));
      addSignalListener(context.signal, entry.abort);
      this.#queue.push(entry);
      try {
        throwIfStopped(context);
      } catch (error) {
        remove();
        reject(error);
      }
    });
  }

  #release() {
    while (this.#queue.length > 0) {
      const entry = this.#queue.shift();
      clearTimeout(entry.timer);
      removeSignalListener(entry.context.signal, entry.abort);
      try {
        throwIfStopped(entry.context);
        entry.resolve(() => this.#release());
        return;
      } catch (error) {
        entry.reject(error);
      }
    }
    this.#active -= 1;
  }
}

class PinnedAgentBase {
  constructor({ address, port, hostname, secure, context, onDial, isAllowedPeer, ca }) {
    this.address = address;
    this.port = port;
    this.hostname = hostname;
    this.secure = secure;
    this.context = context;
    this.signal = context.signal;
    this.onDial = onDial;
    this.isAllowedPeer = isAllowedPeer;
    this.ca = ca;
  }

  createConnection(_options, callback) {
    let raw;
    try {
      const options = { host: this.address, port: this.port, family: net.isIP(this.address) };
      // Node's request/agent path can run after an async guard, or after the
      // clock expires while timer delivery is blocked. Check at native entry.
      throwIfStopped(this.context);
      raw = net.connect(options);
    } catch (error) {
      callback(error instanceof RetrievalError ? error : new RetrievalError("TRANSPORT_FAILURE"));
      return undefined;
    }
    let finished = false;
    let timer;
    const finish = (error, socket) => {
      if (finished) return;
      if (!error) {
        try { throwIfStopped(this.context); }
        catch (stopped) { error = stopped; }
      }
      finished = true;
      clearTimeout(timer);
      removeSignalListener(this.signal, onAbort);
      if (error) {
        raw.destroy();
        callback(error);
      } else {
        callback(null, socket);
      }
    };
    const onAbort = () => finish(new RetrievalError("CANCELED"));
    const checkPeer = (socket, record = false) => {
      throwIfStopped(this.context);
      const peer = socket.remoteAddress;
      if (!peer || !this.isAllowedPeer(peer)) throw new RetrievalError("POLICY_DENIED");
      if (record) this.onDial?.(Object.freeze({ peer, address: this.address, port: this.port }));
      throwIfStopped(this.context);
    };
    timer = setTimeout(() => finish(new RetrievalError("DEADLINE_EXCEEDED")),
      Math.min(DEFAULT_RUN_LIMITS.connectMilliseconds, Math.max(1, Math.ceil(this.context.deadline - monotonicNow()))));
    addSignalListener(this.signal, onAbort);
    if (signalIsAborted(this.signal)) return onAbort();
    raw.once("error", () => finish(new RetrievalError("TRANSPORT_FAILURE")));
    raw.once("connect", () => {
      try {
        checkPeer(raw, true);
        if (!this.secure) return finish(null, raw);
        const tlsOptions = {
          socket: raw,
          servername: net.isIP(this.hostname) === 0 ? this.hostname : undefined,
          rejectUnauthorized: true,
          ca: this.ca,
          ALPNProtocols: ["http/1.1"],
          minVersion: "TLSv1.2",
          checkServerIdentity: (_serverName, certificate) => tls.checkServerIdentity(this.hostname, certificate),
        };
        throwIfStopped(this.context);
        const tlsSocket = tls.connect(tlsOptions);
        tlsSocket.once("error", () => finish(new RetrievalError("TRANSPORT_FAILURE")));
        tlsSocket.once("secureConnect", () => {
          try {
            checkPeer(tlsSocket);
            if (!tlsSocket.authorized) throw new RetrievalError("TRANSPORT_FAILURE");
            finish(null, tlsSocket);
          } catch (error) {
            finish(error instanceof RetrievalError ? error : new RetrievalError("TRANSPORT_FAILURE"));
          }
        });
      } catch (error) {
        finish(error instanceof RetrievalError ? error : new RetrievalError("TRANSPORT_FAILURE"));
      }
    });
    return undefined;
  }
}

class PinnedHttpAgent extends http.Agent {
  constructor(options) {
    super({ keepAlive: false, maxSockets: 1 });
    this.connection = new PinnedAgentBase({ ...options, secure: false });
  }
  createConnection(options, callback) { return this.connection.createConnection(options, callback); }
}

class PinnedHttpsAgent extends https.Agent {
  constructor(options) {
    super({ keepAlive: false, maxSockets: 1 });
    this.connection = new PinnedAgentBase({ ...options, secure: true });
  }
  createConnection(options, callback) { return this.connection.createConnection(options, callback); }
}

function createContext(signal, totalMilliseconds = DEFAULT_RUN_LIMITS.totalMilliseconds, deadlineAtMonotonic) {
  const controller = new AbortController();
  const context = {
    signal: controller.signal,
    // A private original deadline can only shorten the ordinary fetch budget.
    deadline: Math.min(monotonicNow() + totalMilliseconds, deadlineAtMonotonic ?? Infinity),
    deadlineReached: false,
  };
  const onAbort = () => controller.abort();
  if (signal && signalIsAborted(signal)) onAbort();
  else if (signal) addSignalListener(signal, onAbort);
  const timer = setTimeout(() => {
    context.deadlineReached = true;
    controller.abort();
  }, Math.max(1, Math.ceil(context.deadline - monotonicNow())));
  return {
    context,
    close() {
      clearTimeout(timer);
      if (signal) removeSignalListener(signal, onAbort);
      controller.abort();
    },
  };
}

function makeHostHeader(hostname, port, protocol) {
  const host = net.isIP(hostname) === 6 ? `[${hostname}]` : hostname;
  const defaultPort = protocol === "https:" ? 443 : 80;
  return port === defaultPort ? host : `${host}:${port}`;
}

function requestOnce(validated, address, context, seam, accept = ACCEPT, conditional = null) {
  throwIfStopped(context);
  const { url, hostname, port } = validated;
  const secure = url.protocol === "https:";
  const agent = secure
    ? new PinnedHttpsAgent({
      address, port, hostname, context, onDial: seam?.onDial,
      isAllowedPeer: (peer) => sameAddress(peer, address),
      ca: seam?.testTlsCa,
    })
    : new PinnedHttpAgent({
      address, port, hostname, context, onDial: seam?.onDial,
      isAllowedPeer: (peer) => sameAddress(peer, address),
    });
  const requester = secure ? https.request : http.request;
  const options = {
    protocol: url.protocol,
    hostname: address,
    family: net.isIP(address),
    port,
    method: "GET",
    path: `${url.pathname}${url.search}`,
    agent,
    headers: {
      host: makeHostHeader(hostname, port, url.protocol),
      accept,
      "accept-encoding": "gzip",
      "user-agent": "event-intelligence-controlled-retrieval/0.1",
      connection: "close",
      ...(conditional ? conditionalRequestHeaders(conditional) : {}),
    },
    setHost: false,
    maxHeaderSize: 16 * 1024,
  };
  return new Promise((resolve, reject) => {
    let request;
    const onAbort = () => request.destroy(new RetrievalError(context.deadlineReached ? "DEADLINE_EXCEEDED" : "CANCELED"));
    const cleanup = () => removeSignalListener(context.signal, onAbort);
    const fail = (error) => {
      cleanup();
      agent.destroy();
      if (error instanceof RetrievalError) reject(error);
      else reject(new RetrievalError("TRANSPORT_FAILURE"));
    };
    try {
      throwIfStopped(context);
      request = requester(options, (response) => resolve({ response, agent, request, cleanup }));
      request.once("error", fail);
      addSignalListener(context.signal, onAbort);
      throwIfStopped(context);
      request.end();
    } catch (error) {
      request?.destroy();
      fail(error);
    }
  });
}

function parseMime(contentType, mode = "document") {
  if (typeof contentType !== "string" || contentType.length > 256) throw new RetrievalError("UNSUPPORTED_MEDIA");
  const separator = contentType.indexOf(";");
  let offset = separator === -1 ? contentType.length : separator;
  const mime = contentType.slice(0, offset).replace(/^[ \t]+|[ \t]+$/g, "").toLowerCase();
  if (!SUPPORTED_MIME.has(mime) || (mode === "svg-asset" ? mime !== SVG_ASSET_ACCEPT : mime === SVG_ASSET_ACCEPT)) {
    throw new RetrievalError("UNSUPPORTED_MEDIA");
  }
  // The public document retains the historical base MIME string. Validate
  // interpretation-changing parameters before discarding them: downstream
  // text readers support UTF-8 only and cannot recover an erased declaration.
  let charsetSeen = false;
  const skipWhitespace = () => {
    while (contentType[offset] === " " || contentType[offset] === "\t") offset += 1;
  };
  const readToken = () => {
    const token = MIME_PARAMETER_TOKEN.exec(contentType.slice(offset))?.[0];
    if (!token) throw new RetrievalError("UNSUPPORTED_MEDIA");
    offset += token.length;
    return token;
  };
  while (offset < contentType.length) {
    skipWhitespace();
    if (offset === contentType.length) break;
    if (contentType[offset++] !== ";") throw new RetrievalError("UNSUPPORTED_MEDIA");
    skipWhitespace();
    // RFC 9110 parameters allow empty semicolon-delimited segments.
    if (offset === contentType.length || contentType[offset] === ";") continue;
    const name = readToken().toLowerCase();
    if (contentType[offset++] !== "=") throw new RetrievalError("UNSUPPORTED_MEDIA");
    let value;
    if (contentType[offset] === '"') {
      offset += 1;
      value = "";
      let closed = false;
      while (offset < contentType.length) {
        let code = contentType.charCodeAt(offset++);
        if (code === 0x22) { closed = true; break; }
        if (code === 0x5c) {
          if (offset === contentType.length) throw new RetrievalError("UNSUPPORTED_MEDIA");
          code = contentType.charCodeAt(offset++);
        }
        if (code !== 0x09 && (code < 0x20 || code === 0x7f || code > 0xff)) {
          throw new RetrievalError("UNSUPPORTED_MEDIA");
        }
        value += String.fromCharCode(code);
      }
      if (!closed) throw new RetrievalError("UNSUPPORTED_MEDIA");
    } else {
      value = readToken();
    }
    if (TEXTUAL_MIME.has(mime)) {
      // Extended/continued charset parameters are not part of this module's
      // supported encoding contract; never choose one parser's interpretation.
      if (name.startsWith("charset*")) throw new RetrievalError("UNSUPPORTED_MEDIA");
      if (name === "charset") {
        if (charsetSeen || !["utf-8", "utf8"].includes(value.toLowerCase())) {
          throw new RetrievalError("UNSUPPORTED_MEDIA");
        }
        charsetSeen = true;
      }
    }
  }
  return mime;
}

function bodyLimit(mime) {
  return mime.startsWith("image/") || mime === "application/pdf"
    ? DEFAULT_RUN_LIMITS.decodedMediaBytesPerRequest
    : DEFAULT_RUN_LIMITS.decodedTextBytesPerRequest;
}

function readContentLength(value, maximum) {
  if (value === undefined) return;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) throw new RetrievalError("RESOURCE_LIMIT");
  const length = Number(value);
  if (!Number.isSafeInteger(length) || length > maximum) throw new RetrievalError("RESOURCE_LIMIT");
}

async function consumeBody(response, mime, context, fetcherState, lifecycle, onDecodeStart, mode = "document") {
  throwIfStopped(context);
  const encoding = String(response.headers["content-encoding"] ?? "identity").toLowerCase().trim();
  if (encoding !== "identity" && encoding !== "gzip") throw new RetrievalError("UNSUPPORTED_MEDIA");
  const configuredMediaLimit = lifecycle?.options.decodedMediaBytesPerResponse ?? DEFAULT_RUN_LIMITS.decodedMediaBytesPerRequest;
  const maximum = mode === "svg-asset" ? Math.min(SVG_ASSET_MAX_BYTES, configuredMediaLimit) : mime.startsWith("image/") || mime === "application/pdf"
    ? lifecycle?.options.decodedMediaBytesPerResponse ?? DEFAULT_RUN_LIMITS.decodedMediaBytesPerRequest
    : lifecycle?.options.decodedTextBytesPerResponse ?? DEFAULT_RUN_LIMITS.decodedTextBytesPerRequest;
  const wireMaximum = DEFAULT_RUN_LIMITS.wireBytesPerRequest;
  readContentLength(response.headers["content-length"], wireMaximum);
  let encoded = 0;
  let decoded = 0;
  let completion;
  let wireGuard;
  let gunzip;
  let producedDecoded = 0;
  const chunkSize = lifecycle?.options.gzipChunkSize ?? 16 * 1024;
  const readableHighWaterMark = lifecycle?.options.gzipReadableHighWaterMark ?? 64 * 1024;
  const writableHighWaterMark = lifecycle?.options.gzipWritableHighWaterMark ?? 16 * 1024;
  wireGuard = new Transform({
    transform(chunk, _encoding, callback) {
      encoded += chunk.length;
      if (encoded > wireMaximum) callback(new RetrievalError("RESOURCE_LIMIT"));
      else callback(null, chunk);
    },
    readableHighWaterMark: writableHighWaterMark,
    writableHighWaterMark,
  });
  const outputGuard = new Transform({
    transform(chunk, _encoding, callback) {
      producedDecoded += chunk.length;
      if (producedDecoded > maximum) callback(new RetrievalError("RESOURCE_LIMIT"));
      else callback(null, chunk);
    },
    readableHighWaterMark,
    writableHighWaterMark,
  });
  if (encoding === "gzip") {
    gunzip = createGunzip({
      chunkSize,
      readableHighWaterMark,
      writableHighWaterMark,
    });
  }
  const chunks = [];
  try {
    await onDecodeStart();
    throwIfStopped(context);
    completion = (gunzip
      ? pipeline(response, wireGuard, gunzip, outputGuard)
      : pipeline(response, wireGuard, outputGuard)).catch((error) => {
      // The iterator below observes stream errors. Keep the completion promise
      // handled as well so a concurrent pipeline rejection cannot go unobserved.
      if (!outputGuard.destroyed) outputGuard.destroy(error);
    });
    for await (const chunk of outputGuard) {
      throwIfStopped(context);
      decoded += chunk.length;
      if (decoded > maximum || fetcherState.decodedBytes + chunk.length > DEFAULT_RUN_LIMITS.decodedBytesPerRun) {
        throw new RetrievalError("RESOURCE_LIMIT");
      }
      fetcherState.decodedBytes += chunk.length;
      chunks.push(Buffer.from(chunk));
    }
    if (completion) await completion;
    return Buffer.concat(chunks, decoded);
  } catch (error) {
    response.destroy(error instanceof Error ? error : undefined);
    outputGuard.destroy(error instanceof Error ? error : undefined);
    wireGuard.destroy(error instanceof Error ? error : undefined);
    gunzip?.destroy(error instanceof Error ? error : undefined);
    if (completion) await completion;
    if (context.deadlineReached) throw new RetrievalError("DEADLINE_EXCEEDED");
    if (signalIsAborted(context.signal) && !(error instanceof RetrievalError)) throw new RetrievalError("CANCELED");
    throw error instanceof RetrievalError ? error : new RetrievalError("TRANSPORT_FAILURE");
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

function detectMime(body) {
  if (body.length >= 24 && body.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
    && body.subarray(12, 16).toString("ascii") === "IHDR") return "image/png";
  if (body.length >= 6 && ["GIF87a", "GIF89a"].includes(body.subarray(0, 6).toString("ascii"))) return "image/gif";
  if (body.length >= 3 && body[0] === 0xff && body[1] === 0xd8 && body[2] === 0xff) return "image/jpeg";
  if (body.length >= 12 && body.subarray(0, 4).toString("ascii") === "RIFF" && body.subarray(8, 12).toString("ascii") === "WEBP") return "image/webp";
  if (body.subarray(0, 5).toString("ascii") === "%PDF-") return "application/pdf";
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(body).replace(/^\uFEFF/, "").trimStart(); }
  catch { throw new RetrievalError("UNSUPPORTED_MEDIA"); }
  if (/^(?:<!doctype\s+html\b|<html\b|<head\b|<body\b)/i.test(text) || /^<\?xml[\s\S]{0,256}<html\b/i.test(text)) return "text/html";
  if (text.startsWith("{") || text.startsWith("[")) {
    try { JSON.parse(text); return "application/json"; }
    catch { throw new RetrievalError("UNSUPPORTED_MEDIA"); }
  }
  if (text.includes("\u0000")) throw new RetrievalError("UNSUPPORTED_MEDIA");
  return "text/plain";
}

function imageSize(body, mime) {
  let width;
  let height;
  if (mime === "image/png" && body.length >= 24) {
    width = body.readUInt32BE(16);
    height = body.readUInt32BE(20);
  } else if (mime === "image/gif" && body.length >= 10) {
    width = body.readUInt16LE(6);
    height = body.readUInt16LE(8);
  } else if (mime === "image/jpeg") {
    let offset = 2;
    while (offset + 4 <= body.length) {
      if (body[offset] !== 0xff) throw new RetrievalError("UNSUPPORTED_MEDIA");
      while (body[offset] === 0xff) offset += 1;
      const marker = body[offset++];
      if ([0xd8, 0xd9, 0x01, ...Array.from({ length: 8 }, (_, index) => 0xd0 + index)].includes(marker)) continue;
      if (offset + 2 > body.length) break;
      const segmentLength = body.readUInt16BE(offset);
      if (segmentLength < 2 || offset + segmentLength > body.length) break;
      if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
        if (segmentLength < 7) throw new RetrievalError("UNSUPPORTED_MEDIA");
        height = body.readUInt16BE(offset + 3);
        width = body.readUInt16BE(offset + 5);
        break;
      }
      offset += segmentLength;
    }
  } else if (mime === "image/webp" && body.length >= 25) {
    const chunk = body.subarray(12, 16).toString("ascii");
    if (chunk === "VP8X" && body.length >= 30) {
      width = 1 + body.readUIntLE(24, 3);
      height = 1 + body.readUIntLE(27, 3);
    } else if (chunk === "VP8 " && body.length >= 30) {
      if (body[23] === 0x9d && body[24] === 0x01 && body[25] === 0x2a) {
        width = body.readUInt16LE(26) & 0x3fff;
        height = body.readUInt16LE(28) & 0x3fff;
      }
    } else if (chunk === "VP8L" && body.length >= 25 && body[20] === 0x2f) {
      const b1 = body[21]; const b2 = body[22]; const b3 = body[23]; const b4 = body[24];
      width = 1 + (((b2 & 0x3f) << 8) | b1);
      height = 1 + (((b4 & 0x0f) << 10) | (b3 << 2) | ((b2 & 0xc0) >> 6));
    }
  }
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1) throw new RetrievalError("UNSUPPORTED_MEDIA");
  if (width > DEFAULT_RUN_LIMITS.imageMaximumDimension || height > DEFAULT_RUN_LIMITS.imageMaximumDimension
    || width * height > DEFAULT_RUN_LIMITS.imageMaximumPixels) throw new RetrievalError("RESOURCE_LIMIT");
  return Object.freeze({ width, height });
}

function validateFinalBody(body, declaredMime, mode = "document") {
  if (mode === "svg-asset") {
    if (declaredMime !== SVG_ASSET_ACCEPT || body.byteLength > SVG_ASSET_MAX_BYTES) {
      throw new RetrievalError(body.byteLength > SVG_ASSET_MAX_BYTES ? "RESOURCE_LIMIT" : "UNSUPPORTED_MEDIA");
    }
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(body); }
    catch { throw new RetrievalError("UNSUPPORTED_MEDIA"); }
    // The source asset inspector validates the complete XML document. This
    // transport check only establishes a bounded SVG root signature while
    // tolerating the XML declaration and prolog comments it can parse. Decode
    // the whole bounded body so a multibyte code point crossing the old prefix
    // boundary is not mistaken for malformed UTF-8.
    let signature = text.replace(/^\uFEFF/, "");
    while (true) {
      signature = signature.replace(/^[\x20\t\r\n]+/, "");
      if (signature.startsWith("<?xml")) {
        const declaration = /^<\?xml\b[^?]*\?>/i.exec(signature);
        if (!declaration) throw new RetrievalError("UNSUPPORTED_MEDIA");
        signature = signature.slice(declaration[0].length);
        continue;
      }
      if (signature.startsWith("<!--")) {
        const end = signature.indexOf("-->", 4);
        if (end < 0 || signature.slice(4, end).includes("--")) throw new RetrievalError("UNSUPPORTED_MEDIA");
        signature = signature.slice(end + 3);
        continue;
      }
      break;
    }
    if (!/^<svg(?:[\x20\t\r\n]|>)/i.test(signature)) {
      throw new RetrievalError("UNSUPPORTED_MEDIA");
    }
    return undefined;
  }
  const detected = detectMime(body);
  const accepted = declaredMime === "application/xhtml+xml"
    ? detected === "text/html"
    : declaredMime === "application/ld+json"
      ? detected === "application/json"
      : detected === declaredMime;
  if (!accepted) throw new RetrievalError("UNSUPPORTED_MEDIA");
  const dimensions = declaredMime.startsWith("image/") ? imageSize(body, declaredMime) : undefined;
  return dimensions;
}

export class SafeFetcher {
  #seam;
  #state = { requestCount: 0, decodedBytes: 0 };
  #semaphore = new FetchSemaphore();

  constructor(testOptions) {
    this.#seam = getTestSeam(testOptions);
  }

  async fetch(input, options = {}) {
    return this.#fetch(input, options, "document");
  }

  /** Fetch one bounded SVG response for host-controlled asset inspection. */
  async fetchSvgAsset(input, options = {}) {
    return this.#fetch(input, options, "svg-asset");
  }

  async #fetch(input, options, mode) {
    let externalSignal;
    let context;
    let closeContext = () => {};
    let release;
    try {
      externalSignal = validateFetchOptions(options);
      const lifecycle = safeFetchLifecycleFor(this);
      const conditional = mode === "document" ? conditionalFetchFor(this) : null;
      const createdContext = createContext(externalSignal,
        lifecycle?.options.totalMilliseconds ?? DEFAULT_RUN_LIMITS.totalMilliseconds,
        lifecycle?.options.deadlineAtMonotonic);
      context = createdContext.context;
      closeContext = createdContext.close;
      release = await this.#semaphore.acquire(context);
      let current = input;
      let firstHopUrl;
      let redirects = 0;
      const redirectChain = [];
      const hops = [];
      while (true) {
        throwIfStopped(context);
        if (this.#state.requestCount >= DEFAULT_RUN_LIMITS.requests) throw new RetrievalError("REQUEST_LIMIT");
        // Keep historical per-instance accounting: even a URL rejected during parsing consumes a slot.
        this.#state.requestCount += 1;
        const validated = this.#seam?.validateUrl
          ? this.#seam.validateUrl(current)
          : parseAndValidateUrl(current);
        if (conditional && validated.url.href !== conditional.sourceUrl) throw new RetrievalError("POLICY_DENIED");
        if (firstHopUrl === undefined) firstHopUrl = validated.url.href;
        const hopIndex = hops.length;
        let hopAdmissionReturned = false;
        try {
          await lifecycle?.hooks.beforeHop?.(Object.freeze({ url: validated.url.href, hopIndex, redirects }));
          hopAdmissionReturned = true;
          throwIfStopped(context);
        } catch (error) {
          if (hopAdmissionReturned) await lifecycle?.hooks.onKnownZero?.(Object.freeze({ hopIndex, reason: "before_dispatch_stopped" }));
          throw error;
        }
        const hop = { url: validated.url.href, statusCode: null, dispatchIntent: false,
          responseReceived: false, bodyComplete: false, decodedBytes: null };
        hops.push(hop);
        let resolved;
        try {
          const host = validateHostnameForResolver(validated.hostname, this.#seam);
          resolved = this.#seam?.resolve
            ? await this.#seam.resolve(host, { signal: context.signal, deadline: context.deadline })
            : await resolveSystemHost(host, { signal: context.signal, deadline: context.deadline });
          throwIfStopped(context);
          if (!resolved || !Array.isArray(resolved.addresses) || resolved.addresses.length === 0) throw new RetrievalError("DNS_FAILURE");
          for (const alias of resolved.aliases ?? []) {
            if (isIPHost(alias)) throw new RetrievalError("DNS_FAILURE");
            validateHostnameForResolver(alias, this.#seam);
          }
          for (const address of resolved.addresses) assertAllowedAddress(address, this.#seam);
        } catch (error) {
          await lifecycle?.hooks.onKnownZero?.(Object.freeze({ hopIndex, reason: "pre_dispatch_failure" }));
          throw error;
        }
        const chosenAddress = resolved.addresses[0];
        let result;
        try {
          await lifecycle?.hooks.onDispatchIntent?.(Object.freeze({ url: validated.url.href, hopIndex }));
          throwIfStopped(context);
        } catch (error) {
          await lifecycle?.hooks.onKnownZero?.(Object.freeze({ hopIndex, reason: "dispatch_not_started" }));
          throw error;
        }
        hop.dispatchIntent = true;
        try {
          result = await requestOnce(validated, chosenAddress, context, this.#seam,
            mode === "svg-asset" ? SVG_ASSET_ACCEPT : ACCEPT, conditional);
        } catch (error) {
          await lifecycle?.hooks.onKnownZero?.(Object.freeze({ hopIndex, reason: "no_response" }));
          if (context.deadlineReached) throw new RetrievalError("DEADLINE_EXCEEDED");
          throw error;
        }
        const { response, agent, request, cleanup } = result;
        const finishTransport = () => {
          cleanup();
          agent.destroy();
        };
        let body;
        let returnedBody = false;
        hop.statusCode = response.statusCode;
        hop.responseReceived = true;
        try {
          await lifecycle?.hooks.onResponseHeaders?.(Object.freeze({
            url: validated.url.href, hopIndex, statusCode: response.statusCode,
          }));
          throwIfStopped(context);
        } catch (error) {
          response.destroy();
          finishTransport();
          throw error;
        }
        if (REDIRECT_CODES.has(response.statusCode)) {
          response.destroy();
          finishTransport();
          await lifecycle?.hooks.onKnownZero?.(Object.freeze({ hopIndex, reason: "redirect" }));
          throwIfStopped(context);
          // Asset acquisition has one request and cannot follow a redirect. In
          // particular, no destination DNS lookup or socket may be started.
          if (mode === "svg-asset" || conditional) throw new RetrievalError("REDIRECT_LIMIT");
          const location = response.headers.location;
          if (redirects >= DEFAULT_RUN_LIMITS.redirectsPerFetch) throw new RetrievalError("REDIRECT_LIMIT");
          if (typeof location !== "string" || location.length > 8_192) throw new RetrievalError("POLICY_DENIED");
          let next;
          try { next = new URL(location, validated.url).toString(); }
          catch { throw new RetrievalError("POLICY_DENIED"); }
          // Validate each redirect before consuming a request slot or starting DNS/socket work.
          const validatedNext = this.#seam?.validateUrl
            ? this.#seam.validateUrl(next)
            : parseAndValidateUrl(next);
          redirectChain.push(validatedNext.url.href);
          redirects += 1;
          current = next;
          continue;
        }
        try {
          if (conditional && (response.statusCode === 304 || response.statusCode === 404
            || response.statusCode === 410 || (response.statusCode >= 500 && response.statusCode <= 599))) {
            const validator = conditionalValidatorFromResponse(response);
            // A supported 304 must affirm the exact one validator actually sent.
            // Missing, duplicate or changed validators are not freshness proof.
            if (response.statusCode === 304 && (!validator
              || validator.name !== conditional.validator.name || validator.value !== conditional.validator.value)) {
              throw new RetrievalError("TRANSPORT_FAILURE");
            }
            response.destroy();
            await lifecycle?.hooks.onKnownZero?.(Object.freeze({ hopIndex, reason: "conditional_no_body" }));
            throwIfStopped(context);
            const observedAt = new Date().toISOString();
            const kind = response.statusCode === 304 ? "not_modified"
              : response.statusCode === 404 || response.statusCode === 410 ? "removed" : "outage";
            const observed = Object.freeze({ kind, statusCode: response.statusCode, observedAt });
            recordConditionalResponse(observed, {
              intent: conditional.intent,
              sourceUrl: validated.url.href, statusCode: response.statusCode, kind, observedAt,
              sentValidator: conditional.validator, receivedValidator: validator,
            });
            return observed;
          }
          if (response.statusCode !== 200) {
            await lifecycle?.hooks.onKnownZero?.(Object.freeze({ hopIndex, reason: "status_rejected" }));
            throwIfStopped(context);
            throw new RetrievalError("TRANSPORT_FAILURE");
          }
          let mime;
          try {
            // IncomingMessage.headers silently discards duplicate Content-Type
            // fields. Inspect the distinct values before normalizing the type.
            const contentTypes = response.headersDistinct["content-type"];
            if (!Array.isArray(contentTypes) || contentTypes.length !== 1) throw new RetrievalError("UNSUPPORTED_MEDIA");
            mime = parseMime(contentTypes[0], mode);
          }
          catch (error) {
            await lifecycle?.hooks.onKnownZero?.(Object.freeze({ hopIndex, reason: "content_type_rejected" }));
            throwIfStopped(context);
            throw error;
          }
          let decodeStarted = false;
          try {
            body = await consumeBody(response, mime, context, this.#state, lifecycle, async () => {
              decodeStarted = true;
              await lifecycle?.hooks.onDecodeStart?.(Object.freeze({ hopIndex, mime }));
            }, mode);
          } catch (error) {
            if (!decodeStarted) await lifecycle?.hooks.onKnownZero?.(Object.freeze({ hopIndex, reason: "body_decode_not_started" }));
            throw error;
          }
          hop.bodyComplete = true;
          hop.decodedBytes = body.byteLength;
          await lifecycle?.hooks.onBodyComplete?.(Object.freeze({ hopIndex, decodedBytes: body.byteLength }));
          throwIfStopped(context);
          const dimensions = validateFinalBody(body, mime, mode);
          const fetched = Object.freeze({
            url: validated.url.toString(),
            contentType: mime,
            bytes: body,
            fetchedAt: new Date().toISOString(),
            redirects,
            ...(dimensions ? { image: dimensions } : {}),
          });
          recordSafeFetchProvenance(fetched, {
            requestedUrl: firstHopUrl,
            finalUrl: validated.url.href,
            redirectChain,
            hops,
            mode,
            lifecycleBound: lifecycle !== null,
            bodyHash: createHash("sha256").update(body).digest("hex"),
            conditionalValidator: conditionalValidatorFromResponse(response),
          });
          if (conditional) recordConditionalResponse(fetched, {
            intent: conditional.intent,
            sourceUrl: validated.url.href, statusCode: 200, kind: "body", observedAt: fetched.fetchedAt,
            retrievedAt: fetched.fetchedAt, bodyHash: createHash("sha256").update(body).digest("hex"),
            sentValidator: conditional.validator, receivedValidator: conditionalValidatorFromResponse(response),
          });
          returnedBody = true;
          return fetched;
        } finally {
          if (!returnedBody && body) body.fill(0);
          finishTransport();
        }
      }
    } catch (error) {
      if (context?.deadlineReached) throw new RetrievalError("DEADLINE_EXCEEDED");
      if (externalSignal && signalIsAborted(externalSignal)) throw new RetrievalError("CANCELED");
      if (error instanceof RetrievalError) throw error;
      throw new RetrievalError("TRANSPORT_FAILURE");
    } finally {
      closeContext();
      release?.();
    }
  }
}

function isIPHost(hostname) { return net.isIP(String(hostname).replace(/^\[|\]$/g, "")) !== 0; }

function validateHostnameForResolver(hostname, seam) {
  if (seam?.validateHostname) return seam.validateHostname(hostname);
  return validateHostname(hostname);
}
