# Bounded static PNG pixel reader

Refs [EI #8](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/8),
[EI #12](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/12),
and [gate #22](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/22).

This private component decodes actual PNG scanlines into pixels and creates a
deterministic normalized PNG derivative. It returns hashes and dimensions with
`completeness: "incomplete-pixels-only"` and `requiresInspection: true`. It does
not identify text, interpret a screenshot, select facts, grant image rights, or
complete screenshot/scanned-PDF acceptance.

The existing retriever's image-header checks do not decode raster pixels. This
reader adds that separate byte-processing step without changing retrieval,
private research assembly, SVG assets, the PDF reader, root package exports,
or a foreign research contract. It accepts bytes only; it has no URL, provider,
model, credential, or transport option.

## Supported profile

The `ei-static-png/1` profile accepts:

- The exact PNG signature and one 13-byte `IHDR`.
- 8-bit truecolor RGB (color type 2) or RGBA (color type 6).
- Compression method 0, filter method 0, and noninterlaced rows.
- All five PNG row filters: None, Sub, Up, Average and Paeth.
- One or more contiguous `IDAT` chunks containing one complete zlib stream.
  Empty `IDAT` chunks are permitted within the bounded chunk count; the complete
  compressed stream must be nonempty.
- One empty final `IEND`, with no trailing file bytes.

Every chunk length, name, reserved bit and CRC is checked. The reader validates
dimensions before inflation, caps inflated output to the **exact expected
scanline length**, requires that complete length and complete compressed-input
consumption, and rejects invalid row filters. Trailing junk, a second zlib
stream, missing rows, excess rows and dictionary-dependent streams are rejected.

**All other chunks and encoding features are unsupported.** This includes
`PLTE`, `tRNS`, color profiles/gamma chunks, textual metadata, EXIF, APNG chunks,
indexed/grayscale images, 16-bit samples and Adam7 interlacing. These inputs are
rejected explicitly, rather than silently removing color/transparency/animation
semantics. Many ordinary PNG files therefore remain outside this first profile.
JPEG, WebP, GIF, SVG and PDF are not PNG inputs.

The output contains only a signature, an RGBA8 noninterlaced `IHDR`, one `IDAT`,
and `IEND`. It uses filter 0 on each output row. RGB gains alpha 255; RGBA samples,
including transparent pixels' RGB values, are preserved without premultiplication.
There is no color-management or visual-equivalence claim beyond these numeric
samples. Compression uses fixed parameters in the pinned runtime; it has no
timestamp or variable metadata.

The format rules follow the W3C [PNG Third Edition, 24 June 2025](https://www.w3.org/TR/2025/REC-png-3-20250624/)
(chunk structure/order, CRC, filtering and compression). The worker uses the
already pinned [Node 22.23.3 zlib](https://nodejs.org/download/release/v22.23.3/docs/api/zlib.html)
implementation, including `maxOutputLength`, `info: true` and CRC32. No new
package or native addon is installed.

## Private caller

```js
import { readStaticPng } from "../../src/extraction/png/index.mjs";

const result = await readStaticPng(alreadyAcquiredPrivateBytes, {
  signal: controller.signal,
  timeoutMs: 2000,
  maxOutputBytes: 2 * 1024 * 1024,
});
if (result.kind === "decoded") {
  const privateDerivative = result.copyNormalizedBytes();
  // Keep sourceSha256, normalizedSha256, rgbaSha256, dimensions and decoder
  // profile with this private derivative. Human/model inspection and current
  // disclosure/asset permissions remain separate owner-controlled steps.
} else {
  // A stable private code, optional source hash and decoder profile only.
  // No partial derivative, source text, URL, abort reason or raw exception.
}
```

Only ordinary `Uint8Array` or `Buffer` instances are accepted. A snapshot is
made before asynchronous dispatch using intrinsic typed-array operations.
Proxies, subclasses, shared backing buffers, detached/empty views, strings and
arbitrary input adapters are rejected. Caller byte-array accessors/iterators
are not invoked. Options must be plain own data properties with known names;
accessors, proxies and forged cancellation signals are rejected. The reader
uses native `AbortSignal`/`EventTarget` operations instead of caller shadows.

Each `copyNormalizedBytes()` call returns a new mutable copy. The retained bytes
and frozen metadata cannot be changed through that copy. `sourceSha256` hashes
the exact input snapshot; `normalizedSha256` hashes the normalized PNG;
`rgbaSha256` hashes concatenated RGBA sample rows without filter bytes. The pixel
hash alone does not encode dimensions, source attribution, visual meaning or
permission. These values are private observations, not accepted canonical
research fields.

## Resource and execution boundary

| Resource | Fixed ceiling |
| --- | --- |
| Source bytes | 10 MiB |
| Width / rows | 4096 / 4096 |
| Total pixels | 4,194,304 |
| Inflated scanline bytes, including row filter bytes | 16,781,312 |
| Normalized output bytes | 20 MiB |
| Total PNG chunks, including IHDR and IEND | 1024 |
| Worker protocol JSON header | 4096 bytes, plus a 4-byte length prefix |
| Active children / queued jobs | 1 / 4 per loaded reader instance |
| Wall deadline | Default 5 seconds; caller may select 1–10,000 ms |
| Child address space | 6 GiB virtual address space |
| Child CPU | 5 seconds, soft and hard OS limit |
| Child V8 old-space setting | 256 MiB |
| Open file descriptors / core dumps | 64 / 0 |

`timeoutMs` and `maxOutputBytes` are lower-only relative to their fixed maximums;
other resource settings are not caller configurable. A wall deadline starts
before option validation and input copying. Queue waiting, dispatch, child work
and parent frame/hash validation share that original deadline. A delayed timer
callback does not grant a fresh allowance at dispatch or publication.

The runtime supports Linux with a root-owned, executable, non-group/world-writable
`/usr/bin/prlimit` at that exact real path. It requires Node **22.23.3** with zlib
**1.3.1-e00f703**; other runtime combinations fail closed as unreviewed. The parent
starts a detached child with fixed rlimits, the Node permission model, read access
to the fixed worker directory, and no filesystem-write, child-process, worker
thread or addon grants. `NODE_OPTIONS`, proxies, credentials and other ambient
variables are not inherited; the environment contains only `PATH`, `LANG` and
`LC_ALL`. Stdin carries only source bytes; stdout carries one bounded frame;
stderr is discarded instead of returning untrusted diagnostics.

Cancellation or a running deadline kills the owned process group. The slot is
released and the promise settles only after the child's actual `close` event.
Cancelled/expired queued jobs never dispatch. The first recorded termination
reason is retained across later timer or stream events. A subsequent independent
job can use the released slot. There is no claim that an OS can reap an
uninterruptible process within a hard real-time latency; the reader will not
return overdue pixels or claim an unreaped child has closed.

The worker guards the fixed JavaScript HTTP/HTTP2, socket, datagram, DNS, fetch
and WebSocket APIs before importing the codec. `networkApiAttemptCount` describes
only those guarded entrypoints. Invalid-argument tests verify rejection before
any native request; permission tests exercise actual denied filesystem, child,
worker and addon operations. **These are not a network namespace, host firewall,
seccomp policy, hostile-code sandbox, or native-egress attestation.** The 6 GiB
address-space limit accommodates the tested Node process and is not a measured
physical-memory/RSS cap. Production host containment and admission/budget
authority remain separate requirements.

The parent validates the complete worker frame: exact keys/profile/runtime,
source binding, dimensions, exact chunk-name bytes, output shape and CRC, derivative hash, byte count,
and guarded-API count. It also requires the minimum nonempty zlib envelope,
the fixed encoder's header, and a nonreserved first deflate block type. An
empty IDAT, an eight-byte empty zlib stream, or a shorter envelope is a protocol
rejection even with matching PNG CRCs and derivative hash.
The parent does not inflate untrusted data a second time; complete compressed
stream and pixel-row validation remain the worker's responsibility. These
framing checks do not prove arbitrary faulty-worker pixel semantics.
Rejected/late/malformed frames do not expose pixel bytes.

## Private error codes

| Code | Local meaning |
| --- | --- |
| `INVALID_INPUT`, `INVALID_OPTIONS`, `INVALID_LIMIT` | Invalid byte/signal/options/limit shape |
| `INPUT_TOO_LARGE` | Source bytes exceed the fixed cap |
| `MALFORMED_PNG` | Structure, checksum, stream or row data is invalid/incomplete |
| `UNSUPPORTED_PNG_FEATURE` | Validly framed chunk/encoding outside the strict profile |
| `DIMENSION_LIMIT`, `RESOURCE_LIMIT`, `OUTPUT_LIMIT` | Dimension/pixel, chunk/inflation, or derivative/frame ceiling |
| `QUEUE_FULL`, `CANCELLED`, `TIMEOUT` | Local admission, cancellation or original wall deadline |
| `ISOLATION_UNAVAILABLE`, `DECODER_UNAVAILABLE` | Missing platform/tool profile or unreviewed Node/zlib |
| `DECODER_FAILURE`, `PROTOCOL_ERROR`, `REMOTE_RESOURCE_ATTEMPT` | Child/stream failure, invalid reply, or a guarded network attempt |

These are internal codes. They do not elect EI #8's consumer-visible error
mapping or extend a `shared-contracts` enum. A signal-based child exit without
a recorded timeout/cancellation is a decoder failure; the component does not
invent an OOM/provider diagnosis from an ambiguous exit.

## Verification and remaining scope

On the pinned Linux runtime:

```sh
node tools/verify-static-png.mjs
./node_modules/.bin/tsc --noEmit --strict --target ES2022 \
  --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM \
  --types node tests/extraction/png/types-consumer.mts
npm run typecheck
```

Use the repository's existing `npm ci` and locked compiler installation helper
for a fresh checkout. The new `static-png.yml` workflow runs these commands on
push and PR candidates. The dedicated PNG runner requires all **93** collected
tests to pass with zero failures, cancellations, skips or TODOs; no existing
shared verification gate is weakened. The `deterministic-extraction` mock route
keeps its existing extraction-root and text-PDF tests; it does not recursively
enroll this dedicated PNG directory. PNG platform/profile qualification remains
the separate required 93-case command above.

The suite includes literal RGB/RGBA filter vectors with independently computed
CRC; real decode at exact pixel/row/inflation ceilings; malformed/unsupported
input and output limits; immutable snapshot/copy behavior; actual child close
and recovery; queue saturation and cancellation; delayed-timer dispatch and
delayed parent-validation controls; and strict consumer types. The lifecycle
fixture holds the actual child's input-end boundary, rather than adding a
production callback or inferring a phase from a sleep. Its separate kernel-limit
probe reuses the observed OS/Node/environment prefix, with one additional
read-only grant for **that probe's own** `/proc/self/limits` and a probe entrypoint.
That readback is labeled separately from an actual PNG decode. Synthetic
malformed worker frames exercise the parent protocol and are followed by an
actual decoder recovery; those frames are not provider or raster-decode evidence.

This is a partial EI #12 / EI #8 implementation. Remaining work includes the
other required raster formats, broader PNG encodings, screenshot meaning/OCR,
scanned-PDF rasterization/inspection, accountable inspected observations,
accepted research contracts, provenance/permissions integration and the complete
consumer journey. Local implementation of those formats is not inherently
blocked by provider credentials; any model/provider-backed evidence still needs
its actual authorized configuration, policy, metering and acceptance. Gate #22
and epic #1 remain open.
