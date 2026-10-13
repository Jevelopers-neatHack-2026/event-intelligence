# Private bounded static image to OCR composition

Refs [EI #8](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/8),
[EI #12](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/12),
and [gate #22](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/22).

The repository-private `src/extraction/static-image-ocr/index.mjs` composes the
fixed [PNG](static-png.md), [JPEG/WebP](static-jpeg-webp.md) and
[local OCR](local-ocr.md) readers. It accepts an encoded byte snapshot, obtains
verified owned RGBA samples from the appropriate reader, requires every alpha
sample to be 255, and sends those pixels to the fixed English OCR profile.
Successful results contain immutable, uncertain literal words and pixel boxes.
They retain `completeness: "incomplete-unverified-ocr"`, `requiresReview: true`
and `sourceAuthority: "unverified"`.

This is a local processing component. It does not fetch a URL, accept an arbitrary
decoder/OCR callback, select facts, authorize disclosure, establish image rights,
or provide a canonical research/creative contract. It does not alter the existing
inspection report, private research assembly or scanned-PDF composition.
Those owners must supply their actual integration and accountable acceptance.

## Private caller and supported bytes

```js
import { createStaticImageOcrReader } from "../../src/extraction/static-image-ocr/index.mjs";

const reader = createStaticImageOcrReader({
  runtimeDirectory: trustedOfflineInstalledPillowRuntime,
});
const result = await reader.read(alreadyAcquiredBytes, {
  signal: callerSignal,
  timeoutMs: 10000,
  maxWords: 512,
  maxTextBytes: 8192,
  maxOutputBytes: 256 * 1024,
});
if (result.kind === "observed") {
  // Keep sourceSha256, image.rgbaSha256, image.normalizedSha256, dimensions,
  // fixed decoder/observer profiles and per-word provenance with the words.
  // Words and their uncalibrated confidence scores still require review.
} else {
  // Stable local code/stage, optional source hash and component code only.
  // No source bytes, partial words, raw exception or child diagnostics.
}
```

The host chooses one canonical absolute JPEG/WebP runtime directory. Even
PNG-only callers use this explicit factory configuration; decoding a PNG does
not load Pillow. Runtime validity is checked by the selected fixed reader when
needed. A bad trusted configuration throws `TypeError`; read failures are typed
values. The public API has no request-selected path, URL, source-authority token,
pre-decoded result or provider option, and remains outside root package exports.

Only ordinary `Buffer`/`Uint8Array` instances with non-shared, live backing are
accepted. Native typed-array operations take the source snapshot before the
read call returns its promise. Proxies, subclasses, detached/empty/shared views,
getters, foreign option keys and forged signals are refused. The signature only
selects a decoder; its complete existing container, payload, hash and native
load checks remain mandatory.

Supported PNG is noninterlaced 8-bit RGB/RGBA in the existing strict chunk
profile. JPEG is the existing 8-bit baseline/progressive gray/RGB profile.
WebP is the existing one-frame lossy/lossless profile. Metadata, animation,
unsupported encodings, malformed streams and container tails remain explicit
reader refusals. No EXIF rotation, color management or background inference is
added. A decoded image with any alpha below 255 returns `NON_OPAQUE_IMAGE`
**before OCR**; its colors are neither flattened nor silently discarded.

## Byte chain, observations and deadlines

The composition checks the exact fixed decoder identity, admitted source hash,
format, dimensions, lengths, normalized hash and output limits. It calls the
actual reader's `copyRgbaBytes()` once, takes a separate bounded snapshot and
recomputes its SHA-256. The length must equal `width * height * 4`; its hash must
equal the decoder's raw-pixel hash. The original encoded hash, raw hash and
normalized PNG hash remain distinct. The parent never decodes arbitrary
compressed pixels outside the existing supervised workers.

The OCR input is that checked opaque RGBA, with original source SHA, page 1,
raw derivative SHA and dimensions. Every returned word's provenance must match
that chain. The exact OCR engine/model/profile, syscall-policy receipt, bounds,
token byte count, increasing word identities and in-image integer boxes are
checked again. Unexpected fields, accessors, sparse words, control/bidi text,
invalid confidences or inconsistent provenance reject the complete result.
All accepted words/boxes/provenance are copied into frozen plain records.
Confidence remains an uncalibrated engine score, including zero. Blank images
return `no-text-observed`; that is not proof that the source contains no meaning.

One original `performance.now()` deadline starts before admission and source
copying. It includes queue waiting, decoder dispatch/work/closure, result
validation, raw copying/hash/opacity checks, OCR dispatch/work/closure, word
validation, freezing, report-size calculation and final promise delivery.
Both native readers receive that same absolute deadline and a remaining relative
budget no greater than their own ceiling. No stage grants a fresh timeout.
After each potentially costly phase and before final delivery, the composition
checks the original deadline and native cancellation state again.

PNG and JPEG/WebP now accept the same repository-private **lower-only** optional
`deadlineAtMs` already supported by the OCR/PDF stack. It is a finite nonnegative
number in this process's monotonic clock, not a timestamp from another process
or wall clock. Their effective deadline is
`min(callStart + timeoutMs, deadlineAtMs)`; an exhausted value refuses before
input copying or child creation. Omitting it preserves ordinary reader behavior.
An absolute value cannot extend the existing relative ceiling. Getters and
invalid values are rejected. The composition owns this option internally; its
public request API accepts only a bounded relative timeout.

Cancellation/deadline stops the actual active child through its existing reader.
The composition observes that native stage promise until the child's real close,
retains its admission slot, and publishes no late pixels/words. It never races
away an already-created promise. There is no fresh cleanup allowance and no
claim that a stalled event loop or uninterruptible OS process can be reaped at a
hard real-time bound. Once actual closure is observed, independent work can
recover. Queued cancellation/expiry releases a slot without starting a child.

## Fixed resource accounting

| Resource | Ceiling |
| --- | --- |
| Encoded source snapshot per job | 10 MiB |
| Width/height, total pixels | 4096 each; 4,194,304 pixels |
| Owned RGBA image | 16 MiB, opaque, contiguous row-major samples |
| Decoder normalized PNG | Existing 20 MiB ceiling, unchanged |
| Literal words / UTF-8 token text | 2048 / 32 KiB |
| Serialized composition report | 1 MiB |
| Active / queued composition jobs | 1 / 4 across all factories in one canonical module instance |
| Original wall budget | Default 20 seconds; caller may select 1–30,000 ms |

All request limits can only select values up to their fixed ceilings. The
composition report's `maxOutputBytes` does **not** redefine the decoder's
normalized PNG cap. The OCR stage also retains its independent fixed 512 KiB
framed-output and 256 KiB TSV limits, which may refuse before the report cap.

At saturation, the composition owns at most five encoded snapshots (50 MiB);
admission refuses another job before copying its bytes. The one active decoder
has its additional bounded source snapshot and native buffers. PNG capture is
bounded by normalized 20 MiB plus raw 16 MiB plus the fixed header/prefix; its
paired result retains bounded copies of both payloads. JPEG/WebP capture retains
the separate raw limit and its normalizer creates the bounded PNG. The raw
accessor copy and the composition's independent copy may temporarily coexist
(16 MiB each). Decoder result/accessor references and the composition's encoded
snapshot are released before OCR; the raw source is then copied by the existing
OCR reader. The final composition result retains no raw/encoded bytes or copy
accessors, only bounded metadata and words.

These are finite object/buffer bounds and reference lifetimes, not a measured
whole-process RSS maximum or a garbage-collection timing promise. Callers can
retain many completed reports, and other direct reader users have their own
bounded queues. Separately loaded module instances/processes and tenant-wide
admission still require their host's actual aggregate policy. This component
does not issue or change a Finance budget or durable tenant allocation.

The existing native boundaries are preserved: PNG's pinned Node/zlib,
permission model and `prlimit`; JPEG/WebP's pinned Python/Pillow/native libraries,
complete installation checks and `prlimit`; and OCR's exact model/runtime and
native syscall-policy controls. The PNG/JPEG network guards remain cooperative
API controls, **not** a network namespace, hostile-native-code sandbox or native
egress attestation. Composition does not strengthen or provision host isolation.
It requires the original platform/codec profiles and never relaxes a missing
runtime, malformed frame, skipped case or failed native control into success.

## Setup and verification

Use Linux x86-64, Node22.23.3 and CPython3.12.14. Follow the existing
[JPEG/WebP offline setup](static-jpeg-webp.md#explicit-runtime-and-setup) and
[OCR setup](local-ocr.md); provide the exact previously acquired wheel/archive
paths when working offline. Use a **new nonexistent** JPEG/WebP runtime directory:

```sh
npm ci
node tools/install-typescript-host.mjs

python -I -S -B tools/static-raster/install.py \
  --wheel "$EI_JPEG_WEBP_TEST_WHEEL" \
  --destination "$EI_STATIC_IMAGE_OCR_RASTER_RUNTIME"
python tools/local-ocr/install.py --archives "$EI_LOCAL_OCR_ARCHIVES"

node tools/verify-static-image-ocr.mjs
./node_modules/.bin/tsc --noEmit --strict --target ES2022 \
  --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM \
  --types node --skipLibCheck false --noErrorTruncation \
  tests/extraction/static-image-ocr/types-consumer.mts \
  tests/extraction/png/types-consumer.mts \
  tests/extraction/jpeg-webp/types-consumer.mts \
  tests/extraction/local-ocr/types-consumer.mts
npm run typecheck
```

Set those three path variables to the host's actual pinned wheel, new canonical
runtime directory and exact OCR archive directory first; export
`EI_STATIC_IMAGE_OCR_RASTER_RUNTIME` for the verifier. Do not run fixture
generation in an installed decoder without `-B`. Generated Python cache files
would be unexpected files under its exact installation receipt, so the decoder
correctly refuses that changed inventory. Failed/incomplete setup directories
remain evidence; use a new destination to retry without replacing them.

The dedicated route requires **137/137** cases with no failures, cancellations,
skips or TODOs: 95 explicitly synthetic stage/protocol/admission cases and 42
actual native composition/deadline cases on synthetic image sources. It binds
the complete source map and both native installation-marker hashes before and
after execution. Each attempt gets a unique retained directory, including
failed attempts; a mutable latest pointer never replaces those directories.
Full native library/model checks still occur inside the unchanged readers.
The workflow publishes structured summaries/source maps/dependency receipts;
raw diagnostic logs remain local to the verification attempt.

The native cases include baseline/progressive JPEG, lossy/lossless WebP and
PNG with the existing synthetic English raster, an actually blank PNG,
alpha refusal before OCR, input mutation, malformed metadata/tails, lower
word/text/report limits, active native cancellation and true child close,
decoder-close-to-OCR deadline expiry, final result expiry and recovery.
Deadline tests keep the actual clocks, timers, promises, codecs and OCR workers.
Explicit test interposition marks the phase where a stall/cancel is injected.
The strict overlay cases verify that a caller cannot renew relative budgets.
Synthetic ports are an internal test seam and are never public factory options.

Fixtures retain the source raster/font provenance from `tests/extraction/local-ocr/fixtures/`,
with encoder options and exact encoded/raw hashes in
`tests/extraction/static-image-ocr/fixtures/provenance.json`. The optional
generator uses the exact already pinned Pillow12.3.0 runtime and no download.
Its separate pixel readback uses the same codec family; it is not an independent
decoder implementation or a benchmark of OCR accuracy.

```sh
"$EI_STATIC_IMAGE_OCR_RASTER_RUNTIME/bin/python" -I -B \
  tests/extraction/static-image-ocr/generate-fixtures.py
```

That optional development command rewrites only the checked-in synthetic
fixtures and their provenance; compare their exact hashes before committing.

This local slice does not establish screenshot meaning, text completeness,
field/fact extraction, provider evaluation, rights or accepted cross-repository
handoff. It does not resolve historical hosted initializer failures or alter
their separately owned repair. Accountable inspection/report integration and
the full permitted consumer journey remain separate. Keep #12, #22 and epic #1
open until their complete scoped outcomes and acceptance are recorded.
