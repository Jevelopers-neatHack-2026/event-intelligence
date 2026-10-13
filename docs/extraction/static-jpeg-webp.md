# Private bounded static JPEG/WebP pixels

Refs #12 and #22. This component adds local pixel decoding for a deliberately
narrow set of static JPEG and WebP files. It returns a sanitized PNG and separate
source, RGBA and derivative hashes. Every successful result remains
`incomplete-pixels-only` with `requiresInspection: true`.

The private entry point is `src/extraction/jpeg-webp/index.mjs`. It is not a
package export, URL fetcher, asset permission decision, OCR implementation,
provider adapter or canonical inspection result. The shared verification
selector and release acceptance are separate. PNG decoding has its own private
reader and evidence; this component does not change it.

## Explicit runtime and setup

Supported runtime: Linux x86-64, Node **22.23.3**, CPython **3.12.14**, and the
single Pillow **12.3.0** CPython 3.12 manylinux wheel below. `/usr/bin/prlimit`
must be a regular root-owned executable at that exact canonical path and must
not be writable by group or others. Unsupported installations refuse work.

| Dependency identity | Exact value |
| --- | --- |
| Wheel | `pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` |
| Wheel bytes | `6940830` |
| Wheel SHA-256 | `78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91` |
| JPEG ABI reported by Pillow | `6.2` |
| WebP version reported by Pillow | `1.6.0` |
| Same-wheel JPEG library | `pillow.libs/libjpeg-31e2ca52.so.62.4.0` |
| JPEG library SHA-256 | `6d7c754529b30aff22efaaf88ba02061714591702c03f297f00ccb32ee6d9d9a` |
| Same-wheel WebP library | `pillow.libs/libwebp-51b0b3f7.so.7.2.0` |
| WebP library SHA-256 | `7df9ad3680dd09d756511334791c8c896207863816eb2910840e5fc4ae10028a` |
| Configuration / normalization | `ei-static-jpeg-webp/1` / `rgba8-png-stored-deflate/1` |

Dependency acquisition is an explicit development or host setup action. The
reader never downloads, installs or discovers a runtime. Select the supported
Node and CPython binaries before these commands. `python3.12` below must be
CPython 3.12.14; the installer checks the actual interpreter.

```sh
npm ci
node tools/install-typescript-host.mjs

raster_setup_dir="$(mktemp -d)"
python3.12 -I -m pip --isolated download --disable-pip-version-check \
  --only-binary=:all: --no-deps --require-hashes \
  --dest "$raster_setup_dir/wheels" \
  -r tools/static-raster/requirements.txt

export EI_JPEG_WEBP_TEST_WHEEL="$raster_setup_dir/wheels/pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"
export EI_JPEG_WEBP_TEST_RUNTIME="$raster_setup_dir/runtime"
python3.12 -I -S -B tools/static-raster/install.py \
  --wheel "$EI_JPEG_WEBP_TEST_WHEEL" \
  --destination "$EI_JPEG_WEBP_TEST_RUNTIME"

node tools/verify-static-jpeg-webp.mjs
./node_modules/.bin/tsc --noEmit --strict --target ES2022 \
  --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM \
  --types node tests/extraction/jpeg-webp/types-consumer.mts
npm run typecheck
```

For offline setup, supply the already acquired exact wheel to the installer;
omit the download command. The **destination must not exist**, including as an
empty directory. The new `runtime` child in the example satisfies that rule.
The installer creates a fresh virtual environment, uses `--no-index` and
`--require-hashes`, verifies the native codec versions, then records the Python
executable hash and every installed file under `PIL`, `pillow.libs` and the
matching distribution metadata. An interrupted or failed installation is
retained for diagnosis and has no valid completed marker. Do not treat that
directory as ready or overwrite it to conceal the failed setup.

`runtime.json` is an installation receipt, not a foreign trust grant. The host
must own and protect the runtime, worker source, Python base installation and
OS tools. The worker verifies the receipt hash supplied by the parent, actual
interpreter identity and the complete recorded package inventory before each
decode. Unpaired file/marker changes, symlinks, missing or extra package files
and invalid inventory entries refuse decoding. These checks do not attest an
adversarial host that can replace both the receipt and trusted code. `-I -S -B`
disables ambient Python site startup and bytecode writes; unrelated `.pth` and
`sitecustomize` files are not executed. Only verified Pillow imports and its
native dependencies provide decoding.

The full upstream license and bundled-component notices from the wheel are
retained unchanged in `tools/static-raster/PILLOW-LICENSE.txt` (SHA-256
`dda12a98c1979cf3d94df1cff45d27a4cb3f04a60c76f76902ac54cac03ec0ce`). The installed
wheel also retains its distribution license directory. Pillow's MIT-CMU terms
do not replace the notices for its bundled components. A dependency upgrade
requires a new reviewed pin, feature/ABI checks and regenerated, qualified
pixel evidence.

## Private caller behavior

```js
import { createStaticJpegWebpReader } from "../../src/extraction/jpeg-webp/index.mjs";

const reader = createStaticJpegWebpReader({
  runtimeDirectory: trustedInstalledRuntimeDirectory,
});
const result = await reader.read(alreadyAcquiredBytes, {
  signal: callerSignal,
  timeoutMs: 5000,
  maxOutputBytes: 20 * 1024 * 1024,
});
if (result.kind === "decoded") {
  const privatePngCopy = result.copyNormalizedBytes();
  // Inspect the pixels through the separately authorized inspection route.
  // Preserve sourceSha256, rgbaSha256 and normalizedSha256 as distinct identities.
}
```

The input is a non-shared `Uint8Array` or `Buffer`, copied synchronously before
the promise returns. Caller mutation cannot change queued bytes. The immutable
result does not expose its retained PNG; each `copyNormalizedBytes()` call makes
a new copy. The reader accepts no URL, provider callback or input-selected path.
Configuration and option accessors, proxies, coercions, malformed cancellation
objects, shared buffers and limits above the ceilings are refused without
invoking caller getters. A malformed trusted factory configuration throws
`TypeError`; read refusals are discriminated values with no pixel derivative.

### Strict supported profiles

| Format | Supported profile | Refused semantics |
| --- | --- | --- |
| JPEG | One complete 8-bit baseline SOF0 or progressive SOF2 image; one gray component or three components numbered 1–3; legal scan/restart/byte-stuffing structure; native coefficient validation and actual pixel load | CMYK, Adobe transforms, other SOF families/precision, arithmetic/lossless JPEG, DNL/deferred dimensions, multiple images, incomplete segments/scans, or bytes after the final EOI |
| JPEG metadata | No APP/COM metadata, except one exact ordinary JFIF 1.0–1.2 header before the frame, with no thumbnail and unit-zero 1:1 density | EXIF/orientation, ICC, XMP, comments, MPF/MPO, JFXX, physical/non-square density, duplicate JFIF, and every other APP marker |
| WebP | Exact RIFF/WEBP container; simple `VP8 ` or `VP8L`, or alpha-only `VP8X,ALPH,VP8 ` / `VP8X,VP8L`; one image with matching canvas/native dimensions | Animation/ANIM/ANMF, ICC/EXIF/XMP, unknown or duplicate chunks, contradictory image types, illegal ALPH ordering, reserved flags/versions, nonzero odd padding, false signatures and container tails |

Container validation never claims pixels. The supervised worker opens a
`BytesIO` with one exact format in Pillow's allowlist, checks mode/dimensions and
one-frame status, **calls `Image.load()`**, rechecks the decoded shape, converts
and loads RGBA, and checks its exact byte length. Truncated-image allowance
remains false. Declared header dimensions or a successful open are insufficient.

JPEG has an additional native check because Pillow 12.3.0 intentionally discards
libjpeg warnings. A complete marker frame with missing entropy can otherwise
load synthesized fill pixels. The worker first reads all JPEG coefficients and
finishes decompression with the **same wheel's** libjpeg, using its original
error manager and requiring zero warnings. It installs no custom C callbacks.
The library's ABI/version/structure-size check must accept the exact Linux
x86-64 context (JPEG62, 632 bytes) before input; the public error-manager layout
is also fixed and checked (168 bytes). Native fatal errors terminate only the
disposable child. Native warning/error bytes reach the bounded stderr pipe;
any stderr rejects the result, and untrusted stderr text is not exposed by the
public private-reader result. This is stricter warning handling of the same
decoder family, not an independent second codec implementation.

WebP additionally requires native completion with the **exact declared VP8 or
VP8L payload**, excluding RIFF padding and following chunks. The pinned public
`WebPGetInfo` and `WebPDecodeRGBAInto` APIs check dimensions and complete into a
bounded caller-owned buffer. This prevents an insufficient lossless payload
from borrowing its RIFF padding byte. Raw ALPH must contain exactly one sample
per pixel; compressed ALPH is checked as the specification's headerless
lossless image stream with its implicit canvas header supplied. Pillow still
performs the actual full-image load and alpha filtering. Without separate ALPH,
the raw native and Pillow RGBA hashes must also agree.

Native WebP success does not expose a consumed-byte count. This reader therefore
does not claim every compressed payload byte was necessary or require a unique
compressed representation. A complete alternate payload may produce different
pixels or retain the same pixels under a different source hash. Unused bytes
inside a declared payload never survive the sanitized PNG. Bytes outside the
exact RIFF container, unknown chunks and incomplete native payloads are refused.

Color handling is deliberately limited. Gray becomes opaque RGB, supported JPEG
uses the pinned native RGB conversion, and WebP preserves its decoded alpha.
No EXIF rotation, ICC color correction or metadata-derived physical scale is
applied. Accepted dimensions/mode must agree before and after decoding. The
normalized PNG contains only IHDR (RGBA8), one IDAT and IEND. It has filter-zero
rows and fixed stored DEFLATE blocks, with no metadata or encoder heuristic.
This makes the derivative bytes deterministic for exact RGBA pixels at the cost
of a larger PNG. Lossy source colors remain the pinned codec's decoded colors;
the derivative does not claim color calibration or original author intent.

### Limits and supervision

| Bound | Ceiling |
| --- | --- |
| Input | 10 MiB |
| Dimensions / pixels / frames | 4096 per axis / 4,194,304 pixels / 1 frame |
| JPEG non-entropy segments or WebP chunks | 1024; entropy parsing is additionally bounded by the input byte ceiling |
| Raw RGBA / deterministic PNG | 16 MiB / 20 MiB |
| Child frame header / stderr | 4096 bytes / 16 KiB |
| Runtime marker | 256 KiB |
| Child address space / CPU | 512 MiB / 5 CPU seconds |
| Child descriptors / file growth / core | 64 / zero / zero |
| Active children / queued reads | 1 / 4 per canonical module instance |
| Original monotonic deadline | 5000 ms default, at most 10000 ms; caller may lower it |

The deadline starts before validation and the input copy. Queue waiting, runtime
validation, spawning, native work, framed output, normalization and final result
acceptance all use that original deadline. An overdue timer callback cannot
renew it. Expired queued jobs never dispatch. Deadline/cancellation checks also
run at actual child spawn and final return, including when the event loop was
stalled before those boundaries. Input is written only after the fresh spawn
check. An aborted or failed job cannot promote a frame that later arrives.

Linux `/usr/bin/prlimit` applies actual address-space, CPU, descriptor, file-size
and core limits before CPython starts. The child receives only `PATH`, `LANG`
and `LC_ALL`, fixed argv and piped media bytes. The parent bounds stdout/stderr,
kills the detached child group on abort/timeout/overflow, and retains its active
slot until the real child `close` event. Saturation is explicit `QUEUE_FULL`;
new work can recover after closure. Separate Node processes or separately loaded
module instances require host-level aggregate admission; this local pool is not
a tenant or deployment-wide quota.

These are resource limits and fail-closed result deadlines, not a real-time OS
scheduling guarantee. A blocked host event loop or delayed kernel process reap
can delay a refusal's delivery. The reader waits for child closure instead of
freeing capacity while a decoder is still alive. CPU seconds also differ from
wall-clock seconds. Parent memory is bounded by the finite input/queue/frame/
normalization limits, but the child's address-space rlimit is not a Node heap
limit.

The worker blocks cooperative Python socket/lookup APIs, captured Python lookup
wrappers and audited socket operations. It also rejects filesystem opens,
subprocesses and dynamic native-library lookups after trusted imports finish.
Violations remain sticky even if a decoder catches their exception. The tests
include a calibrated real loopback canary with zero decoder connections.
**Python API/audit guards are not an OS egress sandbox or hostile-native-code
containment.** Native codec vulnerabilities or hostile host code can bypass
Python-level guards. An actual deployment needs its separately approved host
isolation and egress policy; this component does not claim or provision it.

## Verification and remaining acceptance

`tools/verify-static-jpeg-webp.mjs` and the dedicated workflow execute all 158
required cases. Missing runtime/wheel input, unsupported runtime, nonzero exits,
timeouts, incomplete case counts, failures, cancellations, skipped cases and
TODOs make that route fail. The strict consumer and project type checks are
separate required workflow steps. Runtime decoding performs no registry or
provider request; only the named development setup step acquires dependencies.

Fixtures are small **synthetic** JPEG/WebP bytes, including baseline/progressive
JPEG, restart/stuffing, lossy/lossless WebP, raw/compressed alpha and a 4-megapixel
bound case. Their byte hashes are recorded. Lossless and uniform-gray controls
also compare with authored pixel values; lossy pixel goldens come from a
separately invoked pinned Pillow reference decode. The PNG consumer uses
independent zlib inflation, PNG CRCs, dimensions and exact pixels. Synthetic
worker/protocol faults are labeled as such and do not stand in for real codec
decoding. CPU/address-space/descriptor limits and process closure are exercised
on real Linux children, followed by actual fresh decode recovery.

The controls also cover malformed entropy, false headers, metadata and animation
refusals, exact container ends, immutable input/output, hostile framing, queue
and callback stalls, cancellation, installation drift and the offline setup
failure boundaries. Earlier failed author runs remain historical evidence; a
later passing case does not erase them.

This slice does not qualify the full inspection-adapters selector, OCR quality,
field extraction, private host/provider authorization, rights or permissions,
cross-repository consumers, or release acceptance. Those require their actual
implementation and accountable evidence. Do not close #12, gate #22 or epic #1
solely because this private format route passes.

### Primary implementation references

- [Pillow Image API: lazy open, format allowlist and load](https://pillow.readthedocs.io/en/stable/reference/Image.html)
- [Pillow image-format behavior](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [Pillow 12.3.0 native JPEG warning handling](https://github.com/python-pillow/Pillow/blob/12.3.0/src/libImaging/JpegDecode.c)
- [libjpeg-turbo 3.1.4.1 public ABI and error manager](https://github.com/libjpeg-turbo/libjpeg-turbo/blob/3.1.4.1/src/jpeglib.h)
- [WebP RIFF container specification](https://developers.google.com/speed/webp/docs/riff_container)
- [WebP 1.6.0 public decode API and its completion/error contract](https://github.com/webmproject/libwebp/blob/v1.6.0/src/webp/decode.h)
- [WebP lossless image-stream specification](https://developers.google.com/speed/webp/docs/webp_lossless_bitstream_specification)
