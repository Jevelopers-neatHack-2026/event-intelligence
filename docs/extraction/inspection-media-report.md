# Local native media report bindings

`src/extraction/inspection-report/media.mjs` composes deterministic report bytes
from an existing, revalidated [local inspection report](inspection-report.md),
native PNG/JPEG/WebP/scanned-PDF observations, copied derivative bytes, complete
component checker output, and selected source/runtime receipts. It does not run
a decoder, read a file, fetch a URL, invoke a supplied method, or dispatch OCR.

This is the local `ei-local-inspection-media-report/2` format. It adds no canonical
contract export or accepted schema pin. `overall` remains `incomplete`,
`acceptance.evaluated` remains `false`, and neither rights nor Finance authority
is created. The generic `inspection-adapters` selector is not registered by this
change. A successful dedicated integrity check is evidence for the supported
local report consumer, not completion of issue #12, gate #22, or epic #1.

## What the consumer binds

| Input | Checked relationship | Result and limit |
| --- | --- | --- |
| Original v1 report | Exact report bytes and digest reconstruct from its complete original input, selected package/schema/support-matrix bytes and pins | Retained as a separate, unchanged prerequisite artifact; its held/missing mapping and acceptance reasons remain visible |
| Source snapshots | Before/after JSON digests, exact selected revision/tree, sorted file paths, physical modes, lengths and hashes | Dirty, changed or mismatched source remains incomplete; a supplied snapshot is evidence selected by a host, not a signature or permission |
| Native data projection | Exact component version, declared fields, bounded effective limits, supported format and typed decoded/refused result | No callable copy method enters the pure composer; undeclared native metadata is rejected |
| Original source bytes | Copied and independently hashed against the selected source digest and the native source digest when returned | A refusal that omitted `sourceSha256` retains explicit `null`; non-byte input cannot establish a source identity |
| Copied normalized PNG | Separate digest/length plus fixed PNG signature, three-chunk shape, CRCs, dimensions and RGBA8 output header | This checks PNG bytes and framing. It does not inflate PNG or claim verified decoded samples |
| Copied static-image raw RGBA8 | Separate raw digest/length, dimensions, stride and transparent/translucent/opaque sample counts | Verifies only the provided raw sample domain; it does not independently decode PNG, flatten alpha, run OCR or grant rights |
| Copied scanned-PDF page | Separate raw RGBA8 digest/length, one-based page sequence, source digest, stride, dimensions and opaque alpha | The retained bytes are raw samples, not a PNG file; physical page points remain separate from pixel dimensions |
| Native checker stdout/stderr | Full raw wrapper streams, one terminal native summary, exact native file/case inventory, actual TAP verdicts/counts, exit and signal | Failed, skipped, missing, contradictory, ambiguous, recorded or relabeled live evidence cannot become complete local coverage |
| Pinned runtime receipt | Exact selected manifest bytes, declared versions/wheel identity and bounded file inventory; PDF closure uses the installer's Python ASCII JSON hash domain | JPEG/WebP results also return the selected manifest digest. Scanned-PDF results do not return a closure digest, so the receipt remains separately host-selected |

The existing [PNG](static-png.md), [JPEG/WebP](static-jpeg-webp.md) and
[scanned-PDF](scanned-pdf.md) implementations own their admitted input profiles,
native limits, syscall/cooperative controls and runtime verification. Their
versions and refusal codes are consumed unchanged. The report does not widen
those profiles or turn a cooperative network counter into native egress proof.

### Byte and geometry domains

PNG and JPEG/WebP readers now expose two independent copy methods:
`copyNormalizedBytes()` returns encoded PNG, and `copyRgbaBytes()` returns
contiguous row-major RGBA8 samples. The caller supplies the normalized derivative
first and may supply raw `image-rgba8` second. The report separately hashes each
copy against the matching native digest and exact length. A raw image must have
`width * height * 4` bytes; its stride is `width * 4`, and it has no page ordinal.
Both copied representations count against the existing aggregate derivative cap.

Only supplied matching raw bytes set `componentReportedRgba.verified: true`.
The report counts zero, intermediate and 255 alpha samples without changing any
pixel or choosing a background. It preserves RGB values under transparent
pixels. Those counts describe bytes, not visual meaning or an opaque OCR grant.
The normalized PNG is still checked for framing, CRC and geometry without
inflation; independently verifying both hashes does not independently establish
that the two representations decode to the same pixels. That common sample
origin remains the fixed native reader's responsibility.

If raw bytes are omitted, the reported raw digest stays `verified: false`, and
`COMPONENT_RGBA_DOMAIN_NOT_INDEPENDENTLY_VERIFIED` keeps selected coverage
incomplete. Encoded PNG bytes cannot stand in for raw samples. The local media
report advances from schema 1 to schema 2 for these assertions. Earlier schema-1
artifacts and their encoded-only 93/158-case reader evidence stay historical;
the validator does not relabel them. The original text-report schema and the
method-free data-projection envelope remain version 1.

Scanned-PDF `pages[].copyRgbaBytes()` does supply raw opaque RGBA8 samples. Each
copied page must match its own digest, `width * height * 4` byte length,
`width * 4` stride, source digest and consecutive one-based page number. Every
alpha byte must be 255 under the admitted profile. `pageWidthPoints` and
`pageHeightPoints` are physical page measurements; `width`, `height` and stride
describe the raster. No OCR words, text confidence, visual boxes, orientation,
event fact or evidence permission is inferred from these fields.

The existing text-PDF report retains approximate page geometry and derived-text
UTF-8 hashes in their own domains. It does not claim original PDF byte offsets.
The media layer does not convert that geometry to pixel boxes or merge native
text and scanned pixels into fabricated text recognition.

### Pure data projections

The trusted component caller copies derivatives before calling the report API.
For example, after an actual successful `readStaticPng` call:

```js
const { copyNormalizedBytes, copyRgbaBytes, ...metadata } = nativePng;
const copiedPng = copyNormalizedBytes();
const copiedRgba = copyRgbaBytes();
const observation = {
  id: "poster-png",
  component: "static-png",
  format: "png",
  pins,
  executionId: "png-checks",
  sourceBytes: originalBytes,
  expectedSourceSha256: originalSha256,
  projection: {
    schemaVersion: "ei-native-media-data-projection/1",
    component: "static-png",
    result: metadata,
  },
  derivatives: [{
    role: "normalized-png",
    page: null,
    bytes: copiedPng,
    expectedSha256: nativePng.normalizedSha256,
  }, {
    role: "image-rgba8",
    page: null,
    bytes: copiedRgba,
    expectedSha256: nativePng.rgbaSha256,
  }],
};
```

The example consumes an already obtained, trusted native result. It is not an
adapter for arbitrary objects. The composer accepts plain data records and dense
arrays, rejects proxies/accessors/subclasses/callable methods without invoking
them, and copies only ordinary non-shared `Uint8Array`/`Buffer` views through
their native slots. Runtime receipts contribute declared identities, not their
arbitrary metadata. Selected pins retain the v1 strict declared-field boundary.

`composeInspectionMediaReport(input)` returns frozen report data, its SHA-256,
byte length and an independent `copyBytes()` result.
`validateInspectionMediaReport(reportBytes, expectedSha256, input)` checks the
supplied bytes, rejects duplicate JSON keys, and requires exact reconstruction.
Changing the source, result, limits, pins, matrix, summary, receipt or report
without an honest matching input cannot validate the old bytes.

## Complete inventory and incomplete acceptance

`declaredCoverage: complete` means all formats required by the selected local
support matrix are present with complete supported local execution evidence and
the supplied source/runtime joins. It is not a claim that the matrix is accepted
or exhaustive. The required formats come from the byte-bound v1 matrix; the
media layer cannot silently lower that selection or invent a new one.

`overall: incomplete` and the empty acceptance/owner-acknowledgement fields are
unconditional. Held or missing canonical mappings, unrecorded accountable
acceptance and facts requiring review remain reasons. Missing copied raw RGBA
remains an explicit byte-domain limitation. Missing formats, refused component
results, unavailable runtime receipts, changed source, incomplete native checks, unknown process outcomes
and unknown required stderr remain additional coverage blockers.

Execution IDs are unique across the v1 and media inventories. Observation IDs
are also globally unique, and duplicate component/source/format rows are
refused. Sorting independent observations, executions or runtime receipts does
not alter canonical report bytes. Re-validating the same immutable input is
deterministic. Cancellation/refusal and a later successful fresh attempt remain
separate results; the report does not retry a component or replace an earlier
failure with a later summary.

### Child stderr and wrapper stderr

The scanned-PDF verifier returns hashes for its captured child TAP and child
stderr. Its own wrapper output also contains its summary and may contain its own
Node warning. The API therefore accepts `childStderrBytes` separately and checks
those bytes against the returned child digest. It never assumes that the entire
wrapper stderr is the child stream. `null` retains an incomplete binding.

The maintained actual-consumer fixture preserves the whole wrapper stream. The
existing verifier writes its captured child stderr as one contiguous block. When
direct separate bytes are unavailable, the fixture examines at most 256 known
newline boundaries as prefix/suffix intervals in a wrapper of at most 256 KiB.
Only a unique exact byte interval matching the native child digest is copied,
with its offset, length, digest and recovery method recorded. Ambiguous, missing
or over-limit recovery remains unknown. The native summary does not expose a
child length; the fixture records the recovered length and does not invent an
independent length attestation. No warning is suppressed and no provider mode is
changed to manufacture an empty stream.

## Bounded checks

The report accepts at most 32 total observations, three media executions and four
pages per scanned-PDF observation. A source or derivative is limited to 20 MiB;
all original sources (including v1 text/PDF) and all copied derivatives have
separate 64 MiB aggregate caps. Native components' lower format-specific limits
remain enforced. Source receipt JSON is limited to 1 MiB/4,096 files, runtime JSON
to 256 KiB, checker stdout to 1 MiB, each stderr to 256 KiB, and final report JSON
to 4 MiB. JSON traversal also has depth and node bounds. Required cases are never
turned into skips to fit an unavailable environment.

The dedicated checker has two explicitly selected test files and 148 required
top-level cases. Its actual fixture additionally runs the existing deterministic
50-case route, native text-PDF 14-case route, PNG 107-case route, JPEG/WebP
160-case route and scanned-PDF 99-case route. These nested component results are
retained separately; they are not added into a misleading top-level count.
The PNG worker protocol is `ei-static-png-worker/2`; its source profile remains
`ei-static-png/1`. JPEG/WebP keeps its existing worker protocol. The report
requires the corresponding 107/160-case inventories and the exact current native
limits, including the PNG raw-output ceiling. No older result is silently upgraded.
Tests use local synthetic bytes with real native readers, copied derivatives,
source snapshots and raw summaries. Deliberately altered metadata/receipt/TAP
controls are labeled synthetic and cannot establish component acceptance. Raw
controls include copy isolation/recovery, swapped hash domains, missing or
duplicate derivatives, alpha preservation, callable/proxy refusal and the
combined encoded/raw byte ceiling.

Acquire only the existing locked wheels and install them through the component
installers. An example for Linux x86_64 with Node22.23.3/Python3.12.14 is:

```sh
python -I -m pip --isolated download --disable-pip-version-check \
  --only-binary=:all: --no-deps --require-hashes \
  --dest /absolute/temporary/media-wheels \
  -r tools/static-raster/requirements.txt -r tools/scanned-pdf/requirements.txt
python -I -S -B tools/static-raster/install.py \
  --wheel /absolute/temporary/media-wheels/pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl \
  --destination /absolute/temporary/jpeg-runtime
python -I -S -B tools/scanned-pdf/install.py \
  --wheel /absolute/temporary/media-wheels/pypdfium2-5.14.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
EI_JPEG_WEBP_TEST_RUNTIME=/absolute/temporary/jpeg-runtime \
EI_JPEG_WEBP_TEST_WHEEL=/absolute/temporary/media-wheels/pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl \
node tools/verify-inspection-media-report.mjs --mode mock
```

The PNG checker uses the declared Node/zlib profile. Scanned-PDF runtime files
must remain in the installer's own ordinary, non-symlink location. The JPEG/WebP
runtime and wheel variables are also required by its original integrity/recovery
checks. Missing runtime bytes fail this dedicated checker; alternate versions
are not silently substituted. `--mode live` is explicitly blocked.

Set `EI_INSPECTION_MEDIA_REPORT_CAPTURE` to a new absolute directory outside the
source checkout to retain actual component stdout/stderr, source snapshots,
recovered child stderr and the example report. The fixture refuses to overwrite
previous artifacts. Native wheels, installed libraries, credentials and private
provider data are not part of that capture.

The accompanying workflow installs the existing pinned dependencies, runs the
actual dedicated check, compiles seven strict consumers and checks project types.
It preserves raw capture even on failure. It does not change another component's
selector, source, tests, dependency locks or workflow.

## Remaining dependencies

Canonical report-to-evidence mapping and accepted pins still require the
shared-contracts and integration owners' explicit accepted delivery. Product and
Creative still own their actual assembly and consumer acceptance. Broader media
profiles, OCR, confidence/calibration policy and factual review are distinct
component/acceptance work. The inspected source profiles support a useful local
aggregate today; those remaining inputs do not erase the implemented report
behavior or permit it to claim final research acceptance.
