# Private scanned-PDF raster reader

Refs #12 and #8. This is a local image-only PDF implementation slice. It returns real bounded page pixels and provenance; it does not close either issue or a master acceptance gate.

## Result and elected support profile

`src/extraction/scanned-pdf/index.mjs` exposes the private `readScannedPdf(Uint8Array, options?)` module. The existing package export catalog is unchanged. Accepted inputs produce deterministic **raw opaque RGBA8 raster derivatives**, one per page, with the exact source SHA256, one-based page number, original page dimensions in PDF points, raster width/height, byte length and derivative SHA256. Pixel coordinates begin at the top left; the channels retain the admitted DeviceRGB values. The result stays `incomplete-pixels-only` and `requiresInspection: true`.

The supported `classic-full-page-rgb-flate-v1` profile is deliberately limited:

| Area | Supported | Refused |
| --- | --- | --- |
| Container | PDF 1.4–1.7 header; consecutive generation-zero indirect objects; one consistent classic cross-reference table and trailer; a single flat page tree | Incremental/hybrid/object-stream/linearized arrangements, unreferenced objects, duplicate keys, unsupported trailer/catalog entries and malformed references |
| Page | Positive origin-zero MediaBox; exactly one full-page embedded image, painted by `q a 0 0 d 0 0 cm /Image Do Q` | Text, fonts, forms, paths, clipping operators, annotations, rotation/crop/transform alternatives and additional page resources |
| Image | DeviceRGB, 8 bits per component, a single complete Flate stream, no prediction parameters | JPEG/JPEG2000/CCITT/JBIG2 filters, grayscale/CMYK/indexed/ICC color, masks/transparency, embedded metadata and extra image parameters |
| Resource/action handling | In-memory source bytes only; no form initialization, JavaScript callback or source-selected path API | Encryption, actions, JavaScript/XFA, attachments, URI/remote file references and unsupported keys |
| Observation | Original image resolution rendered across the original PDF page geometry; exact opaque RGBA rows | OCR, text/date/logo interpretation, candidate facts, visual confidence, rights, provider acceptance and canonical derived-media routing |

The admission parser checks the complete represented object/reference/stream structure and consumes every declared object. It bounds Flate expansion and requires the exact expected RGB sample count with no trailing or concatenated stream. PDFium then independently loads the in-memory document, checks the actual page/object/image metadata, decodes the embedded bitmap and renders the page through its progressive API. **The source RGB samples, PDFium image bitmap and final page raster must agree for every pixel.** A successful render status alone cannot turn an omitted or damaged image into a successful derivative.

This subset can render image-only PDFs whose scan is embedded as RGB Flate. Other scanned PDFs remain unsupported; rejection must remain visible to the caller, which can request a supported input or manual transcription through its separately authorized flow. This component does not silently select another decoder or provider.

## Fixed resource and lifecycle boundaries

| Resource | Ceiling |
| --- | ---: |
| Copied source bytes | 16 MiB |
| Pages | 4 |
| Raster width or height | 4096 pixels |
| Pixels on one page and across the whole document | 4,194,304 |
| Raw RGBA output across all pages | 16 MiB |
| Original page width or height | 14,400 PDF points |
| Indirect objects / parser tokens / recursive value depth | 32 / 10,000 / 8 |
| Page content stream / worker JSON header | 512 bytes / 16 KiB |
| Concurrent child / waiting requests in this module instance | 1 / 4 |
| Default request allowance / maximum caller allowance | 10 seconds / 30 seconds |
| Child address space / CPU / open-file limit / core | 1 GiB / 5 CPU seconds / 64 / 0 |

The request deadline starts before option validation and source copying. Queue waiting, runtime acquisition, trusted bootstrap, native decoding, frame parsing, hashing and result construction spend that same allowance. Callers may lower `timeoutMs` and `maxOutputBytes`. A native AbortSignal cancels a queued request or kills its active process group. The slot and promise are released only after actual child `close`; timeout, cancellation, malformed output and resource failure are followed by a fresh child on the next request. A document that exceeds an aggregate limit returns a refusal, without a partially successful page list.

Inputs are copied using intrinsic typed-array access. Paths, URLs, shared backing stores, proxies, subclasses and caller getters are not adapter surfaces. Public result objects are frozen; each `copyRgbaBytes()` call returns a separate mutable byte copy. Errors expose a fixed code and the known source identity, without child stderr, source URLs or private transcripts.

## Native restrictions and their measured scope

The fixed Linux x86_64 child runs CPython 3.12.14 under a root-owned `/usr/bin/prlimit`. `-I -S -B` disables environment/user-path influence, system site initialization and bytecode writes. The child environment has only fixed PATH/LANG/LC_ALL values. The worker validates the exact installed wheel files, verifies its loaded runtime closure, loads and initializes the trusted PDFium library, creates its fixed render callback, closes extra descriptors and confirms that it is single-threaded. **Only then** does it set/verify `no_new_privs` and install the mandatory architecture-bound seccomp filter, before the first source-byte read.

The filter defaults to EPERM and allows only the enumerated memory, signal, clock, basic descriptor I/O and exit operations needed by this measured decoder profile. New filesystem opens, path-based metadata/mutation, executable/process/thread creation, socket operations and io_uring are denied. The only remaining descriptors are the fixed byte channels. A failed restriction or enforcement control returns `ISOLATION_UNAVAILABLE` before parsing media. Eight safe invalid-argument native controls verify denial; that count describes the controls, **not a measured count of resource attempts made by a source PDF**.

The maintained native test first establishes that PDFium can load an owned synthetic fixture file. After sealing, PDFium's actual file loader fails, direct native open/unlink/socket/connect controls return EPERM, the owned bytes remain unchanged, and a source received in memory still decodes and renders exact pixels. This is actual native syscall/library evidence, separate from the synthetic worker frames used to test parent protocol validation.

No network namespace or Landlock capability is assumed. No JavaScript API guard is presented as native egress enforcement. This is a bounded application/process restriction profile with OS resource limits; it is not a production host/OS containment acceptance or a claim that every native library vulnerability is eliminated. A trusted installation and host remain prerequisites. The worker does not initialize or lazily allow fonts, models, remote resources or arbitrary native extensions after sealing.

## Reproducible development dependency

The exact reviewed wheel is:

```text
pypdfium2-5.14.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
3799581 bytes
sha256:11f281613fa22313d9c7ab89947665e84eccf8ebe40e1198a84a88352305648d
```

`tools/scanned-pdf/lock.json` pins all 71 archive members and their bytes/hashes. The inspected binary metadata identifies PDFium 156.0.8076.0 from pdfium-binaries with an empty feature-flag tuple; V8/XFA-enabled builds are not admitted. The installer verifies the archive and every RECORD entry before extraction and preserves all 18 bundled license/notice files. It runs no package setup/entrypoint and resolves no transitive package dependency. The runtime worker imports the verified raw bindings directly.

```bash
# Use the declared CPython 3.12.14 and Node 22.23.3 toolchains.
python tools/scanned-pdf/install.py
npm ci
node tools/install-typescript-host.mjs
node tools/verify-scanned-pdf.mjs
./node_modules/.bin/tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM --types node --skipLibCheck false --noErrorTruncation tests/extraction/scanned-pdf/types-consumer.mts
npm run typecheck
```

The first command is an explicit development dependency download from PyPI. For an already acquired exact archive, use `python tools/scanned-pdf/install.py --wheel /approved/path/to/the/exact.whl`. Runtime requests never download, install, repin or provision anything. The generated `tools/scanned-pdf/runtime/` stays ignored and private to that checkout. `python tools/scanned-pdf/install.py --check` verifies an existing installation without replacement.

The installer captures the resolved interpreter, fixed limiter and loaded standard-library source/cache and native shared-library files in a **host-specific** digest/mode receipt. The worker rechecks that exact local closure before reading media, and the parent verifies the interpreter and limiter before spawning them. This records the actual host closure; it does not invent one universal binary digest for every CPython build or attest the broader host image. Reproduce the installation on another declared host, retain that host's receipt, and run the required checks. Unexpected runtime drift fails closed and requires a deliberate reviewed reinstall.

Licensing/provenance: the [publisher's pinned README](https://github.com/pypdfium2-team/pypdfium2/blob/1a9a921f26e2bf4c10754f3efb5172d6a77d43c1/README.md) distinguishes wrapper licenses from PDFium and its bundled dependencies. The [official 5.14.0 distribution](https://pypi.org/project/pypdfium2/5.14.0/) supplies the exact archive metadata. Keep every bundled notice with any later redistribution of those runtime bytes; this source change does not publish a wheel or declare all components covered by a single wrapper license. The exact native member and notice identities are in the lock. Kernel mechanism references: [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html) and [no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html).

## Validation and remaining acceptance

`node tools/verify-scanned-pdf.mjs` requires all 99 maintained cases and zero failed, cancelled, skipped or TODO cases. It records the exact Git revision/tree, complete source-byte map digest, runtime, actual TAP counts and output digests. The dedicated workflow installs the exact dependency and runs these checks plus the strict private consumer and project typecheck; its artifact preserves the dependency lock, elected profile, local runtime receipt and verification summary.

The 99 cases comprise 57 source/admission/API checks (including actual pixel vectors and recovery), 8 lifecycle controls, 24 separately synthetic protocol cases, 1 native filesystem/network/library control with actual raster recovery, and 9 dependency/runtime checks. Actual production provider/media runs and OCR quality cases are not represented by those counts.

EI #12 still needs broader required image/PDF format coverage, bounded OCR or another explicitly accepted observation route, page/box-linked candidate-fact policy, shared-budget/usage integration, durable permission/correction behavior for derivatives, and the canonical/consumer acceptance required by the owning repositories. PNG and JPEG/WebP components have separate owner lanes. EI #8 consumer-visible error mapping and host acceptance remain separate. This private raster slice makes no accepted ResearchAPI, Finance, Creative, permission or master-gate claim.
