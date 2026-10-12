# Bounded local OCR observations

Refs [EI #12](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/12),
[EI #8](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/8),
[gate #22](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/22).
This repository-private slice turns supplied pixels into uncertain English word observations. It does not close those issues or establish canonical facts, consumer acceptance, asset permission, provider performance or a production-host containment claim. It adds no npm package export.

## Supported operation

`readLocalOcr` accepts one tightly packed `gray8` raster or opaque `rgba8` raster. Dimensions, byte length, alpha bytes and the supplied derivative hash must agree. The supplied source hash and page number are retained as **caller-supplied, unverified origin claims**. The caller must establish the original source/evidence relationship; this function only verifies the derivative bytes it receives.

The exact English `tessdata_fast` model, LSTM engine mode 1 and single-block page segmentation mode 6 are fixed. This is a narrow printed-English interpretation profile. It neither detects the actual language nor guarantees that mixed scripts, handwriting, rotated text, unusual layouts or low-quality text are correctly recognized. Those inputs can yield incorrect or empty observations and still require inspection. Model scores are uncalibrated engine scores, not probabilities or factual verification.

No URL, path, encoded image/PDF, model selection, language override, font, configuration file or provider is accepted. Decode a supported source with its separately bounded media reader first. The OCR reader does not broaden another reader's supported formats or route acquisition through a different network path.

```js
import { readLocalOcr } from "../../src/extraction/local-ocr/index.mjs";

// `page` is an already-produced opaque RGBA derivative from a trusted caller's
// bounded source-reader operation. Supplying these fields grants no authority.
const observation = await readLocalOcr({
  bytes: page.copyRgbaBytes(),
  width: page.width,
  height: page.height,
  format: "rgba8",
  source: {
    sha256: sourcePdfSha256,
    page: page.page,
    derivativeSha256: page.sha256,
  },
}, { signal, timeoutMs: 10000, maxWords: 2048, maxTextBytes: 32768 });

if (observation.kind === "observed") {
  // Each token retains its box and source/page/derivative provenance. Keep these
  // words quarantined and review-required; do not promote them to accepted facts.
  for (const word of observation.words) {
    inspectLiteralToken(word.text, word.box, word.confidence, word.provenance);
  }
}
```

The result is immutable. `kind: "observed"` always carries `completeness: "incomplete-unverified-ocr"` and `requiresReview: true`. Every token has a top-left pixel box, Tesseract block/paragraph/line/word indices, the declared page and original source hash, and the verified derivative hash. Word strings remain literal engine tokens; this API does not reconstruct original whitespace or infer event fields. It preserves low-confidence words rather than dropping uncertainty. `status: "no-text-observed"` means this engine/profile produced no words, not that the source contains no text. A refusal has no word collection, so failure cannot be mistaken for an empty recognized page.

Untrusted instructions, links, prices or claims recognized as text remain observations. No token authorizes tools, spending, disclosure or creative use. Existing privacy review, evidence storage, conflict/correction, permission and handoff boundaries still need their own host composition and accountable acceptance.

## Exact dependencies and trusted installation

The supported development host is Linux x86_64 with Node **22.23.3**, CPython **3.12.14**, `/usr/bin/prlimit`, `/usr/bin/dpkg-deb` and compatible Ubuntu 24.04 native support libraries. The three exact Ubuntu archive URLs, lengths, SHA-256 values, source descriptors, complete regular-file inventories and notices are recorded in [`tools/local-ocr/lock.json`](../../tools/local-ocr/lock.json). Additional actual source/model correspondence and build/notice provenance are in [`provenance.json`](../../tools/local-ocr/provenance.json).

| Dependency | Pin | Archive SHA-256 |
| --- | --- | --- |
| Tesseract shared library | `5.3.4-1build5`, upstream `5.3.4` | `a38438115dc203b5abc1e6a6b24eb5273ba82161a11faa2f619bf5f7622efb14` |
| Leptonica shared library | `1.82.0-3build4`, upstream `1.82.0` | `c2bb81d58f032b09917c0d50994cce905287a1596304a4e99681a03601456ea8` |
| English fast model | package `1:4.1.0-2` | `b1996b3113c78663f4dd16cf18aa1f288b07e9624f8d4a0ddbd7d9b52a234ba7` |

The model itself is 4,113,088 bytes, SHA-256 `7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2`. All 41 reviewed regular package files, including the three package copyright notices, are staged with mode `0444`; package symlinks are not installed. Package scripts and global installations are not executed. The installer only decompresses the verified package data streams with `dpkg-deb`, verifies each file and copies those exact bytes into the ignored local runtime directory.

From the repository root, use either ordinary development dependency intake or the three already-acquired offline archives:

```sh
python tools/local-ocr/install.py
# Or: python tools/local-ocr/install.py --archives /absolute/path/to/exact-archives
python tools/local-ocr/install.py --check
npm ci
node tools/install-typescript-host.mjs
node tools/verify-local-ocr.mjs
./node_modules/.bin/tsc --noEmit --strict --target ES2022 --module NodeNext \
  --moduleResolution NodeNext --lib ES2022,DOM --types node --skipLibCheck false \
  --noErrorTruncation tests/extraction/local-ocr/types-consumer.mts
npm run typecheck
```

The installer is a trusted development action. Its optional HTTPS downloads are dependency acquisition, not OCR/provider requests. Runtime calls never download or provision anything. Ubuntu source-descriptor signatures were not locally verified; exact reviewed archive/source bytes and file digests are pinned. The model tag's GitHub signature verification is separately attributed in the provenance record, not substituted for local archive verification.

The native engine is initialized with the exact model before any source bytes are read. Initialization checks the actual engine version, Leptonica version, single loaded language, engine mode and page segmentation mode. The selected Tesseract and Leptonica libraries must actually be mapped from the staged paths. CPython executable/modules, the limiter and all other mapped native files are recorded with absolute path, mode, size and SHA-256 in a **host-specific trusted installation receipt**. Every worker recomputes and compares that complete loaded closure before input. The parent checks the limiter and interpreter identities before launching them. No request silently re-baselines drift.

This is not a portable byte-identical OS image or a source-reproducible rebuild of all system libraries. Other native dependencies are provided by the declared compatible host and bound by its installation receipt; available distro source/version/copyright metadata and copied notices are retained separately. Runtime-owned files without distro package metadata are explicitly labeled as file-digest-only provenance. Missing libraries, changed models, unsupported interpreters or unavailable enforcement fail the required route; they do not become skipped passes. Replacing an installation is an explicit development operation, with the old receipt/results preserved.

## Native and process boundary

The wrapper launches a detached child with only stdin/stdout byte pipes, ignored stderr and a fixed minimal environment. `OMP_THREAD_LIMIT=1` and `OMP_NUM_THREADS=1` are set before loading Tesseract. After trusted initialization, the worker verifies that the real process has one thread, closes every descriptor above 2, sets/verifies `no_new_privs`, and installs a mandatory x86_64 seccomp default-deny policy. No source pixels are read until enforcement succeeds.

The narrowly allowed syscalls support existing pipes, memory management, signals, clocks, pid/tid and futex. The policy denies new descriptors, filesystem opening/path metadata/deletion, sockets/connect, process/thread creation, exec, io_uring and namespaces. It includes eight explicit denial controls. Those controls count deliberate enforcement probes, **not attempts made by an input**. No native networking absence is inferred from JavaScript guards. The shipped library is compiled with dependencies including curl/archive/OpenMP; containment relies on the measured syscall boundary and closed descriptor set, not on a claim that such symbols were omitted.

Maintained tests first demonstrate that a valid owned native Tesseract config can change its mode before sealing. After sealing, native config reads/writes and model reopening fail, libc open/unlink fail, an inherited owned descriptor is closed, and actual OCR still recognizes the synthetic pixels. Separate tests require actual child cancellation/close and recovery. These tests establish the declared child boundary, not complete OS containment or all possible native exploit resistance. The current environment cannot create the requested network namespaces; no namespace grant is assumed.

## Ceilings, deadlines and refusals

| Boundary | Fixed ceiling |
| --- | --- |
| Input | 16 MiB, exactly one tightly packed raster |
| Dimensions/pixels | 4,096 per dimension; 4,194,304 pixels |
| Declared source page | integer 1–10,000; one page per invocation |
| Output tokens | 2,048 words; 32,768 combined UTF-8 token bytes |
| Internal/native output | 256 KiB TSV; 512 KiB framed observation JSON |
| Per Node process queue | one active child, four waiting requests |
| Original wall-clock allowance | 10 seconds default; 30 seconds maximum |
| Native process limits | 1 GiB address space, 5 CPU seconds, 64 descriptors, no core file |

Options may lower the wall-clock, word and token-byte limits. The original deadline starts before input snapshot/hash and runtime checking, includes queue time, child initialization, recognition and parent result validation, and is checked again after synchronous parent work. Queued expiry never starts a child. Cancellation/timeout kills the owned process group; the active slot and result stay pending until the child's actual `close` event. There is no fresh cleanup allowance or automatic retry. A subsequent independent request can recover after a refusal or native crash.

The native TSV parser validates the page row, word ordering, finite scores, exact columns, UTF-8, controls and pixel bounds. The parent independently checks the fixed protocol, engine/model/runtime/source binding, requested limits, token byte counts, boxes and word identities. Excess output is rejected wholly; required words are not silently truncated. Raw stderr and native exceptions are not returned to callers. Errors are fixed private codes such as `INVALID_PROVENANCE`, `UNSUPPORTED_RASTER`, `RUNTIME_MISMATCH`, `ISOLATION_UNAVAILABLE`, `OUTPUT_LIMIT`, `CANCELLED`, `TIMEOUT` or `OCR_FAILURE`; these are not newly invented canonical Research API enums.

## Evidence and remaining acceptance

The dedicated workflow runs all **122** maintained Node cases, including a required case that executes all **26** synthetic TSV parser vectors. Counts distinguish real native execution on synthetic raster fixtures from simulated worker protocol/lifecycle cases. No model benchmark, public event accuracy, provider/OCR service, paid request, downstream consumer ACK or factual acceptance is claimed. The checked-in 220,000-byte synthetic raster has fixed hashes and generation/font provenance; no fonts are loaded by the runtime OCR reader.

`tools/verify-local-ocr.mjs` records the actual Git revision/tree, complete source-file map, source unchanged check, exact commands/counts and output digests. Each execution gets its own retained attempt directory, including failures; `verification.json` is only the latest pointer. The workflow preserves these records with dependency/runtime receipts and notices. Unsupported runtime, execution failure, skipped/cancelled/TODO cases or unexpected test counts fail qualification.

Remaining EI12 scope includes accepted application composition across all supported media, explicit handling and review of unreliable/mixed-layout recognition, evidence persistence and downstream interpretation. Screenshot/image/PDF features outside each predecessor's declared profile, accepted canonical contract mapping, metering/host policy and Creative/Assembly acceptance remain separate. The local implementation can be reviewed and merged without inventing those owner decisions.

Primary implementation references: [Tesseract 5.3.4 C API](https://github.com/tesseract-ocr/tesseract/blob/5.3.4/include/tesseract/capi.h), [raw-image API semantics](https://github.com/tesseract-ocr/tesseract/blob/5.3.4/include/tesseract/baseapi.h), [official trained-data profiles](https://tesseract-ocr.github.io/tessdoc/Data-Files.html), and the exact Ubuntu source descriptors in the dependency lock. These describe engine mechanics; the local receipts and tests establish this slice's observed behavior.
