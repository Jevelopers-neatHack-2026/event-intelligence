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

The supported development host is Linux x86_64 with Node **22.23.3**, CPython **3.12.14**, `/usr/bin/prlimit`, `/usr/bin/dpkg-deb` and compatible Ubuntu 24.04 native support libraries. The four exact Ubuntu archive URLs, lengths, SHA-256 values, source descriptors, complete regular-file inventories and notices are recorded in [`tools/local-ocr/lock.json`](../../tools/local-ocr/lock.json). Additional actual source/model correspondence and build/notice provenance are in [`provenance.json`](../../tools/local-ocr/provenance.json).

| Dependency | Pin | Archive SHA-256 |
| --- | --- | --- |
| Tesseract shared library | `5.3.4-1build5`, upstream `5.3.4` | `a38438115dc203b5abc1e6a6b24eb5273ba82161a11faa2f619bf5f7622efb14` |
| Leptonica shared library | `1.82.0-3build4`, upstream `1.82.0` | `c2bb81d58f032b09917c0d50994cce905287a1596304a4e99681a03601456ea8` |
| English fast model | package `1:4.1.0-2` | `b1996b3113c78663f4dd16cf18aa1f288b07e9624f8d4a0ddbd7d9b52a234ba7` |
| Required GIF support library | `libgif7_5.2.2-1ubuntu1.2_amd64.deb` | `8137945ac9167f26d0264f403ffb48a45974f096e8acab5479e33fdba6c28a36` |

The model itself is 4,113,088 bytes, SHA-256 `7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2`. All 46 reviewed regular package files, including the four package copyright notices, are staged with mode `0444`; package symlinks are not installed. Package scripts and global installations are not executed. The installer only decompresses the verified package data streams with `dpkg-deb`, verifies each file and copies those exact bytes into the ignored local runtime directory.

From the repository root, use either ordinary development dependency intake or the four already-acquired offline archives:

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

The native engine is initialized with the exact model before any source bytes are read. Initialization checks the actual engine version, Leptonica version, single loaded language, engine mode and page segmentation mode. The selected Tesseract, Leptonica and GIF support libraries must actually be mapped from the staged paths. CPython executable/modules, the limiter and all other mapped native files are recorded with absolute path, mode, size and SHA-256 in a **host-specific trusted installation receipt**. Every worker recomputes and compares that complete loaded closure before input. The parent checks the limiter and interpreter identities before launching them. No request silently re-baselines drift.

This is not a portable byte-identical OS image or a source-reproducible rebuild of all system libraries. Other native dependencies are provided by the declared compatible host and bound by its installation receipt; available distro source/version/copyright metadata and copied notices are retained separately. Runtime-owned files without distro package metadata are explicitly labeled as file-digest-only provenance. Missing libraries, changed models, unsupported interpreters or unavailable enforcement fail the required route; they do not become skipped passes. Replacing an installation is an explicit development operation, with the old receipt/results preserved.

### Initialization evidence, including failed attempts

Every invocation that reaches the fixed `--describe-runtime` initializer creates a unique directory under `tools/local-ocr/runtime/initialization-attempts/`. It records the actual command, interpreter identity, startup phase, exit/signal/timeout and child reaping state, source revision/tree and complete before/after file maps, and bounded structured projections of stdout/stderr. Files use exclusive creation and read-only modes; subsequent installs or checks create new attempt directories and never replace or delete earlier ones. A started attempt without a final summary is incomplete evidence, not a success.

The child has no stdin source, and the receipt does not dump environment values or media. Existing exact model/library checks, the fixed minimal environment and prlimit values remain unchanged. Capture retains at most256KiB stdout and64KiB stderr; an exceeded cap fails initialization and stops the owned process group. The original20-second startup allowance includes source binding and validation, with one shared1-second kill/reap allowance; filesystem evidence writes are separate bounded I/O and are not a hard host I/O latency guarantee. Source inventory is bounded to4096 entries,16MiB per entry and64MiB total. A changed source map fails the attempt. Captured-prefix hashes, observed/captured/stored byte lengths, cap/sanitization truncation and observed EOF are recorded separately; a discarded suffix is never presented as a complete stream.

Only `--describe-runtime`, before any source input, can emit a bounded schema2 exception diagnostic with its phase, a recognized exception type, fixed classification, integer errno when available, and up to eight known source frame names/line numbers. Unknown frame/type identifiers become fixed markers. Exception messages are never stringified or retained. It includes no locals, environment, model bytes or unrestricted traceback. The actual `--recognize` path retains its fixed rejection protocol and exposes no added startup diagnostic. These records are for the trusted developer initializer, never arbitrary caller-controlled commands or secret-bearing request data.

A failure of either fixed Leptonica or Tesseract `CDLL` load can additionally emit **schema3** with a `loader` object containing only `target`, `reason` and `dependency`. The target is a source-owned label. Only an exact built-in `OSError` with a single exact built-in string argument of at most4096 characters is considered for classification; exception/subclass stringifiers and argument getters are never called. Two complete message forms are recognized: an exact direct `DT_NEEDED` soname followed by `: cannot open shared object file: No such file or directory` or `: cannot open shared object file: Permission denied`. Their reasons are `dependency_not_found` and `dependency_permission_denied`. The allowed sonames are read from the two already-pinned ELF files and independently checked by the maintained test. No path, suffix, version, symbol or other fragment is copied from the message. An unknown prefix/suffix, transitive or unlisted soname, non-string/custom argument, multiple arguments, oversized message or other loader condition stays `unclassified` with `dependency: null`. An exception subclass or custom exception dictionary receives no added loader fields. This is a narrow diagnosis of an actually observed response, not a prediction that a missing library caused an earlier failure.

The collector accepts only complete JSON containing validated fixed descriptor/error fields or the exact schema2/schema3 worker diagnostic. It independently validates every loader target, reason and target-specific dependency, rejects extra fields and invalid combinations, and requires the initialization/OSError phase for schema3. It validates values as well as keys, refuses duplicate keys, and hashes descriptor path strings instead of retaining arbitrary child-provided paths. Unrecognized, invalid, incomplete or truncated streams are replaced by a fixed omission reason. Captured-prefix lengths/hashes and observed EOF remain available; omitted text cannot return through an error fallback. A validated descriptor projection is diagnostic evidence, not a replacement for the existing native descriptor verification or a new installation authority. Raw subprocess text is not retained, including apparently benign free-form messages: arbitrary text has no reliable credential grammar.

Inspect the attempt's `summary.json`, `stdout.txt` and `stderr.txt` when initialization fails. A validated pre-input worker rejection preserves its actual fixed code; the startup-only phase/type/errno/source-frame diagnostic can narrow the actual condition without inferring a host or dependency cause. An unknown code remains absent, not copied as arbitrary text. A validated fixed error core can retain its known code in the summary even when extra fields make the raw stream unrecognized and omitted. `initialized` means only that the startup response passed the existing manifest-key check. A full installation still requires the exact descriptor/receipt comparison and the remaining installation steps. An absent runtime manifest is not silently adopted by `--check`; preserve the failed runtime and its attempt records before any explicit replacement. Archive acquisition failures before the initializer retain their existing intake behavior and are not described as completed startup attempts.

The always-upload CI path includes every initialization attempt even if native setup fails before npm, tests or typechecks. The two original PR90 OCR jobs on `0fdf4e3afaf9a3aa90d6668726e2e7f2ac8c5929` failed before the122-case route. Their uploaded archives contained only nine static profile/dependency/notice files because the prior installer discarded its captured startup response. Those runs and all required downstream skips remain failures. The original hosted condition is unknown until an actual subsequent initializer response supplies it; this diagnostics change does not elect a different native dependency or weaken a check.

The first diagnostics candidate `4bcbc0020de0052a0ca2568ef035fbb1654d3cfd` passed its139 local cases but failed an independent2-of-4 privacy control: quoted credentials containing spaces and a URL truncated before its userinfo delimiter leaked synthetic message canaries. Those failures remain preserved. The structured-only schema deliberately removes that candidate's promise to retain benign arbitrary messages; the original probe's benign-message predicate is therefore historical, while its confidentiality predicates stay applicable. Direct collector controls separately test quoted, oversized/truncated, unrecognized JSON, extra/unknown structured fields and duplicate keys so suppressing worker messages cannot hide a collector leak.

The structured-only candidate `c014f1e6fc534631a70c0195a8f3b1c9fa1dfb60` passed its151 local cases but an independent pre-input worker-to-collector control found its known-code list omitted the existing `MODEL_UNAVAILABLE` engine initialization refusal. The collector now retains that fixed code alongside `INVALID_OPTIONS`, `RUNTIME_MISMATCH`, `OUTPUT_LIMIT` and `OCR_FAILURE`; unknown code strings remain omitted. The injected existing-code regression verifies preservation without claiming the native initialization failure actually occurred or diagnosing the original hosted failure.

The published structured follow-up `f66a5bc65224b64c291389e0bddf8427f04bdba1` subsequently failed both natural hosted OCR initializations on its exact tree. Those immutable attempts now include the original schema2 diagnosis: `initialize`, `OSError`, `operating_system_error`, null errno, and frames reaching the first Leptonica `CDLL` call. They ended with fixed `OCR_FAILURE`, zero child exit, successful reaping and unchanged436-file source maps; required tests/types did not run. The exact dynamic-loader reason was not captured by schema2. Schema3 adds only the closed diagnostic classification above. It neither retroactively supplies that missing observation nor changes dependency pins, search/loading flags, model checks, native restrictions, receipt comparisons or the compatible-host requirement. At that revision, a subsequent actual hosted result was required before choosing a dependency or host correction.

### Pinned GIF support after the observed hosted prerequisite

Both natural hosted initializations on public `19436f9f83a73056d979b628b0fb6ea441c93703` / literal `1f95c9304fd0942322ba09f571220c94b7de19ec` produced the exact schema3 condition `leptonica / dependency_not_found / libgif.so.7`. Their required178-case OCR routes and typechecks did not execute; those failures and skips remain preserved. This supplies the reason for those two attempts only, not the unknown reason for the earlier0f/f66 attempts.

The fourth archive supplies the exact38,904-byte `libgif.so.7.2.0`, SHA-256 `70ac81372d0ddbdf03dbdd7a9f994df625928cedf794b7c0a06c9eac27a4edc3`, and four regular documentation files. Its SONAME is `libgif.so.7`; its sole direct ELF dependency is `libc.so.6` (the amd64 package requires `libc6 >=2.14`), already part of the compatible host. The original source and distribution recipe match the acquired source descriptor's SHA-256 values. The full MIT/ISC package copyright and upstream COPYING are retained without removing notices. No package scripts, global package installation, search-path environment, runtime provisioning or additional format support is introduced.

Before Leptonica initialization, the worker queries the fixed SONAME with `RTLD_NOLOAD | RTLD_NOW`. An existing handle is refused, including an ambient library with a different filename and a prior copy of the exact pin. Each worker initializes once, so no production request needs an existing GIF handle. The worker then loads the verified staged absolute GIF path with the same global visibility needed by Leptonica and checks its actual mapped identity before source intake. A preload error remains inside the fixed startup/recognition refusal boundary; no raw loader text or new diagnostic target is exposed.

The parent/worker source, model, byte/frame/pixel limits, minimal environment, original deadlines, seccomp and actual-close policies remain as declared above. Other host support libraries remain individually bound by the trusted installation receipt. This change does not claim a complete pinned OS image or containment of arbitrary hostile code already executing in the process. The maintained `dlsym`/`dladdr` control proves Leptonica's dependency lookup origin; it is not presented as a proof of every possible ELF relocation/interposition behavior.

An old three-archive runtime fails the new complete-inventory check. Preserve its attempts/manifest and perform an explicit fresh development installation with all four exact archives; `--check` never repairs or silently adopts it. New actual hosted startup and required checks must qualify the correction; an unrelated loader prerequisite, if observed later, remains a distinct result.

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

The dedicated workflow runs all **188** maintained Node cases: the prior122,30 initializer evidence/privacy cases,26 loader-diagnostic cases, and10 pinned-GIF dependency cases, including a required prior case that executes all **26** synthetic TSV parser vectors inside the Node count. The added tests use explicitly synthetic actual child processes for malformed, empty, nonzero, signaled, timed-out, oversized and withheld startup text, plus validated fixed fields. A real pinned worker's pre-input file-mode refusal and successful native closure recovery exercise the actual installer, while separate injected startup exceptions check structured phase/type/errno, quoted/truncated canaries, a forbidden exception stringifier, the existing model initialization refusal and the unchanged `--recognize` privacy boundary. The loader controls independently exercise both source-owned targets, exact known messages, unknown/private messages, custom argument/dictionary/subclass traps, forged collector schemas and a real `dlopen` failure for an absent synthetic local file. They do not claim an injected loader message occurred on CI. An independent test-only ELF decoder verifies both diagnostic allowlists against the actual pinned files; it adds no production parser or dependency. The ten GIF cases verify exact native dependency lookup, real prior named/renamed/exact-pin SONAME refusals before Leptonica, missing/tampered/writable/symlink rejection with actual OCR recovery, and independent ELF identity. One separately labeled fault omits the absolute preload and requires refusal through the real mapped-closure gate or the actual missing-host-library load. Counts distinguish real native execution on synthetic raster fixtures from simulated worker protocol/lifecycle cases. No model benchmark, public event accuracy, provider/OCR service, paid request, downstream consumer ACK or factual acceptance is claimed. The checked-in 220,000-byte synthetic raster has fixed hashes and generation/font provenance; no fonts are loaded by the runtime OCR reader.

`tools/verify-local-ocr.mjs` records the actual Git revision/tree, complete source-file map, source unchanged check, exact commands/counts and output digests. Each execution gets its own retained attempt directory, including failures; `verification.json` is only the latest pointer. The workflow preserves these records with dependency/runtime receipts and notices. Unsupported runtime, execution failure, skipped/cancelled/TODO cases or unexpected test counts fail qualification.

Remaining EI12 scope includes accepted application composition across all supported media, explicit handling and review of unreliable/mixed-layout recognition, evidence persistence and downstream interpretation. Screenshot/image/PDF features outside each predecessor's declared profile, accepted canonical contract mapping, metering/host policy and Creative/Assembly acceptance remain separate. The local implementation can be reviewed and merged without inventing those owner decisions.

Primary implementation references: [Tesseract 5.3.4 C API](https://github.com/tesseract-ocr/tesseract/blob/5.3.4/include/tesseract/capi.h), [raw-image API semantics](https://github.com/tesseract-ocr/tesseract/blob/5.3.4/include/tesseract/baseapi.h), [official trained-data profiles](https://tesseract-ocr.github.io/tessdoc/Data-Files.html), and the exact Ubuntu source descriptors in the dependency lock. These describe engine mechanics; the local receipts and tests establish this slice's observed behavior.
