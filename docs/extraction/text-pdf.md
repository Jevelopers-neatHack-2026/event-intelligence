# Internal text-PDF reader

`src/extraction/pdf/index.mjs` accepts only a caller-supplied `Uint8Array` snapshot. It copies the bytes synchronously, computes their SHA-256 digest, and passes the bounded copy to a supervised child over stdin. It does not accept a path, URL, password, HTTP headers, range request, base URL, loader, or decoder safety override. This is an internal extraction component; it is not exported from the package root or registered as a complete inspection adapter.

The byte limit, copied subview and digest use native typed-array slots rather than caller properties or conversion methods. Node `Buffer` and genuine `Uint8Array` subclasses retain their native byte semantics. Proxies, detached or out-of-bounds views, empty input and shared backing stores are rejected before isolation checks or worker admission. Shared backing stores cannot provide a stable input snapshot while another thread writes them.

The pinned decoder is `pdfjs-dist@6.4.299` (Apache-2.0); `package-lock.json` records the exact package integrity. The reader uses the legacy ESM decoder with the byte-data entry point. It explicitly disables XFA, WASM, font-face creation, system-font lookup, worker fetch, image decoding, image sizing, and canvas-area work. It does not render pages or execute PDF JavaScript. PDF.js 6.4.299 does not expose an `isEvalSupported` option, so the reader does not pass or claim that control.

The repository `.npmrc` sets `omit=optional` so `npm ci` does not install PDF.js's optional native canvas renderer. The lockfile still records optional packages, including PDF.js and TypeScript platform packages. This setting also affects other npm installs run from this repository. The decoder emits optional-canvas and rendering-polyfill warnings when imported without canvas; the supervisor discards child stderr, while preserving typed failure results. The text reader does not need canvas or rendering support.

TypeScript 7.0.2 also ships its compiler as an optional, platform-specific package. Each workflow that invokes `tsc` runs `node tools/install-typescript-host.mjs` after `npm ci`. The helper checks that the exact host package and platform are present in the committed lock, then installs only that pinned package with optional dependencies omitted; it does not edit `package.json` or `package-lock.json`. On Darwin arm64 the equivalent local command is `npm install --no-save --package-lock=false --omit=optional --ignore-scripts --no-audit --no-fund @typescript/typescript-darwin-arm64@7.0.2`. This keeps canvas omitted while making the TypeScript 7 host compiler available.

## Results and limits

Successful results are frozen, private derived observations. They bind to the input byte digest and include the decoder/configuration version, ordered zero-based pages, page dimensions, normalized rotation, and approximate text-item rectangles in top-left viewport points. They do not contain original source byte ranges: decoded PDF text cannot be mapped back to exact source-byte offsets by this reader. Results are untrusted extraction material, not verified facts, provenance records, source authority, permissions, or evidence-store facts.

Every page is marked `requiresInspection: true`, and every successful result, including `no-text`, is marked `incomplete-text-only`. Empty and scanned pages return `no-text` with `NO_EMBEDDED_TEXT`; mixed text/image pages remain incomplete and require inspection even when embedded text is present. This path performs no OCR, image inspection, vision, event-fact inference, or completeness claim. A later reviewed integration must decide how these derived observations can enter evidence workflows.

The fixed ceilings are:

| Resource | Ceiling |
| --- | ---: |
| Input bytes | 20 MiB |
| Pages | 20 |
| Page width or height | 14,400 points |
| Text code units per item | 20,000 |
| Text items | 2,000 |
| Total text code units | 100,000 |
| Child stdout | 2 MiB |
| Outline items / depth | 10,000 / 128 |
| Active child processes / waiting jobs | 1 / 4 |
| Default job deadline / maximum deadline | 15 s / 20 s |

Callers may lower the text, output, and deadline ceilings. They cannot raise the fixed limits or disable supervision. The deadline includes queue wait. Cancellation, timeout, protocol failure, child crash, resource failure, and output overflow return a typed rejection without pages; the parent kills the process group and waits for the child close event before resolving.

## Process containment and platform support

The reader runs only on Linux with a root-owned, executable, non-writable `/usr/bin/prlimit` at that exact path. It applies hard and soft `RLIMIT_AS` of 6 GiB, CPU time of 15 seconds, 64 open files, and a zero core-file limit before starting a fresh Node 22 child. Node's default WebAssembly trap-handler reserves a 10 GiB virtual-memory cage, which exceeds this address-space ceiling even though PDF.js's own WebAssembly use is disabled. The child therefore starts with Node's documented `--disable-wasm-trap-handler` option, which uses inline bounds checks, plus `--max-old-space-size=512`; the latter supplements the OS limit and does not cap ArrayBuffers or process RSS ([Node 22.23.3 CLI documentation](https://nodejs.org/download/release/v22.23.3/docs/api/cli.html#--disable-wasm-trap-handler)). The parent enforces the wall deadline and a hard stdout byte cap, and terminates the child process group on cancellation or failure.

`tests/extraction/pdf/rlimit-probe.c` checks the live kernel values with `getrlimit`, demonstrates that a 7 GiB virtual mapping fails under the 6 GiB address-space limit, and verifies the file-descriptor ceiling. The Linux reader test also starts Node and runs the decoder with these limits applied, using only a checked-in synthetic fixture. The Mac development path has no supported equivalent here and returns `ISOLATION_UNAVAILABLE` before parsing. CI targets Ubuntu 24.04. Other Linux hosts, including the production CloudLinux environment, have not been certified; they must independently meet the same checks before enabling this reader.

The Node permission model and process limits are resource controls, not a malicious-code sandbox. This implementation does not claim that PDF.js or Node is confined against a parser vulnerability. The child receives no application secrets or request headers and never receives an arbitrary filesystem path, but its operating-system identity remains the invoking user. The address-space cap bounds virtual memory; no separate decoded-stream byte counter is exposed by this PDF.js API. Large compressed streams therefore remain bounded by the hard process limit, CPU limit, and deadline, rather than by a per-stream expansion ceiling.

## Rejection and no-egress policy

The reader returns constant typed codes such as `MALFORMED_PDF`, `ENCRYPTED_PDF`, `ACTIVE_PDF_FEATURE`, `REMOTE_REFERENCE`, `UNSUPPORTED_PDF_FEATURE`, `PAGE_LIMIT`, `DIMENSION_LIMIT`, `TEXT_LIMIT`, `OUTPUT_LIMIT`, `RESOURCE_LIMIT`, `CANCELLED`, and `TIMEOUT`. It never includes source text, URL, file name, metadata, exception text, or PDF.js warning text in result diagnostics.

Before parsing, a bounded byte scan decodes PDF name `#xx` escapes and conservatively rejects known active-action, external-reference, attachment, XFA, and object-stream names. Object streams are unsupported so an action dictionary hidden inside one cannot pass this preflight. The reader also rejects JavaScript detected by PDF.js document/page action APIs, any open action, attachments, remote outlines, and all page annotations. This is a rejection policy for the supported byte forms, not a general-purpose PDF sanitizer or a proof that every possible malformed or unknown active construct is absent. The decoder never invokes PDF actions, rendering, remote-resource factories, or file loaders.

The child installs an API-level guard before dynamically importing PDF.js. It blocks and counts calls through Node HTTP(S), sockets, TLS, DNS, `fetch`, and WebSocket APIs. These counters measure attempted calls through those APIs; they are not host firewall or production egress telemetry. The input is supplied as bytes, and the decoder receives no URL or base URL.

The tests use only checked-in synthetic fixtures. The mixed fixture visibly contains a raster-only event poster alongside one short embedded text line; extraction returns only that line and requires inspection, demonstrating that visible page content is missing from the text layer. The compressed-expansion fixture is a small Flate stream that expands to 111,000 extracted PDF text code units; the reader returns `TEXT_LIMIT` before it can produce any page result. A synthetic fragmented-pipe probe verifies that progress is ignored after cancellation or callback failure, terminal errors retain first-error precedence, the caller waits for child close, and queued work resumes only after close; it exercises reader protocol logic, not OS confinement. Tests also cover ordinary and rotated Unicode text, multipage order and geometry, empty/scanned/mixed pages, encrypted and malformed documents, active and remote actions, attachments, giant dimensions, page/text/output ceilings, cancellation, queue saturation, timeout, Linux resource enforcement, and measured blocked network API attempts. `text-pdf.yml` runs on Ubuntu 24.04 with Node 22.23.3. Passing that workflow establishes behavior only on that runner; it does not establish production host confinement, public API integration, OCR, or full issue acceptance.

The registered `deterministic-extraction` verifier route currently collects 50 cases across three test files, including the extractor-owned buffer cleanup cases. The Linux containment test is skipped on Darwin, where the reader fails closed with `ISOLATION_UNAVAILABLE`; the strict verifier route is therefore incomplete on Darwin and must not be reported as a full local pass. Linux CI is required for the complete registered route.
