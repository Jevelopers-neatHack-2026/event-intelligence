# Private declarations from retained HTML

Refs [issue18 AC1](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/18).
This is a private deterministic source reader for a small supported subset of
color and typography declarations. It supplies attributable observations for
later review. It does not establish an official palette, rendered appearance,
company identity, available font, font license, asset role or reproduction rights.
It makes no network or provider request and creates no model observation.

## Source and authority boundary

`createBrandDeclarationReader({ evidenceStoreOptions, deadlineMs })` constructs
the actual existing EvidenceStore. The host supplies its authenticated tenant,
key, retention and private-access callbacks. There is no default allow policy.
The adapter owns the private payload consumer; an arbitrary store object or a
request-supplied payload callback is not accepted. Its exposed `evidenceStore`
retains existing methods for ingest, lookup and other store operations. Ordinary
direct `withPrivatePayload` calls refuse because they do not carry the adapter's
opaque active-operation token.

`reader.read({ evidence, request, signal })` accepts a genuine evidence handle and
current host request. It reopens raw retained HTML with the current tenant, key,
ACL and retention checks. The complete source must be reconstructed from
contiguous exact text-range positions, each with its original byte hash. The
full reconstructed bytes must match the retained full-source hash. Excerpt-only,
derived PDF and asset representations refuse. The bytes are copied before
parser awaits, then cleared on cleanup. JavaScript source strings and already
returned authorized snapshots cannot be reliably zeroized or retracted.

After parsing, the adapter reopens the same evidence again and checks exact
source identity, expiry and current access. Final synchronous authority runs
after serialization and the configured clock; native elapsed/retention guards
run after that callback. A revocation, tenant change, unavailable key, expiry,
cancellation or original deadline prevents return of a partial result.

EvidenceStore handles are module-branded references, not per-adapter permission.
A genuine handle can be used with another genuine store for the same underlying
scope, subject to fresh host authorization. Copies cannot. After process restart,
the host obtains a fresh scope and looks up the durable evidence ID through the
store before reading. No cross-process opaque capability or durable permission
is introduced here.

## Supported declaration profile

Profile `ei-private-html-brand-declarations/1` uses the locked parse5 parser and
the repository's existing UTF-16-to-UTF-8 source-offset mapping. Input must be
UTF-8 `text/html`, with no conflicting MIME or in-document charset declaration.
XHTML, stylesheet documents and binary media are outside this profile.

| Source | Accepted value |
| --- | --- |
| `<meta name="theme-color" content="…">` | Exact `#RGB` or `#RRGGBB` |
| Inline `color` or `background-color` declaration | Exact `#RGB` or `#RRGGBB`, with ASCII CSS whitespace |
| Inline `font-family` declaration | Comma-separated quoted ASCII names of at most64 characters, or `serif`, `sans-serif`, `monospace`, `cursive`, `fantasy`, `system-ui`; at most8 entries |

Hex values normalize to lowercase six-digit hex. Quoted font names retain their
spelling and have kind `declared-name`; generic names have kind `generic-family`.
Neither kind proves font installation, glyph coverage, selection by a browser or
licensing. The original exact declaration and its byte range remain alongside
the normalized observation. The containing start-tag range retains the location
of conditional or contextual attributes without evaluating them. Repeated
declarations on different elements remain separate; no document-wide winner or
official brand is selected.

No stylesheet, selector, cascade, inheritance, media query, CSS variable, URL,
function, escape, comment or `!important` is evaluated. Scripts, noscript and
template contents are not evaluated. Entire foreign SVG/MathML subtrees are
excluded, including HTML-namespace descendants under integration points such as
SVG `foreignObject` and MathML `annotation-xml`. Ordinary HTML siblings remain
eligible. Stylesheet blocks and external stylesheet links receive fixed
unsupported observations and are never fetched. Other unrelated CSS properties
do not become brand observations. Complex or malformed style attributes receive
an unsupported observation, not a repaired partial CSS interpretation. Duplicate
relevant declarations in one attribute are ambiguous and the whole attribute is
unsupported. Duplicate HTML attributes or other parse errors, except missing
doctype, refuse the document rather than selecting parse5's recovered first value.

Attribute entity decoding and CR normalization can change text relative to the
original source. This first profile requires decoded attribute text to equal its
exact original raw value; otherwise the attribute is explicitly unsupported.
It never projects decoded characters onto a false raw byte range. Color names,
alpha colors, arbitrary unquoted family names and non-ASCII family syntax are
unsupported. The subset is deliberately bounded; absence of supported values
does not establish that the page has no palette or typography.

## Output and bounds

Output is an immutable **private snapshot**, not a continuing access capability.
It retains evidence ID/version, original source origin/URL/retrieval/expiry,
full-source hash, exact declaration and containing-element UTF-8 ranges, and
the declaration excerpt hash. Hashes identify source bytes; they do not establish
authenticity, source independence or approved use.

Every result remains `tenant_private`, `untrusted_source_declarations`,
`incomplete-supported-subset`, `canonicalAdoption: false`, `not_dispatched`, with
unknown official brand, font availability and permission. The status is either
`declarations_observed` or `no_supported_declarations`; unsupported observations
remain explicit. The adapter does not publish a fact, change an asset descriptor,
prepare a role question, send a Creative payload or choose a canonical wire schema.

| Resource | Fixed ceiling |
| --- | --- |
| Retained complete source | 512KiB /128 contiguous positions; the existing store's independent per-position and aggregate limits still apply |
| Parsed nodes | 20,000 |
| Supported plus unsupported observations | 64 total |
| Relevant HTML attribute token | 4,096 UTF-16 code units |
| Returned individual declaration | 256 UTF-16 code units |
| Serialized output | 32KiB UTF-8 |
| Original elapsed operation | 2,500ms default and maximum, lower-only configurable |
| Active operation per adapter | One; another read returns `BUSY` |

Every resource overflow rejects the whole read; there is no successful prefix.
An oversized retained input may be refused by the existing store before this
adapter's consumer runs. The test names and evidence distinguish that upstream
refusal from adapter-owned parser bounds.

The original captured monotonic deadline includes source opening, parser work,
final reopening and return validation. Parsing yields through native scheduling;
cancellation and elapsed guards apply before/after awaited work and before return.
Clock/authority/key callbacks are trusted in-process host code and cannot be
preempted. An unresolved callback retains the adapter's capacity after timeout or
cancellation until the underlying operation settles; late private reads refuse.
This prevents repeated cancellations from refunding unknown pending work.
There is no OS sandbox or network-isolation claim. The source reader imports no
network transport; the negative fetch spy proves only its covered call path.

## Verification and remaining acceptance

Use pinned Node22.23.3 and the locked host TypeScript compiler:

```sh
node tools/verify-brand-declarations.mjs
node --test tests/brand-declarations/verifier.test.mjs
./node_modules/.bin/tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM --types node --skipLibCheck false tests/brand-declarations/types-consumer.mts
npm run typecheck
```

The dedicated workflow runs those commands after fresh locked dependency setup.
The dedicated verifier requires exactly57 maintained reader cases, independently
of the number that enqueued, and rejects failures, cancellations, skips, TODO and
incomplete case counts. A separate four-case verifier-only suite runs disposable
synthetic complete/missing/reduced/skipped inventories; it does not recursively
run itself and its synthetic passes are not reader behavior evidence. Fixtures use actual native SQLite and the actual pinned HTML parser,
with synthetic sources, encryption keys, retention and host authority. Grammar
unit cases and explicitly labeled parser-phase cancellation instrumentation are
separate from native-time deadline cases. These are local mock-mode results.

Current roles, real issuer/rights verification, canonical producer/consumer
acceptance, actual metering and Creative handoff remain separate obligations.
This partial source-declaration contribution does not complete AC1, issue18,
release gate22 or epic1.
