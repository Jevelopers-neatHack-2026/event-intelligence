# Retained source attribution and dependence

The private source composer groups supported declarations of source dependence without electing an authoritative publisher. This contributes concrete local behavior for [issue #10 AC3](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/10): altered copies can remain in one corroboration cluster when retained source evidence explicitly connects them. The policy is owned in this repository's Agent/research implementation scope. It does not change shared-contracts, source authority, a foreign consumer agreement or canonical acceptance.

## Supported evidence

`composeSourceIdentity` returns `ei-source-identity-composition-internal/v2`, with the private graph `ei-source-corroboration-internal/v1` under policy `explicit-source-declaration/v1`. The method is `retained-source-declaration`, version `1`. All clusters retain `independence: "unknown"`, `origin: "not_established"` and `sourceAuthority: "not_evaluated"`.

The bounded declaration profile is a **direct scalar JSON-LD string** at the extracted event or organization's exact RFC 6901 pointer followed by `/isBasedOn`. The parser-owned decoded string supplies the URL; the original serialized UTF-8 byte range, position digest, full-source digest and entity pointer remain attached to the claim. XHTML entity references remain in the exact raw source slice. A valid declaration is appended through the existing evidence store as a separate `sourced` fact with field `isBasedOn`, original `rawValue`, decoded and normalized `normalizedValue`, and the existing evidence support. The method and policy versions belong to the graph; the fact schema is unchanged.

An entity must already have an eligible retained identity claim. A declaration alone does not create an event or organization candidate. Each node keeps the existing evidence-bound, script-block and entity-ordinal identity. Statements belonging to one event on a multi-event page do not join its sibling events.

| Evidence or condition | Result |
| --- | --- |
| Same complete bytes, same entity kind, script/ordinal and pointer | Corresponding entities share an `exact_content` edge. Siblings remain separate. |
| A retained direct `isBasedOn` URL resolves to exactly one retained entity of the same kind on a source with exactly one entity of that kind | A `source_declared_derivation` edge joins those candidates. |
| Target URL absent from the retained input set | Keep the sourced declaration; record `target_not_retained`; do not fetch the target. |
| Several retained targets match, or the target page contains another entity of that kind | Keep the declaration; record `target_ambiguous`. Ineligible entities also count toward ambiguity. |
| A declaration points to its own candidate | Record `self_reference`; do not elect an origin. |
| A retained chain or cycle | Compute bounded transitive clusters; preserve each declaration and its direction; origin remains unestablished. |
| Same name, branding, host, `sameAs`, `@id`, `url`, canonical or Open Graph metadata | These do not establish a derivation edge. Navigation metadata keeps its separate existing use. |
| Object, array, non-string scalar, nested or misleading dotted/escaped property | Do not infer a direct declaration. Nonempty scalar descendants remain unsupported claims when extracted. Empty containers produce no scalar claim. |
| Relative, credential-bearing, query-bearing, fragment-bearing, whitespace-containing or non-HTTP(S) URL | Leave the extracted value unsupported. Do not strip, resolve or fetch it. |

URL matching uses the stored original and final retrieval URLs after conservative HTTP(S) normalization. Matching a URL is not evidence that its publisher is independent or original. A missing edge means only that this retained profile did not establish dependence. Event and organization graphs do not join across kinds. Every support remains explicitly unknown for independence, including single-node clusters.

## Retention, replay and limits

The composer retains the exact selected declaration positions through the existing evidence API and validates all appended facts in its terminal aggregate read. Current authorization, tenant isolation, expiry and source integrity apply to declarations in the same way as other sourced facts. Store handles remain opaque. A denial or expiry releases no composition result; existing multi-source writes are not made atomic by this feature.

Older idempotent evidence may lack a declaration's selected position. The composer preserves that immutable evidence record and its original retrieval/expiry metadata. It records `legacy_position_unavailable`, appends no attribution fact for that position, and creates no declared-dependence edge. It never substitutes newly fetched bytes for a position absent from the old record. Other retained positions and identity facts continue through their existing validation. Mixed legacy and newly retained same-byte sources remain usable, with a separate status for each declaration.

The existing limits of eight sources, 23 identity candidates and 128 total stored facts/selected positions include attribution work. The graph separately caps claims at 128, edges at 256 and serialized UTF-8 bytes at 65,536. Descriptor snapshots bound nesting, node counts, strings and arrays before policy evaluation. Excess work fails the whole operation; it is not truncated or reported as complete. These limits do not certify server latency or memory use.

Graph and cluster digests use versioned, domain-separated hashes over bounded deterministic data. A graph binds source and entity identities, original position digests, declaration status and policy results. Reordering the same retained sources or replaying them after reopening the store preserves the semantic graph digest. Append-generated fact IDs are intentionally excluded from that stable digest. The separately returned `corroborationFactBindings` maps each retained `claimId` to exactly one distinct actual `factId`. Those per-result bindings are included in the current question sidecar's digest. Two entities making identical declarations still retain two facts and two bindings.

## Question preparation and compatibility

The private question adapter accepts explicit historical composition v1 and current v2. Historical v1 keeps its original observation JSON, sidecar version and hashing domains; missing attribution in that historical profile does not establish independence. A malformed v2 cannot silently fall back to v1.

For current v2, the adapter recomputes graph policy and digests, checks entity/source/support identities against the supplied composition, and requires a bijection between retained declarations and the returned attribution facts. It rejects missing facts, reused fact bindings, extra attribution facts, changed source identities, and rehashed graph results inconsistent with their declared policy inputs. These are consistency checks on the supplied private object. They do not authenticate it, validate an arbitrary caller's account of legacy retention, verify a publisher's declaration, or replace a current authorized store read.

Each selected candidate/source observation retains its distinct claims and adds compact `corroboration` context: cluster ID, relationship, edge bases, unresolved count and explicit unknown authority/independence. Shared clusters never collapse the two candidate observations or discard conflicting dates or names. The observation text contains no unselected source URLs or fact values. The private v2 sidecar binds the graph digest, per-result fact bindings, selected clusters/edges and these contexts to the maintained question plan.

All existing question limits remain enforced: 4,096 bytes per text field, 10,000 aggregate bytes counting both `text` and `claimText`, and 65,536 serialized sidecar bytes. Actual v2 composer fixtures reach the exact text/aggregate boundaries with retained declarations, then reject the next input byte. Explicit legacy v1 fixtures continue exercising the historical sidecar boundary. The plan stays unpromoted, not dispatched, without source-officialness or verified-fact authority. No canonical Question/DecisionPort, provider receipt, Creative handoff or acceptance acknowledgement is created.

## Verification

All new source fixtures are synthetic. Tests execute the actual deterministic parser, encrypted SQLite evidence store, composer and private question consumer; they do not perform a public-source or provider request. The regression set covers altered/conflicting copies, exact copies with multiple entities, chains/cycles, ambiguous and missing targets, misleading paths/metadata, unsupported values, XHTML slices, permission and expiry after reopening, actual pinned-v1 replay, fact-binding omissions/reuse, bounds, cancellation and recovery. The frozen predecessor source is acquired from commit `dc97a96d07abd5d7b66c0c18f46021e85fd60cea` with its checked SHA-256; historical fixtures remain unchanged.

Run on the repository's pinned Node 22.23.3 runtime:

```sh
make verify CASE=question-preparation MODE=mock
node --test tests/extraction/*.test.mjs tests/evidence/*.test.mjs tests/discovery/identity/*.test.mjs
node --test tests/research/private-retrieval.test.mjs
node --test tests/contracts/installed-research-consumer/launcher.test.mjs
npm run typecheck
./node_modules/.bin/tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM --types node --typeRoots node_modules/@types --skipLibCheck false tests/discovery/source-identity/types-consumer.mts tests/decisions/questions/from-source-identity-types-consumer.mts tests/decisions/questions/types-consumer.mts
```

Installed research diagnostics must capture the current local source closure and each exact proposal pin. Diagnostic success does not turn the still-incompatible ResearchBoundary contract into an accepted interface. This local slice leaves issue #10's other scoped outcomes, gate #22 and epic #1 open pending their actual implementations and accountable acceptance.
