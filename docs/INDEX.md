# Documentation index

Use this map to choose a maintained guide. The package exports only controlled-retrieval security APIs; local modules and tests do not establish an app consumer or acceptance.

## Start here
- [Components and command map](components.md) describes current source surfaces and checks.
- [Controlled retrieval](security/controlled-retrieval.md) is the network security boundary. Follow its origin, DNS, redirect, response-size, timeout and content-type rules.
- [Private retrieval](discovery/private-retrieval.md) and [content boundary](privacy/content-boundary.md) describe separate restrictions; neither trusts fetched page content.

## Processing and review
- [Text and PDF extraction](extraction/text-pdf.md), [bounded frontier](discovery/bounded-frontier.md), [source identity](discovery/source-identity.md), and [occurrence identity](discovery/occurrence-identity.md) cover candidate processing.
- [Provenance store](evidence/provenance-store.md), [immutable history](review/immutable-history.md), [correction/cache binding](review/correction-cache-binding.md), and [scoped reuse](cache/scoped-reuse.md) describe traceability and reuse.
- [Asset source discovery](brand-research/asset-source-discovery.md), [asset permissions](security/asset-permissions.md), and [safe assets](security/safe-assets.md) govern candidate assets and permitted use.

## Contracts
[Consumer handoff](contracts/consumer-handoff.md) and the [installed 0.9.7 diagnostic](contracts/installed-research-consumer-0.9.7.md) describe compatibility and the incompatible hold. [Provider readiness](providers/readiness-handoff.md) describes the pending provider/account readiness boundary. See [ownership](architecture/OWNERSHIP.md) and [acceptance allocation](architecture/ACCEPTANCE.md); current acceptance is in the master tracker.
