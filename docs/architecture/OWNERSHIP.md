# event-intelligence ownership and implementation boundary

**Repository status:** Public on GitHub; verified October 12, 2026.
**Proposed owner:** Agent and research.
**Implementation state:** Source includes discovery, extraction, privacy, evidence, review, cache, asset permission and controlled-retrieval modules. The private Node.js 22 package exports only its security API. Local implementation does not establish accepted interfaces or application integration.

## Responsibility

Turn an event URL into a reusable, sourced Event Intelligence Package. Own source discovery, factual extraction, conflict handling, event identity, asset candidates, and research caching.

Keep sourced facts, model inferences, customer corrections, and unresolved questions distinguishable. Record evidence origins and retrieval times. Publicly discovered images remain asset candidates until the applicable permission and approval process is satisfied.

## Current implementation surface

The ESM package export map is limited to the root security API and URL-policy, DNS-resolver, and controlled-fetch subpaths. Other source folders are internal implementation surfaces, not package-level public APIs. Current source includes bounded discovery and occurrence/entity identity; HTML, XHTML, JSON-LD and text-PDF extraction; evidence and provenance stores; privacy and untrusted-content boundaries; correction history and cache binding; scoped reuse; private retrieval and asset-release gates; and asset permission inspection. See the [component map](../components.md) and [controlled retrieval guide](../security/controlled-retrieval.md). No provider adapters or public research-package API are exposed in the export map.

## Integration targets and handoff

Planned integration depends on accepted shared-contracts interfaces, a metered cost-intelligence client, and producer/consumer evidence. The installed research-consumer diagnostic records an incompatible hold; see [consumer handoff](../contracts/consumer-handoff.md) and [installed consumer 0.9.7](../contracts/installed-research-consumer-0.9.7.md). Reused research must retain its original expenditure record; cross-customer attribution requires an accepted allocation policy.

## P0 target slice

Design intent: research one supported event page, preserve references for essential facts, expose one conflicting or missing field, and deliver an approved asset set or clearly identified original-artwork fallback. This is not a completion claim.

## Acceptance boundary

- [ ] Essential event facts are traceable to evidence or explicit customer input.
- [ ] Untrusted page content cannot expand tool permissions.
- [ ] Fetching enforces the agreed network and redirect boundaries.
- [ ] Conflicts and unavailable facts remain visible to downstream consumers.
- [ ] Cached reuse preserves provenance and avoids duplicate expense creation.
- [ ] Asset permission status is carried into creative handoff.

The canonical current-state architecture describes implementation across repositories. The historical v1.0 architecture kit remains design intent: [current organization architecture](https://github.com/Jevelopers-neatHack-2026/getticketstub.com/blob/main/docs/architecture/CURRENT-STATE.md) · [v1.0 design intent](https://github.com/Jevelopers-neatHack-2026/getticketstub.com/blob/main/docs/architecture-kit/v1.0/docs/architecture.md).

Use the [repository acceptance view](ACCEPTANCE.md) for criterion allocation only. Current criteria and evidence live in the [master checklist](https://github.com/Jevelopers-neatHack-2026/integration-evals/blob/main/planning/acceptance-checklist.md) and [JSON tracker](https://github.com/Jevelopers-neatHack-2026/integration-evals/blob/main/planning/acceptance-checklist.json). See the [central implementation plan](https://github.com/Jevelopers-neatHack-2026/getticketstub.com/blob/main/docs/planning/implementation-plan.md), [contract catalog](https://github.com/Jevelopers-neatHack-2026/shared-contracts/blob/main/docs/contract-catalog.md) and [organization contribution guidance](https://github.com/Jevelopers-neatHack-2026/.github/blob/main/CONTRIBUTING.md). Named owner and reviewer assignments remain kickoff decisions.

For a guide-by-topic list, see the [documentation index](../INDEX.md).
