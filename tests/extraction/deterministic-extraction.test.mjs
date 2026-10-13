import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { extractDeterministically } from "../../src/extraction/index.mjs";

const FIXTURES = new URL("./fixtures/", import.meta.url);
const SOURCE_URL = "https://events.example.test/calendar";
const FETCHED_AT = "2026-10-10T12:00:00.000Z";

async function fixture(name, contentType = "text/html; charset=utf-8") {
  const bytes = await readFile(fileURLToPath(new URL(name, FIXTURES)));
  return document(bytes, contentType);
}

function document(bytes, contentType = "text/html; charset=utf-8") {
  return { url: SOURCE_URL, fetchedAt: FETCHED_AT, contentType, bytes: Buffer.from(bytes) };
}

function assertExactRanges(result, sourceBytes) {
  const candidates = [
    ...result.canonicalSuggestions,
    ...result.pageMetadata,
    ...result.visibleText,
    ...result.statusMentions,
    ...result.accessSignals,
    ...result.assetSources.map((asset) => asset.candidate),
    ...result.events.flatMap((entity) => entity.candidates),
    ...result.organizations.flatMap((entity) => entity.candidates),
  ];
  for (const candidate of candidates) {
    const { startByte, endByte } = candidate.source.locator;
    assert.ok(startByte >= 0 && endByte >= startByte && endByte <= sourceBytes.length);
    assert.equal(sourceBytes.subarray(startByte, endByte).toString("utf8"), candidate.rawValue);
  }
  for (const entity of [...result.events, ...result.organizations]) {
    if (!entity.source) continue;
    const { startByte, endByte } = entity.source.locator;
    assert.equal(sourceBytes.subarray(startByte, endByte).toString("utf8")[0], "{");
    assert.ok(endByte <= sourceBytes.length);
  }
  for (const block of result.jsonLdBlocks) {
    const { startByte, endByte } = block.locator;
    assert.ok(endByte <= sourceBytes.length);
    assert.ok(endByte >= startByte);
  }
}

test("keeps multiple JSON-LD events separate and preserves exact UTF-8 byte positions", async () => {
  const input = await fixture("multi-event.html");
  const result = await extractDeterministically(input);

  assert.equal(result.status, "PARTIAL");
  assert.equal(result.sourceHash, "sha256:" + createHash("sha256").update(input.bytes).digest("hex"));
  assert.deepEqual(result.parserVersions, {
    html: "parse5@8.0.1",
    htmlStream: "parse5-parser-stream@8.0.0",
    xml: "sax@1.6.1",
    json: `node@${process.versions.node}/JSON.parse+ei-json-index@1`,
  });
  assert.equal(result.events.length, 2);
  assert.deepEqual(result.events.map((event) => event.ordinal), [0, 1]);
  assert.deepEqual(result.events.map((event) => event.jsonPointer), ["/@graph/0", "/@graph/1"]);
  assert.equal(result.events[0].candidates.find((candidate) => candidate.field === "name").normalizedValue, "Café Night 🎵");
  assert.equal(result.events[1].candidates.find((candidate) => candidate.field === "name").normalizedValue, "Fall Relay");
  assert.equal(result.organizations.length, 1);
  assert.equal(result.ambiguities[0].kind, "multiple_event_occurrences");
  assert.equal(result.visibleText.some((candidate) => /secret event text/i.test(candidate.normalizedValue)), false);
  assert.equal(result.visibleText.some((candidate) => /secret display copy/i.test(candidate.normalizedValue)), false);

  const remoteId = result.events[0].candidates.find((candidate) => candidate.source.property === "@id");
  assert.equal(remoteId.suggestionOnly, true);
  assert.equal(remoteId.normalizedValue, "https://remote.example/events/one");
  assert.equal(result.canonicalSuggestions[0].suggestionOnly, true);
  assert.equal(result.canonicalSuggestions[0].urlSuggestion, "https://events.example.test/calendar/fall");
  assertExactRanges(result, input.bytes);
});

test("retains visible cancellation and reschedule copy alongside conflicting metadata", async () => {
  const input = await fixture("conflict-cancellation.html");
  const result = await extractDeterministically(input);

  assert.equal(result.status, "PARTIAL");
  assert.equal(result.statusMentions.length, 1);
  assert.match(result.statusMentions[0].normalizedValue, /Cancelled.*moved to 14 October/i);
  assert.ok(result.conflicts.some((conflict) => conflict.scope === result.events[0].entityId && conflict.field === "name"));
  assert.equal(result.visibleText.some((candidate) => /secret announcement/i.test(candidate.normalizedValue)), false);
  assertExactRanges(result, input.bytes);
});

test("does not infer JS_REQUIRED from an arbitrary script tag", async () => {
  const result = await extractDeterministically(await fixture("script-only-static.html"));
  assert.equal(result.status, "PARTIAL");
  assert.equal(result.visibleText.length, 1);
});

test("reports JS_REQUIRED only for a sparse application shell or explicit noscript requirement", async () => {
  const shell = await extractDeterministically(await fixture("sparse-js-shell.html"));
  assert.equal(shell.status, "JS_REQUIRED");
  assert.equal(shell.visibleText.length, 0);

  const explicit = document(Buffer.from("<html><body><noscript>JavaScript is required to continue.</noscript></body></html>"));
  const requirement = await extractDeterministically(explicit);
  assert.equal(requirement.status, "JS_REQUIRED");
  assert.ok(requirement.diagnostics.some((item) => item.code === "NOSCRIPT_REQUIRES_JAVASCRIPT"));

  const hiddenRequirement = document(Buffer.from('<html><body><div hidden><noscript>JavaScript is required to continue.</noscript></div></body></html>'));
  assert.equal((await extractDeterministically(hiddenRequirement)).status, "NO_ANSWER");
  const directlyHiddenRequirement = document(Buffer.from('<html><body><noscript hidden>JavaScript is required to continue.</noscript></body></html>'));
  assert.equal((await extractDeterministically(directlyHiddenRequirement)).status, "NO_ANSWER");

  const templateShell = document(Buffer.from('<html><body><main id="root"></main><template><script src="/assets/app.js"></script></template></body></html>'));
  assert.equal((await extractDeterministically(templateShell)).status, "NO_ANSWER");
});

test("keeps surrogate pairs intact when callers lower the parser chunk limit", async () => {
  const input = document(Buffer.from("<p>Emoji 😊 after split</p>"));
  const result = await extractDeterministically(input, { limits: { htmlChunkCodeUnits: 1 } });
  assert.equal(result.visibleText[0].normalizedValue, "Emoji 😊 after split");
  assertExactRanges(result, input.bytes);
});

test("preserves BOM, CRLF, entity, and non-ASCII offsets against original bytes", async () => {
  const input = document(Buffer.from(
    '\uFEFF<!doctype html>\r\n<html><head><meta property="og:title" content="Caf&eacute; &amp; 🍵"></head>\r\n<body>\r\n<p>Line\r\n  café 🐈 &amp; tea</p>\r\n</body></html>',
  ));
  const result = await extractDeterministically(input);
  assert.equal(result.pageMetadata[0].rawValue, "Caf&eacute; &amp; 🍵");
  assert.equal(result.pageMetadata[0].normalizedValue, "Café & 🍵");
  assert.ok(result.visibleText.some((candidate) => candidate.normalizedValue.includes("café 🐈 & tea")));
  assertExactRanges(result, input.bytes);
});

test("parses XHTML with XML self-closing, CDATA, entity, and UTF-8 source semantics", async () => {
  const input = document(Buffer.from(
    '\uFEFF<?xml version="1.0" encoding="UTF-8"?>\r\n<!DOCTYPE html SYSTEM "https://remote.invalid/xhtml.dtd">\r\n'
    + '<html xmlns="http://www.w3.org/1999/xhtml"><head><meta property="og:title" content="Caf&#xE9; &amp; 🍵" />'
    + '<script src="/app.js" />'
    + '<script type="application/ld+json"><![CDATA[{"@type":"Event","name":"Café Night"}]]></script></head>'
    + '<body><p>Visible &amp; retained.</p><p><![CDATA[Cancelled: this event will not take place.]]></p></body></html>',
  ), "application/xhtml+xml");
  const result = await extractDeterministically(input);
  assert.equal(result.status, "PARTIAL");
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].candidates.find((candidate) => candidate.field === "name").normalizedValue, "Café Night");
  assert.equal(result.pageMetadata[0].rawValue, "Caf&#xE9; &amp; 🍵");
  assert.equal(result.pageMetadata[0].normalizedValue, "Café & 🍵");
  assert.ok(result.visibleText.some((candidate) => candidate.normalizedValue === "Visible & retained."));
  assert.equal(result.visibleText.find((candidate) => candidate.normalizedValue === "Visible & retained.").rawValue, "Visible &amp; retained.");
  assert.equal(result.statusMentions.length, 1);
  assert.equal(result.statusMentions[0].normalizedValue, "Cancelled: this event will not take place.");
  assert.equal(result.statusMentions[0].rawValue, "Cancelled: this event will not take place.");
  assertExactRanges(result, input.bytes);
});

test("preserves full XHTML canonical and metadata attribute names with XML syntax whitespace", async () => {
  const forms = [
    {
      name: "canonical href",
      render: (attribute, shadow) => `<link rel="canonical" ${attribute}="/canonical-real" ${shadow}="/canonical-noise" />`,
      renderReversed: (attribute, shadow) => `<link rel="canonical" ${shadow}="/canonical-noise" ${attribute}="/canonical-real" />`,
      renderLookalikeOnly: (shadow) => `<link rel="canonical" ${shadow}="/canonical-noise" />`,
      value: "/canonical-real",
      select: (result) => result.canonicalSuggestions,
    },
    {
      name: "Open Graph description content",
      render: (attribute, shadow) => `<meta property="og:description" ${attribute}="real description" ${shadow}="noise description" />`,
      renderReversed: (attribute, shadow) => `<meta property="og:description" ${shadow}="noise description" ${attribute}="real description" />`,
      renderLookalikeOnly: (shadow) => `<meta property="og:description" ${shadow}="noise description" />`,
      value: "real description",
      select: (result) => result.pageMetadata.filter((candidate) => candidate.field === "openGraph.description"),
    },
  ];
  const codePoints = [
    { name: "U+1680", value: "\u1680" },
    { name: "U+FEFF", value: "\uFEFF" },
  ];

  for (const form of forms) {
    for (const codePoint of codePoints) {
      const attribute = form.name.startsWith("canonical") ? "href" : "content";
      const shadow = `${attribute}${codePoint.value}`;
      const cases = [
        { name: "genuine then lookalike", markup: form.render(attribute, shadow), expected: form.value },
        { name: "lookalike then genuine", markup: form.renderReversed(attribute, shadow), expected: form.value },
        { name: "lookalike only", markup: form.renderLookalikeOnly(shadow), expected: null },
      ];

      for (const item of cases) {
        const source = `<html xmlns="http://www.w3.org/1999/xhtml"><head>🧭${item.markup}</head><body></body></html>`;
        const bytes = Buffer.from(source, "utf8");
        const input = document(bytes, "application/xhtml+xml; charset=utf-8");
        const result = await extractDeterministically(input);
        const label = `${form.name} ${codePoint.name} ${item.name}`;
        assert.equal(result.diagnostics.some((diagnostic) => diagnostic.code === "MALFORMED_XHTML"), false, label);
        const selected = form.select(result);
        if (item.expected === null) {
          assert.equal(selected.length, 0, `${label}: Unicode-suffixed attribute is not treated as the exact name`);
          assert.equal(JSON.stringify(result).includes("noise"), false, `${label}: lookalike value is not promoted`);
        } else {
          assert.equal(selected.length, 1, `${label}: genuine ${form.name} remains available`);
          const candidate = selected[0];
          assert.equal(candidate.rawValue, item.expected, label);
          const valueIndex = source.indexOf(item.expected);
          const startByte = Buffer.byteLength(source.slice(0, valueIndex), "utf8");
          const endByte = startByte + Buffer.byteLength(item.expected, "utf8");
          assert.deepEqual(candidate.source.locator, { kind: "text-range", startByte, endByte }, label);
          assert.equal(bytes.subarray(startByte, endByte).toString("utf8"), item.expected, label);
          assert.equal(JSON.stringify(result).includes("noise"), false, `${label}: lookalike value is not promoted`);
        }
        assertExactRanges(result, bytes);
      }
    }
  }
});

test("keeps each legal XML syntax whitespace character between XHTML attribute names and values", async () => {
  for (const whitespace of ["\t", "\n", "\r", " "]) {
    const source = `<html xmlns="http://www.w3.org/1999/xhtml"><head>🧭`
      + `<link${whitespace}rel="canonical"${whitespace}href${whitespace}=${whitespace}"/calendar.xml" />`
      + `<meta${whitespace}property="og:description"${whitespace}content${whitespace}=${whitespace}"venue details" />`
      + `<link${whitespace}rel="icon"${whitespace}href${whitespace}=${whitespace}"/icon.png" />`
      + `</head><body></body></html>`;
    const bytes = Buffer.from(source, "utf8");
    const result = await extractDeterministically(document(bytes, "application/xhtml+xml; charset=utf-8"));
    assert.equal(result.diagnostics.some((diagnostic) => diagnostic.code === "MALFORMED_XHTML"), false,
      `XML whitespace ${JSON.stringify(whitespace)} is accepted`);
    assert.equal(result.canonicalSuggestions[0]?.rawValue, "/calendar.xml");
    assert.equal(result.pageMetadata.find((candidate) => candidate.field === "openGraph.description")?.rawValue, "venue details");
    assert.ok(result.assetSources.some((asset) => asset.sourceForm === "html-icon-link"
      && asset.candidate.rawValue === "/icon.png"));
    assertExactRanges(result, bytes);
  }
});

test("tracks empty, adjacent, chunked, and flushed XHTML CDATA content with source semantics", async () => {
  const emptyAtStart = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><body><p><![CDATA[]]>Cancelled event</p></body></html>',
  ), "application/xhtml+xml");
  const emptyStartResult = await extractDeterministically(emptyAtStart);
  assert.equal(emptyStartResult.statusMentions.length, 1);
  assert.equal(emptyStartResult.statusMentions[0].normalizedValue, "Cancelled event");
  assert.equal(emptyStartResult.statusMentions[0].rawValue, "Cancelled event");
  assertExactRanges(emptyStartResult, emptyAtStart.bytes);

  const emptyBeforeNotice = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>Before <![CDATA[]]>Cancelled event</p></body></html>',
  ), "application/xhtml+xml");
  const emptyResult = await extractDeterministically(emptyBeforeNotice);
  assert.equal(emptyResult.statusMentions.length, 1);
  assert.equal(emptyResult.statusMentions[0].normalizedValue, "Before Cancelled event");
  assert.equal(emptyResult.statusMentions[0].rawValue, "Before <![CDATA[]]>Cancelled event");
  assertExactRanges(emptyResult, emptyBeforeNotice.bytes);

  const emptyThenNonemptyCdata = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><body><p><![CDATA[]]><![CDATA[Cancelled event]]></p></body></html>',
  ), "application/xhtml+xml");
  const emptyThenCdataResult = await extractDeterministically(emptyThenNonemptyCdata);
  assert.equal(emptyThenCdataResult.statusMentions.length, 1);
  assert.equal(emptyThenCdataResult.statusMentions[0].normalizedValue, "Cancelled event");
  assert.equal(emptyThenCdataResult.statusMentions[0].rawValue, "Cancelled event");
  assertExactRanges(emptyThenCdataResult, emptyThenNonemptyCdata.bytes);

  const adjacent = document(Buffer.from(
    '\uFEFF<?xml version="1.0" encoding="UTF-8"?>\r\n'
    + '<html xmlns="http://www.w3.org/1999/xhtml"><body><p><![CDATA[Before 😊]]><![CDATA[]]><![CDATA[ Cancelled event]]></p></body></html>',
  ), "application/xhtml+xml");
  const adjacentResult = await extractDeterministically(adjacent, { limits: { htmlChunkCodeUnits: 257 } });
  assert.equal(adjacentResult.statusMentions.length, 1);
  assert.equal(adjacentResult.statusMentions[0].normalizedValue, "Before 😊 Cancelled event");
  assert.equal(adjacentResult.statusMentions[0].rawValue, "Before 😊]]><![CDATA[]]><![CDATA[ Cancelled event");
  assertExactRanges(adjacentResult, adjacent.bytes);

  const chunkSize = 257;
  const boundaryPrefix = '<html xmlns="http://www.w3.org/1999/xhtml"><body><p><![CDATA[';
  const boundaryPayload = "x".repeat(chunkSize - boundaryPrefix.length - 1) + "😊" + "y".repeat(20_000) + " Cancelled event";
  const boundaryInput = document(Buffer.from(`${boundaryPrefix}${boundaryPayload}]]></p></body></html>`), "application/xhtml+xml");
  const boundaryResult = await extractDeterministically(boundaryInput, { limits: { htmlChunkCodeUnits: chunkSize } });
  assert.equal(boundaryResult.statusMentions.length, 1);
  assert.equal(boundaryResult.statusMentions[0].normalizedValue, boundaryPayload);
  assert.equal(boundaryResult.statusMentions[0].rawValue, boundaryPayload);
  assertExactRanges(boundaryResult, boundaryInput.bytes);

  const longText = "x".repeat(100_000);
  const longCdata = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><body><p><![CDATA['
    + longText + " Cancelled event]]></p></body></html>",
  ), "application/xhtml+xml");
  const longResult = await extractDeterministically(longCdata);
  assert.equal(longResult.status, "PARTIAL");
  assert.equal(longResult.statusMentions.length, 1);
  assert.equal(longResult.statusMentions[0].normalizedValue, `${longText} Cancelled event`);
  assert.equal(longResult.statusMentions[0].rawValue, `${longText} Cancelled event`);
  assertExactRanges(longResult, longCdata.bytes);

  const longDescription = "x".repeat(100_000);
  const longJsonCdata = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><head><script type="application/ld+json"><![CDATA['
    + JSON.stringify({ "@type": "Event", name: "Long XHTML JSON", description: longDescription })
    + ']]></script></head><body><p>Cancelled after long JSON.</p></body></html>',
  ), "application/xhtml+xml");
  const longJsonResult = await extractDeterministically(longJsonCdata);
  assert.equal(longJsonResult.events.length, 1);
  assert.equal(longJsonResult.events[0].candidates.find((candidate) => candidate.field === "description").normalizedValue, longDescription);
  assert.deepEqual(longJsonResult.jsonLdBlocks.map((block) => block.status), ["parsed"]);
  assert.ok(longJsonResult.statusMentions.some((candidate) => /Cancelled after long JSON/.test(candidate.normalizedValue)));
  assertExactRanges(longJsonResult, longJsonCdata.bytes);
});

test("discovers bounded HTML and JSON-LD asset source claims from exact parser locators", async () => {
  const bytes = Buffer.from(`<!doctype html><html><head>
    <meta property="og:image" content="https://img.example.com/page&amp;cover.png">
    <link rel="apple-touch-icon" href="//cdn.example.com/icon.png">
  </head><body>
    <img src="../poster.png?size=small&amp;v=2" alt="unverified claim">
    <script type="application/ld+json">${JSON.stringify({
      "@context": "https://schema.org",
      "@graph": [
        {
          "@type": "Event", name: "Same-name festival",
          image: ["https://img.example.com/event-a.png", { "@type": "ImageObject", url: "/event-a-2.png" }],
          organizer: { name: "Unverified host", logo: { url: "//cdn.example.com/claimed-host.svg" } },
          "organizer.logo": "https://img.example.com/literal-dotted-key.svg",
          "image.url": "https://img.example.com/literal-image-key.svg",
          "image/0/url": "https://img.example.com/literal-slash-key.svg",
        },
        {
          "@type": "Event", name: "Same-name festival",
          image: "https://img.example.com/event-b.png",
        },
      ],
    })}</script>
  </body></html>`);
  const input = document(bytes);
  const result = await extractDeterministically(input);
  assert.equal(result.status, "PARTIAL");
  assert.equal(result.assetSourcesTruncated, false);
  assert.equal(result.events.length, 2);

  const forms = result.assetSources.map((asset) => asset.sourceForm);
  assert.deepEqual(forms.filter((form) => form === "open-graph-image").length, 1);
  assert.deepEqual(forms.filter((form) => form === "html-icon-link").length, 1);
  assert.deepEqual(forms.filter((form) => form === "html-img-src").length, 1);
  const jsonAssets = result.assetSources.filter((asset) => formIsJsonLd(asset.sourceForm));
  assert.equal(jsonAssets.length, 4);
  assert.ok(jsonAssets.some((asset) => asset.candidate.normalizedValue === "https://img.example.com/event-a.png"));
  assert.ok(jsonAssets.some((asset) => asset.candidate.normalizedValue === "/event-a-2.png"));
  assert.ok(jsonAssets.some((asset) => asset.candidate.normalizedValue === "//cdn.example.com/claimed-host.svg"));
  assert.ok(jsonAssets.some((asset) => asset.candidate.normalizedValue === "https://img.example.com/event-b.png"));
  assert.equal(jsonAssets.some((asset) => /literal-(?:dotted|image|slash)-key/.test(asset.candidate.normalizedValue)), false);
  const nestedOrganizer = jsonAssets.find((asset) => asset.candidate.normalizedValue === "//cdn.example.com/claimed-host.svg");
  assert.deepEqual(nestedOrganizer.association.kind, "nested-entity-source-claim");
  assert.equal(nestedOrganizer.association.parentEntityKind, "event");
  assert.equal(nestedOrganizer.association.roleHint, "organizer");
  assert.equal(nestedOrganizer.association.parentEntityId, result.events[0].entityId);
  assert.equal(nestedOrganizer.association.parentPointer, result.events[0].jsonPointer);
  assert.ok(nestedOrganizer.association.assetPointer.includes("/organizer/logo/url"));
  const eventImages = jsonAssets.filter((asset) => asset.candidate.normalizedValue?.includes("event-"));
  assert.equal(eventImages[0].association.entityId, result.events[0].entityId);
  assert.ok(eventImages.some((asset) => asset.association.assetPointer.endsWith("/image/1/url")));
  assert.equal(eventImages.at(-1).association.entityId, result.events[1].entityId);
  assert.ok(result.assetSources.filter((asset) => asset.association.kind === "unassigned-page")
    .every((asset) => asset.association.entityId === undefined));
  assertExactRanges(result, bytes);
});

test("uses ASCII HTML whitespace syntax when attributing unquoted canonical, metadata, and asset values", async () => {
  const nbsp = "\u00a0";
  const emSpace = "\u2003";
  const bytes = Buffer.from(
    `<html><head><link rel=canonical href=/calendar${nbsp}edition>`
    + `<meta property=og:description content=venue${emSpace}copy>`
    + `<meta property=og:image content=/card${nbsp}image.png>`
    + `<link rel=icon href=/icon${emSpace}mark.svg></head><body>`
    + `<img src=${nbsp}><img src=/leading${nbsp}start.png><img src=/internal${emSpace}space.png>`
    + `<img src="/quoted${nbsp}space.png"><img src=/entity&#160;value.png></body></html>`,
  );
  const input = document(bytes);
  const result = await extractDeterministically(input);
  assert.equal(result.status, "PARTIAL");
  const assertRawBytes = (candidate, raw, label) => {
    assert.equal(candidate.rawValue, raw, `${label} keeps the complete source spelling`);
    const { startByte, endByte } = candidate.source.locator;
    assert.equal(bytes.subarray(startByte, endByte).toString("utf8"), raw, `${label} maps to the complete original UTF-8 range`);
  };

  assertRawBytes(result.canonicalSuggestions[0], `/calendar${nbsp}edition`, "canonical href");
  const description = result.pageMetadata.find((candidate) => candidate.field === "openGraph.description");
  assertRawBytes(description, `venue${emSpace}copy`, "Open Graph description");
  const targets = [
    { form: "open-graph-image", raw: `/card${nbsp}image.png` },
    { form: "html-icon-link", raw: `/icon${emSpace}mark.svg` },
    { form: "html-img-src", raw: nbsp },
    { form: "html-img-src", raw: `/leading${nbsp}start.png` },
    { form: "html-img-src", raw: `/internal${emSpace}space.png` },
    { form: "html-img-src", raw: `/quoted${nbsp}space.png` },
    { form: "html-img-src", raw: "/entity&#160;value.png" },
  ];
  for (const expected of targets) {
    const asset = result.assetSources.find((candidate) => candidate.sourceForm === expected.form
      && candidate.candidate.rawValue === expected.raw);
    assert.ok(asset, `${expected.form} candidate retains ${JSON.stringify(expected.raw)}`);
    assertRawBytes(asset.candidate, expected.raw, expected.form);
  }
  assert.equal(result.assetSources.find((asset) => asset.candidate.rawValue === nbsp).candidate.normalizedValue, "");
  assertExactRanges(result, bytes);
});

function formIsJsonLd(value) {
  return value === "jsonld-image" || value === "jsonld-logo";
}

test("keeps XHTML image and icon attributes mapped to exact entity-decoded source bytes", async () => {
  const input = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><head><link rel="icon" href="../icons/caf&#xE9;.svg" /></head>'
    + '<body><img src="/caf&#xE9;.png" /><script type="application/ld+json"><![CDATA['
    + '{"@type":"Event","name":"Café","logo":{"@type":"ImageObject","contentUrl":"https://cdn.example.com/caf\\u00e9.png"}}'
    + ']]></script></body></html>',
  ), "application/xhtml+xml");
  const result = await extractDeterministically(input);
  assert.equal(result.status, "PARTIAL");
  assert.equal(result.assetSources.length, 3);
  assert.ok(result.assetSources.some((asset) => asset.sourceForm === "html-icon-link" && asset.candidate.rawValue === "../icons/caf&#xE9;.svg"));
  assert.ok(result.assetSources.some((asset) => asset.sourceForm === "html-img-src" && asset.candidate.rawValue === "/caf&#xE9;.png"));
  assert.ok(result.assetSources.some((asset) => asset.sourceForm === "jsonld-logo" && asset.candidate.normalizedValue === "https://cdn.example.com/café.png"));
  assertExactRanges(result, input.bytes);
});

test("binds XHTML case-distinct attributes to one decoded value and original source range", async () => {
  const forms = [
    { form: "html-img-src", attribute: "src", render: (attributes) => `<img ${attributes} />`, place: "body" },
    { form: "html-icon-link", attribute: "href", render: (attributes) => `<link rel="icon" ${attributes} />`, place: "head" },
    { form: "open-graph-image", attribute: "content", render: (attributes) => `<meta property="og:image" ${attributes} />`, place: "head" },
  ];

  for (const form of forms) {
    for (const order of ["lowercase-first", "uppercase-first"]) {
      const real = `/${form.form}-real.png`;
      const noise = `/${form.form}-noise.png`;
      const lower = `${form.attribute}="${real}"`;
      const upper = `${form.attribute.toUpperCase()}="${noise}"`;
      const attributes = order === "lowercase-first" ? `${lower} ${upper}` : `${upper} ${lower}`;
      const markup = form.render(attributes);
      const source = `<html xmlns="http://www.w3.org/1999/xhtml"><head>${form.place === "head" ? `🧭${markup}` : ""}</head>`
        + `<body>${form.place === "body" ? `🧭${markup}` : ""}</body></html>`;
      const bytes = Buffer.from(source, "utf8");
      const result = await extractDeterministically(document(bytes, "application/xhtml+xml; charset=utf-8"));
      const selected = result.assetSources.find((candidate) => candidate.sourceForm === form.form)?.candidate;
      const label = `${form.form} ${order}`;
      assert.ok(selected, `${label}: the source form is retained`);
      assert.equal(selected.rawValue, real, `${label}: exact lowercase XML name wins regardless of order`);
      assert.equal(selected.normalizedValue, real, `${label}: normalized value comes from that exact attribute`);
      const startByte = Buffer.byteLength(source.slice(0, source.indexOf(real)), "utf8");
      const endByte = startByte + Buffer.byteLength(real, "utf8");
      assert.deepEqual(selected.source.locator, { kind: "text-range", startByte, endByte }, `${label}: locator uses the same attribute`);
      assert.equal(bytes.subarray(startByte, endByte).toString("utf8"), real, label);
      assert.equal(JSON.stringify(result).includes(noise), false, `${label}: shadow value is not promoted`);
      assertExactRanges(result, bytes);
    }

    const uppercaseOnly = `/${form.form}-uppercase-only.png`;
    const markup = form.render(`${form.attribute.toUpperCase()}="${uppercaseOnly}"`);
    const source = `<html xmlns="http://www.w3.org/1999/xhtml"><head>${form.place === "head" ? markup : ""}</head>`
      + `<body>${form.place === "body" ? markup : ""}</body></html>`;
    const bytes = Buffer.from(source, "utf8");
    const result = await extractDeterministically(document(bytes, "application/xhtml+xml; charset=utf-8"));
    const selected = result.assetSources.find((candidate) => candidate.sourceForm === form.form)?.candidate;
    assert.ok(selected, `${form.form}: uppercase-only compatibility alias remains supported`);
    assert.equal(selected.rawValue, uppercaseOnly, `${form.form}: decoded value is from the alias`);
    const startByte = Buffer.byteLength(source.slice(0, source.indexOf(uppercaseOnly)), "utf8");
    assert.deepEqual(selected.source.locator, {
      kind: "text-range", startByte, endByte: startByte + Buffer.byteLength(uppercaseOnly, "utf8"),
    }, `${form.form}: uppercase-only alias keeps its exact range`);
    assertExactRanges(result, bytes);
  }

  for (const order of ["lowercase-first", "uppercase-first"]) {
    const lowerFirst = order === "lowercase-first";
    const pair = (lowerName, lowerValue, upperName, upperValue) => lowerFirst
      ? `${lowerName}="${lowerValue}" ${upperName}="${upperValue}"`
      : `${upperName}="${upperValue}" ${lowerName}="${lowerValue}"`;
    const conflictingMetadata = document(Buffer.from(
      '<html xmlns="http://www.w3.org/1999/xhtml"><head>🧭'
        + `<link ${pair("rel", "canonical", "REL", "icon")} ${pair("href", "/canonical-real", "HREF", "/canonical-shadow")} />`
        + `<meta ${pair("property", "og:description", "PROPERTY", "og:image")} ${pair("content", "real description", "CONTENT", "shadow description")} />`
        + `<script ${pair("type", "text/plain", "TYPE", "application/ld+json")}>{"@type":"Event","name":"shadow"}</script>`
        + '</head><body></body></html>',
    ), "application/xhtml+xml; charset=utf-8");
    const metadataResult = await extractDeterministically(conflictingMetadata);
    assert.equal(metadataResult.canonicalSuggestions.length, 1, order);
    assert.equal(metadataResult.canonicalSuggestions[0].rawValue, "/canonical-real", order);
    assert.equal(metadataResult.assetSources.some((asset) => asset.sourceForm === "html-icon-link"), false,
      `${order}: exact lowercase rel controls the canonical/icon distinction`);
    assert.equal(metadataResult.pageMetadata.find((item) => item.field === "openGraph.description")?.rawValue, "real description", order);
    assert.equal(metadataResult.assetSources.some((asset) => asset.sourceForm === "open-graph-image"), false,
      `${order}: exact lowercase property controls the Open Graph field`);
    assert.equal(metadataResult.events.length, 0, `${order}: exact lowercase type controls JSON-LD script recognition`);
    assertExactRanges(metadataResult, conflictingMetadata.bytes);
  }

  const uppercaseOnlyMetadata = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><head>'
      + '<link REL="canonical" HREF="/uppercase-canonical" />'
      + '<meta PROPERTY="og:description" CONTENT="uppercase description" />'
      + '<script TYPE="application/ld+json">{"@type":"Event","name":"uppercase event"}</script>'
      + '</head><body></body></html>',
  ), "application/xhtml+xml; charset=utf-8");
  const uppercaseMetadataResult = await extractDeterministically(uppercaseOnlyMetadata);
  assert.equal(uppercaseMetadataResult.canonicalSuggestions[0]?.rawValue, "/uppercase-canonical");
  assert.equal(uppercaseMetadataResult.pageMetadata.find((item) => item.field === "openGraph.description")?.rawValue,
    "uppercase description");
  assert.equal(uppercaseMetadataResult.events.length, 1, "uppercase-only TYPE remains a supported compatibility alias");
  assertExactRanges(uppercaseMetadataResult, uppercaseOnlyMetadata.bytes);

  for (const order of ["fallback-first", "fallback-reversed"]) {
    const firstAlias = order === "fallback-first";
    const pair = (firstName, firstValue, secondName, secondValue) => firstAlias
      ? `${firstName}="${firstValue}" ${secondName}="${secondValue}"`
      : `${secondName}="${secondValue}" ${firstName}="${firstValue}"`;
    const fallbackCollision = document(Buffer.from(
      '<html xmlns="http://www.w3.org/1999/xhtml"><head>🧭'
        + `<link ${pair("REL", "icon", "Rel", "canonical")} ${pair("HREF", "/alias-first.png", "Href", "/alias-second.png")} />`
        + `<meta ${pair("PROPERTY", "og:description", "Property", "og:image")} ${pair("CONTENT", "alias description", "Content", "alias shadow")} />`
        + `<script ${pair("TYPE", "text/plain", "Type", "application/ld+json")}>{"@type":"Event","name":"fallback event"}</script>`
        + '</head><body></body></html>',
    ), "application/xhtml+xml; charset=utf-8");
    const fallbackResult = await extractDeterministically(fallbackCollision);
    if (firstAlias) {
      assert.equal(fallbackResult.canonicalSuggestions.length, 0, `${order}: first REL alias controls icon classification`);
      assert.equal(fallbackResult.assetSources.find((asset) => asset.sourceForm === "html-icon-link")?.candidate.rawValue,
        "/alias-first.png", `${order}: first HREF alias binds the icon range`);
      assert.equal(fallbackResult.pageMetadata.find((item) => item.field === "openGraph.description")?.rawValue,
        "alias description", `${order}: first CONTENT alias is retained`);
      assert.equal(fallbackResult.assetSources.some((asset) => asset.sourceForm === "open-graph-image"), false);
      assert.equal(fallbackResult.events.length, 0, `${order}: first TYPE alias keeps this script unrecognized`);
    } else {
      assert.equal(fallbackResult.canonicalSuggestions[0]?.rawValue, "/alias-second.png",
        `${order}: reversed REL/HREF aliases bind the canonical suggestion`);
      assert.equal(fallbackResult.assetSources.some((asset) => asset.sourceForm === "html-icon-link"), false);
      assert.equal(fallbackResult.pageMetadata.some((item) => item.field === "openGraph.description"), false);
      assert.equal(fallbackResult.assetSources.find((asset) => asset.sourceForm === "open-graph-image")?.candidate.rawValue,
        "alias shadow", `${order}: reversed PROPERTY/CONTENT aliases bind the image range`);
      assert.equal(fallbackResult.events.length, 1, `${order}: first TYPE alias enables JSON-LD recognition`);
    }
    assertExactRanges(fallbackResult, fallbackCollision.bytes);
  }

  const htmlDuplicate = document(Buffer.from('<!doctype html><html><body><img src="/first.png" SRC="/second.png"></body></html>'));
  const htmlResult = await extractDeterministically(htmlDuplicate);
  assert.equal(htmlResult.assetSources.find((asset) => asset.sourceForm === "html-img-src")?.candidate.rawValue, "/first.png",
    "HTML keeps parse5's existing first duplicate behavior");
  assertExactRanges(htmlResult, htmlDuplicate.bytes);
});

test("a typed nested organizer logo is associated with its Organization only once", async () => {
  const input = document(Buffer.from(`<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@graph": [{
      "@type": "Event",
      name: "Community Festival",
      organizer: {
        "@type": "Organization",
        name: "Acme Arts",
        logo: "https://cdn.example.com/acme.svg",
      },
    }],
  })}</script>`));
  const result = await extractDeterministically(input);

  assert.equal(result.events.length, 1);
  assert.equal(result.organizations.length, 1);
  const logoSources = result.assetSources.filter((asset) => asset.sourceForm === "jsonld-logo");
  assert.equal(logoSources.length, 1);
  assert.equal(logoSources[0].association.kind, "entity-source-claim");
  assert.equal(logoSources[0].association.entityKind, "organization");
  assert.equal(logoSources[0].association.entityId, result.organizations[0].entityId);
  assert.equal(logoSources[0].association.entityPointer, result.organizations[0].jsonPointer);
  assert.equal(logoSources[0].association.entityId === result.events[0].entityId, false);
  assertExactRanges(result, input.bytes);
});

test("marks asset-source candidate truncation as incomplete instead of returning a complete prefix", async () => {
  const input = document(Buffer.from('<html><body><img src="/one.png"><img src="/two.png"></body></html>'));
  const result = await extractDeterministically(input, { limits: { maxAssetSources: 1 } });
  assert.equal(result.assetSources.length, 1);
  assert.equal(result.assetSourcesTruncated, true);
  assert.equal(result.status, "RESOURCE_LIMIT");
  assert.ok(result.diagnostics.some((item) => item.code === "ASSET_SOURCE_LIMIT"));
});

test("a parser deadline returns an incomplete resource outcome rather than asset success", async () => {
  const input = document(Buffer.from(
    `<html><body>${"x".repeat(100_000)}<img src="/after-deadline.png"></body></html>`,
  ));
  const result = await extractDeterministically(input, { limits: { htmlChunkCodeUnits: 1, parseTimeoutMs: 1 } });
  assert.equal(result.status, "RESOURCE_LIMIT");
  assert.equal(result.termination, "PARSER_DEADLINE");
  assert.ok(result.diagnostics.some((item) => item.code === "PARSER_DEADLINE"));
  assert.equal(result.assetSources.length, 0);
});

test("parses XML-decoded XHTML JSON-LD while mapping candidates to original source bytes", async () => {
  const input = document(Buffer.from(
    '\uFEFF<?xml version="1.0" encoding="UTF-8"?>\r\n'
    + '<html xmlns="http://www.w3.org/1999/xhtml"><head>'
    + '<script type="application/ld+json">\r\n'
    + '{"@type":"Event","name":"Rock &amp; Roll","description":"Café &amp; tea &#x1F37A;"}'
    + '</script>'
    + '<script type="application/ld+json">{&quot;@type&quot;:&quot;Event&quot;,&quot;name&quot;:&quot;Entity Punctuation&quot;}</script>'
    + '<script type="application/ld+json"><![CDATA[{"@type":"Event","name":"Split ]]><![CDATA[CDATA"}]]></script>'
    + '<script type="application/ld+json">{"@type":"Event","name":"Rock &amp; <![CDATA[Roll]]>","description":"The \\&quot;Show\\&quot;"}</script>'
    + '</head><body><p>Visible café copy.</p></body></html>',
  ), "application/xhtml+xml");
  const result = await extractDeterministically(input);
  const names = result.events.map((event) => event.candidates.find((candidate) => candidate.field === "name"));
  assert.deepEqual(names.map((candidate) => candidate.normalizedValue), [
    "Rock & Roll",
    "Entity Punctuation",
    "Split CDATA",
    "Rock & Roll",
  ]);
  assert.equal(names[0].rawValue, '"Rock &amp; Roll"');
  assert.equal(names[1].rawValue, "&quot;Entity Punctuation&quot;");
  assert.equal(names[2].rawValue, '"Split ]]><![CDATA[CDATA"');
  assert.equal(names[3].rawValue, '"Rock &amp; <![CDATA[Roll]]>"');
  const firstDescription = result.events[0].candidates.find((candidate) => candidate.field === "description");
  assert.equal(firstDescription.normalizedValue, "Café & tea 🍺");
  assert.equal(firstDescription.rawValue, '"Café &amp; tea &#x1F37A;"');
  const quotedDescription = result.events[3].candidates.find((candidate) => candidate.field === "description");
  assert.equal(quotedDescription.normalizedValue, 'The "Show"');
  assert.equal(quotedDescription.rawValue, '"The \\&quot;Show\\&quot;"');
  const rawEventSource = (event) => {
    const { startByte, endByte } = event.source.locator;
    return input.bytes.subarray(startByte, endByte).toString("utf8");
  };
  assert.equal(rawEventSource(result.events[1]), '{&quot;@type&quot;:&quot;Event&quot;,&quot;name&quot;:&quot;Entity Punctuation&quot;}');
  assert.equal(rawEventSource(result.events[2]), '{"@type":"Event","name":"Split ]]><![CDATA[CDATA"}');
  assert.equal(rawEventSource(result.events[3]), '{"@type":"Event","name":"Rock &amp; <![CDATA[Roll]]>","description":"The \\&quot;Show\\&quot;"}');
  assert.equal(result.jsonLdBlocks.length, 4);
  assert.ok(result.jsonLdBlocks.every((block) => block.status === "parsed"));
  assert.equal(result.visibleText[0].normalizedValue, "Visible café copy.");
  assertExactRanges(result, input.bytes);
});

test("maps XHTML comments and long numeric references without losing visible or JSON-LD evidence", async () => {
  const chunkSizes = [undefined, 1];
  const makeXhtml = (body) => document(Buffer.from(
    `<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>${body}</body></html>`,
  ), "application/xhtml+xml");

  for (const htmlChunkCodeUnits of chunkSizes) {
    const options = htmlChunkCodeUnits === undefined ? undefined : { limits: { htmlChunkCodeUnits } };
    const inlineComments = makeXhtml(
      "<p>Before<!-- ignored --><!-- adjacent --><!----> Cancelled event</p>",
    );
    const inlineResult = await extractDeterministically(inlineComments, options);
    assert.equal(inlineResult.status, "PARTIAL");
    assert.equal(inlineResult.statusMentions.length, 1);
    assert.equal(inlineResult.statusMentions[0].normalizedValue, "Before Cancelled event");
    assert.equal(
      inlineResult.statusMentions[0].rawValue,
      "Before<!-- ignored --><!-- adjacent --><!----> Cancelled event",
    );
    assertExactRanges(inlineResult, inlineComments.bytes);

    const leadingEmptyComment = makeXhtml("<p><!---->Cancelled event</p>");
    const leadingResult = await extractDeterministically(leadingEmptyComment, options);
    assert.equal(leadingResult.statusMentions.length, 1);
    assert.equal(leadingResult.statusMentions[0].normalizedValue, "Cancelled event");
    assert.equal(leadingResult.statusMentions[0].rawValue, "Cancelled event");
    assertExactRanges(leadingResult, leadingEmptyComment.bytes);

    const commentAndFormatting = makeXhtml("<!-- ignored -->\n<p>Cancelled event</p>");
    const formattingResult = await extractDeterministically(commentAndFormatting, options);
    assert.equal(formattingResult.statusMentions.length, 1);
    assert.equal(formattingResult.statusMentions[0].normalizedValue, "Cancelled event");
    assert.equal(formattingResult.statusMentions[0].rawValue, "Cancelled event");
    assertExactRanges(formattingResult, commentAndFormatting.bytes);

    const jsonWithComments = makeXhtml(
      '<script type="application/ld+json">{"@type":"Event",<!-- property boundary --><!---->"name":"Café 😊<!-- value boundary --> &amp; Roll"}</script>',
    );
    const jsonResult = await extractDeterministically(jsonWithComments, options);
    assert.equal(jsonResult.events.length, 1);
    const name = jsonResult.events[0].candidates.find((candidate) => candidate.field === "name");
    assert.equal(name.normalizedValue, "Café 😊 & Roll");
    assert.equal(name.rawValue, '"Café 😊<!-- value boundary --> &amp; Roll"');
    const { startByte, endByte } = jsonResult.events[0].source.locator;
    assert.equal(
      jsonWithComments.bytes.subarray(startByte, endByte).toString("utf8"),
      '{"@type":"Event",<!-- property boundary --><!---->"name":"Café 😊<!-- value boundary --> &amp; Roll"}',
    );
    assertExactRanges(jsonResult, jsonWithComments.bytes);

    const cdataLiteralComment = makeXhtml("<p><![CDATA[Cancelled event <!-- literal -->]]></p>");
    const cdataResult = await extractDeterministically(cdataLiteralComment, options);
    assert.equal(cdataResult.statusMentions.length, 1);
    assert.equal(cdataResult.statusMentions[0].normalizedValue, "Cancelled event <!-- literal -->");
    assert.equal(cdataResult.statusMentions[0].rawValue, "Cancelled event <!-- literal -->");
    assertExactRanges(cdataResult, cdataLiteralComment.bytes);

    const longNumericReference = makeXhtml("<p>&#000000000000000000067;ancelled event</p>");
    const numericResult = await extractDeterministically(longNumericReference, options);
    assert.equal(numericResult.statusMentions.length, 1);
    assert.equal(numericResult.statusMentions[0].normalizedValue, "Cancelled event");
    assert.equal(numericResult.statusMentions[0].rawValue, "&#000000000000000000067;ancelled event");
    assertExactRanges(numericResult, longNumericReference.bytes);
  }
});

test("reports SAX token-buffer exhaustion as RESOURCE_LIMIT, distinct from malformed XHTML", async () => {
  const longToken = "x".repeat(100_000);
  const longDigits = "0".repeat(100_000);
  const cases = [
    { bufferName: "comment", body: `<!--${longToken}--><p>Cancelled event</p>` },
    { bufferName: "attribValue", body: `<p title="${longToken}">Cancelled event</p>` },
    { bufferName: "procInstBody", body: `<?probe ${longToken}?><p>Cancelled event</p>` },
    { bufferName: "entity", body: `<p>&#${longDigits}67;ancelled event</p>` },
  ];

  for (const htmlChunkCodeUnits of [undefined, 257]) {
    const options = htmlChunkCodeUnits === undefined ? undefined : { limits: { htmlChunkCodeUnits } };
    for (const { bufferName, body } of cases) {
      const input = document(Buffer.from(
        `<html xmlns="http://www.w3.org/1999/xhtml"><body>${body}</body></html>`,
      ), "application/xhtml+xml");
      assert.ok(input.bytes.length < 2 * 1024 * 1024);
      const result = await extractDeterministically(input, options);
      assert.equal(result.status, "RESOURCE_LIMIT");
      assert.equal(result.termination, "RESOURCE_LIMIT");
      assert.ok(result.diagnostics.some((item) => item.code === "XHTML_TOKEN_BUFFER_LIMIT"
        && item.bufferName === bufferName && item.limit === 65_536));
      assert.equal(result.diagnostics.some((item) => item.code === "MALFORMED_XHTML"), false);
    }
  }

  const malformed = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>Cancelled event</body></html>',
  ), "application/xhtml+xml");
  const malformedResult = await extractDeterministically(malformed);
  assert.equal(malformedResult.status, "NO_ANSWER");
  assert.equal(malformedResult.termination, null);
  assert.ok(malformedResult.diagnostics.some((item) => item.code === "MALFORMED_XHTML"));
  assert.equal(malformedResult.diagnostics.some((item) => item.code === "XHTML_TOKEN_BUFFER_LIMIT"), false);
});

test("rejects malformed XHTML and internal entity declarations without resolving them", async () => {
  const externalDtdOnly = document(Buffer.from(
    '<!DOCTYPE html SYSTEM "https://remote.invalid/xhtml.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><body>Cancelled event</body></html>',
  ), "application/xhtml+xml");
  const externalDtd = await extractDeterministically(externalDtdOnly);
  assert.equal(externalDtd.status, "PARTIAL");
  assert.match(externalDtd.statusMentions[0].normalizedValue, /Cancelled/);

  const externalEntity = document(Buffer.from(
    '<!DOCTYPE html [<!ENTITY ext SYSTEM "https://remote.invalid/entity">]>'
    + '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>&ext;Cancelled event</p></body></html>',
  ), "application/xhtml+xml");
  const entityResult = await extractDeterministically(externalEntity);
  assert.equal(entityResult.status, "NO_ANSWER");
  assert.ok(entityResult.diagnostics.some((item) => item.code === "XHTML_DTD_UNSUPPORTED"));

  const unknownEntity = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>&unknown;Cancelled event</p></body></html>',
  ), "application/xhtml+xml");
  const unknownResult = await extractDeterministically(unknownEntity);
  assert.equal(unknownResult.status, "NO_ANSWER");
  assert.ok(unknownResult.diagnostics.some((item) => item.code === "MALFORMED_XHTML"));

  const mismatched = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>Cancelled event</body></html>',
  ), "application/xhtml+xml");
  const malformed = await extractDeterministically(mismatched);
  assert.equal(malformed.status, "NO_ANSWER");
  assert.ok(malformed.diagnostics.some((item) => item.code === "MALFORMED_XHTML"));

  const bounded = await extractDeterministically(externalDtdOnly, { limits: { maxHtmlNodes: 2 } });
  assert.equal(bounded.status, "RESOURCE_LIMIT");
  assert.equal(bounded.termination, "RESOURCE_LIMIT");

  const controller = new AbortController();
  const largeXhtml = document(Buffer.from(
    '<html xmlns="http://www.w3.org/1999/xhtml"><body>' + "<p>Static event copy</p>".repeat(2_000) + '</body></html>',
  ), "application/xhtml+xml");
  const inFlight = extractDeterministically(largeXhtml, { signal: controller.signal, limits: { htmlChunkCodeUnits: 1 } });
  setImmediate(() => controller.abort());
  const canceled = await inFlight;
  assert.equal(canceled.status, "CANCELED");
  assert.equal(canceled.termination, "CANCELED");
});

test("retains later cancellation evidence after the general visible-text budget is exhausted", async () => {
  const input = document(Buffer.from("<html><body><p>General introduction.</p><p>Cancelled: this event has moved to a new date.</p></body></html>"));
  const result = await extractDeterministically(input, { limits: { maxVisibleTextSegments: 1 } });
  assert.equal(result.visibleText.length, 1);
  assert.equal(result.statusMentions.length, 1);
  assert.match(result.statusMentions[0].normalizedValue, /Cancelled.*new date/);
  assert.equal(result.status, "PARTIAL");
  assert.equal(result.termination, "RESOURCE_LIMIT");
  assert.ok(result.diagnostics.some((item) => item.code === "VISIBLE_TEXT_LIMIT"));
  assertExactRanges(result, input.bytes);
});

test("reports access challenges while keeping their visible source evidence", async () => {
  const input = await fixture("access-restricted.html");
  const result = await extractDeterministically(input);
  assert.equal(result.status, "ACCESS_RESTRICTED");
  assert.ok(result.accessSignals.length > 0);
  assertExactRanges(result, input.bytes);
});

test("matches status and access phrases across visible inline markup after text quota", async () => {
  const input = document(Buffer.from(
    '<html><body><p>Introduction.</p><p>The event has <strong>moved</strong> to October 15.</p>'
    + '<h1>Access <em>denied</em></h1><p>access <span hidden>blocked</span> denied</p>'
    + '<p>access</p><p>denied</p></body></html>',
  ));
  const result = await extractDeterministically(input, { limits: { maxVisibleTextSegments: 1 } });
  assert.equal(result.status, "ACCESS_RESTRICTED");
  assert.equal(result.visibleText.length, 1);
  assert.equal(result.statusMentions.length, 1);
  assert.equal(result.statusMentions[0].normalizedValue, "The event has moved to October 15.");
  assert.equal(result.accessSignals.length, 1);
  assert.equal(result.accessSignals[0].normalizedValue, "Access denied");
  assert.ok(result.accessSignals[0].rawValue.includes("<em>denied"));
  assertExactRanges(result, input.bytes);

  const splitOnlyByHidden = document(Buffer.from('<p>access <span hidden>noise</span> denied</p>'));
  const hidden = await extractDeterministically(splitOnlyByHidden);
  assert.equal(hidden.accessSignals.length, 0);
  const splitAcrossBlocks = document(Buffer.from('<p>access</p><p>denied</p>'));
  const blocks = await extractDeterministically(splitAcrossBlocks);
  assert.equal(blocks.accessSignals.length, 0);
});

test("preserves ordered nested noscript JavaScript requirements and excludes hidden descendants", async () => {
  const input = document(Buffer.from(
    '<html><body><noscript>Please <b>enable <i>JavaScript</i></b> to continue'
    + '<span hidden>JavaScript is not required</span></noscript></body></html>',
  ));
  const result = await extractDeterministically(input);
  assert.equal(result.status, "JS_REQUIRED");
  assert.ok(result.diagnostics.some((item) => item.code === "NOSCRIPT_REQUIRES_JAVASCRIPT"));
  assertExactRanges(result, input.bytes);

  const hiddenJoin = document(Buffer.from(
    '<html><body><noscript>Java<span hidden> ignored </span>Script is required to continue</noscript></body></html>',
  ));
  assert.equal((await extractDeterministically(hiddenJoin)).status, "NO_ANSWER");
});

test("keeps malformed JSON-LD bounded and returns remaining visible evidence", async () => {
  const input = await fixture("malformed-jsonld.html");
  const result = await extractDeterministically(input);
  assert.equal(result.status, "PARTIAL");
  assert.equal(result.events.length, 0);
  assert.equal(result.jsonLdBlocks[0].status, "malformed");
  assert.ok(result.diagnostics.some((item) => item.code === "MALFORMED_JSONLD"));
  assert.ok(result.visibleText.some((candidate) => candidate.normalizedValue === "Visible fallback copy."));
  assertExactRanges(result, input.bytes);
});

test("returns stable empty, unsupported media, and encoding outcomes", async () => {
  const empty = await extractDeterministically(document(Buffer.alloc(0)));
  assert.equal(empty.status, "NO_ANSWER");

  const binary = await extractDeterministically(document(Buffer.from([0, 1, 2]), "application/octet-stream"));
  assert.equal(binary.status, "UNSUPPORTED_MEDIA");
  assert.deepEqual(binary.assetSources, []);
  assert.equal(binary.assetSourcesTruncated, false);
  assert.equal(Object.isFrozen(binary.assetSources), true);

  const legacyCharset = await extractDeterministically(document(Buffer.from("<p>hello</p>"), "text/html; charset=windows-1252"));
  assert.equal(legacyCharset.status, "UNSUPPORTED_ENCODING");

  const legacyHtmlBytes = Buffer.from('<meta charset="windows-1252"><p>caf\u00e9</p>', "latin1");
  const legacyHtml = await extractDeterministically(document(legacyHtmlBytes, "text/html"));
  assert.equal(legacyHtml.status, "UNSUPPORTED_ENCODING");
  const legacyXhtmlBytes = Buffer.from(
    '<?xml version="1.0" encoding="windows-1252"?><html xmlns="http://www.w3.org/1999/xhtml"><body>caf\u00e9</body></html>',
    "latin1",
  );
  const legacyXhtml = await extractDeterministically(document(legacyXhtmlBytes, "application/xhtml+xml"));
  assert.equal(legacyXhtml.status, "UNSUPPORTED_ENCODING");

  const malformedUtf8 = await extractDeterministically(document(Buffer.from([0x3c, 0x70, 0x3e, 0xff, 0x3c, 0x2f, 0x70, 0x3e])));
  assert.equal(malformedUtf8.status, "MALFORMED_ENCODING");

  const textWithMetaLikeCopy = await extractDeterministically(document(
    Buffer.from('<meta charset="windows-1252"> Plain text remains UTF-8.'),
    "text/plain; charset=utf-8",
  ));
  assert.equal(textWithMetaLikeCopy.status, "PARTIAL");
  assert.equal(textWithMetaLikeCopy.visibleText.length, 1);

  const jsonLdWithMetaLikeDescription = await extractDeterministically(document(
    Buffer.from('{"@type":"Event","name":"UTF-8 event","description":"<meta charset=\\"windows-1252\\">"}'),
    "application/ld+json",
  ));
  assert.equal(jsonLdWithMetaLikeDescription.status, "PARTIAL");
  assert.equal(jsonLdWithMetaLikeDescription.events.length, 1);

  const falseMetaCases = [
    '<!-- <meta charset="windows-1252"> --><p>Cancelled event</p>',
    '<meta name="description" content="charset=windows-1252"><p>Cancelled event</p>',
    '<script>const example = \'<meta charset="windows-1252">\';</script><p>Cancelled event</p>',
    '<meta http-equiv="refresh" content="text/html; charset=windows-1252"><p>Cancelled event</p>',
  ];
  for (const markup of falseMetaCases) {
    const result = await extractDeterministically(document(Buffer.from(markup), "text/html"));
    assert.equal(result.status, "PARTIAL");
    assert.ok(result.statusMentions.length > 0);
  }
  const trueMeta = await extractDeterministically(document(
    Buffer.from('<meta http-equiv="Content-Type" content="text/html; charset=windows-1252"><p>Cancelled event</p>'),
    "text/html",
  ));
  assert.equal(trueMeta.status, "UNSUPPORTED_ENCODING");
  const directCharset = await extractDeterministically(document(
    Buffer.from('<meta charset="windows-1252"><p>Cancelled event</p>'),
    "text/html",
  ));
  assert.equal(directCharset.status, "UNSUPPORTED_ENCODING");
  const headerWins = await extractDeterministically(document(
    Buffer.from('<meta charset="windows-1252"><p>Cancelled event</p>'),
    "text/html; charset=utf-8",
  ));
  assert.equal(headerWins.status, "PARTIAL");
  const unsupportedXmlDeclaration = await extractDeterministically(document(
    Buffer.from('<?xml version="1.0" encoding="windows-1252"?><html xmlns="http://www.w3.org/1999/xhtml"><body>Cancelled</body></html>'),
    "application/xhtml+xml",
  ));
  assert.equal(unsupportedXmlDeclaration.status, "UNSUPPORTED_ENCODING");
  const xmlHeaderWins = await extractDeterministically(document(
    Buffer.from('<?xml version="1.0" encoding="windows-1252"?><html xmlns="http://www.w3.org/1999/xhtml"><body>Cancelled</body></html>'),
    "application/xhtml+xml; charset=utf-8",
  ));
  assert.equal(xmlHeaderWins.status, "PARTIAL");
});

test("enforces document, DOM, and JSON-LD entity ceilings", async () => {
  const documentLimited = await extractDeterministically(await fixture("multi-event.html"), { limits: { maxDocumentBytes: 8 } });
  assert.equal(documentLimited.status, "RESOURCE_LIMIT");
  assert.equal(documentLimited.termination, "RESOURCE_LIMIT");

  const htmlLimited = await extractDeterministically(await fixture("multi-event.html"), { limits: { maxHtmlNodes: 2 } });
  assert.equal(htmlLimited.status, "RESOURCE_LIMIT");

  const entityLimited = await extractDeterministically(await fixture("multi-event.html"), { limits: { maxEntities: 1 } });
  assert.equal(entityLimited.events.length + entityLimited.organizations.length, 1);
  assert.ok(entityLimited.diagnostics.some((item) => item.code === "JSONLD_ENTITY_LIMIT"));
});

test("bounds page metadata, canonical suggestions, JSON-LD blocks, and entity candidates", async () => {
  const noisyPage = document(Buffer.from([
    '<link rel="canonical" href="/first">',
    '<link rel="canonical" href="/second">',
    '<meta property="og:title" content="First">',
    '<meta property="og:title" content="Second">',
  ].join("")));
  const pageLimited = await extractDeterministically(noisyPage, {
    limits: { maxCanonicalSuggestions: 1, maxPageMetadataCandidates: 1 },
  });
  assert.equal(pageLimited.canonicalSuggestions.length, 1);
  assert.equal(pageLimited.pageMetadata.length, 1);
  assert.ok(pageLimited.diagnostics.some((item) => item.code === "CANONICAL_SUGGESTION_LIMIT"));
  assert.ok(pageLimited.diagnostics.some((item) => item.code === "PAGE_METADATA_LIMIT"));

  const twoBlocks = document(Buffer.from([
    '<script type="application/ld+json">{"@type":"Event","name":"One"}</script>',
    '<script type="application/ld+json">{"@type":"Event","name":"Two"}</script>',
  ].join("")));
  const blockLimited = await extractDeterministically(twoBlocks, { limits: { maxJsonLdBlocks: 1 } });
  assert.equal(blockLimited.status, "PARTIAL");
  assert.equal(blockLimited.termination, "RESOURCE_LIMIT");
  assert.ok(blockLimited.diagnostics.some((item) => item.code === "JSONLD_BLOCK_LIMIT"));

  const candidateLimited = await extractDeterministically(document(
    Buffer.from('{"@type":"Event","name":"One","startDate":"2026-10-12"}'),
    "application/ld+json",
  ), { limits: { maxCandidatesPerEntity: 1 } });
  assert.equal(candidateLimited.events[0].candidates.length, 1);
  assert.equal(candidateLimited.status, "PARTIAL");
  assert.equal(candidateLimited.termination, "RESOURCE_LIMIT");
  assert.equal(candidateLimited.jsonLdBlocks[0].status, "resource_limited");
  assert.ok(candidateLimited.diagnostics.some((item) => item.code === "JSONLD_CANDIDATE_LIMIT"));
});

test("reports JSON and plain-text quota exhaustion with resource outcomes and retained partial evidence", async () => {
  const depthJson = '{"@type":"Event","name":"Show","extra":' + '['.repeat(65) + '0' + ']'.repeat(65) + '}';
  const standaloneDepth = await extractDeterministically(document(Buffer.from(depthJson), "application/ld+json"));
  assert.equal(standaloneDepth.status, "RESOURCE_LIMIT");
  assert.equal(standaloneDepth.termination, "RESOURCE_LIMIT");
  assert.equal(standaloneDepth.jsonLdBlocks[0].status, "resource_limited");

  const embeddedNodeLimit = await extractDeterministically(document(Buffer.from(
    '<html><body><script type="application/ld+json">{"@type":"Event","name":"Event"}</script></body></html>',
  )), { limits: { maxJsonNodes: 1 } });
  assert.equal(embeddedNodeLimit.status, "RESOURCE_LIMIT");
  assert.equal(embeddedNodeLimit.termination, "RESOURCE_LIMIT");
  assert.equal(embeddedNodeLimit.jsonLdBlocks[0].status, "resource_limited");

  const embeddedByteLimit = await extractDeterministically(document(Buffer.from(
    '<html><body><script type="application/ld+json">{"@type":"Event","name":"Event"}</script></body></html>',
  )), { limits: { maxJsonLdBytes: 8 } });
  assert.equal(embeddedByteLimit.status, "RESOURCE_LIMIT");
  assert.equal(embeddedByteLimit.jsonLdBlocks[0].status, "resource_limited");

  const embeddedPartial = await extractDeterministically(document(Buffer.from(
    '<html><body><script type="application/ld+json">{"@type":"Event","name":"Event"}</script>'
    + '<p>Fallback source copy.</p></body></html>',
  )), { limits: { maxJsonNodes: 2 } });
  assert.equal(embeddedPartial.status, "PARTIAL");
  assert.equal(embeddedPartial.termination, "RESOURCE_LIMIT");
  assert.equal(embeddedPartial.jsonLdBlocks[0].status, "resource_limited");
  assert.ok(embeddedPartial.visibleText.some((candidate) => candidate.normalizedValue === "Fallback source copy."));

  const standaloneByteLimit = await extractDeterministically(document(
    Buffer.from('{"@type":"Event","name":"Event"}'), "application/ld+json",
  ), { limits: { maxJsonLdBytes: 8 } });
  assert.equal(standaloneByteLimit.status, "RESOURCE_LIMIT");
  assert.equal(standaloneByteLimit.jsonLdBlocks[0].status, "resource_limited");

  const plainNoEvidence = await extractDeterministically(document(Buffer.from("Long enough"), "text/plain"), {
    limits: { maxVisibleTextBytes: 0 },
  });
  assert.equal(plainNoEvidence.status, "RESOURCE_LIMIT");
  assert.equal(plainNoEvidence.termination, "RESOURCE_LIMIT");
  assert.equal(plainNoEvidence.visibleText.length, 0);

  const plainPartial = await extractDeterministically(document(
    Buffer.from("Introduction then cancellation notice"), "text/plain",
  ), { limits: { maxVisibleTextBytes: 12 } });
  assert.equal(plainPartial.status, "PARTIAL");
  assert.equal(plainPartial.termination, "RESOURCE_LIMIT");
  assert.equal(plainPartial.visibleText[0].rawValue, "Introduction");
  assert.equal(plainPartial.statusMentions.length, 1);
  assert.match(plainPartial.statusMentions[0].normalizedValue, /cancellation/);
  assertExactRanges(plainPartial, Buffer.from("Introduction then cancellation notice"));
});

test("cuts plain-text byte quotas only at valid UTF-8 boundaries", async () => {
  const cases = [
    { text: "😊abcdefghijk", limit: 10, expected: "😊abcdef", truncated: true },
    { text: "A😊BC", limit: 4, expected: "A", truncated: true },
    { text: "A😊BC", limit: 5, expected: "A😊", truncated: true },
    { text: "A😊BC", limit: 7, expected: "A😊BC", truncated: false },
    { text: "😊😊ABC", limit: 9, expected: "😊😊A", truncated: true },
    { text: "\uFEFFFirst\r\n😊 second", limit: 10, expected: "\uFEFFFirst\r\n", truncated: true },
    { text: "A".repeat(20), limit: 10, expected: "A".repeat(10), truncated: true },
  ];

  for (const { text, limit, expected, truncated } of cases) {
    const input = document(Buffer.from(text), "text/plain");
    const result = await extractDeterministically(input, { limits: { maxVisibleTextBytes: limit } });
    assert.equal(result.visibleText.length, 1, `${JSON.stringify(text)} at ${limit} bytes`);
    assert.equal(result.visibleText[0].rawValue, expected, `${JSON.stringify(text)} at ${limit} bytes`);
    assert.ok(Buffer.byteLength(result.visibleText[0].rawValue) <= limit);
    assert.equal(result.visibleText[0].source.locator.startByte, 0);
    assert.equal(result.visibleText[0].source.locator.endByte, Buffer.byteLength(expected));
    assert.equal(result.termination, truncated ? "RESOURCE_LIMIT" : null);
    assert.equal(result.status, "PARTIAL");
    assert.equal(result.diagnostics.some((item) => item.code === "VISIBLE_TEXT_LIMIT"), truncated);
    assertExactRanges(result, input.bytes);
  }
});

test("retains early plain-text event copy with the default byte quota after supplementary characters", async () => {
  const cases = [
    `😊 The festival starts October 15 at Green Hall.\n${"x".repeat(530_000)}`,
    `Introduction. 😊 The festival starts October 15 at Green Hall.\n${"x".repeat(530_000)}`,
  ];

  for (const text of cases) {
    const input = document(Buffer.from(text), "text/plain");
    const result = await extractDeterministically(input);
    assert.equal(result.status, "PARTIAL");
    assert.equal(result.termination, "RESOURCE_LIMIT");
    assert.equal(result.visibleText.length, 1);
    assert.ok(result.visibleText[0].normalizedValue.startsWith(text.slice(0, text.indexOf("\n"))));
    assert.match(result.visibleText[0].normalizedValue, /October 15 at Green Hall/);
    assert.equal(Buffer.byteLength(result.visibleText[0].rawValue), 512 * 1024);
    assert.equal(result.visibleText[0].source.locator.endByte, 512 * 1024);
    assertExactRanges(result, input.bytes);
  }
});

test("applies signal count and document-byte ceilings consistently across plain text and XML/HTML", async () => {
  const cases = [
    ["text/plain", "Cancelled event: access denied"],
    ["text/html", "<p>Cancelled event: access denied</p>"],
    ["application/xhtml+xml", '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>Cancelled event: access denied</p></body></html>'],
  ];

  for (const [contentType, source] of cases) {
    const input = document(Buffer.from(source), contentType);
    const noSignals = await extractDeterministically(input, { limits: { maxStatusSignalCandidates: 0 } });
    assert.equal(noSignals.statusMentions.length, 0, contentType);
    assert.equal(noSignals.accessSignals.length, 0, contentType);
    assert.equal(noSignals.termination, "RESOURCE_LIMIT", contentType);
    assert.ok(noSignals.diagnostics.some((item) => item.code === "STATUS_SIGNAL_LIMIT"), contentType);
    assert.ok(noSignals.diagnostics.some((item) => item.code === "ACCESS_SIGNAL_LIMIT"), contentType);
    assertExactRanges(noSignals, input.bytes);

    const oneOfEach = await extractDeterministically(input, { limits: { maxStatusSignalCandidates: 1 } });
    assert.equal(oneOfEach.statusMentions.length, 1, contentType);
    assert.equal(oneOfEach.accessSignals.length, 1, contentType);
    assert.equal(oneOfEach.status, "ACCESS_RESTRICTED", contentType);
    assert.equal(oneOfEach.termination, null, contentType);
    assertExactRanges(oneOfEach, input.bytes);

    const signalAfterVisibleQuota = await extractDeterministically(input, {
      limits: { maxVisibleTextBytes: 1, maxStatusSignalCandidates: 1 },
    });
    assert.equal(signalAfterVisibleQuota.statusMentions.length, 1, contentType);
    assert.equal(signalAfterVisibleQuota.accessSignals.length, 1, contentType);
    assert.equal(signalAfterVisibleQuota.status, "ACCESS_RESTRICTED", contentType);
    assert.equal(signalAfterVisibleQuota.termination, "RESOURCE_LIMIT", contentType);
    assert.ok(signalAfterVisibleQuota.diagnostics.some((item) => item.code === "VISIBLE_TEXT_LIMIT"), contentType);
    assertExactRanges(signalAfterVisibleQuota, input.bytes);

    const documentQuota = await extractDeterministically(input, { limits: { maxDocumentBytes: 1 } });
    assert.equal(documentQuota.status, "RESOURCE_LIMIT", contentType);
    assert.equal(documentQuota.termination, "RESOURCE_LIMIT", contentType);
    assert.equal(documentQuota.statusMentions.length, 0, contentType);
    assert.equal(documentQuota.accessSignals.length, 0, contentType);
    assert.ok(documentQuota.diagnostics.some((item) => item.code === "DOCUMENT_BYTE_LIMIT"), contentType);
  }
});

test("records HTML/XHTML parser side requests and browser launches with interception controls and recovery", { timeout: 45_000 }, (t) => {
  const prefix = "PARSER_SIDE_REQUEST_PROBE_JSON=";
  const expectedApis = [
    "http.request",
    "http.get",
    "http.ClientRequest",
    "https.request",
    "https.get",
    "http2.connect",
    "net.connect",
    "net.createConnection",
    "net.Socket.connect",
    "net.Server.listen",
    "tls.connect",
    "dgram.createSocket",
    "dgram.Socket.connect",
    "dgram.Socket.send",
    "dgram.Socket.bind",
    "dns.lookup",
    "dns.lookupService",
    "dns.resolve",
    "dns.resolve4",
    "dns.resolve6",
    "dns.resolveAny",
    "dns.resolveCaa",
    "dns.resolveCname",
    "dns.resolveMx",
    "dns.resolveNaptr",
    "dns.resolveNs",
    "dns.resolvePtr",
    "dns.resolveSoa",
    "dns.resolveSrv",
    "dns.resolveTxt",
    "dns.reverse",
    "dns.promises.lookup",
    "dns.promises.lookupService",
    "dns.promises.resolve",
    "dns.promises.resolve4",
    "dns.promises.resolve6",
    "dns.promises.resolveAny",
    "dns.promises.resolveCaa",
    "dns.promises.resolveCname",
    "dns.promises.resolveMx",
    "dns.promises.resolveNaptr",
    "dns.promises.resolveNs",
    "dns.promises.resolvePtr",
    "dns.promises.resolveSoa",
    "dns.promises.resolveSrv",
    "dns.promises.resolveTxt",
    "dns.promises.reverse",
    "dns.Resolver.resolve",
    "dns.Resolver.resolve4",
    "dns.Resolver.resolve6",
    "dns.Resolver.resolveAny",
    "dns.Resolver.resolveCaa",
    "dns.Resolver.resolveCname",
    "dns.Resolver.resolveMx",
    "dns.Resolver.resolveNaptr",
    "dns.Resolver.resolveNs",
    "dns.Resolver.resolvePtr",
    "dns.Resolver.resolveSoa",
    "dns.Resolver.resolveSrv",
    "dns.Resolver.resolveTxt",
    "dns.Resolver.reverse",
    "dns.promises.Resolver.resolve",
    "dns.promises.Resolver.resolve4",
    "dns.promises.Resolver.resolve6",
    "dns.promises.Resolver.resolveAny",
    "dns.promises.Resolver.resolveCaa",
    "dns.promises.Resolver.resolveCname",
    "dns.promises.Resolver.resolveMx",
    "dns.promises.Resolver.resolveNaptr",
    "dns.promises.Resolver.resolveNs",
    "dns.promises.Resolver.resolvePtr",
    "dns.promises.Resolver.resolveSoa",
    "dns.promises.Resolver.resolveSrv",
    "dns.promises.Resolver.resolveTxt",
    "dns.promises.Resolver.reverse",
    "global.fetch",
    "global.WebSocket",
    "child_process.exec",
    "child_process.execFile",
    "child_process.execSync",
    "child_process.execFileSync",
    "child_process.fork",
    "child_process.spawn",
    "child_process.spawnSync",
    "worker_threads.Worker",
    "process.dlopen"
  ];
  const expectedFixtures = ["multi-event-html", "remote-html", "remote-xhtml", "external-dtd-xhtml",
    "js-shell-html", "js-shell-xhtml", "access-html", "access-xhtml",
    "cancelled-html", "cancelled-xhtml", "recovery-html"];
  const expectedStatuses = ["PARTIAL", "PARTIAL", "PARTIAL", "PARTIAL", "JS_REQUIRED", "JS_REQUIRED",
    "ACCESS_RESTRICTED", "ACCESS_RESTRICTED", "CANCELED", "CANCELED", "PARTIAL"];
  const expectedEvents = [2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 2];
  const probe = fileURLToPath(new URL("./support/parser-egress-probe.mjs", import.meta.url));
  const cwd = fileURLToPath(new URL("../../", import.meta.url));

  function checkReceipt(run, mode) {
    assert.equal(run.error, undefined, "probe spawn or watchdog failed");
    assert.equal(run.signal, null, "probe did not settle normally");
    assert.equal(run.status, mode === "healthy" ? 0 : 1, "unexpected child exit");
    const lines = run.stdout.trimEnd().split("\n");
    assert.equal(lines.length, 1, "one complete receipt is mandatory");
    assert.ok(lines[0].startsWith(prefix), "missing fixed receipt");
    const row = JSON.parse(lines[0].slice(prefix.length));
    assert.equal(row.schemaVersion, "ei-parser-side-request-probe/1");
    assert.equal(row.mode, mode);
    assert.equal(row.node, process.versions.node);
    assert.equal(row.measurement, "fixed Node API interposition before product import; not kernel or hostile-native containment");
    assert.deepEqual(row.registrations.map((entry) => entry.api), expectedApis);
    assert.deepEqual(row.registrations.map((entry) => entry.category),
      expectedApis.map((api) => /^(child_process|worker_threads|process)\./.test(api) ? "launch" : "network"));
    assert.deepEqual(row.positiveControls, [...expectedApis, "http.request.esm-binding"]);
    assert.equal(row.scriptExecuted, false);
    if (mode === "healthy") {
      assert.equal(row.kind, "success");
      assert.equal(row.phase, "complete");
      assert.equal(row.activeFixture, null);
      assert.equal(row.parserAttemptCount, 0);
      assert.deepEqual(row.parserAttempts, []);
      assert.deepEqual(row.fixtures.map((entry) => entry.id), expectedFixtures);
      assert.deepEqual(row.fixtures.map((entry) => entry.status), expectedStatuses);
      assert.deepEqual(row.fixtures.map((entry) => entry.events), expectedEvents);
      for (const fixtureRow of row.fixtures) {
        assert.match(fixtureRow.inputSha256, /^[0-9a-f]{64}$/);
        assert.ok(Number.isSafeInteger(fixtureRow.exactRanges) && fixtureRow.exactRanges >= 0);
        assert.equal(fixtureRow.networkAttempts, 0);
        assert.equal(fixtureRow.launchAttempts, 0);
        assert.equal(fixtureRow.scriptExecuted, false);
      }
      for (const index of [0, 1, 2, 3, 6, 7, 10]) assert.ok(row.fixtures[index].exactRanges > 0);
    } else {
      assert.equal(row.kind, "failure");
      assert.equal(row.errorCode, "PARSER_SIDE_EFFECT_RECORDED");
      assert.equal(row.phase, mode === "caught-network" ? "late-control" : "fixture");
      assert.equal(row.activeFixture, mode === "caught-network" ? null : "remote-html");
      assert.equal(row.parserAttemptCount, 1);
      assert.deepEqual(row.fixtures.map((entry) => entry.id),
        mode === "caught-network" ? expectedFixtures : ["multi-event-html"]);
      assert.deepEqual(row.parserAttempts, [{
        api: mode === "caught-network" ? "http.request" : "child_process.spawn",
        category: mode === "caught-network" ? "network" : "launch",
        phase: mode === "caught-network" ? "late-control" : "fixture",
        fixture: mode === "caught-network" ? null : "remote-html",
      }]);
    }
    return row;
  }

  function execute(mode) {
    const run = spawnSync(process.execPath, ["--unhandled-rejections=strict", probe, mode], {
      cwd, encoding: "utf8", timeout: 10_000, killSignal: "SIGKILL", maxBuffer: 256 * 1024,
      env: { PATH: process.env.PATH ?? "", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", TZ: "UTC" },
    });
    // Preserve every child receipt and stderr, including the two expected failing controls.
    t.diagnostic("parser probe " + mode + " stdout:\n" + run.stdout);
    if (run.stderr) t.diagnostic("parser probe " + mode + " stderr:\n" + run.stderr);
    return { run, receipt: checkReceipt(run, mode) };
  }

  const normal = execute("healthy");
  execute("caught-network");
  execute("caught-browser");
  const recovery = execute("healthy");
  assert.deepEqual(recovery.receipt.fixtures, normal.receipt.fixtures);
  let refusalControls = 0;
  function rejectsIncomplete(overrides) {
    assert.throws(() => checkReceipt({ ...normal.run, ...overrides }, "healthy"));
    refusalControls += 1;
  }
  rejectsIncomplete({ stdout: "" });
  rejectsIncomplete({ stdout: normal.run.stdout + normal.run.stdout });
  rejectsIncomplete({ status: null, signal: "SIGKILL" });
  rejectsIncomplete({ error: Object.assign(new Error("synthetic watchdog control"), { code: "ETIMEDOUT" }) });
  rejectsIncomplete({ stdout: prefix + JSON.stringify({ ...normal.receipt, fixtures: [] }) + "\n" });
  rejectsIncomplete({ stdout: prefix + JSON.stringify({ ...normal.receipt, positiveControls: [] }) + "\n" });
  assert.equal(refusalControls, 6);
  t.diagnostic("PARSER_SIDE_REQUEST_RECORDER_JSON=" + JSON.stringify({
    schemaVersion: "ei-parser-side-request-recorder/1", mode: "local-synthetic",
    guardedApis: 86, positiveInterceptionControlsPerChild: 87, parserFixturesPerHealthyChild: 11,
    healthyChildren: 2, expectedFailingChildren: 2, receiptRefusalControls: refusalControls,
    parserNetworkAttempts: 0, parserLaunchAttempts: 0, recovery: "passed",
    limits: "Node API interposition on fixed parser fixtures; external/kernel/native egress not measured",
  }));
});
