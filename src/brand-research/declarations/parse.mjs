import { parseHtmlDocument, declaredCharsetFromHtmlDocument } from '../../extraction/html.mjs';
import { createByteOffsetMap, exactRange, decodeUtf8, declaredCharset } from '../../extraction/source.mjs';
import { createHash } from 'node:crypto';

export const DECLARATION_LIMITS = Object.freeze({
  sourceBytes: 512 * 1024, positions: 128, nodes: 20_000, observations: 64,
  attributeCodeUnits: 4_096, declarationCodeUnits: 256, families: 8,
  outputBytes: 32 * 1024, deadlineMs: 2_500,
});
const GENERICS = new Set(['serif', 'sans-serif', 'monospace', 'cursive', 'fantasy', 'system-ui']);
const PROPERTIES = new Set(['color', 'background-color', 'font-family']);
const SPACE = /^[\t\n\f\r ]*$/;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

function hex(value) {
  if (!/^#[a-fA-F0-9]{3}(?:[a-fA-F0-9]{3})?$/.test(value)) return null;
  const digits = value.slice(1).toLowerCase();
  return `#${digits.length === 3 ? [...digits].map((v) => v + v).join('') : digits}`;
}

function families(value) {
  const result = [];
  // This deliberately accepts neither escapes nor arbitrary CSS token syntax.
  // Quoted names contain no delimiter, so commas cannot be hidden inside them.
  for (const token of value.split(',')) {
    const item = token.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '');
    const quoted = /^(["'])([A-Za-z0-9][A-Za-z0-9 _-]{0,63})\1$/.exec(item);
    const generic = GENERICS.has(item.toLowerCase()) ? item.toLowerCase() : null;
    if (!quoted && !generic) return null;
    result.push(Object.freeze(quoted
      ? { kind: 'declared-name', name: quoted[2] }
      : { kind: 'generic-family', name: generic }));
    if (result.length > DECLARATION_LIMITS.families) return null;
  }
  return Object.freeze(result);
}

function attribute(node, name, text) {
  const found = node.attrs?.find((item) => item.name === name);
  if (!found) return null;
  const location = node.sourceCodeLocation?.attrs?.[name];
  if (!location) return { unsupported: true };
  const token = text.slice(location.startOffset, location.endOffset);
  if (token.length > DECLARATION_LIMITS.attributeCodeUnits) return { overLimit: true };
  const match = /^[^\t\n\f\r =/>]+[\t\n\f\r ]*=[\t\n\f\r ]*(?:"([^"]*)"|'([^']*)'|([^\t\n\f\r >]+))$/.exec(token);
  if (!match) return { unsupported: true };
  const raw = match[1] ?? match[2] ?? match[3];
  const equals = token.indexOf('=');
  let start = equals + 1;
  while (SPACE.test(token[start] ?? '') && start < token.length) start += 1;
  if (token[start] === '"' || token[start] === "'") start += 1;
  // parse5 decodes entities and normalizes CR/NUL. Do not invent a raw span for
  // the transformed value: this initial profile refuses the whole attribute.
  if (raw !== found.value) return { unsupported: true };
  return { raw, start: location.startOffset + start, end: location.startOffset + start + raw.length };
}

export async function parseDeclarations(bytes, contentType, { signal, check, fail, remainingMs }) {
  const encoding = declaredCharset(contentType);
  if (encoding !== null && !['utf-8', 'utf8'].includes(encoding)) fail('UNSUPPORTED_SOURCE');
  const decoded = decodeUtf8(bytes);
  if (!decoded.ok) fail('UNSUPPORTED_SOURCE');
  const text = decoded.text;
  const offsets = createByteOffsetMap(text, bytes.length);
  if (!offsets) fail('SOURCE_MISMATCH');
  check();
  const parsed = await parseHtmlDocument(text, { signal, limits: {
    maxHtmlParseErrors: 32, htmlChunkCodeUnits: 16 * 1024,
    parseTimeoutMs: Math.max(1, Math.min(DECLARATION_LIMITS.deadlineMs, remainingMs())),
  } });
  check();
  if (!parsed.ok) fail(parsed.code === 'CANCELED' ? 'CANCELED' : 'PARSER_FAILURE');
  const htmlEncoding = declaredCharsetFromHtmlDocument(parsed.document, offsets);
  if (htmlEncoding !== null && !['utf-8', 'utf8'].includes(htmlEncoding)) fail('UNSUPPORTED_SOURCE');
  // Duplicate attributes are deliberately not repaired by taking parse5's first
  // match. Other malformed-source recovery is likewise outside this profile.
  if (parsed.parseErrors.some((item) => item.code !== 'missing-doctype')) fail('MALFORMED_HTML');
  const declarations = [];
  const unsupported = [];
  let nodes = 0;
  const stack = [{ node: parsed.document, inert: false }];
  function bound() {
    if (declarations.length + unsupported.length > DECLARATION_LIMITS.observations) fail('RESOURCE_LIMIT');
  }
  function unsupportedAt(code, node) {
    const loc = node.sourceCodeLocation?.startTag ?? node.sourceCodeLocation;
    const range = loc ? exactRange(text, bytes, offsets, loc.startOffset, loc.endOffset) : null;
    unsupported.push(Object.freeze({ code, locator: range?.locator ?? null }));
    bound();
  }
  function emit(property, value, start, end, sourceForm, node) {
    const raw = text.slice(start, end);
    if (raw.length > DECLARATION_LIMITS.declarationCodeUnits) fail('RESOURCE_LIMIT');
    const normalized = property === 'font-family' ? families(value) : hex(value);
    if (normalized === null) { unsupportedAt('UNSUPPORTED_VALUE', node); return; }
    const range = exactRange(text, bytes, offsets, start, end);
    const element = node.sourceCodeLocation?.startTag;
    const context = element ? exactRange(text, bytes, offsets, element.startOffset, element.endOffset) : null;
    if (!range || !context) fail('SOURCE_MISMATCH');
    declarations.push(Object.freeze({ property, value: normalized, rawDeclaration: range.rawValue,
      sourceForm, tagName: node.tagName, locator: range.locator, elementLocator: context.locator,
      excerptHash: hash(bytes.subarray(range.locator.startByte, range.locator.endByte)),
    }));
    bound();
  }
  while (stack.length) {
    check();
    const { node, inert } = stack.pop();
    if (++nodes > DECLARATION_LIMITS.nodes) fail('RESOURCE_LIMIT');
    if (nodes % 128 === 0) { await new Promise((resolve) => setImmediate(resolve)); check(); }
    const hidden = inert || ['template', 'noscript', 'script'].includes(node.tagName);
    if (node.tagName === 'style' && !inert) unsupportedAt('STYLESHEET_NOT_EVALUATED', node);
    if (node.tagName === 'link' && node.attrs?.some((a) => a.name === 'rel' && a.value.toLowerCase().split(/\s+/).includes('stylesheet'))) {
      unsupportedAt('EXTERNAL_STYLESHEET_NOT_FETCHED', node);
    }
    if (node.tagName && !hidden && node.namespaceURI === 'http://www.w3.org/1999/xhtml') {
      const style = attribute(node, 'style', text);
      if (style?.overLimit) fail('RESOURCE_LIMIT');
      if (style?.unsupported) unsupportedAt('RAW_ATTRIBUTE_UNSUPPORTED', node);
      else if (style) {
        // The supported grammar never contains a semicolon in a quoted name.
        // Refuse complex CSS at attribute level rather than guessing boundaries.
        let quote = null;
        let quotedDelimiter = false;
        for (const ch of style.raw) {
          if (quote) {
            if (ch === quote) quote = null;
            else if (ch === ';') quotedDelimiter = true;
          } else if (ch === '"' || ch === "'") quote = ch;
        }
        if (quote || quotedDelimiter || /[\\(){}/*!\u0000-\u0008\u000b\u000e-\u001f]/.test(style.raw)) unsupportedAt('COMPLEX_STYLE_UNSUPPORTED', node);
        else {
          const parts = [];
          let offset = 0;
          let malformed = false;
          for (const part of style.raw.split(';')) {
            if (!SPACE.test(part)) {
              const match = /^([\t\n\f\r ]*)([a-zA-Z-]+)[\t\n\f\r ]*:[\t\n\f\r ]*(.*?)[\t\n\f\r ]*$/.exec(part);
              if (!match) { malformed = true; break; }
              const property = match[2].toLowerCase();
              if (PROPERTIES.has(property)) parts.push({ property, value: match[3], start: style.start + offset + match[1].length, end: style.start + offset + part.replace(/[\t\n\f\r ]+$/g, '').length });
            }
            offset += part.length + 1;
          }
          const seen = new Set();
          const duplicate = parts.some((part) => { if (seen.has(part.property)) return true; seen.add(part.property); return false; });
          if (malformed || duplicate) unsupportedAt(duplicate ? 'DUPLICATE_DECLARATION' : 'MALFORMED_STYLE', node);
          else for (const part of parts) emit(part.property, part.value, part.start, part.end, 'inline-style', node);
        }
      }
      if (node.tagName === 'meta') {
        const name = attribute(node, 'name', text);
        if (name?.overLimit) fail('RESOURCE_LIMIT');
        if (name?.unsupported) unsupportedAt('RAW_ATTRIBUTE_UNSUPPORTED', node);
        if (name?.raw?.toLowerCase() === 'theme-color') {
          const content = attribute(node, 'content', text);
          if (content?.overLimit) fail('RESOURCE_LIMIT');
          if (!content || content.unsupported) unsupportedAt('RAW_ATTRIBUTE_UNSUPPORTED', node);
          else emit('theme-color', content.raw, content.start, content.end, 'meta-theme-color', node);
        }
      }
    }
    // Template contents are never evaluated. Foreign SVG/MathML descendants
    // retain their namespaces and do not become HTML style declarations.
    const children = node.childNodes ?? [];
    for (let i = children.length - 1; i >= 0; i -= 1) stack.push({ node: children[i], inert: hidden });
  }
  check();
  declarations.sort((a, b) => a.locator.startByte - b.locator.startByte);
  return Object.freeze({ declarations: Object.freeze(declarations), unsupported: Object.freeze(unsupported) });
}
