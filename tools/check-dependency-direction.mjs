import { createHash } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { isBuiltin } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { version as typescriptVersion } from "typescript";
import { API } from "typescript/unstable/sync";
import { NodeFlags, SyntaxKind } from "typescript/unstable/ast";

const REPOSITORY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MODULE_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const DEPENDENCY_GROUPS = ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"];
const LOADER_NAMES = new Set(["require", "createRequire", "getBuiltinModule"]);
const NATIVE_GUARD = "src/extraction/pdf/network-guard.mjs";
const PNG_NATIVE_GUARD = "src/extraction/png/network-guard.mjs";
const PNG_DNS_METHODS = ["lookup", "lookupService", "resolve", "resolve4", "resolve6",
  "resolveAny", "resolveCaa", "resolveCname", "resolveMx", "resolveNaptr",
  "resolveNs", "resolvePtr", "resolveSoa", "resolveSrv", "resolveTxt", "reverse"];
const PNG_NATIVE_MODULES = [
  ["node:http", ["request", "get", "ClientRequest"]], ["node:https", ["request", "get"]],
  ["node:http2", ["connect"]], ["node:net", ["connect", "createConnection"]],
  ["node:tls", ["connect"]], ["node:dgram", ["createSocket"]],
  ["node:dns", PNG_DNS_METHODS], ["node:dns/promises", PNG_DNS_METHODS],
];
const NATIVE_MODULES = [
  ["node:http", ["request", "get"], "http"],
  ["node:https", ["request", "get"], "https"],
  ["node:net", ["connect", "createConnection"], "socket"],
  ["node:tls", ["connect"], "tls"],
  ["node:dgram", ["createSocket"], "datagram"],
  ["node:dns", ["lookup", "resolve", "resolve4", "resolve6"], "dns"],
  ["node:dns/promises", ["lookup", "resolve", "resolve4", "resolve6"], "dns-promises"],
];

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const identifier = (node, name) => node?.kind === SyntaxKind.Identifier && node.text === name;
const literal = (node) => [SyntaxKind.StringLiteral, SyntaxKind.NoSubstitutionTemplateLiteral].includes(node?.kind) ? node.text : undefined;
const harnessIdentity = (value) => typeof value === "string" && /(?:^|[/\\:#])agent-harness(?:[/.@?#]|$)/i.test(value);
const within = (root, target) => target === root || (!path.relative(root, target).startsWith(`..${path.sep}`) && path.relative(root, target) !== ".." && !path.isAbsolute(path.relative(root, target)));

function propertyName(node) {
  if (node?.kind === SyntaxKind.Identifier) return node.text;
  if (node?.kind === SyntaxKind.ComputedPropertyName) return literal(node.expression);
  return literal(node);
}

function inAssignmentPattern(node) {
  let current = node;
  while (current.parent) {
    const parent = current.parent;
    if (parent.kind === SyntaxKind.BinaryExpression) return parent.left === current && parent.operatorToken.kind === SyntaxKind.EqualsToken;
    if ([SyntaxKind.ForOfStatement, SyntaxKind.ForInStatement].includes(parent.kind)) return parent.initializer === current;
    if (![SyntaxKind.ObjectLiteralExpression, SyntaxKind.ArrayLiteralExpression, SyntaxKind.PropertyAssignment, SyntaxKind.SpreadAssignment, SyntaxKind.SpreadElement, SyntaxKind.ParenthesizedExpression].includes(parent.kind)) return false;
    current = parent;
  }
  return false;
}

// A removed binding carries no loader, but inline type bindings can still leave
// a runtime module import. Do not use this predicate to classify module edges.
function erasedSpecifierBinding(node) {
  if (![SyntaxKind.ImportSpecifier, SyntaxKind.ExportSpecifier].includes(node.kind)) return false;
  if (node.isTypeOnly) return true;
  let parent = node.parent;
  while (parent && ![SyntaxKind.ImportDeclaration, SyntaxKind.ExportDeclaration, SyntaxKind.SourceFile].includes(parent.kind)) parent = parent.parent;
  return parent?.importClause?.isTypeOnly === true || parent?.isTypeOnly === true;
}

function visit(node, callback) {
  callback(node);
  node.forEachChild((child) => { visit(child, callback); });
}

function constantArray(node) {
  if (node?.kind === SyntaxKind.ArrayLiteralExpression) return node.elements.map(constantArray);
  if (node?.kind === SyntaxKind.StringLiteral) return node.text;
  return null;
}

function constantDeclaration(statement, name) {
  if (statement?.kind !== SyntaxKind.VariableStatement) return undefined;
  const list = statement.declarationList;
  if (!(list.flags & NodeFlags.Const) || list.declarations.length !== 1) return undefined;
  const declaration = list.declarations[0];
  return identifier(declaration.name, name) ? declaration : undefined;
}

// This is a shape/set exception for one native-only loop, never a file exemption.
function nativeGuardException(source, relative) {
  if (relative !== NATIVE_GUARD) return undefined;
  const imports = source.statements.filter((node) => node.kind === SyntaxKind.ImportDeclaration && literal(node.moduleSpecifier) === "node:module");
  if (imports.length !== 1) return undefined;
  const loaderImport = imports[0];
  const bindings = loaderImport.importClause?.namedBindings;
  if (loaderImport.importClause?.name || loaderImport.importClause?.isTypeOnly || bindings?.kind !== SyntaxKind.NamedImports || bindings.elements.length !== 1) return undefined;
  const imported = bindings.elements[0];
  if (imported.propertyName || imported.isTypeOnly || !identifier(imported.name, "createRequire")) return undefined;
  const declarations = source.statements.map((node) => constantDeclaration(node, "require")).filter(Boolean);
  if (declarations.length !== 1) return undefined;
  const declaration = declarations[0];
  const factory = declaration.initializer;
  if (factory?.kind !== SyntaxKind.CallExpression || !identifier(factory.expression, "createRequire") || factory.arguments.length !== 1) return undefined;
  const location = factory.arguments[0];
  if (location.kind !== SyntaxKind.PropertyAccessExpression || !identifier(location.name, "url") || location.expression.kind !== SyntaxKind.MetaProperty || location.expression.keywordToken !== SyntaxKind.ImportKeyword || !identifier(location.expression.name, "meta")) return undefined;
  const functions = source.statements.filter((node) => node.kind === SyntaxKind.FunctionDeclaration && identifier(node.name, "installPdfNetworkGuard"));
  if (functions.length !== 1 || functions[0].parameters.length !== 0 || functions[0].asteriskToken || functions[0].modifiers?.some((node) => node.kind === SyntaxKind.AsyncKeyword) || !functions[0].body) return undefined;
  const loops = functions[0].body.statements.filter((node) => node.kind === SyntaxKind.ForOfStatement);
  if (loops.length !== 1) return undefined;
  const loop = loops[0];
  if (loop.awaitModifier || loop.initializer.kind !== SyntaxKind.VariableDeclarationList || !(loop.initializer.flags & NodeFlags.Const) || loop.initializer.declarations.length !== 1 || loop.initializer.declarations[0].initializer) return undefined;
  const names = loop.initializer.declarations[0].name;
  if (names.kind !== SyntaxKind.ArrayBindingPattern || names.elements.length !== 3 || names.elements.some((node, index) => node.kind !== SyntaxKind.BindingElement || node.dotDotDotToken || node.propertyName || node.initializer || !identifier(node.name, ["moduleName", "methods", "kind"][index]))) return undefined;
  if (JSON.stringify(constantArray(loop.expression)) !== JSON.stringify(NATIVE_MODULES) || loop.statement.kind !== SyntaxKind.Block) return undefined;
  const target = constantDeclaration(loop.statement.statements[0], "target");
  const call = target?.initializer;
  if (call?.kind !== SyntaxKind.CallExpression || !identifier(call.expression, "require") || call.arguments.length !== 1 || !identifier(call.arguments[0], "moduleName")) return undefined;
  return {
    loaderImport,
    call,
    modules: NATIVE_MODULES,
    identifiers: new Set([imported.name, declaration.name, factory.expression, call.expression]),
  };
}

// The PNG child has a distinct fixed eight-module loop. Recognize its exact
// loader binding, loop, DNS constant and five prototype loads; no file exemption.
function pngNativeGuardException(source, relative) {
  if (relative !== PNG_NATIVE_GUARD) return undefined;
  const imports = source.statements.filter((n) => n.kind === SyntaxKind.ImportDeclaration && literal(n.moduleSpecifier) === "node:module");
  if (imports.length !== 1) return undefined;
  const loaderImport = imports[0];
  const bindings = loaderImport.importClause?.namedBindings;
  if (loaderImport.importClause?.name || loaderImport.importClause?.isTypeOnly || bindings?.kind !== SyntaxKind.NamedImports || bindings.elements.length !== 2) return undefined;
  if (bindings.elements.some((n, i) => n.propertyName || n.isTypeOnly || !identifier(n.name, ["createRequire", "syncBuiltinESMExports"][i]))) return undefined;
  const declarations = source.statements.map((n) => constantDeclaration(n, "require")).filter(Boolean);
  if (declarations.length !== 1) return undefined;
  const declaration = declarations[0];
  const factory = declaration.initializer;
  if (factory?.kind !== SyntaxKind.CallExpression || !identifier(factory.expression, "createRequire") || factory.arguments.length !== 1) return undefined;
  const location = factory.arguments[0];
  if (location.kind !== SyntaxKind.PropertyAccessExpression || !identifier(location.name, "url") || location.expression.kind !== SyntaxKind.MetaProperty || location.expression.keywordToken !== SyntaxKind.ImportKeyword || !identifier(location.expression.name, "meta")) return undefined;
  const functions = source.statements.filter((n) => n.kind === SyntaxKind.FunctionDeclaration && identifier(n.name, "installPngNetworkGuard"));
  if (functions.length !== 1) return undefined;
  const fn = functions[0];
  if (fn.parameters.length || fn.asteriskToken || fn.modifiers?.some((n) => n.kind === SyntaxKind.AsyncKeyword) || !fn.body) return undefined;
  const dns = fn.body.statements.map((n) => constantDeclaration(n, "dnsMethods")).filter(Boolean);
  if (dns.length !== 1 || JSON.stringify(constantArray(dns[0].initializer)) !== JSON.stringify(PNG_DNS_METHODS)) return undefined;
  const dnsIdentifiers = new Set([dns[0].name]);
  const array = (n) => {
    if (identifier(n, "dnsMethods")) { dnsIdentifiers.add(n); return PNG_DNS_METHODS; }
    if (n?.kind === SyntaxKind.ArrayLiteralExpression) return n.elements.map(array);
    return n?.kind === SyntaxKind.StringLiteral ? n.text : null;
  };
  const loops = fn.body.statements.filter((n) => n.kind === SyntaxKind.ForOfStatement);
  if (loops.length !== 1) return undefined;
  const loop = loops[0];
  if (loop.awaitModifier || loop.initializer.kind !== SyntaxKind.VariableDeclarationList || !(loop.initializer.flags & NodeFlags.Const) || loop.initializer.declarations.length !== 1 || loop.initializer.declarations[0].initializer) return undefined;
  const names = loop.initializer.declarations[0].name;
  if (names.kind !== SyntaxKind.ArrayBindingPattern || names.elements.length !== 2 || names.elements.some((n, i) => n.kind !== SyntaxKind.BindingElement || n.dotDotDotToken || n.propertyName || n.initializer || !identifier(n.name, ["name", "methods"][i]))) return undefined;
  if (JSON.stringify(array(loop.expression)) !== JSON.stringify(PNG_NATIVE_MODULES) || loop.statement.kind !== SyntaxKind.ExpressionStatement) return undefined;
  const patch = loop.statement.expression;
  if (patch.kind !== SyntaxKind.CallExpression || !identifier(patch.expression, "patch") || patch.arguments.length !== 2 || !identifier(patch.arguments[1], "methods")) return undefined;
  const call = patch.arguments[0];
  if (call.kind !== SyntaxKind.CallExpression || !identifier(call.expression, "require") || call.arguments.length !== 1 || !identifier(call.arguments[0], "name")) return undefined;
  const allowedCalls = new Set([call]);
  const prototypes = [
    ["node:net", "Socket", ["connect"]], ["node:net", "Server", ["listen"]],
    ["node:dgram", "Socket", ["connect", "send", "bind"]],
    ["node:dns", "Resolver", PNG_DNS_METHODS], ["node:dns/promises", "Resolver", PNG_DNS_METHODS],
  ];
  const offset = fn.body.statements.indexOf(loop) + 1;
  for (const [i, [moduleName, constructor, methods]] of prototypes.entries()) {
    const statement = fn.body.statements[offset + i];
    const invocation = statement?.kind === SyntaxKind.ExpressionStatement ? statement.expression : undefined;
    if (invocation?.kind !== SyntaxKind.CallExpression || !identifier(invocation.expression, "patch") || invocation.arguments.length !== 2 || JSON.stringify(array(invocation.arguments[1])) !== JSON.stringify(methods)) return undefined;
    const target = invocation.arguments[0];
    if (target.kind !== SyntaxKind.PropertyAccessExpression || !identifier(target.name, "prototype")) return undefined;
    const owner = target.expression;
    if (owner.kind !== SyntaxKind.PropertyAccessExpression || !identifier(owner.name, constructor)) return undefined;
    const load = owner.expression;
    if (load.kind !== SyntaxKind.CallExpression || !identifier(load.expression, "require") || load.arguments.length !== 1 || literal(load.arguments[0]) !== moduleName) return undefined;
    allowedCalls.add(load);
  }
  let drift = false;
  visit(source, (n) => {
    if (n.kind === SyntaxKind.CallExpression && identifier(n.expression, "require") && !allowedCalls.has(n)) drift = true;
    if (identifier(n, "dnsMethods") && !dnsIdentifiers.has(n)) drift = true;
  });
  if (drift) return undefined;
  return { loaderImport, call, modules: PNG_NATIVE_MODULES,
    identifiers: new Set([bindings.elements[0].name, declaration.name, factory.expression, call.expression]) };
}

function jsonImport(node) {
  const attributes = node.attributes;
  return node.kind === SyntaxKind.ImportDeclaration && !node.importClause?.isTypeOnly
    && attributes?.token === SyntaxKind.WithKeyword && attributes.attributes?.length === 1
    && propertyName(attributes.attributes[0].name) === "type"
    && literal(attributes.attributes[0].value) === "json";
}

function collectSources(root, violations, dataFiles = new Map()) {
  const sources = new Map();
  const collect = (directory) => {
    for (const entry of readdirSync(directory).sort()) {
      const filename = path.join(directory, entry);
      const relative = path.relative(root, filename).split(path.sep).join("/");
      const stat = lstatSync(filename);
      if (stat.isSymbolicLink()) {
        violations.push({ code: "SOURCE_SYMLINK", file: relative });
      } else if (stat.isDirectory()) {
        collect(filename);
      } else if (stat.isFile() && (MODULE_FILE.test(entry) || entry.endsWith(".json"))) {
        const bytes = readFileSync(filename);
        const text = bytes.toString("utf8");
        if (!Buffer.from(text).equals(bytes)) violations.push({ code: "SOURCE_ENCODING", file: relative });
        const identity = { path: relative, sha256: digest(bytes), mode: (stat.mode & 0o777).toString(8), text };
        if (entry.endsWith(".json")) {
          try { JSON.parse(text); } catch { violations.push({ code: "INVALID_JSON_DATA", file: relative }); }
          dataFiles.set(filename, identity);
        } else sources.set(filename, identity);
      } else if (MODULE_FILE.test(entry) || entry.endsWith(".json")) {
        violations.push({ code: "UNSUPPORTED_SOURCE_ENTRY", file: relative });
      }
    }
  };
  const directory = path.join(root, "src");
  if (lstatSync(directory).isSymbolicLink()) violations.push({ code: "SOURCE_SYMLINK", file: "src" });
  else collect(directory);
  return sources;
}

/** Parse the local engine graph. This does not inspect or accept foreign repositories. */
export function checkDependencyDirection(directory = REPOSITORY) {
  const root = realpathSync(directory);
  const violations = [];
  const edges = [];
  let sources = new Map();
  const dataFiles = new Map();
  let inputBytes;
  let workspace;
  let api;
  let nativeRequireLoops = 0;
  const inputs = { typescript: typescriptVersion };
  try {
    inputBytes = new Map(["package.json", "package-lock.json"].map((name) => [name, readFileSync(path.join(root, name))]));
    const manifest = JSON.parse(inputBytes.get("package.json"));
    const lock = JSON.parse(inputBytes.get("package-lock.json"));
    inputs.package_sha256 = digest(inputBytes.get("package.json"));
    inputs.lock_sha256 = digest(inputBytes.get("package-lock.json"));
    if (manifest.devDependencies?.typescript !== typescriptVersion || lock.packages?.["node_modules/typescript"]?.version !== typescriptVersion) violations.push({ code: "PARSER_PIN_MISMATCH", file: "package.json" });
    for (const group of DEPENDENCY_GROUPS) {
      const declared = manifest[group] ?? {};
      const locked = lock.packages?.[""]?.[group] ?? {};
      if (JSON.stringify(Object.entries(declared).sort()) !== JSON.stringify(Object.entries(locked).sort())) violations.push({ code: "LOCK_ROOT_MISMATCH", file: "package-lock.json", group });
      for (const [name, target] of Object.entries(declared)) {
        if (harnessIdentity(name) || harnessIdentity(target)) violations.push({ code: "HARNESS_DEPENDENCY", file: "package.json", group, package: name });
      }
    }
    for (const [name, entry] of Object.entries(lock.packages ?? {})) {
      if (harnessIdentity(name) || harnessIdentity(entry.name) || harnessIdentity(entry.resolved)) violations.push({ code: "HARNESS_LOCK_ENTRY", file: "package-lock.json", package: name });
    }
    sources = collectSources(root, violations, dataFiles);
    if (sources.size === 0) violations.push({ code: "NO_ENGINE_SOURCES", file: "src" });
    workspace = mkdtempSync(path.join(tmpdir(), "ei-dependency-direction-"));
    const config = path.join(workspace, "tsconfig.json");
    writeFileSync(config, JSON.stringify({ compilerOptions: { noLib: true, noResolve: true, types: [], allowJs: true }, files: [...sources.keys()] }));
    api = new API({ cwd: root });
    const snapshot = api.updateSnapshot({ openProjects: [config] });
    const project = snapshot.getProject(config);
    if (!project) throw new Error("Parser did not load the complete source project");
    for (const [filename, identity] of sources) {
      const source = project.program.getSourceFile(filename);
      if (!source || source.text !== identity.text) {
        violations.push({ code: "PARSER_SOURCE_MISMATCH", file: identity.path });
        continue;
      }
      const diagnostics = project.program.getSyntacticDiagnostics(filename);
      for (const diagnostic of diagnostics) violations.push({ code: "SOURCE_SYNTAX", file: identity.path, diagnostic: diagnostic.code });
      const exception = nativeGuardException(source, identity.path) ?? pngNativeGuardException(source, identity.path);
      if (exception) nativeRequireLoops += 1;
      const where = (node, position = node.getStart(source)) => ({ file: identity.path, line: source.getLineAndCharacterOfPosition(position).line + 1 });
      const refuse = (code, node) => { violations.push({ code, ...where(node) }); };
      const add = (specifier, kind, node, typeOnly = false, position) => {
        const deny = (code) => { violations.push({ code, ...where(node, position) }); };
        if (typeof specifier !== "string" || specifier.length === 0) { deny("UNRESOLVED_MODULE_SPECIFIER"); return; }
        const edge = { from: identity.path, line: where(node, position).line, kind, specifier, type_only: typeOnly || /\.d\.[cm]?ts$/.test(filename) };
        if (harnessIdentity(specifier)) { deny("ENGINE_IMPORTS_HARNESS"); return; }
        if (specifier.includes("\\") || /[\0?#%]/.test(specifier)) { deny("UNSUPPORTED_MODULE_SPECIFIER"); return; }
        // A Node declaration reference names the @types/node package, not the
        // runtime node:module loader. Keep the original directive in the edge.
        if (kind === "reference-types" && specifier === "node") specifier = "@types/node";
        if (isBuiltin(specifier)) {
          if (["node:module", "module"].includes(specifier) && node !== exception?.loaderImport) { deny("UNACCOUNTED_MODULE_LOADER"); return; }
          edge.target = specifier.startsWith("node:") ? specifier : `node:${specifier}`;
          edge.layer = "node";
        } else if (specifier.startsWith("./") || specifier.startsWith("../")) {
          const target = path.resolve(path.dirname(filename), specifier);
          if (!within(path.join(root, "src"), target)) { deny("ENGINE_SOURCE_ESCAPE"); return; }
          if (specifier.endsWith(".json")) {
            if (!jsonImport(node)) { deny("UNSUPPORTED_JSON_IMPORT"); return; }
            if (!dataFiles.has(target)) { deny("UNRESOLVED_LOCAL_MODULE"); return; }
            edge.target = dataFiles.get(target).path;
            edge.layer = "engine-data";
            edge.attributes = { type: "json" };
            edges.push(edge);
            return;
          }
          if (node.attributes) { deny("UNSUPPORTED_IMPORT_ATTRIBUTES"); return; }
          let resolved = target;
          if (typeOnly || /\.d\.[cm]?ts$/.test(filename)) {
            const declaration = target.replace(/\.mjs$/, ".d.mts").replace(/\.cjs$/, ".d.cts").replace(/\.js$/, ".d.ts");
            if (sources.has(declaration)) resolved = declaration;
          }
          if (!sources.has(resolved)) { deny("UNRESOLVED_LOCAL_MODULE"); return; }
          edge.target = sources.get(resolved).path;
          edge.layer = "engine";
        } else {
          if (specifier.startsWith("/") || specifier.includes(":") || specifier.startsWith("#") || specifier.split("/").some((part) => ["", ".", ".."].includes(part))) { deny("UNSUPPORTED_MODULE_SPECIFIER"); return; }
          const parts = specifier.split("/");
          const name = specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
          const groups = typeOnly || /\.d\.[cm]?ts$/.test(filename) ? DEPENDENCY_GROUPS : DEPENDENCY_GROUPS.filter((group) => group !== "devDependencies");
          if (!groups.some((group) => Object.hasOwn(manifest[group] ?? {}, name))) { deny("UNDECLARED_ENGINE_DEPENDENCY"); return; }
          if (!lock.packages?.[`node_modules/${name}`]) { deny("UNLOCKED_ENGINE_DEPENDENCY"); return; }
          edge.target = name;
          edge.layer = "declared-package";
        }
        edges.push(edge);
      };
      visit(source, (node) => {
        if (node.kind === SyntaxKind.ImportDeclaration || node.kind === SyntaxKind.ExportDeclaration) {
          if (node.moduleSpecifier) add(literal(node.moduleSpecifier), node.kind === SyntaxKind.ImportDeclaration ? "import" : "reexport", node, node.importClause?.isTypeOnly === true || node.isTypeOnly === true);
        } else if (node.kind === SyntaxKind.ImportType) {
          add(literal(node.argument?.literal), "type-import", node, true);
        } else if (node.kind === SyntaxKind.ExternalModuleReference) {
          add(literal(node.expression), "import-equals", node);
        } else if (node.kind === SyntaxKind.CallExpression) {
          const callee = node.expression;
          const directRequire = identifier(callee, "require");
          const moduleRequire = callee.kind === SyntaxKind.PropertyAccessExpression && identifier(callee.expression, "module") && identifier(callee.name, "require");
          const requireResolve = callee.kind === SyntaxKind.PropertyAccessExpression && identifier(callee.expression, "require") && identifier(callee.name, "resolve");
          const builtinLoader = callee.kind === SyntaxKind.PropertyAccessExpression && identifier(callee.expression, "process") && identifier(callee.name, "getBuiltinModule");
          if (node === exception?.call) {
            for (const [specifier] of exception.modules) add(specifier, "bounded-native-require", node);
          } else if (callee.kind === SyntaxKind.ImportKeyword || directRequire || moduleRequire || requireResolve || builtinLoader) {
            if (node.arguments.length < 1 || (callee.kind !== SyntaxKind.ImportKeyword && node.arguments.length !== 1)) refuse("UNRESOLVED_MODULE_SPECIFIER", node);
            else add(literal(node.arguments[0]), callee.kind === SyntaxKind.ImportKeyword ? "dynamic-import" : "require", node);
          } else if (identifier(callee, "eval")) refuse("UNACCOUNTED_CODE_LOADER", node);
        } else if (node.kind === SyntaxKind.NewExpression && identifier(node.expression, "Function")) {
          refuse("UNACCOUNTED_CODE_LOADER", node);
        }
        if (node.kind === SyntaxKind.Identifier && ["require", "createRequire"].includes(node.text) && !exception?.identifiers.has(node) && !erasedSpecifierBinding(node.parent)) {
          const parent = node.parent;
          const directCall = parent.kind === SyntaxKind.CallExpression && parent.expression === node && node.text === "require";
          const resolveCall = parent.kind === SyntaxKind.PropertyAccessExpression && parent.expression === node && identifier(parent.name, "resolve") && parent.parent.kind === SyntaxKind.CallExpression && parent.parent.expression === parent;
          const moduleCall = node.text === "require" && parent.kind === SyntaxKind.PropertyAccessExpression && parent.name === node && identifier(parent.expression, "module") && parent.parent.kind === SyntaxKind.CallExpression && parent.parent.expression === parent;
          if (!directCall && !resolveCall && !moduleCall) refuse("UNACCOUNTED_MODULE_LOADER", node);
        }
        if (identifier(node, "module") && !erasedSpecifierBinding(node.parent)) {
          const parent = node.parent;
          const exports = parent.kind === SyntaxKind.PropertyAccessExpression && parent.expression === node && identifier(parent.name, "exports");
          const directRequire = parent.kind === SyntaxKind.PropertyAccessExpression && parent.expression === node && identifier(parent.name, "require") && parent.parent.kind === SyntaxKind.CallExpression && parent.parent.expression === parent;
          if (!exports && !directRequire) refuse("UNACCOUNTED_MODULE_LOADER", node);
        }
        // Recognized loader properties remain capabilities when extracted or
        // selected through an alias. This is a syntax rule, not alias execution.
        if (node.kind === SyntaxKind.BindingElement && LOADER_NAMES.has(propertyName(node.propertyName ?? node.name))) refuse("UNACCOUNTED_MODULE_LOADER", node);
        if ([SyntaxKind.PropertyAssignment, SyntaxKind.ShorthandPropertyAssignment].includes(node.kind) && LOADER_NAMES.has(propertyName(node.name)) && inAssignmentPattern(node)) refuse("UNACCOUNTED_MODULE_LOADER", node);
        if ([SyntaxKind.ImportSpecifier, SyntaxKind.ExportSpecifier].includes(node.kind) && LOADER_NAMES.has(propertyName(node.propertyName ?? node.name)) && !erasedSpecifierBinding(node) && !exception?.identifiers.has(node.name)) refuse("UNACCOUNTED_MODULE_LOADER", node);
        if (node.kind === SyntaxKind.ElementAccessExpression && (identifier(node.expression, "require") || identifier(node.expression, "module") || LOADER_NAMES.has(literal(node.argumentExpression)))) refuse("UNACCOUNTED_MODULE_LOADER", node);
        if (node.kind === SyntaxKind.ElementAccessExpression && identifier(node.expression, "globalThis") && ["require", "module", "createRequire", "getBuiltinModule"].includes(literal(node.argumentExpression))) refuse("UNACCOUNTED_MODULE_LOADER", node);
        if (node.kind === SyntaxKind.PropertyAccessExpression && identifier(node.name, "getBuiltinModule") && !(identifier(node.expression, "process") && node.parent.kind === SyntaxKind.CallExpression && node.parent.expression === node)) refuse("UNACCOUNTED_MODULE_LOADER", node);
      });
      for (const reference of source.referencedFiles) add(reference.fileName, "reference-path", source, true, reference.pos);
      for (const reference of source.typeReferenceDirectives) add(reference.fileName, "reference-types", source, true, reference.pos);
      if ([NATIVE_GUARD, PNG_NATIVE_GUARD].includes(identity.path) && !exception) violations.push({ code: "NATIVE_REQUIRE_EXCEPTION_DRIFT", file: identity.path });
    }
  } catch (error) {
    violations.push({ code: "INCOMPLETE_GRAPH", detail: error instanceof Error ? error.message : String(error) });
  } finally {
    try { api?.close(); } catch { violations.push({ code: "INCOMPLETE_PARSER_CLEANUP" }); }
    try { if (workspace) rmSync(workspace, { recursive: true, force: true }); } catch { violations.push({ code: "INCOMPLETE_WORKSPACE_CLEANUP" }); }
  }
  try {
    const readbackViolations = [];
    const dataAfter = new Map();
    const after = collectSources(root, readbackViolations, dataAfter);
    if (readbackViolations.length !== 0 || after.size !== sources.size || [...sources].some(([name, record]) => after.get(name)?.sha256 !== record.sha256 || after.get(name)?.mode !== record.mode)) violations.push({ code: "SOURCE_CHANGED_DURING_SCAN", file: "src" });
    if (dataAfter.size !== dataFiles.size || [...dataFiles].some(([name, record]) => dataAfter.get(name)?.sha256 !== record.sha256 || dataAfter.get(name)?.mode !== record.mode)) violations.push({ code: "DATA_CHANGED_DURING_SCAN", file: "src" });
    for (const [name, bytes] of inputBytes ?? []) if (!readFileSync(path.join(root, name)).equals(bytes)) violations.push({ code: "INPUT_CHANGED_DURING_SCAN", file: name });
  } catch (error) {
    violations.push({ code: "INCOMPLETE_READBACK", detail: error instanceof Error ? error.message : String(error) });
  }
  const files = [...sources.values()].map(({ text: _text, ...identity }) => identity);
  const data_files = [...dataFiles.values()].map(({ text: _text, ...identity }) => identity);
  const graph = { files, data_files, edges };
  return {
    schema_version: "ei-dependency-direction/v1",
    status: violations.length === 0 ? "passed" : "failed",
    mode: "local-static-import-graph",
    inputs,
    graph_sha256: digest(JSON.stringify(graph)),
    counts: { source_files: files.length, data_files: data_files.length, edges: edges.length, bounded_native_require_loops: nativeRequireLoops, violations: violations.length },
    ...graph,
    violations,
    acceptance: { local_import_boundary: violations.length === 0 ? "passed" : "failed", foreign_harness_to_engine: "not_inspected", accepted_contract_pin: "not_asserted", decision_capability_behavior: "not_executed" },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) {
    process.stderr.write("This check accepts no arguments; it always reads this repository's src and manifests.\n");
    process.exitCode = 2;
  } else {
    const result = checkDependencyDirection();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.status === "passed" ? 0 : 1;
  }
}
