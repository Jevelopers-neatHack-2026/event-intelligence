import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { checkDependencyDirection } from "../../tools/check-dependency-direction.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const NATIVE_PATH = "src/extraction/pdf/network-guard.mjs";
const NATIVE_SOURCE = readFileSync(path.join(ROOT, NATIVE_PATH), "utf8");

function fixture(files, mutate = () => {}) {
  const directory = mkdtempSync(path.join(tmpdir(), "ei-dependency-direction-test-"));
  const manifest = { name: "synthetic-ei-engine", type: "module", dependencies: { "synthetic-contract-only": "0.0.0-synthetic" }, devDependencies: { typescript: "7.0.2" } };
  const lock = { lockfileVersion: 3, packages: { "": { dependencies: { ...manifest.dependencies }, devDependencies: { ...manifest.devDependencies } }, "node_modules/typescript": { version: "7.0.2" }, "node_modules/synthetic-contract-only": { version: "0.0.0-synthetic" } } };
  try {
    mutate(manifest, lock, directory);
    writeFileSync(path.join(directory, "package.json"), JSON.stringify(manifest));
    writeFileSync(path.join(directory, "package-lock.json"), JSON.stringify(lock));
    mkdirSync(path.join(directory, "src"), { recursive: true });
    for (const [name, text] of Object.entries(files)) {
      const target = path.join(directory, name);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, text);
    }
    return checkDependencyDirection(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

const refuses = (result, code) => {
  assert.equal(result.status, "failed", JSON.stringify(result));
  assert.ok(result.violations.some((item) => item.code === code), JSON.stringify(result.violations));
  assert.equal(result.acceptance.foreign_harness_to_engine, "not_inspected");
  assert.equal(result.acceptance.accepted_contract_pin, "not_asserted");
};

test("current source graph has no Harness import and preserves external acceptance gaps", () => {
  const result = checkDependencyDirection(ROOT);
  assert.equal(result.status, "passed", JSON.stringify(result.violations));
  assert.ok(result.counts.source_files > 0);
  assert.ok(result.edges.some((edge) => edge.layer === "engine"));
  assert.ok(result.edges.some((edge) => edge.layer === "declared-package"));
  assert.equal(result.counts.bounded_native_require_loops, 1);
  assert.equal(result.edges.filter((edge) => edge.kind === "bounded-native-require").length, 7);
  assert.equal(result.acceptance.foreign_harness_to_engine, "not_inspected");
  assert.equal(result.acceptance.accepted_contract_pin, "not_asserted");
  assert.equal(result.acceptance.decision_capability_behavior, "not_executed");
  assert.match(result.graph_sha256, /^[a-f0-9]{64}$/);
});

test("synthetic contract-only, local, Node, declaration and literal dynamic imports pass without executing source", () => {
  const result = fixture({
    "src/index.mjs": 'import "synthetic-contract-only/port"; import "node:fs"; export { value } from "./value.mjs"; await import("./value.mjs"); throw new Error("must never execute");',
    "src/value.mjs": 'export const value = 1;',
    "src/value.d.mts": 'export declare const value: number;',
    "src/index.d.mts": 'export type Value = typeof import("./value.mjs").value; import type { Port } from "synthetic-contract-only"; export type { Port };',
  });
  assert.equal(result.status, "passed", JSON.stringify(result.violations));
  assert.ok(result.edges.some((edge) => edge.kind === "type-import" && edge.target === "src/value.d.mts"));
  assert.ok(result.edges.some((edge) => edge.kind === "dynamic-import"));
  assert.equal(result.acceptance.accepted_contract_pin, "not_asserted");
});

test("comments, quoted import text, regex literals and inert templates do not create graph edges", () => {
  const result = fixture({ "src/index.mjs": '// import "agent-harness";\nconst text = \'require("agent-harness")\'; const regex = /import("agent-harness")/; const template = `import "agent-harness"`; export { text, regex, template };' });
  assert.equal(result.status, "passed", JSON.stringify(result.violations));
  assert.equal(result.edges.length, 0);
});

for (const [name, source] of [
  ["bare import", 'import "agent-harness";'],
  ["scoped subpath", 'import { execute } from "@jevelopers/agent-harness/execute";'],
  ["namespace reexport", 'export * as harness from "@jevelopers/agent-harness";'],
  ["named reexport", 'export { run } from "agent-harness";'],
  ["type-only declaration", 'import type { DecisionPort } from "@jevelopers/agent-harness";'],
  ["inline type import", 'type Port = import("agent-harness").DecisionPort;'],
  ["CommonJS import equals", 'import harness = require("agent-harness");'],
  ["literal dynamic import", 'void import("agent-harness");'],
  ["escaped literal dynamic import", 'void import("\\u0061gent-harness");'],
  ["no-substitution template import", 'void import(`agent-harness`);'],
  ["direct require", 'require("agent-harness");'],
  ["module require", 'module.require("agent-harness");'],
  ["require resolve", 'require.resolve("agent-harness");'],
]) {
  test(`rejects synthetic Harness dependency through ${name}`, () => {
    refuses(fixture({ "src/index.mts": source }), "ENGINE_IMPORTS_HARNESS");
  });
}

for (const [name, source, code] of [
  ["relative traversal", 'import "../outside.mjs";', "ENGINE_SOURCE_ESCAPE"],
  ["normalized traversal", 'import "./part/../../outside.mjs";', "ENGINE_SOURCE_ESCAPE"],
  ["encoded traversal", 'import "./%2e%2e/outside.mjs";', "UNSUPPORTED_MODULE_SPECIFIER"],
  ["absolute path", 'import "/tmp/outside.mjs";', "UNSUPPORTED_MODULE_SPECIFIER"],
  ["file URL", 'import "file:///tmp/outside.mjs";', "UNSUPPORTED_MODULE_SPECIFIER"],
  ["network URL", 'import "https://example.invalid/module.mjs";', "UNSUPPORTED_MODULE_SPECIFIER"],
  ["import alias", 'import "#port";', "UNSUPPORTED_MODULE_SPECIFIER"],
  ["missing local module", 'import "./absent.mjs";', "UNRESOLVED_LOCAL_MODULE"],
  ["undeclared runtime package", 'import "typescript";', "UNDECLARED_ENGINE_DEPENDENCY"],
  ["computed import", 'void import("synthetic-" + "contract-only");', "UNRESOLVED_MODULE_SPECIFIER"],
  ["variable import", 'void import(selected);', "UNRESOLVED_MODULE_SPECIFIER"],
  ["template substitution", 'void import(`synthetic-${selected}`);', "UNRESOLVED_MODULE_SPECIFIER"],
  ["variable require", 'require(selected);', "UNRESOLVED_MODULE_SPECIFIER"],
  ["aliased require", 'const load = require; load("synthetic-contract-only");', "UNACCOUNTED_MODULE_LOADER"],
  ["computed module require", 'module["require"]("synthetic-contract-only");', "UNACCOUNTED_MODULE_LOADER"],
  ["computed require through a module alias", 'const loader = module; loader["require"]("agent-harness");', "UNACCOUNTED_MODULE_LOADER"],
  ["computed global require", 'globalThis["require"]("agent-harness");', "UNACCOUNTED_MODULE_LOADER"],
  ["aliased factory", 'import { createRequire as load } from "node:module"; const local = load(import.meta.url); local("synthetic-contract-only");', "UNACCOUNTED_MODULE_LOADER"],
  ["namespace factory", 'import * as loader from "node:module"; loader.createRequire(import.meta.url)("synthetic-contract-only");', "UNACCOUNTED_MODULE_LOADER"],
  ["builtin module loader", 'process.getBuiltinModule("module");', "UNACCOUNTED_MODULE_LOADER"],
  ["aliased builtin loader", 'const load = process.getBuiltinModule;', "UNACCOUNTED_MODULE_LOADER"],
  ["builtin loader through a process alias", 'const p = process; const m = p.getBuiltinModule("module"); m["createRequire"](import.meta.url)("agent-harness");', "UNACCOUNTED_MODULE_LOADER"],
  ["eval loader", 'eval("import(\\"agent-harness\\")");', "UNACCOUNTED_CODE_LOADER"],
  ["generated function", 'new Function("return import(\\"agent-harness\\")");', "UNACCOUNTED_CODE_LOADER"],
]) {
  test(`rejects unaccounted ${name}`, () => {
    refuses(fixture({ "src/index.mjs": source, "outside.mjs": "export {};" }), code);
  });
}

test("type references to Harness cannot hide in declaration directives", () => {
  refuses(fixture({ "src/index.d.mts": '/// <reference types="@jevelopers/agent-harness" />\nexport {};\n' }), "ENGINE_IMPORTS_HARNESS");
});

test("a declared locked Node type reference remains eligible", () => {
  const result = fixture({ "src/index.d.mts": '/// <reference types="node" />\nexport {};\n' }, (manifest, lock) => {
    manifest.devDependencies["@types/node"] = "22.20.5";
    lock.packages[""].devDependencies["@types/node"] = "22.20.5";
    lock.packages["node_modules/@types/node"] = { version: "22.20.5" };
  });
  assert.equal(result.status, "passed", JSON.stringify(result.violations));
  assert.ok(result.edges.some((edge) => edge.kind === "reference-types" && edge.target === "@types/node" && edge.specifier === "node" && edge.line === 1 && edge.type_only === true));
});

test("literal CommonJS dependencies preserve ordinary module exports", () => {
  const result = fixture({ "src/index.cjs": 'module.exports = require("synthetic-contract-only");' });
  assert.equal(result.status, "passed", JSON.stringify(result.violations));
  assert.equal(result.edges.length, 1);
  assert.equal(result.edges[0].kind, "require");
});

test("relative declaration references cannot leave the engine", () => {
  refuses(fixture({ "src/index.d.mts": '/// <reference path="../outside.d.mts" />\nexport {};\n', "outside.d.mts": "export {};" }), "ENGINE_SOURCE_ESCAPE");
});

test("parse errors are refusals even when preceding imports are eligible", () => {
  refuses(fixture({ "src/index.mjs": 'import "synthetic-contract-only"; const value = ;' }), "SOURCE_SYNTAX");
});

test("empty source sets do not become successful import evidence", () => {
  refuses(fixture({}), "NO_ENGINE_SOURCES");
});

test("an existing file cannot hide outside src behind a symlink", () => {
  refuses(fixture({ "src/index.mjs": 'import "./escape.mjs";', "outside.mjs": 'export {};' }, (_manifest, _lock, root) => {
    mkdirSync(path.join(root, "src"));
    symlinkSync("../outside.mjs", path.join(root, "src/escape.mjs"));
  }), "SOURCE_SYMLINK");
});

test("declared npm aliases cannot rename the Harness", () => {
  refuses(fixture({ "src/index.mjs": 'import "innocent";' }, (manifest, lock) => {
    manifest.dependencies.innocent = "npm:@jevelopers/agent-harness@0.0.0-synthetic";
    lock.packages[""].dependencies.innocent = manifest.dependencies.innocent;
    lock.packages["node_modules/innocent"] = { name: "@jevelopers/agent-harness", version: "0.0.0-synthetic" };
  }), "HARNESS_DEPENDENCY");
});

test("transitive lock entries cannot hide the Harness package", () => {
  refuses(fixture({ "src/index.mjs": "export {};" }, (_manifest, lock) => {
    lock.packages["node_modules/synthetic-contract-only/node_modules/agent-harness"] = { version: "0.0.0-synthetic" };
  }), "HARNESS_LOCK_ENTRY");
});

test("unlocked imports, lock drift and parser pin drift fail independently", async (t) => {
  await t.test("unlocked dependency", () => refuses(fixture({ "src/index.mjs": 'import "synthetic-contract-only";' }, (_manifest, lock) => { delete lock.packages["node_modules/synthetic-contract-only"]; }), "UNLOCKED_ENGINE_DEPENDENCY"));
  await t.test("root lock mismatch", () => refuses(fixture({ "src/index.mjs": "export {};" }, (_manifest, lock) => { lock.packages[""].dependencies.extra = "0.0.0-synthetic"; }), "LOCK_ROOT_MISMATCH"));
  await t.test("parser mismatch", () => refuses(fixture({ "src/index.mjs": "export {};" }, (manifest) => { manifest.devDependencies.typescript = "0.0.0-synthetic"; }), "PARSER_PIN_MISMATCH"));
});

test("the current native loop passes by shape and set, without granting file-wide permission", () => {
  const result = fixture({ [NATIVE_PATH]: NATIVE_SOURCE });
  assert.equal(result.status, "passed", JSON.stringify(result.violations));
  assert.equal(result.counts.bounded_native_require_loops, 1);
  assert.equal(result.edges.filter((edge) => edge.kind === "bounded-native-require").length, 7);
});

for (const [name, source, code] of [
  ["Harness array entry", NATIVE_SOURCE.replace('"node:http"', '"agent-harness"'), "NATIVE_REQUIRE_EXCEPTION_DRIFT"],
  ["extra native entry", NATIVE_SOURCE.replace('["node:http",', '["node:fs", [], "fs"],\n    ["node:http",'), "NATIVE_REQUIRE_EXCEPTION_DRIFT"],
  ["different methods", NATIVE_SOURCE.replace('["request", "get"]', '["request"]'), "NATIVE_REQUIRE_EXCEPTION_DRIFT"],
  ["mutable loop binding", NATIVE_SOURCE.replace('for (const [moduleName', 'for (let [moduleName'), "NATIVE_REQUIRE_EXCEPTION_DRIFT"],
  ["shadowed function argument", NATIVE_SOURCE.replace('installPdfNetworkGuard()', 'installPdfNetworkGuard(require)'), "NATIVE_REQUIRE_EXCEPTION_DRIFT"],
  ["computed loop source", NATIVE_SOURCE.replace('] of [', '] of select([').replace('  ]) {', '  ])) {'), "NATIVE_REQUIRE_EXCEPTION_DRIFT"],
  ["additional Harness import", `${NATIVE_SOURCE}\nimport "agent-harness";`, "ENGINE_IMPORTS_HARNESS"],
  ["additional computed load", `${NATIVE_SOURCE}\nrequire(selected);`, "UNRESOLVED_MODULE_SPECIFIER"],
  ["escaped factory reference", `${NATIVE_SOURCE}\nconst escaped = createRequire;`, "UNACCOUNTED_MODULE_LOADER"],
]) {
  test(`native-only exception rejects ${name}`, () => {
    refuses(fixture({ [NATIVE_PATH]: source }), code);
  });
}

test("identical source has a stable graph digest and changed source gets a new digest", () => {
  const first = fixture({ "src/index.mjs": 'import "node:fs";' });
  const replay = fixture({ "src/index.mjs": 'import "node:fs";' });
  const changed = fixture({ "src/index.mjs": 'import "node:path";' });
  assert.equal(first.status, "passed");
  assert.equal(first.graph_sha256, replay.graph_sha256);
  assert.notEqual(first.graph_sha256, changed.graph_sha256);
});

test("CLI cannot redirect the evidence root or accept arbitrary options", () => {
  const child = spawnSync(process.execPath, [path.join(ROOT, "tools/check-dependency-direction.mjs"), "--root=/tmp"], { encoding: "utf8" });
  assert.equal(child.status, 2);
  assert.equal(child.stdout, "");
  assert.match(child.stderr, /accepts no arguments/);
});

const BUILTIN_LOADER_ESCAPES = [
  ["destructured loader", 'const { getBuiltinModule: load } = process; load("module")["createRequire"](import.meta.url)("agent-harness");'],
  ["constant bracket loader through an alias", 'const p = process; p["getBuiltinModule"]("module")["createRequire"](import.meta.url)("agent-harness");'],
  ["constant bracket loader through global process", 'globalThis.process["getBuiltinModule"]("module")["createRequire"](import.meta.url)("agent-harness");'],
  ["computed destructuring selector", 'const { ["getBuiltinModule"]: load } = process; load("module")["createRequire"](import.meta.url)("agent-harness");'],
  ["shorthand destructured loader", 'const { getBuiltinModule } = process; getBuiltinModule("module")["createRequire"](import.meta.url)("agent-harness");'],
  ["imported loader alias", 'import { getBuiltinModule as load } from "node:process"; load("module")["createRequire"](import.meta.url)("agent-harness");'],
  ["reexported loader alias", 'export { getBuiltinModule as load } from "node:process";'],
];

for (const [name, source] of BUILTIN_LOADER_ESCAPES) {
  test(`independent-review regression refuses ${name}`, () => {
    refuses(fixture({ "src/index.mjs": source }), "UNACCOUNTED_MODULE_LOADER");
  });
}

for (const [name, source] of [
  ["named assignment", 'let load; ({ getBuiltinModule: load } = process); void load;'],
  ["constant computed assignment", 'let load; ({ ["getBuiltinModule"]: load } = process); void load;'],
  ["shorthand assignment", 'let getBuiltinModule; ({ getBuiltinModule } = process);'],
]) {
  test(`destructuring extraction through ${name} remains an unaccounted loader`, () => {
    refuses(fixture({ "src/index.mjs": source }), "UNACCOUNTED_MODULE_LOADER");
  });
}

test("an inert loader-named object field is not an extraction or module edge", () => {
  const result = fixture({ "src/index.mjs": 'const descriptor = { getBuiltinModule: "inert data" }; export { descriptor };' });
  assert.equal(result.status, "passed", JSON.stringify(result.violations));
  assert.equal(result.edges.length, 0);
});

for (const [name, source] of BUILTIN_LOADER_ESCAPES.slice(0, 3)) {
  test(`the finite native loop does not exempt an additional ${name}`, () => {
    const result = fixture({ [NATIVE_PATH]: `${NATIVE_SOURCE}\n${source}` });
    refuses(result, "UNACCOUNTED_MODULE_LOADER");
    assert.equal(result.counts.bounded_native_require_loops, 1);
    assert.equal(result.edges.filter((edge) => edge.kind === "bounded-native-require").length, 7);
  });
}

test("native Node confirms the refused extraction forms can reach harmless builtins", () => {
  const { getBuiltinModule: load } = process;
  const p = process;
  let reassigned;
  ({ getBuiltinModule: reassigned } = process);
  assert.equal(typeof load("module")["createRequire"](import.meta.url)("node:fs").readFileSync, "function");
  assert.equal(typeof p["getBuiltinModule"]("module")["createRequire"](import.meta.url)("node:fs").readFileSync, "function");
  assert.equal(typeof globalThis.process["getBuiltinModule"]("module")["createRequire"](import.meta.url)("node:fs").readFileSync, "function");
  assert.equal(typeof reassigned("fs").readFileSync, "function");
});

function withDevTypes(manifest, lock) {
  manifest.devDependencies["synthetic-dev-types"] = "0.0.0-synthetic";
  lock.packages[""].devDependencies["synthetic-dev-types"] = "0.0.0-synthetic";
  lock.packages["node_modules/synthetic-dev-types"] = { version: "0.0.0-synthetic" };
}

for (const [name, source] of [
  ["ordinary type-only import", 'import type { Port } from "synthetic-dev-types"; export type { Port };'],
  ["named inline type-only import", 'import { type Port } from "synthetic-dev-types"; export type { Port };'],
  ["named inline type-only reexport", 'export { type Port } from "synthetic-dev-types";'],
  ["multiple aliased type-only bindings", 'import { type Port as P, type Label as L } from "synthetic-dev-types"; export type { P, L };'],
  ["erased loader-named type bindings", 'import { type createRequire, type getBuiltinModule, type module } from "synthetic-dev-types"; export type { createRequire, getBuiltinModule, module };'],
]) {
  test(`declaration files permit declared locked development types for ${name}`, () => {
    const result = fixture({ "src/index.d.mts": source }, withDevTypes);
    assert.equal(result.status, "passed", JSON.stringify(result.violations));
    assert.equal(result.edges.find((edge) => edge.specifier === "synthetic-dev-types")?.type_only, true);
    assert.equal(result.acceptance.accepted_contract_pin, "not_asserted");
  });
}

test("statement-level import type in executable TypeScript remains erased", () => {
  const result = fixture({ "src/index.mts": 'import type { Port } from "synthetic-dev-types"; export type { Port };' }, withDevTypes);
  assert.equal(result.status, "passed", JSON.stringify(result.violations));
  assert.equal(result.edges.find((edge) => edge.specifier === "synthetic-dev-types")?.type_only, true);
});

for (const [name, source] of [
  ["named inline type-only import", 'import { type Port } from "synthetic-dev-types"; export type { Port };'],
  ["named inline type-only reexport", 'export { type Port } from "synthetic-dev-types";'],
  ["multiple inline type-only bindings", 'import { type Port as P, type Label as L } from "synthetic-dev-types"; export type { P, L };'],
  ["inline loader-named type bindings", 'import { type createRequire, type getBuiltinModule, type module } from "synthetic-dev-types"; export type { createRequire, getBuiltinModule, module };'],
  ["mixed named import", 'import { type Port, value } from "synthetic-dev-types"; export { value };'],
  ["mixed named reexport", 'export { type Port, value } from "synthetic-dev-types";'],
  ["default import with inline types", 'import value, { type Port } from "synthetic-dev-types"; export { value };'],
  ["empty named import", 'import {} from "synthetic-dev-types";'],
  ["empty named reexport", 'export {} from "synthetic-dev-types";'],
]) {
  test(`${name} still requires a declared production dependency`, () => {
    const files = { "src/index.mts": source };
    refuses(fixture(files, withDevTypes), "UNDECLARED_ENGINE_DEPENDENCY");
    const result = fixture(files, (manifest, lock) => {
      withDevTypes(manifest, lock);
      manifest.dependencies["synthetic-dev-types"] = "0.0.0-synthetic";
      lock.packages[""].dependencies["synthetic-dev-types"] = "0.0.0-synthetic";
    });
    assert.equal(result.status, "passed", JSON.stringify(result.violations));
    assert.equal(result.edges.find((edge) => edge.specifier === "synthetic-dev-types")?.type_only, false);
  });
}

for (const [name, source, expected] of [
  ["statement-level import type", 'import type { Port } from "synthetic-dev-types"; export type { Port };', "ENTRY_EXECUTED\n"],
  ["inline type import", 'import { type Port } from "synthetic-dev-types"; export type { Port };', "SYNTHETIC_DEPENDENCY_EXECUTED\nENTRY_EXECUTED\n"],
  ["inline type reexport", 'export { type Port } from "synthetic-dev-types";', "SYNTHETIC_DEPENDENCY_EXECUTED\nENTRY_EXECUTED\n"],
]) {
  test(`native TypeScript execution preserves the module policy for ${name}`, (t) => {
    const directory = mkdtempSync(path.join(tmpdir(), "ei-native-type-edge-test-"));
    try {
      const dependency = path.join(directory, "node_modules/synthetic-dev-types");
      mkdirSync(dependency, { recursive: true });
      writeFileSync(path.join(dependency, "package.json"), JSON.stringify({ name: "synthetic-dev-types", version: "0.0.0-synthetic", type: "module", exports: "./index.mjs" }));
      writeFileSync(path.join(dependency, "index.mjs"), 'console.log("SYNTHETIC_DEPENDENCY_EXECUTED");\n');
      const entry = path.join(directory, "entry.mts");
      writeFileSync(entry, `${source}\nconsole.log("ENTRY_EXECUTED");\n`);
      const child = spawnSync(process.execPath, ["--unhandled-rejections=strict", entry], { encoding: "utf8", timeout: 5000 });
      assert.equal(child.error, undefined);
      assert.equal(child.signal, null);
      assert.equal(child.status, 0, child.stderr);
      assert.equal(child.stdout, expected);
      t.diagnostic(JSON.stringify({ runtime: process.version, mode: "native-synthetic-mts", stdout: child.stdout }));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
