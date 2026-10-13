# Local engine dependency direction

Refs: [EI #3, acceptance criterion 3](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/3).

`make verify-dependencies` tests the checker with synthetic import graphs, then
parses this checkout's complete `src` JavaScript/TypeScript module and declaration
set using the already pinned TypeScript 7.0.2 native parser. Install the locked
dependencies and host compiler using the repository quickstart first. The
always-on `verify` workflow runs this command on pushes and pull requests.

The check rejects engine imports or reexports of `agent-harness`, including
scoped names, subpaths, escaped literals, inline type imports, declaration
references and CommonJS loads. It also rejects Harness identities in dependency
declarations, npm aliases and lock entries. Runtime package imports must name a
declared, locked production dependency. Statement-level `import type` / `export
type` and declaration files may use declared development dependencies. Outside
declarations, inline type bindings still require a production dependency: native
Node execution preserves their module load, as does TypeScript emission with
`verbatimModuleSyntax`. Mixed, default and empty import/reexport forms also retain
this runtime rule. Maintained native `.mts` controls verify the difference; the
project's `noEmit` typecheck does not establish runtime erasure. Relative imports
must resolve to a scanned file inside `src`; symlinks, source traversal, missing
modules, package aliases, URL imports,
unparsed source and unaccounted computed loads fail the check.

Local JSON data is inventoried separately from executable modules. The supported
data edge is a literal static `import` inside `src`, with exactly
`with { type: "json" }`, resolving to an existing regular `.json` file under
`src`. Missing, extra, duplicate or incorrect attributes, old `assert` syntax,
dynamic/CommonJS/type-only/reexport JSON loads, missing targets and escaping
paths fail conservatively. A JSON attribute cannot make executable JavaScript a
data module. All `.json` files under `src`, including unimported files, must be
valid JSON encoded as exact UTF-8 without a BOM. Symlinks are refused. The parser
does not receive JSON as TypeScript source, and no imported module or data is
executed. A profile's JSON contents remain data, not an adopted contract or a
native-runtime qualification.

Recognized loader properties (`require`, `createRequire`, `getBuiltinModule`)
remain unaccounted when extracted by binding or assignment destructuring,
runtime import/reexport bindings or constant bracket access, including access
through aliases. Inert object fields are not extraction syntax. The
checker refuses these forms before any scanned code executes. Explicitly erased
type-only bindings do not acquire runtime loader capabilities; that does not
erase the surrounding module edge. Maintained tests also execute the relevant
native Node forms against harmless builtins so that
the negative fixtures describe real loader access, rather than invented APIs.

The PDF network guard has one intentional computed `require`: a constant loop
over seven native Node modules. The checker verifies its import, loader binding,
function/loop structure, constant destructuring, exact native-module/method/kind
array and direct first-statement call. It expands these seven edges in the
report. This exception does not exempt the file: additional imports, escaped
loader references and computed loads still fail. A legitimate future change to
that loop needs an explicit checker/test update and review. Source text in
comments, strings or inert templates does not become an import edge, and the
checker never executes scanned modules.

The PNG network guard has a separate exact-path exception for its eight native
modules. It requires the two exact unaliased `node:module` imports, immutable
loader binding based on `import.meta.url`, zero-argument synchronous guard,
immutable two-element loop binding, exact module/method array, fixed DNS method
constant, direct loop load and five fixed literal prototype loads. Additional
uses of the DNS constant or direct loads invalidate that exception; generic
loader-escape and Harness checks still apply everywhere. The two guards expand
to seven and eight computed edges respectively. The maintained PNG source-text
fixture is byte-identical to public PR86 commit
`11f1440d58728fd79ba5f656dbf78ce8ba6ecb9c`, guard Git blob
`5f0a99624b2695dda363af6ebc153e1762e175da`; reading it does not execute its network
interposition. Future production changes must receive a separate checker/test
review instead of acquiring general computed-loader permission.

`node tools/check-dependency-direction.mjs` emits a versioned JSON receipt with
every scanned path/hash/mode, parsed edge, package/lock hashes, parser version,
graph digest, native-loop count and violations. It accepts no arguments and reads
its own repository, independent of the caller's working directory. Source and
manifest readback must still match the parsed snapshot. A failure or incomplete
parse returns a nonzero exit code. The test fixtures are synthetic; their
`synthetic-contract-only` package is never installed or treated as an accepted
contract.

The receipt's additive `data_files` inventory and `counts.data_files` distinguish
JSON from executable `files` / `counts.source_files`. `engine-data` edges retain
the explicit JSON attribute. Both inventories, all edges and their byte/mode
identities contribute to `graph_sha256`; after-scan readback also detects data
addition, deletion, mode changes and byte changes. Counts depend on the exact
checkout: importing a future media component must add its actual files and edges,
not reuse an earlier graph digest or inventory. This remains the local
`ei-dependency-direction/v1` receipt, with no foreign schema change.

The maintained suite has **154** cases, including the original98 controls and
56 additional PNG/data cases. It retains executable native `.mts` policy controls
as separately labeled synthetic tests; the checker itself never runs scanned
sources. PNG/media production byte snapshots can be checked with the exported
checker function in a separate static diagnostic; such a pass does not execute
their decoders, install runtimes or qualify their hosted/product behavior.

## Acceptance boundary

This is repository-local evidence for the engine side of EI #3 AC3. Current EI
uses local structural ports and ordinary declared implementation dependencies;
this check neither selects nor adopts a canonical research contract pin. It does
not inspect another engine or the Harness repository, prove that the Harness
imports engines, execute timeout/abstention/malformed-decision cases, or complete
the shared handoff manifest. Those outcomes remain with their existing owners and
require their actual source and consumer evidence.

This source-level import graph is not a general sandbox or a semantic audit of
arbitrary generated code, worker/process entry points, native/Python code,
third-party package contents, or renamed copies of a foreign implementation. It
accounts for module import syntax and recognized loaders conservatively; it
does not replace the existing transport, content, process or permission guards.
Keep the pending cross-repository dependency-direction fixture and capability
preservation acceptance open until the corresponding owners record them.
