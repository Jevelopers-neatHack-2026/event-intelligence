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
declared, locked production dependency. Type-only declarations may use declared
development dependencies. Relative imports must resolve to a scanned file inside
`src`; symlinks, source traversal, missing modules, package aliases, URL imports,
unparsed source and unaccounted computed loads fail the check.

The PDF network guard has one intentional computed `require`: a constant loop
over seven native Node modules. The checker verifies its import, loader binding,
function/loop structure, constant destructuring, exact native-module/method/kind
array and direct first-statement call. It expands these seven edges in the
report. This exception does not exempt the file: additional imports, escaped
loader references and computed loads still fail. A legitimate future change to
that loop needs an explicit checker/test update and review. Source text in
comments, strings or inert templates does not become an import edge, and the
checker never executes scanned modules.

`node tools/check-dependency-direction.mjs` emits a versioned JSON receipt with
every scanned path/hash/mode, parsed edge, package/lock hashes, parser version,
graph digest, native-loop count and violations. It accepts no arguments and reads
its own repository, independent of the caller's working directory. Source and
manifest readback must still match the parsed snapshot. A failure or incomplete
parse returns a nonzero exit code. The test fixtures are synthetic; their
`synthetic-contract-only` package is never installed or treated as an accepted
contract.

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
