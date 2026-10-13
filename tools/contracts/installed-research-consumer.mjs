import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir, release } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
const fixtureRoot = new URL('../../tests/contracts/installed-research-consumer/', import.meta.url);
const candidatePins = Object.freeze({ '0.9.7': 'pin.json', '0.10.2': 'pin-0.10.2.json' });
const digest = (bytes, algorithm = 'sha256', encoding = 'hex') => createHash(algorithm).update(bytes).digest(encoding);
const canonical = (value) => value === null || typeof value !== 'object' ? JSON.stringify(value)
  : Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
    : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
const readJson = async (file) => JSON.parse(await readFile(file, 'utf8'));
const json = (value) => JSON.stringify(value, null, 2) + '\n';

function options(args) {
  const parsed = {};
  for (let i = 0; i < args.length; i += 2) {
    assert.ok(['--archive', '--output', '--tsc', '--candidate'].includes(args[i]), 'unknown option');
    assert.ok(args[i + 1] && !args[i + 1].startsWith('--'), 'missing option value');
    assert.equal(parsed[args[i]], undefined, 'duplicate option');
    parsed[args[i]] = args[i] === '--candidate' ? args[i + 1] : path.resolve(args[i + 1]);
  }
  assert.ok(parsed['--archive'] && parsed['--output'],
    'usage: node tools/contracts/installed-research-consumer.mjs --archive exact.tgz --output new-directory [--candidate 0.9.7|0.10.2] [--tsc compiler-path]');
  const candidate = parsed['--candidate'] ?? '0.9.7';
  assert.ok(Object.hasOwn(candidatePins, candidate), 'UNSUPPORTED_CANDIDATE: choose an explicitly pinned diagnostic version');
  return { archive: parsed['--archive'], output: parsed['--output'],
    candidate, candidateExplicit: parsed['--candidate'] !== undefined,
    tsc: parsed['--tsc'] ?? path.join(root, 'node_modules/typescript/bin/tsc') };
}

async function verifyInstalledFiles(directory, pin) {
  const pkg = await readJson(path.join(directory, 'package.json'));
  assert.equal(pkg.name, pin.package);
  assert.equal(pkg.version, pin.version);
  assert.equal(Object.keys(pkg.dependencies ?? {}).length, 0, 'candidate has no runtime dependencies');
  const content = await readJson(path.join(directory, 'generated/package-content-manifest.json'));
  assert.equal(content.self_exclusion, 'generated/package-content-manifest.json');
  assert.equal(content.digest, pin.content_digest);
  assert.equal(`sha256:${digest(canonical(content.files))}`, pin.content_digest);
  const names = [];
  async function visit(relative = '') {
    for (const entry of await readdir(path.join(directory, relative), { withFileTypes: true })) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      assert.equal(entry.isSymbolicLink(), false, 'installed package must not contain symlinks');
      if (entry.isDirectory()) await visit(name);
      else {
        assert.equal(entry.isFile(), true, 'installed package entries must be ordinary files');
        if (name !== content.self_exclusion) names.push(name);
      }
    }
  }
  await visit();
  assert.deepEqual(names.sort(), Object.keys(content.files).sort(), 'exact installed package file inventory');
  for (const name of names) {
    assert.equal(`sha256:${digest(await readFile(path.join(directory, name)))}`, content.files[name], name);
  }
  const schemaBytes = await readFile(path.join(directory, 'generated/schema-manifest.json'));
  const fixtureBytes = await readFile(path.join(directory, 'generated/fixture-manifest.json'));
  assert.equal(digest(schemaBytes), pin.schema_manifest_sha256);
  assert.equal(digest(fixtureBytes), pin.fixture_manifest_sha256);
  const fixtureManifest = JSON.parse(fixtureBytes.toString());
  assert.equal(fixtureManifest.digest, pin.fixture_digest);
  assert.equal(`sha256:${digest(canonical(fixtureManifest.files))}`, pin.fixture_digest);
  const schemaManifest = JSON.parse(schemaBytes.toString());
  assert.equal(schemaManifest.package_version, pin.version);
  return { package_files_verified: names.length, schemaManifest,
    fixture_files_verified: Object.keys(fixtureManifest.files).length,
    fixture_execution: 'not_run_upstream_fixtures', content_digest: content.digest, fixture_digest: fixtureManifest.digest };
}

async function main() {
  const config = options(process.argv.slice(2));
  // Every invocation gets a fresh directory. Existing failures/receipts must survive.
  await mkdir(config.output, { recursive: false, mode: 0o700 });
  const pinFile = new URL(candidatePins[config.candidate], fixtureRoot);
  const pinBytes = await readFile(pinFile);
  const pin = JSON.parse(pinBytes.toString('utf8'));
  const pinRelative = path.relative(root, fileURLToPath(pinFile)).split(path.sep).join('/');
  const report = { receipt_kind: 'ei_installed_consumer_diagnostic_v1', recorded_at: new Date().toISOString(),
    producer: pin, diagnostic_status: 'failed', consumer_acceptance: 'INCOMPATIBLE_HOLD',
    candidate_selection: { version: config.candidate, explicit: config.candidateExplicit,
      pin_path: pinRelative, pin_sha256: digest(pinBytes) },
    commands: [], failures: [], skips: [], provider_mode: 'offline_no_provider_transport',
    environment: { node: process.version, os: process.platform, architecture: process.arch, kernel: release() },
    stages: { domain_owner_acceptance: null, product_acceptance: null, release: null },
    required_checks: { archive_identity: 'not_run', installed_content: 'not_run', actual_caller: 'not_run', installed_types: 'not_run' },
  };
  let temporary;
  const run = async (label, command, args, cwd) => {
    const entry = { label, command: [command, ...args], cwd, exit_code: null,
      stdout: `${label}.stdout.log`, stderr: `${label}.stderr.log` };
    report.commands.push(entry);
    try {
      const result = await exec(command, args, { cwd, maxBuffer: 8 * 1024 * 1024, timeout: 60_000,
        env: { ...process.env, PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH ?? ''}`,
          npm_config_offline: 'true', npm_config_audit: 'false', npm_config_fund: 'false' } });
      entry.exit_code = 0;
      await writeFile(path.join(config.output, entry.stdout), result.stdout);
      await writeFile(path.join(config.output, entry.stderr), result.stderr);
      return result.stdout.trim();
    } catch (error) {
      entry.exit_code = Number.isInteger(error.code) ? error.code : null;
      entry.failure_code = error.killed ? 'COMMAND_TIMEOUT_OR_KILLED' : error.code;
      await writeFile(path.join(config.output, entry.stdout), error.stdout ?? '');
      await writeFile(path.join(config.output, entry.stderr), error.stderr ?? '');
      throw error;
    }
  };
  try {
    report.required_checks.archive_identity = 'failed';
    assert.equal(pin.version, config.candidate, 'selected diagnostic pin must match the explicit version');
    assert.equal(process.version, pin.node, 'exact private baseline toolchain required');
    const archiveInfo = await lstat(config.archive);
    assert.ok(archiveInfo.isFile() && !archiveInfo.isSymbolicLink(), 'archive must be an ordinary local file');
    const bytes = await readFile(config.archive);
    const sha256 = digest(bytes);
    const sri = `sha512-${digest(bytes, 'sha512', 'base64')}`;
    report.archive = { path: config.archive, sha256, sri };
    assert.equal(sha256, pin.archive_sha256, 'ARCHIVE_DIGEST_MISMATCH: no installation attempted');
    assert.equal(sri, pin.archive_sri, 'ARCHIVE_SRI_MISMATCH: no installation attempted');
    report.required_checks.archive_identity = 'passed';
    report.consumer_sha = await run('01-consumer-head', 'git', ['rev-parse', 'HEAD'], root);
    report.consumer_tree = await run('02-consumer-tree', 'git', ['rev-parse', 'HEAD^{tree}'], root);
    report.consumer_worktree_status = await run('03-consumer-status', 'git', ['status', '--porcelain'], root);
    report.consumer_worktree_dirty = report.consumer_worktree_status.length > 0;
    report.source_file_hashes = {};
    for (const relative of ['tools/contracts/installed-research-consumer.mjs',
      'tests/contracts/installed-research-consumer/pin.json', 'tests/contracts/installed-research-consumer/caller.mjs',
      'tests/contracts/installed-research-consumer/consumer.mts', 'tests/contracts/installed-research-consumer/decision-caller.mjs',
      'src/review/history/store.mjs', 'src/review/history/cache-binding-capability.mjs', 'src/private/boundary-guard.mjs',
      'src/evidence/store.mjs', 'src/discovery/identity/from-extraction.mjs', 'src/discovery/identity/from-extraction.d.mts',
      'src/discovery/identity/corroboration.mjs', 'src/discovery/identity/corroboration.d.mts',
      'src/discovery/entities/identity.mjs', 'src/discovery/occurrences/identity.mjs',
      'src/extraction/index.mjs', 'src/extraction/jsonld.mjs', 'src/extraction/source.mjs',
      'src/decisions/questions/index.mjs', 'src/decisions/questions/index.d.mts',
      'src/decisions/questions/from-source-identity.mjs', 'src/decisions/questions/from-source-identity.d.mts',
      'src/decisions/questions/prepare.mjs', 'src/decisions/questions/registry.mjs',
      'src/decisions/questions/sensitive-content.mjs', 'evals/policies/promotion-v1.json',
      'evals/corpus/labels.jsonl', 'evals/corpus/manifest.json']) {
      report.source_file_hashes[relative] = digest(await readFile(path.join(root, relative)));
    }
    report.source_file_hashes[pinRelative] = digest(pinBytes);
    temporary = await mkdtemp(path.join(tmpdir(), 'ei-installed-research-'));
    // Install the exact bytes that were checked, avoiding a second read of the caller's archive.
    const verifiedArchive = path.join(temporary, 'verified-shared-contracts.tgz');
    await writeFile(verifiedArchive, bytes, { flag: 'wx' });
    await writeFile(path.join(temporary, 'package.json'), json({ private: true, type: 'module' }));
    report.required_checks.installed_content = 'failed';
    await run('04-installed-package', 'npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', verifiedArchive], temporary);
    const installed = path.join(temporary, 'node_modules/@jevelopers/shared-contracts');
    report.installed_from = sha256;
    report.installed_verification = await verifyInstalledFiles(installed, pin);
    report.required_checks.installed_content = 'passed';
    const observationFile = path.join(config.output, 'observations.json');
    const callerUrl = new URL('caller.mjs', fixtureRoot).href;
    await writeFile(path.join(temporary, 'consumer.mjs'), `
import * as contracts from '@jevelopers/shared-contracts';
import * as research from '@jevelopers/shared-contracts/research-creative';
import * as operations from '@jevelopers/shared-contracts/operations';
import { writeFile } from 'node:fs/promises';
import { runInstalledResearchConsumer } from ${JSON.stringify(callerUrl)};
const result = await runInstalledResearchConsumer({ contracts, research, operations,
  directory: ${JSON.stringify(path.join(temporary, 'synthetic-history'))}, consumerSha: ${JSON.stringify(report.consumer_sha)} });
await writeFile(${JSON.stringify(observationFile)}, JSON.stringify(result, null, 2) + '\\n');
console.log(JSON.stringify({ diagnostic_status: result.diagnostic_status, consumer_acceptance: result.consumer_acceptance, counts: result.counts }));
process.exitCode = result.counts.failed ? 1 : 0;
`);
    let callerFailed = false;
    try {
      await run('05-actual-caller-and-controls', process.execPath, ['consumer.mjs'], temporary);
      report.required_checks.actual_caller = 'passed';
    } catch (error) {
      callerFailed = true;
      report.required_checks.actual_caller = 'failed';
      report.failures.push({ phase: 'actual_caller', name: error.name, code: error.code ?? null,
        message: 'Caller command failed; preserve 05-actual-caller-and-controls stdout/stderr and observations if available.' });
    }
    report.observations = await readJson(observationFile);
    const typeSource = (await readFile(new URL('consumer.mts', fixtureRoot), 'utf8'))
      .replaceAll('__EI_HISTORY_MODULE__', path.join(root, 'src/review/history/store.mjs'))
      .replaceAll('__EI_QUESTIONS_MODULE__', path.join(root, 'src/decisions/questions/index.mjs'));
    await writeFile(path.join(temporary, 'consumer.mts'), typeSource);
    report.required_checks.installed_types = 'failed';
    report.environment.typescript = await run('06-type-version', process.execPath, [config.tsc, '--version'], temporary);
    await run('07-installed-types', process.execPath, [config.tsc, '--noEmit', '--strict', '--module', 'NodeNext',
      '--moduleResolution', 'NodeNext', path.join(temporary, 'consumer.mts')], temporary);
    report.required_checks.installed_types = 'passed';
    report.schema_pins = report.installed_verification.schemaManifest.schemas.filter((row) =>
      report.observations.contracts_exercised.includes(`${row.contract}/${row.version}`));
    assert.equal(report.schema_pins.length, report.observations.contracts_exercised.length, 'each exercised contract has an exact schema pin');
    delete report.installed_verification.schemaManifest;
    assert.equal(callerFailed, false, 'actual caller diagnostics failed; retained observations name each failure');
    assert.equal(report.observations.counts.skipped, 0);
    assert.equal(report.observations.counts.scenarios, 49, 'all 38 original and 11 DecisionPort diagnostic scenarios executed');
    assert.equal(report.observations.observations.decisionPort.handler_calls, 0, 'no diagnostic handler dispatch');
    assert.equal(report.observations.observations.decisionPort.coverage.actual_result_consumption.status, 'unsupported');
    assert.equal(report.observations.observations.decisionPort.coverage.actual_result_consumption.executed, false);
    report.diagnostic_status = report.observations.diagnostic_status;
    report.counts = report.observations.counts;
  } catch (error) {
    report.failures.push({ name: error.name, code: error.code ?? null, message: error.message });
  } finally {
    if (temporary) {
      try { await rm(temporary, { recursive: true, force: true }); }
      catch (error) {
        report.diagnostic_status = 'failed';
        report.failures.push({ phase: 'cleanup', name: error.name, code: error.code ?? null, message: error.message });
      }
    }
    report.skips = Object.entries(report.required_checks).filter(([, status]) => status === 'not_run')
      .map(([id]) => ({ id, status: 'not_executed_after_prerequisite_failure' }));
    await writeFile(path.join(config.output, 'receipt.json'), json(report), { flag: 'wx' });
  }
  console.log(json({ diagnostic_status: report.diagnostic_status, consumer_acceptance: report.consumer_acceptance,
    counts: report.counts ?? report.observations?.counts ?? null, receipt: path.join(config.output, 'receipt.json'),
    failures: report.failures }));
  return report.diagnostic_status === 'passed_expected_incompatibility' ? 0 : 1;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try { process.exitCode = await main(); }
  catch (error) { console.error(error.code === 'EEXIST' ? 'OUTPUT_EXISTS: choose a new directory; prior evidence is preserved' : error.message); process.exitCode = 1; }
}
