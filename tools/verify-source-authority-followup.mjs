import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from 'node:test';
import { spec } from 'node:test/reporters';
import { finished } from 'node:stream/promises';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EXPECTED_CASES = 76;
const files = [
  'tests/research/source-authority-followup/composer.test.mjs',
  'tests/research/source-authority-followup/integration.test.mjs',
];
const hash = (value) => createHash('sha256').update(value).digest('hex');
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
async function source() {
  const paths = [...new Set(git('ls-files', '-co', '--exclude-standard', '-z').split('\0').filter(Boolean))].sort();
  const entries = [];
  for (const name of paths) {
    const absolute = path.join(root, name);
    const [bytes, metadata] = await Promise.all([readFile(absolute), stat(absolute)]);
    entries.push({ path: name, sha256: hash(bytes), bytes: bytes.length, mode: metadata.mode & 0o777 });
  }
  return { revision: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}'),
    dirty: git('status', '--porcelain=v1', '--untracked-files=all') !== '',
    files: entries.length, manifestSha256: hash(JSON.stringify(entries)), entries };
}

const before = await source();
const stream = run({ files: files.map((name) => path.join(root, name)), cwd: root, concurrency: 1, isolation: 'process' });
let summary;
let enqueued = 0;
stream.on('test:enqueue', (event) => { if (event.type === 'test') enqueued += 1; });
stream.on('test:summary', (event) => { if (event.file === undefined) summary = event; });
const report = stream.compose(spec);
const chunks = [];
report.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
const completion = finished(report);
report.pipe(process.stdout, { end: false });
await completion;
const after = await source();
const counts = summary?.counts;
const terminal = counts ? counts.passed + counts.failed + counts.skipped + counts.cancelled + counts.todo : 0;
const sourceUnchanged = JSON.stringify(before) === JSON.stringify(after);
const passed = summary?.success === true && enqueued === EXPECTED_CASES && terminal === EXPECTED_CASES
  && counts.passed === EXPECTED_CASES && counts.failed === 0 && counts.skipped === 0
  && counts.cancelled === 0 && counts.todo === 0 && sourceUnchanged;
const attempt = `${new Date().toISOString().replaceAll(':', '-')}-${randomUUID()}`;
const output = path.join(root, '.tmp', 'source-authority-followup', attempt);
await mkdir(output, { recursive: true });
const reportBytes = Buffer.concat(chunks);
const result = {
  case: 'private-source-authority-followup', mode: 'mock', runtime: process.version,
  status: passed ? 'passed' : 'failed', attempt, files,
  expected_cases: EXPECTED_CASES, enqueued_cases: enqueued, terminal_cases: terminal,
  passed_cases: counts?.passed ?? 0, failed_cases: counts?.failed ?? 0,
  skipped_cases: counts?.skipped ?? 0, cancelled_cases: counts?.cancelled ?? 0, todo_cases: counts?.todo ?? 0,
  source: { revision: before.revision, tree: before.tree, dirty: before.dirty,
    files: before.files, manifestSha256: before.manifestSha256 },
  sourceUnchanged, reportSha256: hash(reportBytes),
  implementation: 'actual private retrieval, native HTTP and SQLite; deterministic private follow-up projection',
  fixture_origin: 'synthetic source bytes, encryption keys, host authorities and clock-consumption callbacks',
  provider_activity: 'none', canonical_adoption: false, consumer_ack: null,
};
await writeFile(path.join(output, 'source-map.json'), `${JSON.stringify({ before, after }, null, 2)}\n`, { flag: 'wx' });
await writeFile(path.join(output, 'report.log'), reportBytes, { flag: 'wx' });
await writeFile(path.join(output, 'summary.json'), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
process.stdout.write(`SOURCE_AUTHORITY_VERIFY_JSON=${JSON.stringify(result)}\n`);
process.exitCode = passed ? 0 : 1;
