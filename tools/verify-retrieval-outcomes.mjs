import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from 'node:test';
import { spec } from 'node:test/reporters';
import { finished } from 'node:stream/promises';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = [path.join(root, 'tests/security/retrieval-outcomes/reader.test.mjs')];
// Maintained inventory, independent of whichever tests happened to enqueue.
const requiredCases = 35;
const stream = run({ files, cwd: root, concurrency: 1, isolation: 'process' });
let summary;
let enqueued = 0;
stream.on('test:enqueue', (event) => { if (event.type === 'test') enqueued += 1; });
stream.on('test:summary', (event) => { if (event.file === undefined) summary = event; });
const report = stream.compose(spec);
const completion = finished(report);
report.pipe(process.stdout, { end: false });
await completion;
const counts = summary?.counts;
const terminal = counts ? counts.passed + counts.failed + counts.skipped + counts.cancelled + counts.todo : 0;
const passed = summary?.success === true && enqueued === requiredCases && terminal === requiredCases
  && counts.passed === requiredCases
  && counts.failed === 0 && counts.skipped === 0 && counts.cancelled === 0 && counts.todo === 0;
process.stdout.write(`RETRIEVAL_OUTCOMES_VERIFY_JSON=${JSON.stringify({
  case: 'private-retrieval-outcomes', mode: 'mock', runtime: process.version,
  status: passed ? 'passed' : 'failed', test_files: files.length,
  expected_cases: requiredCases, observed_cases: enqueued, terminal_cases: terminal, passed_cases: counts?.passed ?? 0,
  failed_cases: counts?.failed ?? 0, skipped_cases: counts?.skipped ?? 0,
  cancelled_cases: counts?.cancelled ?? 0, todo_cases: counts?.todo ?? 0,
  implementation: 'actual SafeFetcher native sockets, decompression, deadlines and cancellation',
  fixture_origin: 'controlled loopback HTTP and synthetic hostile inputs; no public-source journey',
  provider_activity: 'none', canonical_adoption: false, consumer_ack: null,
})}\n`);
process.exitCode = passed ? 0 : 1;
