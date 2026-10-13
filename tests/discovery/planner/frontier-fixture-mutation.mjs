import assert from 'node:assert/strict';

// Privileged, synthetic fixture setup only. These callers intentionally corrupt
// local rows to test higher-level recovery/authentication. This is not an app
// API and must never be used by tests of unauthorized or historical writers.
export function withPrivilegedFrontierFixtureMutation(database, mutate) {
  database.exec('BEGIN IMMEDIATE');
  try {
    const fenced = database.prepare(`SELECT name FROM sqlite_master
      WHERE type = 'table' AND name = 'frontier_write_fence'`).get();
    if (fenced) {
      const opened = database.prepare(`UPDATE frontier_write_fence SET is_open = 1
        WHERE singleton = 1 AND protocol_version = 1 AND is_open = 0`).run();
      assert.equal(opened.changes, 1, 'fixture mutation opens one closed guard inside its transaction');
    } else {
      assert.ok(database.prepare('PRAGMA user_version').get().user_version < 5,
        'only an actual legacy fixture may lack the current guard');
    }
    const result = mutate();
    assert.equal(typeof result?.then, 'undefined', 'fixture mutations must be synchronous');
    if (fenced) {
      const closed = database.prepare(`UPDATE frontier_write_fence SET is_open = 0
        WHERE singleton = 1 AND protocol_version = 1 AND is_open = 1`).run();
      assert.equal(closed.changes, 1, 'fixture mutation restores the closed guard before commit');
    }
    database.exec('COMMIT');
    return result;
  } catch (error) {
    try { database.exec('ROLLBACK'); } catch { /* Retain the fixture failure. */ }
    throw error;
  }
}
