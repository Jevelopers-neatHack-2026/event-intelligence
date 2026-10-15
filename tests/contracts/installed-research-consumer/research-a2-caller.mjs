import assert from 'node:assert/strict';

// No canonical projection or host authority is created. The values are the
// actual SQLite caller outputs from the unchanged 49-case diagnostic.
export function probeResearchA2({ contracts, issuance, observations }) {
  const cases = [];
  for (const name of ['initial', 'corrected']) {
    const value = observations[name];
    assert.ok(value && value.schemaVersion === 1, 'actual history snapshot required');
    const before = JSON.stringify(value);
    const shape = contracts.validateContractVersion('EventIntelligencePackage', '2.0.0', value);
    assert.equal(shape.ok, false, 'local snapshot must not silently become EIP2');
    assert.ok(shape.errors.length > 0);
    const authority = issuance.checkResearchIssuance('EventIntelligencePackage', value, {});
    assert.equal(authority.ok, false);
    assert.deepEqual(authority.errors, [{ code: 'INVALID_TRUST_CONTEXT', path: '' }]);
    assert.equal(JSON.stringify(value), before, 'diagnostic must preserve actual caller output');
    cases.push({ input: name, origin: 'actual_local_history_caller',
      schema: 'EventIntelligencePackage/2.0.0', structural_errors: shape.errors,
      authority_errors: authority.errors, input_unchanged: true });
  }
  return { status: 'passed_expected_incompatibility', cases,
    accepted_migration: false, elected_contract_subset: null, consumer_ack: null,
    coverage: { local_history_snapshots: 2, issuance_dispatch: 0,
      descriptor_support_join: 'not_implemented_pending_owner_mapping',
      nine_pair_fixture_execution: 0, host_authority: 'not_supplied' } };
}
