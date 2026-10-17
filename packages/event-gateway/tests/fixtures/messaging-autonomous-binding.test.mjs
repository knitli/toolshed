import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Execute the actual fixture method without importing workerd or its cloud dependencies.
const source = readFileSync(new URL('./messaging-workerd-worker.ts', import.meta.url), 'utf8');
const method = source.match(/override async alarm\(\) \{[\s\S]*?\n  \}/)?.[0];
assert.ok(method, 'fixture alarm method is present');
const Fixture = new Function('Parent', `return class extends Parent { ${method.replace('override ', '')} }`)(class {
  async alarm() { throw new Error('production alarm must not run'); }
});

test('missing observer rejects before state reads or production alarm effects', async () => {
  const fixture = new Fixture();
  fixture.autonomous = { FIXTURE_AUTONOMOUS_ALARM: 'positive' };
  fixture.fixtureRead = () => { throw new Error('state must not be read'); };
  await assert.rejects(fixture.alarm(), { message: 'fixture_alarm_observer_binding_missing' });
});

test('default mode still needs no observer and performs no state reads', async () => {
  const fixture = new Fixture();
  fixture.autonomous = {};
  fixture.fixtureRead = () => { throw new Error('state must not be read'); };
  await fixture.alarm();
});
