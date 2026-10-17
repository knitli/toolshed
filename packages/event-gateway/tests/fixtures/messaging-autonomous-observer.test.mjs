import test from 'node:test';
import assert from 'node:assert/strict';
import { AutonomousObserver } from './messaging-autonomous-observer.mjs';
const barrier = { attemptId: 'attempt', instanceNonce: 'old', scheduledAlarm: 11000,
  observedAt: 1000, state: { native_claims: [{ state: 'reserving' }] } };
const signal = { attemptId: 'attempt', instanceNonce: 'new', executedAt: 11001,
  state: { native_claims: [{ state: 'unknown' }] } };
test('completion requires crash, replacement instance and matching attempt', () => {
  for (const [value, restarted] of [[signal, false], [{ ...signal, instanceNonce: 'old' }, true],
    [{ ...signal, attemptId: 'other' }, true], [{ ...signal, executedAt: 0 }, true]]) {
    const observer = new AutonomousObserver('positive', () => 0);
    observer.beforeKill(barrier); observer.killed();
    assert.throws(() => observer.signal(value, restarted), /invalid autonomous/);
    assert.equal(observer.canDispatch(), false);
  }
  const observer = new AutonomousObserver('positive', () => 0);
  assert.throws(() => observer.signal(signal, true));
  observer.beforeKill(barrier); observer.killed(); observer.signal(signal, true);
  assert.equal(observer.canDispatch(), true);
  assert.throws(() => observer.signal(signal, true));
});
test('timeout permits diagnostic access only at real monotonic deadline', () => {
  let now = 0;
  const observer = new AutonomousObserver('delete-alarm', () => now);
  observer.beforeKill(barrier); observer.killed(); now = 24999;
  assert.equal(observer.canDispatch(), false); now = 25000;
  assert.equal(observer.canDispatch(), true); now++;
  assert.throws(() => observer.signal(signal, true));
});
test('barrier must prove persisted scheduled alarm and reserving state', () => {
  for (const value of [{ ...barrier, scheduledAlarm: null }, { ...barrier, state: signal.state }]) {
    assert.throws(() => new AutonomousObserver('positive').beforeKill(value));
  }
});
