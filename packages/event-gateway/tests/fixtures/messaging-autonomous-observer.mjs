// Fixture-only evidence; polling this object never dispatches to workerd.
export class AutonomousObserver {
  constructor(mode, now = () => performance.now()) {
    if (!['positive', 'no-super', 'delete-alarm'].includes(mode)) throw new Error('invalid autonomous mode');
    Object.assign(this, { mode, now, barrier: null, completion: null, signals: 0, killedAt: null });
  }
  beforeKill(value) {
    if (this.barrier || !value || typeof value.instanceNonce !== 'string'
      || typeof value.attemptId !== 'string' || !Number.isSafeInteger(value.scheduledAlarm)
      || value.scheduledAlarm <= 0 || !Number.isSafeInteger(value.observedAt)
      || value.state.native_claims.length !== 1
      || value.state.native_claims[0].state !== 'reserving') throw new Error('invalid persisted alarm barrier');
    this.barrier = value;
  }
  killed() { this.killedAt = this.now(); }
  signal(value, restarted) {
    if (++this.signals > 3 || !restarted || !this.barrier || this.killedAt === null
      || this.now() - this.killedAt > 25000 || this.completion
      || value.instanceNonce === this.barrier.instanceNonce
      || typeof value.instanceNonce !== 'string' || value.attemptId !== this.barrier.attemptId
      || !Number.isSafeInteger(value.executedAt) || value.executedAt < Math.max(this.barrier.observedAt, this.barrier.scheduledAlarm))
      throw new Error('invalid autonomous completion');
    this.completion = value;
  }
  canDispatch() { return this.killedAt === null || this.completion !== null || this.now() - this.killedAt >= 25000; }
}
