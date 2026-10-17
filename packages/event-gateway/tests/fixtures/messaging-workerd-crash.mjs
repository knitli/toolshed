// Fixture-only ownership guard. Tests inject fake ChildProcesses; importing this never spawns one.
import childProcess from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';

const phases = new Set(['before-reserve', 'after-reserve', 'after-admission']);
const check = (value, reason) => { if (!value) throw new Error(reason); };
const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const storageIdentity = path => {
  const canonicalPath = realpathSync(path), info = statSync(canonicalPath);
  check(info.isDirectory(), 'crash storage must be a directory');
  return { canonicalPath, device: String(info.dev), inode: String(info.ino) };
};

export class OwnedWorkerdCrash {
  constructor({ binary, binarySha256, persistencePath, timeoutMs = 4000,
    processApi = childProcess, canonical = realpathSync, digest = hash, storage = storageIdentity,
    afterKill = () => {} }) {
    this.binary = canonical(binary);
    this.binarySha256 = binarySha256;
    this.persistencePath = persistencePath;
    this.timeoutMs = timeoutMs;
    this.api = processApi;
    this.canonical = canonical;
    this.digest = digest;
    this.storage = storage;
    this.afterKill = afterKill;
    this.children = [];
    this.killCount = this.restartCount = 0;
    this.phase = this.failure = this.pending = null;
    this.stopping = false;
  }

  install() {
    check(!this.originalSpawn, 'crash capture already installed');
    this.originalSpawn = this.api.spawn;
    this.wrapper = (command, args, options) => {
      try {
        this.healthy();
        check(!this.stopping && this.canonical(command) === this.binary
          && this.digest(this.binary) === this.binarySha256, 'unapproved crash child binary');
        check(Array.isArray(args) && args.length === 7 && args[0] === 'serve'
          && args[1] === '--binary' && args[2] === '--experimental'
          && /^--socket-addr=entry=127\.0\.0\.1:\d{1,5}$/.test(args[3])
          && /^--external-addr=loopback=127\.0\.0\.1:\d{1,5}$/.test(args[4])
          && args[5] === '--control-fd=3' && args[6] === '-'
          && args.slice(3, 5).every(value => Number(value.split(':').at(-1)) <= 65535)
          && options?.windowsHide === true && options.env?.TZ === 'UTC'
          && Object.keys(options).sort().join(',') === 'env,stdio,windowsHide'
          && JSON.stringify(options.stdio) === '["pipe","pipe","pipe","pipe"]',
        'unapproved crash child arguments');
        check(this.children.length === 0 || (this.children.length === 1 && this.killCount === 1
          && this.children[0].signal === 'SIGKILL'), 'unexpected workerd spawn');
        const child = Reflect.apply(this.originalSpawn, this.api, [command, args, options]);
        check(Number.isSafeInteger(child.pid) && child.pid > 0, 'workerd missing owned pid');
        const owned = { child, pid: child.pid, code: null, signal: null, exited: false };
        this.children.push(owned);
        child.once('error', error => this.fail(error));
        child.once('exit', (code, signal) => {
          Object.assign(owned, { code, signal, exited: true });
          if (!this.stopping && !(owned === this.children[0] && this.killCount === 1
            && code === null && signal === 'SIGKILL')) this.fail(new Error('unexpected workerd exit'));
        });
        return child;
      } catch (error) { this.fail(error); throw error; }
    };
    this.api.spawn = this.wrapper;
    syncBuiltinESMExports();
  }

  healthy() { if (this.failure) throw this.failure; }

  fail(error) {
    this.failure ??= error;
    clearTimeout(this.timer);
    this.reject?.(this.failure);
  }

  arm(phase) {
    this.healthy();
    check(phases.has(phase) && this.phase === null && this.children.length === 1
      && !this.children[0].exited, 'invalid crash arm');
    this.before = this.storage(this.persistencePath);
    this.phase = phase;
  }

  async reach(phase) {
    this.healthy();
    if (phase !== this.phase) return false;
    check(!this.pending && !this.stopping && this.children.length === 1, 'duplicate crash barrier');
    check(JSON.stringify(this.storage(this.persistencePath)) === JSON.stringify(this.before),
      'crash storage changed before kill');
    this.pending = new Promise((resolve, reject) => {
      this.resolve = resolve; this.reject = reject;
      this.timer = setTimeout(() => this.fail(new Error('workerd automatic restart deadline')), this.timeoutMs);
    });
    // Retain the rejected result for /fixture/crash-proof without an unhandled rejection.
    this.pending.catch(() => {});
    this.killCount++;
    try {
      check(this.children[0].child.kill('SIGKILL'), 'owned workerd kill failed');
      this.afterKill({ phase, brokerPid: process.pid, oldPid: this.children[0].pid });
    }
    catch (error) { this.fail(error); }
    await this.pending;
    return true;
  }

  restarted() {
    try {
      this.healthy();
      this.restartCount++;
      check(this.pending && !this.stopping && this.restartCount === 1 && this.killCount === 1
        && this.children.length === 2 && this.children[0].exited
        && this.children[0].code === null && this.children[0].signal === 'SIGKILL'
        && !this.children[1].exited && this.children[0].pid !== this.children[1].pid,
      'unexpected workerd restart callback');
      this.after = this.storage(this.persistencePath);
      check(JSON.stringify(this.before) === JSON.stringify(this.after), 'crash storage changed on restart');
      clearTimeout(this.timer);
      this.resolve();
    } catch (error) { this.fail(error); }
  }

  async proof() {
    check(this.pending, 'crash barrier was not reached');
    await this.pending;
    this.healthy();
    check(this.children.length === 2 && !this.children[1].exited
      && JSON.stringify(this.after) === JSON.stringify(this.storage(this.persistencePath)),
    'crash replacement no longer current');
    return { phase: this.phase, brokerPid: process.pid, oldPid: this.children[0].pid,
      newPid: this.children[1].pid, exitCode: this.children[0].code, exitSignal: this.children[0].signal,
      spawnCount: this.children.length, killCount: this.killCount, restartCount: this.restartCount,
      storageBefore: this.before, storageAfter: this.after, admission: this.admission ?? null,
      requestOpenAtKill: this.requestOpenAtKill ?? false };
  }

  stop() {
    this.stopping = true;
    clearTimeout(this.timer);
    this.reject?.(new Error('crash fixture stopping'));
  }

  restore() {
    check(this.api.spawn === this.wrapper, 'crash spawn capture replaced');
    this.api.spawn = this.originalSpawn;
    syncBuiltinESMExports();
  }
}
