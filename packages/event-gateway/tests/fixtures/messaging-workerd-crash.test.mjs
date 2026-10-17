// Offline only: every ChildProcess and filesystem identity is synthetic.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { OwnedWorkerdCrash } from './messaging-workerd-crash.mjs';

const args = ['serve', '--binary', '--experimental', '--socket-addr=entry=127.0.0.1:0',
  '--external-addr=loopback=127.0.0.1:1234', '--control-fd=3', '-'];
const options = { stdio: ['pipe', 'pipe', 'pipe', 'pipe'], windowsHide: true, env: { TZ: 'UTC' } };

function fixture(t, { timeoutMs = 1000, afterKill = () => {} } = {}) {
  const processes = [], kills = [];
  const identity = { canonicalPath: '/synthetic/storage', device: '1', inode: '2' };
  const api = { spawn() {
    const child = new EventEmitter();
    child.pid = 100 + processes.length;
    child.kill = signal => { kills.push([child.pid, signal]); return true; };
    processes.push(child);
    return child;
  } };
  const original = api.spawn;
  const controller = new OwnedWorkerdCrash({ binary: '/synthetic/workerd', binarySha256: 'pin',
    persistencePath: '/synthetic/storage', timeoutMs, processApi: api,
    canonical: path => path, digest: () => 'pin', storage: () => ({ ...identity }), afterKill });
  controller.install();
  t.after(() => { controller.stop(); controller.restore(); assert.equal(api.spawn, original); });
  const spawn = (binary = '/synthetic/workerd', argv = args, config = options) => api.spawn(binary, argv, config);
  return { controller, spawn, processes, kills, identity };
}

test('one owned SIGKILL, automatic replacement and callback preserve storage identity', async t => {
  const { controller, spawn, processes, kills } = fixture(t);
  spawn();
  controller.arm('after-reserve');
  assert.equal(await controller.reach('before-reserve'), false);
  const crash = controller.reach('after-reserve');
  assert.deepEqual(kills, [[100, 'SIGKILL']]);
  processes[0].emit('exit', null, 'SIGKILL');
  spawn();
  controller.restarted();
  assert.equal(await crash, true);
  const proof = await controller.proof();
  assert.equal(proof.oldPid, 100);
  assert.equal(proof.newPid, 101);
  assert.deepEqual([proof.spawnCount, proof.killCount, proof.restartCount], [2, 1, 1]);
  assert.equal(proof.exitSignal, 'SIGKILL');
  assert.deepEqual(proof.storageBefore, proof.storageAfter);
  assert.deepEqual(await controller.proof(), proof);
  await assert.rejects(controller.reach('after-reserve'), /duplicate crash barrier/);
  assert.equal(kills.length, 1);
});

test('unapproved binary, digest, arguments and detached options fail before spawning', async t => {
  for (const mutation of ['path', 'digest', 'args', 'port', 'stdio', 'detached']) {
    await t.test(mutation, t => {
      const { controller, spawn, processes } = fixture(t);
      if (mutation === 'digest') controller.digest = () => 'wrong';
      const argv = [...args];
      if (mutation === 'args') argv.push('--verbose');
      if (mutation === 'port') argv[3] = '--socket-addr=entry=127.0.0.1:65536';
      const config = mutation === 'stdio' ? { ...options, stdio: 'inherit' }
        : mutation === 'detached' ? { ...options, detached: true } : options;
      assert.throws(() => spawn(mutation === 'path' ? '/other/workerd' : '/synthetic/workerd', argv, config), /unapproved/);
      assert.equal(processes.length, 0);
      assert.throws(() => controller.healthy(), /unapproved/);
    });
  }
});

test('replacement cannot spawn before the original owned SIGKILL exit', t => {
  const { controller, spawn, processes } = fixture(t);
  spawn();
  assert.throws(() => spawn(), /unexpected workerd spawn/);
  assert.equal(processes.length, 1);
  assert.throws(() => controller.healthy(), /unexpected workerd spawn/);
});

test('wrong exit signal rejects the pending crash', async t => {
  const { controller, spawn, processes } = fixture(t);
  spawn(); controller.arm('before-reserve');
  const crashed = controller.reach('before-reserve');
  processes[0].emit('exit', null, 'SIGTERM');
  await assert.rejects(crashed, /unexpected workerd exit/);
  await assert.rejects(controller.proof(), /unexpected workerd exit/);
});

test('causal marker is emitted only after successful owned kill', async t => {
  for (const killed of [true, false]) await t.test(String(killed), async t => {
    const markers = [];
    const { controller, spawn, processes } = fixture(t, { afterKill: value => markers.push(value) });
    spawn();
    processes[0].kill = signal => {
      assert.equal(signal, 'SIGKILL');
      assert.equal(markers.length, 0);
      return killed;
    };
    controller.arm('after-reserve');
    const crashed = controller.reach('after-reserve');
    if (killed) {
      assert.deepEqual(markers, [{ phase: 'after-reserve', brokerPid: process.pid, oldPid: 100 }]);
      processes[0].emit('exit', null, 'SIGKILL'); spawn(); controller.restarted();
      await crashed;
    } else {
      await assert.rejects(crashed, /owned workerd kill failed/);
      assert.deepEqual(markers, []);
    }
  });
});

test('missing restart callback has a bounded deadline', async t => {
  const { controller, spawn, processes } = fixture(t, { timeoutMs: 5 });
  spawn(); controller.arm('before-reserve');
  const crashed = controller.reach('before-reserve');
  processes[0].emit('exit', null, 'SIGKILL');
  spawn();
  await assert.rejects(crashed, /automatic restart deadline/);
  await assert.rejects(controller.proof(), /automatic restart deadline/);
});

test('storage path or inode replacement cannot produce successful proof', async t => {
  for (const field of ['canonicalPath', 'inode', 'device']) await t.test(field, async t => {
    const { controller, spawn, processes, identity } = fixture(t);
    spawn(); controller.arm('after-reserve');
    const crashed = controller.reach('after-reserve');
    processes[0].emit('exit', null, 'SIGKILL'); spawn();
    identity[field] = 'changed';
    controller.restarted();
    await assert.rejects(crashed, /storage changed on restart/);
  });
});

test('duplicate restart callback or extra spawn invalidates completed proof', async t => {
  for (const mutation of ['callback', 'spawn', 'exit']) await t.test(mutation, async t => {
    const { controller, spawn, processes } = fixture(t);
    spawn(); controller.arm('after-admission');
    const crashed = controller.reach('after-admission');
    processes[0].emit('exit', null, 'SIGKILL'); spawn(); controller.restarted();
    await crashed;
    if (mutation === 'callback') controller.restarted();
    else if (mutation === 'exit') processes[1].emit('exit', 1, null);
    else assert.throws(() => spawn(), /unexpected workerd spawn/);
    assert.equal(processes.length, 2);
    await assert.rejects(controller.proof(), /unexpected workerd/);
  });
});

test('startup exit, kill failure, and shutdown settle outstanding waiters', async t => {
  await t.test('startup exit', t => {
    const { controller, spawn, processes } = fixture(t);
    spawn(); processes[0].emit('exit', 1, null);
    assert.throws(() => controller.arm('before-reserve'), /unexpected workerd exit/);
  });
  await t.test('kill failure', async t => {
    const { controller, spawn, processes } = fixture(t);
    spawn(); processes[0].kill = () => false;
    controller.arm('before-reserve');
    await assert.rejects(controller.reach('before-reserve'), /owned workerd kill failed/);
  });
  await t.test('shutdown', async t => {
    const { controller, spawn } = fixture(t);
    spawn(); controller.arm('before-reserve');
    const crashed = controller.reach('before-reserve');
    controller.stop();
    await assert.rejects(crashed, /crash fixture stopping/);
  });
});
