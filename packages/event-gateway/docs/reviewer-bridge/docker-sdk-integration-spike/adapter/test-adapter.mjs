import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtempSync, mkdirSync, rmSync, chmodSync, realpathSync, copyFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import {
  createCliOutputCollectorForTest, createDockerAdapterWithFakeBackend, spawnBindingProbeForTest,
} from './adapter.mjs';

const IMAGE = 'sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d';
const TMPFS = 'rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=0700';
const SESSION = '25aee98b-335d-4ec9-8bd3-4a8e8889a6f6';
const CID = 'a'.repeat(64);

const trustedSpawn = childProcess.spawn;
const replacementSpawn = () => { throw new Error('spawn probe must remain inert'); };
try {
  childProcess.spawn = replacementSpawn;
  syncBuiltinESMExports();
  assert.equal(childProcess.spawn, replacementSpawn);
  assert.deepEqual(spawnBindingProbeForTest(trustedSpawn), { capturedMatches: true, importedMatches: false });
} finally {
  childProcess.spawn = trustedSpawn;
  syncBuiltinESMExports();
}
assert.deepEqual(spawnBindingProbeForTest(trustedSpawn), { capturedMatches: true, importedMatches: true });

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fakeInspect(container) {
  return {
    Id: container.id,
    Name: `/${container.name}`,
    Image: IMAGE,
    HostConfig: {
      NetworkMode: 'none', Privileged: false, ReadonlyRootfs: true, PidsLimit: 32,
      Memory: 134217728, MemorySwap: 134217728, NanoCpus: 1000000000,
      IpcMode: 'private', PublishAllPorts: false, AutoRemove: false,
      CapDrop: ['ALL'], CapAdd: [], SecurityOpt: ['no-new-privileges:true'],
      Tmpfs: { '/work': TMPFS }, LogConfig: { Type: 'none' }, RestartPolicy: { Name: 'no' },
    },
    Config: {
      Image: IMAGE, Labels: { 'reviewer.fixture': container.name }, User: '65532:65532',
      Entrypoint: ['python3'], Cmd: ['-I', '-B', '/fixture/protocol-child.py', container.mode, container.sessionId],
      Env: ['PATH=/usr/local/bin:/usr/bin:/bin'],
    },
    Mounts: [{ Type: 'bind', Source: container.fixture, Destination: '/fixture', RW: false },
      { Type: 'tmpfs', Destination: '/work', RW: true }],
    State: { ...container.state },
  };
}

function makeBackend(options = {}) {
  const mode = options.mode ?? 'success';
  const createEntered = deferred();
  const commands = [];
  const data = { mode, containers: new Map(), attached: null, input: Buffer.alloc(0), eof: false,
    createEntered, commands, daemonCalls: 0, name: null, fixture: null, sessionId: null };
  data.attachEntered = deferred();
  data.clientSignals = [];
  data.cliConfigPath = null;
  const record = args => commands.push([...args]);
  const output = value => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
  function stop(container, code = 0) {
    container.state = { Status: 'exited', Running: false, Pid: 0, ExitCode: code };
    data.attached?.finish(code);
  }
  return {
    data,
    async command(args) {
      record(args);
      switch (args[0]) {
        case 'info':
          data.daemonCalls++;
          return output(options.changeDaemonAfter && data.daemonCalls > 1 ? 'fake-daemon-2\n' : 'fake-daemon-1\n');
        case 'image':
          if (options.timeoutImageInspect) throw new Error('docker image inspect timed out');
          return output([{ Id: IMAGE, Os: 'linux', Architecture: 'arm64' }]);
        case 'container': {
          const filter = args[args.indexOf('--filter') + 1];
          if (filter.startsWith('name=')) {
            const container = [...data.containers.values()].find(item => `name=^/${item.name}$` === filter);
            return output(container ? `${container.id}\n` : '');
          }
          const id = filter.slice('id='.length);
          return output(data.containers.has(id) ? `${id}\n` : '');
        }
        case 'create': {
          data.name = args[args.indexOf('--name') + 1];
          data.sessionId = args.at(-1);
          const mount = args.find(value => value.startsWith('type=bind,src='));
          data.fixture = mount.slice('type=bind,src='.length).split(',dst=')[0];
          const childAt = args.indexOf('/fixture/protocol-child.py');
          assert(childAt >= 0);
          assert.deepEqual(args.slice(childAt), ['/fixture/protocol-child.py', mode, SESSION]);
          assert(args.includes('-i') && args.includes('--pull=never'));
          assert(args.includes('--network=none') && args.includes('--cap-drop=ALL'));
          assert(args.includes('--read-only') && args.includes('--ipc=private'));
          assert(args.includes('--log-driver=none') && args.includes('--restart=no'));
          assert(args.includes('--memory=128m') && args.includes('--memory-swap=128m') && args.includes('--cpus=1'));
          assert.equal(args.find(value => value.startsWith('type=bind,src=')),
            `type=bind,src=${data.fixture},dst=/fixture,readonly`);
          createEntered.resolve();
          if (options.createDelay) await options.createDelay.promise;
          const container = { id: CID, name: data.name, mode, sessionId: data.sessionId, fixture: data.fixture,
            state: { Status: 'created', Running: false, Pid: 0, ExitCode: 0 } };
          data.containers.set(CID, container);
          if (options.loseCreateResponse) throw new Error('simulated response loss after daemon dispatch');
          return output(`${CID}\n`);
        }
        case 'inspect': {
          const container = data.containers.get(args[1]);
          if (!container) throw new Error('no such container');
          const value = fakeInspect(container);
      if (options.wrongInspect) value.Id = 'b'.repeat(64);
      if (options.nonEmptyPortBindings) value.HostConfig.PortBindings = { '8080/tcp': [] };
          return output([value]);
        }
        case 'kill': {
          const container = data.containers.get(args.at(-1));
          assert(container, 'only an existing exact ID may be killed');
          if (options.failKill) throw new Error('simulated Docker kill failure');
          const code = args[1] === '--signal=SIGTERM' ? 143 : 137;
          if (container.state.Running && !(options.ignorePid1Term && args[1] === '--signal=SIGTERM')) stop(container, code);
          return output('');
        }
        case 'rm': {
          assert.equal(args[1], '--force');
          if (!options.refuseRemove) data.containers.delete(args[2]);
          return output('');
        }
        default: throw new Error(`fake backend rejected operation: ${args.join(' ')}`);
      }
    },
    testTimeouts: options.testTimeouts,
    attach(args, context) {
      record(args);
      assert.deepEqual(args, ['start', '--attach', '--interactive', CID]);
      const container = data.containers.get(CID);
      assert(container, 'attach requires an owned inspected ID');
      container.state = { Status: 'running', Running: true, Pid: 1, ExitCode: 0 };
      const child = new EventEmitter();
      child.stdin = new Writable({
        write(chunk, _encoding, callback) { data.input = Buffer.concat([data.input, Buffer.from(chunk)]); callback(); },
        final(callback) { data.eof = true; callback(); },
      });
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      child.exitCode = null;
      child.signalCode = null;
      child.finish = code => {
        if (child.exitCode !== null) return;
        child.exitCode = options.attachExit ? options.attachExit.code : code;
        child.signalCode = options.attachExit?.signal ?? null;
        if (options.neverCloseClient) return;
        child.stdout.end();
        child.stderr.end();
        child.emit('close', child.exitCode, child.signalCode);
      };
      child.kill = signal => {
        data.clientSignals.push(signal);
        if (signal === 'SIGKILL' && !options.neverCloseClient) child.finish(137);
        return true;
      };
      data.attached = child;
      data.attachEntered.resolve();
      data.cliConfigPath = context?.configPath ?? null;
      if (options.attachError || options.attachErrorThenClose) queueMicrotask(() => {
        child.emit('error', new Error('simulated attach failure'));
        if (options.attachErrorThenClose) child.finish(1);
      });
      const complete = () => {
        if (options.attachError || options.attachErrorThenClose) return;
        if (mode === 'abort') return;
        if (mode === 'eof') {
          stop(container, 0);
          return;
        }
        if (options.attachOutput) {
          for (const [stream, bytes] of options.attachOutput) child[stream].write(bytes);
        } else {
          child.stdout.write(`${JSON.stringify({ type: 'result', subtype: mode, session_id: SESSION })}\n`);
        }
        if (options.outputOverflowAfterTerminal) child.stdout.write(Buffer.alloc(70 * 1024, 65));
        if (!options.leaveRunningAfterAttach) stop(container, 0);
        else child.finish(0);
      };
      queueMicrotask(() => {
        if (data.eof) complete();
        else child.stdin.once('finish', complete);
      });
      return child;
    },
  };
}

function makeRoot() {
  const root = mkdtempSync(join(tmpdir(), 'reviewer-docker-adapter-'));
  chmodSync(root, 0o700);
  mkdirSync(join(root, 'fixture'));
  copyFileSync(new URL('./fixture/protocol-child.py', import.meta.url), join(root, 'fixture', 'protocol-child.py'));
  return realpathSync(root);
}

function sdkOptions(root) {
  return { command: join(root, 'NEVER-EXECUTED-claude'), cwd: root,
    args: ['--output-format', 'stream-json', '--session-id', SESSION], env: { ANTHROPIC_API_KEY: 'never-forward-me' },
    signal: new AbortController().signal };
}

async function runCase(options = {}) {
  const root = makeRoot();
  try {
    const backend = makeBackend(options);
    const adapter = createDockerAdapterWithFakeBackend({ root, mode: options.mode ?? 'success', sessionId: SESSION }, backend);
    const facade = adapter.spawn(sdkOptions(root));
    const received = [];
    const errors = [];
    facade.stdout.on('data', chunk => received.push(Buffer.from(chunk)));
    facade.on('error', error => errors.push(error));
    return { root, backend, adapter, facade, received, errors, close: () => rmSync(root, { recursive: true, force: true }) };
  } catch (error) { rmSync(root, { recursive: true, force: true }); throw error; }
}

async function shouldReject(promise, pattern) {
  await assert.rejects(promise, pattern);
}

const validationRoot = makeRoot();
try {
  const backend = makeBackend();
  const config = { root: validationRoot, mode: 'success', sessionId: SESSION };
  for (const version of '12345678') {
    for (const variant of '89ab') {
      const sessionId = `${SESSION.slice(0, 14)}${version}${SESSION.slice(15, 19)}${variant}${SESSION.slice(20)}`;
      assert.doesNotThrow(() => createDockerAdapterWithFakeBackend({ ...config, sessionId }, backend));
    }
  }
  for (const sessionId of [null, 42, '', SESSION.toUpperCase(), `${SESSION}\n`, 'a'.repeat(100_000),
    SESSION.replace('-','_'), `${SESSION.slice(0, 14)}0${SESSION.slice(15)}`,
    `${SESSION.slice(0, 14)}9${SESSION.slice(15)}`, `${SESSION.slice(0, 19)}7${SESSION.slice(20)}`,
    `${SESSION.slice(0, 19)}c${SESSION.slice(20)}`, `g${SESSION.slice(1)}`]) {
    assert.throws(() => createDockerAdapterWithFakeBackend({ ...config, sessionId }, backend), /canonical UUID/);
  }
  const adapter = createDockerAdapterWithFakeBackend(config, backend);
  for (const args of [[], ['--session-id'], ['--session-id', SESSION, '--session-id', SESSION],
    ['--session-id', `${SESSION}\n`], ['--session-id', 'a'.repeat(100_000)], ['--session-id', 42]]) {
    assert.throws(() => adapter.spawn({ ...sdkOptions(validationRoot), args }), /SDK (session id mismatch|command arguments)/);
  }
  for (const overrides of [{ command: '/bin/sh' }, { cwd: '/' },
    { command: `${validationRoot}/../NEVER-EXECUTED-claude` }]) {
    assert.throws(() => adapter.spawn({ ...sdkOptions(validationRoot), ...overrides }), /unexpected SDK command/);
  }
  assert.throws(() => createDockerAdapterWithFakeBackend({ ...config, root: 'relative' }, backend), /root must be absolute/);
  assert.equal(backend.data.commands.length, 0, 'invalid arguments must fail before Docker dispatch');
} finally {
  rmSync(validationRoot, { recursive: true, force: true });
}

for (const invalidId of ['', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64),
  `${'a'.repeat(63)}g`, 'a'.repeat(100_000)]) {
  for (const operation of ['create', 'container']) {
    const root = makeRoot();
    try {
      const backend = makeBackend();
      const command = backend.command;
      backend.command = async args => {
        const result = await command(args);
        return args[0] === operation ? Buffer.from(`${invalidId}\n`) : result;
      };
      // An empty listing is valid and means no matching container.
      if (operation === 'container' && invalidId === '') continue;
      const adapter = createDockerAdapterWithFakeBackend({ root, mode: 'success', sessionId: SESSION }, backend);
      const facade = adapter.spawn(sdkOptions(root));
      facade.on('error', () => {});
      await assert.rejects(adapter.settle(), /invalid (created container identity|Docker identity listing)/);
      assert.equal(backend.data.attached, null, 'invalid identities must never reach attach');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
}

const cliOutput = createCliOutputCollectorForTest();
cliOutput.collect('stdout', Buffer.alloc(40 * 1024, 65));
cliOutput.collect('stderr', Buffer.alloc(40 * 1024, 66));
cliOutput.collect('stdout', Buffer.alloc(2 * 1024 * 1024, 67));
assert.equal(cliOutput.totalBytes, 2 * 1024 * 1024 + 80 * 1024);
assert.equal(cliOutput.retainedBytes, 64 * 1024);
assert.equal(cliOutput.allocatedBytes, 64 * 1024,
  'retained prefixes are copied so small views do not pin oversized source buffers');
assert.equal(cliOutput.bytes('stdout').length, 40 * 1024);
assert.equal(cliOutput.bytes('stderr').length, 24 * 1024);
assert.equal(cliOutput.overflow, true);

for (const [payload, pattern] of [
  [Buffer.alloc(64 * 1024 + 1, 65), /protocol input frame limit/],
  [Buffer.alloc(2 * 1024 * 1024 + 1, 10), /combined protocol transport limit/],
  ['\n'.repeat(2 * 1024 * 1024 + 1), /combined protocol transport limit/],
]) {
  const delay = deferred();
  const run = await runCase({ createDelay: delay });
  await run.backend.data.createEntered.promise;
  let callbackError;
  const originalBufferFrom = Buffer.from;
  let oversizedStringCopies = 0;
  Buffer.from = (value, ...args) => {
    if (typeof value === 'string' && value.length > 2 * 1024 * 1024) oversizedStringCopies++;
    return originalBufferFrom(value, ...args);
  };
  let ended;
  try {
    ended = new Promise(resolvePromise => run.facade.stdin.end(payload, error => {
      callbackError = error;
      resolvePromise();
    }));
  } finally { Buffer.from = originalBufferFrom; }
  assert.equal(oversizedStringCopies, 0, 'oversized encoded input is bounded before allocation');
  assert.equal(run.facade.stdin._pendingWrite, null, 'oversized end payload is rejected before pending retention');
  assert.equal(run.facade.stdin.destroyed, true);
  delay.resolve();
  await ended;
  assert(callbackError instanceof Error, 'failed end callback receives an error');
  await assert.rejects(run.adapter.settle(), pattern);
  assert.equal(run.backend.data.attached, null, 'failed end payload must prevent attach');
  assert.equal(run.backend.data.input.length, 0);
  assert.equal(run.backend.data.containers.size, 0);
  run.close();
}

for (const [first, last, encoding, expected] of [
  [null, Buffer.from('buffer\n'), undefined, Buffer.from('buffer\n')],
  [null, 'c3a90a', 'hex', Buffer.from('é\n')],
  [null, new Uint8Array([116, 121, 112, 101, 100, 10]), undefined, Buffer.from('typed\n')],
  ['first\n', Buffer.from('last\n'), undefined, Buffer.from('first\nlast\n')],
]) {
  const delay = deferred();
  const run = await runCase({ createDelay: delay });
  await run.backend.data.createEntered.promise;
  if (first !== null) run.facade.stdin.write(first);
  run.facade.stdin.end(last, encoding);
  assert.equal(run.backend.data.attached, null);
  assert(run.facade.stdin._pendingWrite, 'valid input waits for attach');
  delay.resolve();
  const result = await run.adapter.settle();
  assert.deepEqual(run.backend.data.input, expected);
  assert.equal(result.transportBytes.input, expected.length, 'write and end bytes count exactly once');
  assert.equal(result.transportBytes.total, result.transportBytes.input + result.transportBytes.output);
  assert.equal(run.facade.stdin._pendingWrite, null);
  assert.equal(run.backend.data.eof, true);
  run.close();
}

for (const corked of [false, true]) {
  for (const [first, last, pattern] of [
    [Buffer.from('a'), Buffer.alloc(64 * 1024, 65), /protocol input frame limit/],
    [Buffer.from('\n'), Buffer.alloc(2 * 1024 * 1024, 10), /combined protocol transport limit/],
  ]) {
    const delay = deferred();
    const run = await runCase({ createDelay: delay });
    await run.backend.data.createEntered.promise;
    if (corked) run.facade.stdin.cork();
    let firstError;
    const firstDone = new Promise(resolvePromise => run.facade.stdin.write(first, error => {
      firstError = error;
      resolvePromise();
    }));
    const endDone = new Promise(resolvePromise => run.facade.stdin.end(last, resolvePromise));
    assert.equal(run.facade.stdin.destroyed, true, 'queued end is rejected synchronously before attach');
    assert.equal(run.facade.stdin._pendingWrite, null, 'destruction releases pending input');
    assert(run.facade.stdin.writableLength <= first.length, 'rejected payload never enters the native queue');
    delay.resolve();
    await Promise.all([firstDone, endDone]);
    assert.equal(run.facade.stdin.writableLength, 0, 'destroyed input queue is drained');
    assert(firstError instanceof Error, 'pending write callback is released with failure');
    await assert.rejects(run.adapter.settle(), pattern);
    assert.equal(run.backend.data.attached, null);
    assert.equal(run.backend.data.input.length, 0);
    assert.equal(run.backend.data.containers.size, 0);
    run.close();
  }
}

for (const corked of [false, true]) {
  const run = await runCase();
  if (corked) run.facade.stdin.cork();
  const wrote = new Promise((resolvePromise, reject) => run.facade.stdin.write('é\n', 'utf8', error => {
    if (error) reject(error); else resolvePromise();
  }));
  run.facade.stdin.setDefaultEncoding('hex');
  const ended = new Promise((resolvePromise, reject) => run.facade.stdin.end('650a', error => {
    if (error) reject(error); else resolvePromise();
  }));
  await Promise.all([wrote, ended]);
  const result = await run.adapter.settle();
  assert.deepEqual(run.backend.data.input, Buffer.from('é\ne\n'));
  assert.equal(result.transportBytes.input, 5);
  run.close();
}

for (const endArgs of [[], [null], ['', 'utf8'], [Buffer.alloc(0)]]) {
  const run = await runCase();
  const ended = new Promise((resolvePromise, reject) => run.facade.stdin.end(...endArgs, error => {
    if (error) reject(error); else resolvePromise();
  }));
  const endedAgain = new Promise((resolvePromise, reject) => run.facade.stdin.end(error => {
    if (error) reject(error); else resolvePromise();
  }));
  await Promise.all([ended, endedAgain]);
  assert.equal((await run.adapter.settle()).transportBytes.input, 0, 'empty and repeated end reserve no bytes');
  run.close();
}

const combinedOutput = await runCase();
combinedOutput.facade.stdin.end(Buffer.alloc(2 * 1024 * 1024, 10));
await assert.rejects(combinedOutput.adapter.settle(), /combined protocol transport limit/);
assert.equal(combinedOutput.backend.data.input.length, 2 * 1024 * 1024);
assert.equal(combinedOutput.backend.data.containers.size, 0);
combinedOutput.close();

const endAfterEnd = await runCase();
endAfterEnd.facade.stdin.end();
endAfterEnd.facade.stdin.end('late\n');
await assert.rejects(endAfterEnd.adapter.settle(), /write after end/);
assert.equal(endAfterEnd.backend.data.attached, null);
endAfterEnd.close();

const normal = await runCase();
normal.facade.stdin.write('{"type":"user","message":"early prompt"}\n');
normal.facade.stdin.end();
const firstSettle = normal.adapter.settle();
assert.equal(normal.adapter.settle(), firstSettle);
const success = await firstSettle;
assert.equal(success.exitCode, 0);
assert.equal(normal.facade.exitCode, 0);
assert.equal(normal.facade.killed, false);
assert.equal('pid' in normal.facade, false);
assert.equal(normal.facade.stdinWritable, normal.facade.stdin);
assert.equal(normal.facade.stdoutReadable, normal.facade.stdout);
assert.match(Buffer.concat(normal.received).toString(), /"subtype":"success"/);
assert.match(normal.backend.data.input.toString(), /early prompt/);
assert.equal(normal.backend.data.eof, true);
assert.equal(normal.backend.data.containers.size, 0);
assert.equal(normal.backend.data.daemonCalls, 2);
normal.close();

for (const mode of ['early-terminal', 'eof']) {
  const run = await runCase({ mode });
  run.facade.stdin.end();
  const result = await run.adapter.settle();
  assert.equal(result.exitCode, 0);
  assert.equal(run.backend.data.containers.size, 0);
  assert.equal(run.backend.data.eof, true);
  run.close();
}

const abort = await runCase({ mode: 'abort' });
const inputClosed = new Promise(resolvePromise => abort.facade.stdin.end(resolvePromise));
await inputClosed;
assert.equal(abort.backend.data.eof, true);
assert.equal(abort.facade.kill('SIGTERM'), true);
assert.equal(abort.facade.kill('SIGTERM'), true);
const abortResult = await abort.adapter.settle();
assert.equal(abortResult.exitCode, 143);
assert.equal(abort.facade.killed, true);
assert.equal(abort.backend.data.commands.filter(args => args[0] === 'kill').length, 1);
abort.close();

const ignoresTerm = await runCase({ mode: 'abort', ignorePid1Term: true,
  testTimeouts: { stopWaitMs: 20 } });
const ignoreInputClosed = new Promise(resolvePromise => ignoresTerm.facade.stdin.end(resolvePromise));
await ignoreInputClosed;
const ignoresTermStartedAt = Date.now();
assert.equal(ignoresTerm.facade.kill('SIGTERM'), true);
assert.equal(ignoresTerm.facade.kill('SIGTERM'), true);
const ignoredTermResult = await ignoresTerm.adapter.settle();
assert(Date.now() - ignoresTermStartedAt < 1_500, 'SIGKILL escalation is bounded');
assert.equal(ignoredTermResult.exitCode, 137);
assert.deepEqual(ignoresTerm.backend.data.commands.filter(args => args[0] === 'kill').map(args => args[1]),
  ['--signal=SIGTERM', '--signal=SIGKILL']);
assert.equal(ignoresTerm.backend.data.containers.size, 0);
ignoresTerm.close();

for (const code of [1, 125, null, -1, 0.5, '0']) {
  const run = await runCase({ attachExit: { code } });
  run.facade.stdin.end();
  await assert.rejects(run.adapter.settle(), /Docker attach exit code disagrees/);
  assert.equal(run.backend.data.containers.size, 0, 'exit mismatch still removes the owned stopped container');
  assert.equal(run.facade.exitCode, 1, 'CLI failure cannot become facade success');
  run.close();
}

const signaledAttach = await runCase({ attachExit: { code: 0, signal: 'SIGTERM' } });
signaledAttach.facade.stdin.end();
await assert.rejects(signaledAttach.adapter.settle(), /Docker attach client was signaled/);
assert.equal(signaledAttach.backend.data.containers.size, 0);
signaledAttach.close();

for (const streams of [
  ['stderr', 'stdout'], ['stdout', 'stderr'],
  ['stderr', 'stdout', 'stderr', 'stdout'], ['stdout', 'stderr', 'stdout', 'stderr'],
]) {
  for (const extraByte of [0, 1]) {
    const chunkSize = 64 * 1024 / streams.length;
    const attachOutput = streams.map((stream, index) =>
      [stream, Buffer.alloc(chunkSize + (index === streams.length - 1 ? extraByte : 0), 10)]);
    const run = await runCase({ attachOutput });
    run.facade.stdin.end();
    if (extraByte) {
      await assert.rejects(run.adapter.settle(), /Docker attach (output|diagnostic) limit/);
      assert.equal(run.facade.exitCode, 1);
    } else {
      const result = await run.adapter.settle();
      assert.equal(result.exitCode, 0, 'exact shared 64 KiB limit remains accepted');
      assert.equal(result.transportBytes.output, 32 * 1024, 'stderr is excluded from protocol receipts');
      assert.equal(Buffer.concat(run.received).length, 32 * 1024);
    }
    assert.equal(run.backend.data.containers.size, 0, 'shared stream budget always preserves owned cleanup');
    run.close();
  }
}

const cliExitRunning = await runCase({ leaveRunningAfterAttach: true });
cliExitRunning.facade.stdin.end();
await shouldReject(cliExitRunning.adapter.settle(), /container remained running/);
assert(cliExitRunning.backend.data.commands.some(args => args[0] === 'kill'));
assert.equal(cliExitRunning.backend.data.containers.size, 0);
cliExitRunning.close();

const lostCreate = await runCase({ loseCreateResponse: true });
lostCreate.facade.stdin.end();
await shouldReject(lostCreate.adapter.settle(), /simulated response loss/);
assert(lostCreate.backend.data.commands.some(args => args[0] === 'inspect' && args[1] === CID));
assert(lostCreate.backend.data.commands.some(args => args[0] === 'rm'));
assert.equal(lostCreate.backend.data.containers.size, 0);
lostCreate.close();

const lostCreateBadPolicy = await runCase({ loseCreateResponse: true, nonEmptyPortBindings: true });
lostCreateBadPolicy.facade.stdin.end();
await shouldReject(lostCreateBadPolicy.adapter.settle(), /additional container access/);
assert(lostCreateBadPolicy.backend.data.commands.some(args => args[0] === 'rm'),
  'recovery must adopt an exactly owned container before validating policy');
assert.equal(lostCreateBadPolicy.backend.data.containers.size, 0);
lostCreateBadPolicy.close();

const cidGate = deferred();
const killBeforeCid = await runCase({ createDelay: cidGate });
await killBeforeCid.backend.data.createEntered.promise;
let pendingCallbackCalls = 0;
const pendingInputClosed = new Promise(resolvePromise => killBeforeCid.facade.stdin.write('pending\n', error => {
  pendingCallbackCalls++;
  assert.match(error.message, /closed before stdin attach/);
  resolvePromise();
}));
assert.equal(killBeforeCid.facade.kill('SIGTERM'), true);
cidGate.resolve();
await shouldReject(killBeforeCid.adapter.settle(), /terminated during container creation/);
assert(killBeforeCid.backend.data.commands.some(args => args[0] === 'rm'));
assert(!killBeforeCid.backend.data.commands.some(args => args[0] === 'start'));
assert.equal(killBeforeCid.backend.data.containers.size, 0);
await pendingInputClosed;
assert.equal(pendingCallbackCalls, 1);
assert.equal(killBeforeCid.facade.stdin._pendingWrite, null);
assert.equal(killBeforeCid.facade.stdin.destroyed, true);
killBeforeCid.close();

const timeout = await runCase({ timeoutImageInspect: true });
timeout.facade.stdin.end();
await shouldReject(timeout.adapter.settle(), /timed out/);
assert.equal(timeout.backend.data.commands.some(args => args[0] === 'create'), false);
assert.equal(timeout.backend.data.daemonCalls, 2);
timeout.close();

const daemonMismatch = await runCase({ changeDaemonAfter: true });
daemonMismatch.facade.stdin.end();
await shouldReject(daemonMismatch.adapter.settle(), /daemon identity changed/);
assert.equal(daemonMismatch.backend.data.containers.size, 0);
daemonMismatch.close();

const wrongId = await runCase({ wrongInspect: true });
wrongId.facade.stdin.end();
await shouldReject(wrongId.adapter.settle(), /ownership mismatch/);
assert.equal(wrongId.backend.data.commands.some(args => args[0] === 'kill' || args[0] === 'rm'), false);
assert.equal(wrongId.backend.data.containers.size, 1, 'ambiguous identity must remain untouched');
wrongId.close();

const badPortBindings = await runCase({ nonEmptyPortBindings: true });
badPortBindings.facade.stdin.end();
await shouldReject(badPortBindings.adapter.settle(), /additional container access/);
assert(badPortBindings.backend.data.commands.some(args => args[0] === 'rm'));
assert.equal(badPortBindings.backend.data.containers.size, 0);
badPortBindings.close();

const unconfirmedRemove = await runCase({ refuseRemove: true });
unconfirmedRemove.facade.stdin.end();
await shouldReject(unconfirmedRemove.adapter.settle(), /cleanup incomplete/);
assert(unconfirmedRemove.backend.data.commands.some(args => args[0] === 'container' && args.at(-3) === `id=${CID}`));
assert(unconfirmedRemove.backend.data.commands.some(args => args[0] === 'container' && args.at(-3)?.startsWith('name=')));
unconfirmedRemove.close();

const overflow = await runCase();
overflow.facade.stdin.end();
assert.equal(overflow.facade.stdin.write(Buffer.alloc(2 * 1024 * 1024 + 1, 10)), false);
await shouldReject(overflow.adapter.settle(), /write after end/);
assert.equal(overflow.backend.data.commands.some(args => args[0] === 'create'), false);
overflow.close();

const stickyTransportFailure = await runCase({ outputOverflowAfterTerminal: true });
stickyTransportFailure.facade.stdin.end();
await shouldReject(stickyTransportFailure.adapter.settle(), /protocol output frame limit/);
assert.equal(stickyTransportFailure.backend.data.commands.some(args => args[0] === 'rm'), true);
assert.equal(stickyTransportFailure.backend.data.containers.size, 0);
stickyTransportFailure.close();

const closeUnconfirmed = await runCase({ mode: 'abort', neverCloseClient: true,
  testTimeouts: { attachMs: 20, attachCloseWaitMs: 5, clientTermMs: 5, clientDeadlineMs: 20, stopWaitMs: 20 } });
closeUnconfirmed.facade.stdin.end();
await shouldReject(closeUnconfirmed.adapter.settle(), /close unconfirmed|config retained/);
assert.deepEqual(closeUnconfirmed.backend.data.clientSignals, ['SIGTERM', 'SIGKILL']);
assert.notEqual(closeUnconfirmed.backend.data.attached.exitCode, null,
  'fake child records process exit even though the close event and pipe shutdown are withheld');
assert.equal(closeUnconfirmed.backend.data.containers.size, 0);
assert.equal(realpathSync(closeUnconfirmed.backend.data.cliConfigPath), closeUnconfirmed.backend.data.cliConfigPath);
closeUnconfirmed.close();

const alreadyClosed = await runCase({ attachErrorThenClose: true,
  testTimeouts: { attachCloseWaitMs: 500, clientTermMs: 5, clientDeadlineMs: 20 } });
alreadyClosed.facade.stdin.end();
await shouldReject(alreadyClosed.adapter.settle(), /simulated attach failure/);
assert.equal(alreadyClosed.backend.data.clientSignals.length, 0,
  'a previously observed close event avoids an unnecessary wait and kill');
assert.equal(existsSync(alreadyClosed.backend.data.cliConfigPath), false,
  'config is removed after the attach CLI close event was observed');
alreadyClosed.close();

const cleanupStages = await runCase({ mode: 'abort', attachError: true, failKill: true,
  testTimeouts: { attachMs: 500, attachCloseWaitMs: 5, clientTermMs: 5, clientDeadlineMs: 20, stopWaitMs: 5 } });
cleanupStages.facade.stdin.end();
await cleanupStages.backend.data.attachEntered.promise;
cleanupStages.facade.kill('SIGTERM');
await assert.rejects(cleanupStages.adapter.settle(), error => {
  assert.match(error.message, /simulated attach failure/);
  assert.match(error.message, /cleanup incomplete/);
  assert.match(error.message, /simulated Docker kill failure/);
  return true;
});
assert.deepEqual(cleanupStages.backend.data.clientSignals, ['SIGTERM', 'SIGKILL'],
  'attach CLI close is attempted after stop failure');
assert(cleanupStages.backend.data.commands.some(args => args[0] === 'rm'),
  'owned cleanup runs even after independent stop stages fail');
assert.equal(cleanupStages.backend.data.commands.some(args => args[0] === 'container' && args.at(-3) === `id=${CID}`), true,
  'post-cleanup absence is checked after prior cleanup errors');
assert.equal(cleanupStages.backend.data.containers.size, 0);
cleanupStages.close();

console.log(JSON.stringify({ status: 'PASS', cases: [
  'canonical UUID versions and variants; malformed and oversized UUID rejection',
  'SDK session and exact path policy rejected before dispatch',
  'malformed and oversized CID listings and create results rejected before attach',
  'end payload frame and transport limits before attach; exact Buffer/string/typed-array accounting',
  'queued and corked write/end admission; pending callbacks released; cumulative frame and transport caps',
  'UTF8, hex default encoding, callback overloads and repeated empty end',
  'bounded startup buffering and clean exit code', 'early terminal', 'EOF', 'abort and duplicate kill',
  'attach CLI exit code must agree with inspected status; malformed and signaled exits rejected',
  'shared stdout/stderr 64 KiB exact boundary and overflow in both orders and interleavings',
  'PID 1 ignores TERM and receives bounded SIGKILL', 'attach CLI exit while container runs',
  'lost create response recovery', 'lost create with bad policy recovers exact owned container',
  'kill before CID', 'command timeout', 'daemon identity mismatch', 'wrong ID fails closed',
  'nonempty PortBindings rejected and owned container removed', 'unconfirmed removal', 'closed-input overflow',
  'sticky transport failure after successful terminal', 'attach CLI close timeout retains config despite exitCode',
  'previously observed attach close avoids kill and allows config cleanup',
  'cleanup stages continue after stop failures', 'shared 64 KiB CLI output retention budget',
] }));
