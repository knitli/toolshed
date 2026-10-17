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

function makeBackend({
  mode = 'success',
  createDelay,
  loseCreateResponse = false,
  wrongInspect = false,
  leaveRunningAfterAttach = false,
  refuseRemove = false,
  timeoutImageInspect = false,
  changeDaemonAfter = false,
  nonEmptyPortBindings = false,
  ignorePid1Term = false,
  failKill = false,
  attachError = false,
  attachErrorThenClose = false,
  neverCloseClient = false,
  outputOverflowAfterTerminal = false,
  testTimeouts,
} = {}) {
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
          return output(changeDaemonAfter && data.daemonCalls > 1 ? 'fake-daemon-2\n' : 'fake-daemon-1\n');
        case 'image':
          if (timeoutImageInspect) throw new Error('docker image inspect timed out');
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
          if (createDelay) await createDelay.promise;
          const container = { id: CID, name: data.name, mode, sessionId: data.sessionId, fixture: data.fixture,
            state: { Status: 'created', Running: false, Pid: 0, ExitCode: 0 } };
          data.containers.set(CID, container);
          if (loseCreateResponse) throw new Error('simulated response loss after daemon dispatch');
          return output(`${CID}\n`);
        }
        case 'inspect': {
          const container = data.containers.get(args[1]);
          if (!container) throw new Error('no such container');
          const value = fakeInspect(container);
      if (wrongInspect) value.Id = 'b'.repeat(64);
      if (nonEmptyPortBindings) value.HostConfig.PortBindings = { '8080/tcp': [] };
          return output([value]);
        }
        case 'kill': {
          const container = data.containers.get(args.at(-1));
          assert(container, 'only an existing exact ID may be killed');
          if (failKill) throw new Error('simulated Docker kill failure');
          const code = args[1] === '--signal=SIGTERM' ? 143 : 137;
          if (container.state.Running && !(ignorePid1Term && args[1] === '--signal=SIGTERM')) stop(container, code);
          return output('');
        }
        case 'rm': {
          assert.equal(args[1], '--force');
          if (!refuseRemove) data.containers.delete(args[2]);
          return output('');
        }
        default: throw new Error(`fake backend rejected operation: ${args.join(' ')}`);
      }
    },
    testTimeouts,
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
        child.exitCode = code;
        if (neverCloseClient) return;
        child.stdout.end();
        child.stderr.end();
        child.emit('close', code, null);
      };
      child.kill = signal => {
        data.clientSignals.push(signal);
        if (signal === 'SIGKILL' && !neverCloseClient) child.finish(137);
        return true;
      };
      data.attached = child;
      data.attachEntered.resolve();
      data.cliConfigPath = context?.configPath ?? null;
      if (attachError || attachErrorThenClose) queueMicrotask(() => {
        child.emit('error', new Error('simulated attach failure'));
        if (attachErrorThenClose) child.finish(1);
      });
      const complete = () => {
        if (attachError || attachErrorThenClose) return;
        if (mode === 'abort') return;
        if (mode === 'eof') {
          stop(container, 0);
          return;
        }
        child.stdout.write(`${JSON.stringify({ type: 'result', subtype: mode, session_id: SESSION })}\n`);
        if (outputOverflowAfterTerminal) child.stdout.write(Buffer.alloc(70 * 1024, 65));
        if (!leaveRunningAfterAttach) stop(container, 0);
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
ignoresTerm.facade.kill('SIGTERM');
const ignoredTermResult = await ignoresTerm.adapter.settle();
assert(Date.now() - ignoresTermStartedAt < 1_500, 'SIGKILL escalation is bounded');
assert.equal(ignoredTermResult.exitCode, 137);
assert.deepEqual(ignoresTerm.backend.data.commands.filter(args => args[0] === 'kill').map(args => args[1]),
  ['--signal=SIGTERM', '--signal=SIGKILL']);
assert.equal(ignoresTerm.backend.data.containers.size, 0);
ignoresTerm.close();

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
assert.equal(killBeforeCid.facade.kill('SIGTERM'), true);
cidGate.resolve();
await shouldReject(killBeforeCid.adapter.settle(), /terminated during container creation/);
assert(killBeforeCid.backend.data.commands.some(args => args[0] === 'rm'));
assert(!killBeforeCid.backend.data.commands.some(args => args[0] === 'start'));
assert.equal(killBeforeCid.backend.data.containers.size, 0);
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
await shouldReject(overflow.adapter.settle(), /protocol input frame limit|combined protocol transport limit/);
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
  'bounded startup buffering and clean exit code', 'early terminal', 'EOF', 'abort and duplicate kill',
  'PID 1 ignores TERM and receives bounded SIGKILL', 'attach CLI exit while container runs',
  'lost create response recovery', 'lost create with bad policy recovers exact owned container',
  'kill before CID', 'command timeout', 'daemon identity mismatch', 'wrong ID fails closed',
  'nonempty PortBindings rejected and owned container removed', 'unconfirmed removal', 'closed-input overflow',
  'sticky transport failure after successful terminal', 'attach CLI close timeout retains config despite exitCode',
  'previously observed attach close avoids kill and allows config cleanup',
  'cleanup stages continue after stop failures', 'shared 64 KiB CLI output retention budget',
] }));
