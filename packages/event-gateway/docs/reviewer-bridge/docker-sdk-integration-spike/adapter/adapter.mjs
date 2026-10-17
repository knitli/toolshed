import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { spawn as importedSpawn } from 'node:child_process';
import {
  lstatSync, mkdtempSync, realpathSync, rmSync, readFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough, Writable } from 'node:stream';

// Capture the trusted builtin before SDK entrypoint guards rewrite live ESM builtin bindings.
const nodeSpawn = importedSpawn;

const IMAGE = 'sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d';
const DOCKER = '/usr/local/bin/docker';
const SOCKET = '/Users/adampoulemanos/.docker/run/docker.sock';
const MAX_OUTPUT = 64 * 1024;
const MAX_TRANSPORT = 2 * 1024 * 1024;
const MAX_FRAME = 64 * 1024;
const FIXTURE_SHA256 = 'f5d7ae681045266d2b9f2d806beee8b07c0f527f4feffd523037076c3d9d4cd6';
const COMMAND_TIMEOUT_MS = 15_000;
const CONTAINER_WAIT_MS = 2_000;
const TMPFS = 'rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=0700';
const MODES = new Set(['success', 'early-terminal', 'eof', 'abort']);
function isHex(value) {
  for (const char of value) {
    if (!'0123456789abcdef'.includes(char)) return false;
  }
  return true;
}

function isContainerId(value) {
  return typeof value === 'string' && value.length === 64 && isHex(value);
}

function isUuid(value) {
  if (typeof value !== 'string' || value.length !== 36) return false;
  if (!'12345678'.includes(value[14]) || !'89ab'.includes(value[19])) return false;
  for (let index = 0; index < value.length; index++) {
    if ([8, 13, 18, 23].includes(index)) {
      if (value[index] !== '-') return false;
    } else if (!isHex(value[index])) return false;
  }
  return true;
}
const DIAGNOSTIC_LIMIT = 2048;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function rootInfo(root) {
  invariant(typeof root === 'string' && root.length > 0 && isAbsolute(root), 'root must be absolute');
  const normalized = resolve(root);
  const info = lstatSync(normalized);
  invariant(realpathSync(normalized) === normalized && info.isDirectory() && !info.isSymbolicLink(), 'root must be a physical directory');
  invariant(typeof process.getuid === 'function' && info.uid === process.getuid(), 'root must be owned by this user');
  invariant((info.mode & 0o777) === 0o700 && !normalized.includes(','), 'root must be private and contain no comma');
  const fixture = join(normalized, 'fixture');
  const fixtureInfo = lstatSync(fixture);
  invariant(fixtureInfo.isDirectory() && !fixtureInfo.isSymbolicLink() && realpathSync(fixture) === fixture,
    'fixture directory must be physical');
  invariant(!fixture.includes(','), 'fixture path contains a Docker mount delimiter');
  const child = join(fixture, 'protocol-child.py');
  const childInfo = lstatSync(child);
  invariant(childInfo.isFile() && !childInfo.isSymbolicLink() && realpathSync(child) === child,
    'protocol child must be a physical file');
  invariant(createHash('sha256').update(readFileSync(child)).digest('hex') === FIXTURE_SHA256,
    'protocol child source hash mismatch');
  return { root: normalized, fixture };
}

function socketIdentity() {
  const info = lstatSync(SOCKET);
  invariant(info.isSocket() && info.uid === process.getuid(), 'untrusted local Docker socket');
  return `${info.dev}:${info.ino}:${info.mode}:${info.uid}`;
}

function dockerEnv() {
  return { PATH: '/usr/bin:/bin', HOME: homedir() };
}

function parseJson(bytes, message) {
  try { return JSON.parse(Buffer.from(bytes).toString('utf8')); }
  catch { throw new Error(message); }
}

function listIds(bytes) {
  const text = Buffer.from(bytes).toString('utf8');
  if (!text.trim()) return [];
  const values = text.trimEnd().split('\n');
  invariant(values.every(value => isContainerId(value)), 'invalid Docker identity listing');
  return values;
}

function createArgs(name, fixture, mode, sessionId) {
  return [
    'create', '-i', '--pull=never', '--name', name, '--label', `reviewer.fixture=${name}`,
    '--network=none', '--user=65532:65532', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
    '--read-only', '--ipc=private', '--pids-limit=32', '--memory=128m', '--memory-swap=128m',
    '--cpus=1', '--workdir=/work', '--tmpfs', `/work:${TMPFS}`, '--log-driver=none', '--restart=no',
    '--mount', `type=bind,src=${fixture},dst=/fixture,readonly`, '--entrypoint=python3', IMAGE,
    '-I', '-B', '/fixture/protocol-child.py', mode, sessionId,
  ];
}

function sameArgs(actual, expected) {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function assertDockerOperation(args, state) {
  invariant(Array.isArray(args) && args.every(value => typeof value === 'string'), 'invalid Docker arguments');
  const { name, fixture, mode, sessionId, ownedId } = state;
  const fixed = [
    ['info', '--format', '{{.ID}}'],
    ['image', 'inspect', IMAGE],
    ['container', 'ls', '--all', '--no-trunc', '--filter', `name=^/${name}$`, '--format', '{{.ID}}'],
    createArgs(name, fixture, mode, sessionId),
  ];
  if (fixed.some(item => sameArgs(args, item))) return;
  if (args.length === 2 && args[0] === 'inspect' && isContainerId(args[1])) return;
  if (ownedId && [
    ['start', '--attach', '--interactive', ownedId],
    ['kill', '--signal=SIGTERM', ownedId],
    ['kill', '--signal=SIGKILL', ownedId],
    ['rm', '--force', ownedId],
    ['container', 'ls', '--all', '--no-trunc', '--filter', `id=${ownedId}`, '--format', '{{.ID}}'],
  ].some(item => sameArgs(args, item))) return;
  throw new Error('unsupported Docker operation or identity');
}

function boundedFailure(operation, code, output) {
  const bytes = Buffer.concat(output).subarray(0, MAX_OUTPUT + 1);
  const detail = {
    exitCode: code,
    outputBytesAtLeast: bytes.length,
    outputPrefix: bytes.subarray(0, DIAGNOSTIC_LIMIT).toString('utf8'),
    truncated: bytes.length > DIAGNOSTIC_LIMIT,
  };
  return new Error(`docker ${operation} failed: ${JSON.stringify(detail)}`);
}

function observeChildClose(child) {
  const state = { seen: false, result: null, terminationPromise: null };
  state.promise = new Promise(resolvePromise => {
    child.once('close', (code, signal) => {
      state.seen = true;
      state.result = { code, signal };
      resolvePromise(state.result);
    });
  });
  return state;
}

function terminateClient(child, closeState, { termDelayMs = 1_000, deadlineMs = 2_000 } = {}) {
  if (closeState.seen) return Promise.resolve(true);
  if (closeState.terminationPromise) return closeState.terminationPromise;
  closeState.terminationPromise = new Promise(resolvePromise => {
    let complete = false;
    const finish = confirmed => {
      if (complete) return;
      complete = true;
      clearTimeout(killTimer);
      clearTimeout(deadline);
      resolvePromise(confirmed);
    };
    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* wait for close proof or deadline */ }
    }, termDelayMs);
    const deadline = setTimeout(() => finish(closeState.seen), deadlineMs);
    closeState.promise.then(() => finish(true));
    try { child.kill('SIGTERM'); } catch { /* wait for close proof or deadline */ }
  });
  return closeState.terminationPromise;
}

function makeCliOutputCollector() {
  const streams = { stdout: [], stderr: [] };
  let totalBytes = 0;
  let retainedBytes = 0;
  let overflow = false;
  return {
    collect(stream, chunk) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += bytes.length;
      if (totalBytes > MAX_OUTPUT) overflow = true;
      const remaining = MAX_OUTPUT - retainedBytes;
      if (remaining > 0 && bytes.length > 0) {
        const length = Math.min(bytes.length, remaining);
        const retained = Buffer.allocUnsafeSlow(length);
        bytes.copy(retained, 0, 0, length);
        streams[stream].push(retained);
        retainedBytes += retained.length;
      }
    },
    get totalBytes() { return totalBytes; },
    get retainedBytes() { return retainedBytes; },
    get allocatedBytes() {
      return streams.stdout.reduce((sum, part) => sum + part.buffer.byteLength, 0)
        + streams.stderr.reduce((sum, part) => sum + part.buffer.byteLength, 0);
    },
    get overflow() { return overflow; },
    bytes(stream) { return Buffer.concat(streams[stream]); },
  };
}

// Offline test seam for the shared CLI output budget; production runCli uses the same collector.
export function createCliOutputCollectorForTest() { return makeCliOutputCollector(); }

async function runCli(args, context, timeoutMs = COMMAND_TIMEOUT_MS) {
  const { configPath, expectedSocketIdentity } = context;
  invariant(socketIdentity() === expectedSocketIdentity, 'local Docker socket changed');
  const child = nodeSpawn(DOCKER, [
    `--host=unix://${SOCKET}`, '--config', configPath, ...args,
  ], { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: dockerEnv(), cwd: configPath });
  const closeState = observeChildClose(child);
  context.registerCliClose?.(closeState);
  const captured = makeCliOutputCollector();
  let timedOut = false;
  let termination;
  const terminate = () => (termination ??= terminateClient(child, closeState));
  const collect = (stream, chunk) => {
    captured.collect(stream, chunk);
    if ((captured.overflow || timedOut) && !closeState.seen) void terminate();
  };
  child.stdout.on('data', chunk => collect('stdout', chunk));
  child.stderr.on('data', chunk => collect('stderr', chunk));
  let timer;
  try {
    const result = await new Promise((resolvePromise, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        void terminate().then(confirmed => reject(new Error(`docker ${args[0]} timed out${confirmed ? '' : '; CLI termination unconfirmed'}`)));
      }, timeoutMs);
      child.once('error', reject);
      closeState.promise.then(resolvePromise);
    });
    if (timedOut) throw new Error(`docker ${args[0]} timed out`);
    if (captured.overflow) throw new Error(`docker ${args[0]} output limit`);
    if (result.code !== 0 || result.signal) throw boundedFailure(args[0], result.code,
      [captured.bytes('stdout'), captured.bytes('stderr')]);
    return captured.bytes('stdout');
  } finally {
    clearTimeout(timer);
    if (!closeState.seen) await terminate();
    child.stdout?.destroy();
    child.stderr?.destroy();
  }
}

async function waitForClientClose(child, closeState, timeoutMs, terminationOptions) {
  if (closeState.seen) return;
  let timer;
  const closed = await Promise.race([
    closeState.promise.then(() => true),
    new Promise(resolvePromise => { timer = setTimeout(() => resolvePromise(false), timeoutMs); }),
  ]);
  clearTimeout(timer);
  if (closed || await terminateClient(child, closeState, terminationOptions)) return;
  throw new Error('Docker attach CLI close unconfirmed');
}

function createRealBackend() {
  return {
    async command(args, context, timeoutMs) { return runCli(args, context, timeoutMs); },
    attach(args, context) {
      const { expectedSocketIdentity, configPath } = context;
      invariant(socketIdentity() === expectedSocketIdentity, 'local Docker socket changed');
      return nodeSpawn(DOCKER, [
        `--host=unix://${SOCKET}`, '--config', configPath, ...args,
      ], { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: dockerEnv(), cwd: configPath });
    },
  };
}

function validateImage(value) {
  const image = parseJson(value, 'invalid local image inspection');
  invariant(Array.isArray(image) && image.length === 1 && image[0].Id === IMAGE
    && image[0].Os === 'linux' && image[0].Architecture === 'arm64', 'pinned local image mismatch');
}

function validateOwnership(value, id, name) {
  invariant(value && value.Id === id && value.Name === `/${name}`
    && value.Config?.Labels?.['reviewer.fixture'] === name, 'container ownership mismatch');
}

function hasEntries(value) {
  if (Array.isArray(value)) return value.length > 0;
  if (value && typeof value === 'object') return Object.keys(value).length > 0;
  if (typeof value === 'string') return value.length > 0;
  return value !== undefined && value !== null && value !== false && value !== 0;
}

function validateInspect(value, state, id, { beforeStart = false } = {}) {
  validateOwnership(value, id, state.name);
  invariant(value.Image === IMAGE && value.Config?.Image === IMAGE, 'container image mismatch');
  const host = value.HostConfig ?? {};
  const config = value.Config ?? {};
  const limits = {
    NetworkMode: 'none', Privileged: false, ReadonlyRootfs: true, PidsLimit: 32,
    Memory: 134217728, MemorySwap: 134217728, NanoCpus: 1000000000,
    IpcMode: 'private', PublishAllPorts: false, AutoRemove: false,
  };
  invariant(Object.entries(limits).every(([key, expected]) => host[key] === expected), 'container isolation/limits mismatch');
  invariant((host.PidMode ?? '') === '' || host.PidMode === 'private', 'non-private PID namespace');
  invariant(JSON.stringify(host.CapDrop) === JSON.stringify(['ALL']) && !(host.CapAdd?.length), 'container capabilities mismatch');
  invariant(JSON.stringify(host.SecurityOpt) === JSON.stringify(['no-new-privileges:true']), 'container security options mismatch');
  invariant(JSON.stringify(host.Tmpfs) === JSON.stringify({ '/work': TMPFS }), 'container scratch policy mismatch');
  invariant(host.LogConfig?.Type === 'none' && host.RestartPolicy?.Name === 'no', 'container retention policy mismatch');
  invariant(!['Devices', 'DeviceRequests', 'VolumesFrom', 'PortBindings', 'Links'].some(key => hasEntries(host[key])),
    'additional container access');
  const mounts = value.Mounts ?? [];
  const binds = mounts.filter(mount => mount.Type === 'bind');
  invariant(mounts.every(mount => mount.Type === 'bind'
    || (mount.Type === 'tmpfs' && mount.Destination === '/work')) && binds.length === 1,
  'unexpected container mounts');
  invariant(binds[0].Source === state.fixture && binds[0].Destination === '/fixture' && binds[0].RW === false,
    'fixture mount mismatch');
  invariant(config.User === '65532:65532' && JSON.stringify(config.Entrypoint) === JSON.stringify(['python3'])
    && JSON.stringify(config.Cmd) === JSON.stringify(['-I', '-B', '/fixture/protocol-child.py', state.mode, state.sessionId]),
  'container process command mismatch');
  invariant(!(config.Env ?? []).some(item => /^(GH_|GITHUB_|ACTIONS_|ANTHROPIC_|AWS_|AZURE_|GOOGLE_|OTEL_|HOST_CANARY)/.test(item)),
    'credential environment passed to container');
  if (beforeStart) invariant(value.State?.Status === 'created' && value.State?.Running === false,
    'container started before ownership validation');
}

function readState(bytes, state, id) {
  const values = parseJson(bytes, 'invalid container inspection');
  invariant(Array.isArray(values) && values.length === 1, 'ambiguous container inspection');
  validateInspect(values[0], state, id);
  return values[0].State ?? {};
}

function checkUuidArg(args, sessionId) {
  invariant(Array.isArray(args) && args.every(value => typeof value === 'string'), 'invalid SDK command arguments');
  const at = args.indexOf('--session-id');
  invariant(at >= 0 && args.indexOf('--session-id', at + 1) < 0 && args[at + 1] === sessionId
    && isUuid(args[at + 1]), 'SDK session id mismatch');
}

function createAdapter({ root, mode, sessionId = randomUUID() }, backend) {
  invariant(MODES.has(mode), 'unsupported protocol mode');
  invariant(isUuid(sessionId), 'sessionId must be a canonical UUID');
  const { root: ownedRoot, fixture } = rootInfo(root);
  const name = `reviewer-isolation-${randomBytes(16).toString('hex')}`;
  const state = { name, fixture, mode, sessionId, ownedId: null };
  const testTimeouts = backend.real ? {} : (backend.testTimeouts ?? {});
  const attachTimeoutMs = testTimeouts.attachMs ?? COMMAND_TIMEOUT_MS;
  const attachCloseWaitMs = testTimeouts.attachCloseWaitMs ?? COMMAND_TIMEOUT_MS;
  const stopWaitMs = testTimeouts.stopWaitMs ?? 1_000;
  const terminationOptions = {
    termDelayMs: testTimeouts.clientTermMs ?? 1_000,
    deadlineMs: testTimeouts.clientDeadlineMs ?? 2_000,
  };
  let configPath;
  let daemonBefore;
  let daemonAfter;
  let creationAttempted = false;
  let spawned = false;
  let killed = false;
  let settlePromise;
  let lifecycle;
  let attachProcess;
  let attachCloseState;
  let primaryError;
  let transportBytes = 0;
  let inputBytes = 0;
  let outputBytes = 0;
  let inputEncoding = 'utf8';
  let admittedInputBytes = 0;
  let admittedFrameBytes = 0;
  let inputFrameBytes = 0;
  let outputFrameBytes = 0;
  let cidReadyResolve;
  const cidReady = new Promise(resolvePromise => { cidReadyResolve = resolvePromise; });
  let cidReadySet = false;
  let stopPromise;
  let cleanupPromise;
  let facade;
  let stdin;
  let stdout;
  const cliCloseStates = new Set();
  const context = () => ({ configPath, expectedSocketIdentity: socketId,
    registerCliClose(closeState) { cliCloseStates.add(closeState); } });
  let socketId;

  function setCidReady(value) {
    if (cidReadySet) return;
    cidReadySet = true;
    cidReadyResolve(value);
  }

  function markFailure(error) {
    if (!primaryError) primaryError = error instanceof Error ? error : new Error(String(error));
    requestTermination();
  }

  function transportError(message) {
    const error = new Error(message);
    markFailure(error);
    if (stdin && !stdin.destroyed) stdin.destroy(error);
    if (stdout && !stdout.destroyed) stdout.destroy(error);
  }

  function checkFrameBytes(value, direction) {
    const buffer = Buffer.from(value);
    if (direction === 'input') {
      inputBytes += buffer.length;
      transportBytes += buffer.length;
      for (const byte of buffer) {
        inputFrameBytes = byte === 10 ? 0 : inputFrameBytes + 1;
        if (inputFrameBytes > MAX_FRAME) { transportError('protocol input frame limit'); return false; }
      }
    } else {
      outputBytes += buffer.length;
      transportBytes += buffer.length;
      for (const byte of buffer) {
        outputFrameBytes = byte === 10 ? 0 : outputFrameBytes + 1;
        if (outputFrameBytes > MAX_FRAME) { transportError('protocol output frame limit'); return false; }
      }
    }
    if (Math.max(inputBytes, admittedInputBytes) + outputBytes > MAX_TRANSPORT) { transportError('combined protocol transport limit'); return false; }
    return true;
  }

  function admitInput(chunk, encoding, ending) {
    if (chunk === null || chunk === undefined || typeof chunk === 'function') return true;
    if (stdin.destroyed) return false;
    let buffer;
    try {
      if (typeof chunk === 'string') {
        const selectedEncoding = typeof encoding === 'string' ? encoding : inputEncoding;
        if (!Buffer.isEncoding(selectedEncoding)) return true; // Let Writable report invalid encodings.
        // shortcut: malformed hex/base64 may be overestimated; refine if the SDK uses these encodings.
        if (Buffer.byteLength(chunk, selectedEncoding) + admittedInputBytes + outputBytes > MAX_TRANSPORT) {
          transportError(stdin.writableEnded ? 'write after end' : 'combined protocol transport limit');
          return false;
        }
        buffer = Buffer.from(chunk, selectedEncoding);
      } else if (ArrayBuffer.isView(chunk)) buffer = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      else return true; // Let Writable reject unsupported input types.
    } catch { return true; } // Let Writable report invalid encodings or detached buffers.
    if (stdin.writableEnded) {
      if (!ending || buffer.length > 0) { transportError('write after end'); return false; }
      return true;
    }
    admittedInputBytes += buffer.length;
    if (admittedInputBytes + outputBytes > MAX_TRANSPORT) {
      transportError('combined protocol transport limit');
      return false;
    }
    for (const byte of buffer) {
      admittedFrameBytes = byte === 10 ? 0 : admittedFrameBytes + 1;
      if (admittedFrameBytes > MAX_FRAME) { transportError('protocol input frame limit'); return false; }
    }
    return true;
  }

  function docker(args, timeoutMs) {
    assertDockerOperation(args, state);
    if (backend.real) invariant(socketIdentity() === socketId, 'local Docker socket changed');
    return backend.command(args, context(), timeoutMs);
  }

  async function daemonIdentity() {
    const value = (await docker(['info', '--format', '{{.ID}}'])).toString('utf8').trim();
    invariant(/^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/.test(value), 'invalid Docker daemon identity');
    return value;
  }

  async function inspect(id) {
    return readState(await docker(['inspect', id]), state, id);
  }

  async function recoverOwned() {
    const ids = listIds(await docker([
      'container', 'ls', '--all', '--no-trunc', '--filter', `name=^/${name}$`, '--format', '{{.ID}}',
    ]));
    if (ids.length === 0) return null;
    invariant(ids.length === 1, 'ambiguous owned-container recovery');
    const id = ids[0];
    const values = parseJson(await docker(['inspect', id]), 'invalid recovery inspection');
    invariant(Array.isArray(values) && values.length === 1, 'ambiguous recovery inspection');
    validateOwnership(values[0], id, name);
    state.ownedId = id;
    setCidReady(id);
    validateInspect(values[0], state, id, { beforeStart: true });
    return id;
  }

  async function waitStopped(id, timeoutMs = CONTAINER_WAIT_MS) {
    const deadline = Date.now() + timeoutMs;
    let last;
    while (Date.now() <= deadline) {
      last = await inspect(id);
      if (last.Running === false && last.Pid === 0) {
        invariant(Number.isInteger(last.ExitCode) && last.ExitCode >= 0, 'container exit code unavailable');
        return last.ExitCode;
      }
      await new Promise(resolvePromise => setTimeout(resolvePromise, 100));
    }
    return null;
  }

  async function stopOwned(id) {
    const first = await inspect(id);
    if (first.Running !== true) return;
    try { await docker(['kill', '--signal=SIGTERM', id]); } catch { /* verify before deciding whether to escalate */ }
    if (await waitStopped(id, stopWaitMs) !== null) return;
    await docker(['kill', '--signal=SIGKILL', id]);
    invariant(await waitStopped(id, stopWaitMs) !== null, 'owned container did not stop');
  }

  function requestTermination() {
    killed = true;
    if (!stopPromise) {
      stopPromise = cidReady.then(async id => {
        if (id) await stopOwned(id);
      });
      stopPromise.catch(error => { if (!primaryError) primaryError = error; });
    }
    return stopPromise;
  }

  async function cleanupOwned(id) {
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = (async () => {
      const failures = [];
      let exitCode;
      try {
        const current = await inspect(id);
        if (current.Running) await stopOwned(id);
      } catch (error) { failures.push(`state: ${error.message}`); }
      try {
        const stateAfterStop = await inspect(id);
        invariant(stateAfterStop.Running === false && stateAfterStop.Pid === 0
          && Number.isInteger(stateAfterStop.ExitCode) && stateAfterStop.ExitCode >= 0,
        'container process namespace did not stop');
        exitCode = stateAfterStop.ExitCode;
      } catch (error) { failures.push(`stopped proof: ${error.message}`); }
      try { await docker(['rm', '--force', id]); }
      catch (error) { failures.push(`remove: ${error.message}`); }
      for (const [label, args] of [
        ['id absence', ['container', 'ls', '--all', '--no-trunc', '--filter', `id=${id}`, '--format', '{{.ID}}']],
        ['name absence', ['container', 'ls', '--all', '--no-trunc', '--filter', `name=^/${name}$`, '--format', '{{.ID}}']],
      ]) {
        try { invariant(listIds(await docker(args)).length === 0, `container ${label} unconfirmed`); }
        catch (error) { failures.push(`${label}: ${error.message}`); }
      }
      invariant(failures.length === 0, `container cleanup incomplete: ${failures.join('; ')}`);
      return exitCode;
    })();
    return cleanupPromise;
  }

  function flushStdin() {
    if (!attachProcess?.stdin) return;
    attachProcess.stdin.on('error', error => transportError(`Docker attach stdin: ${error.message}`));
    if (stdin._pendingWrite) {
      const pending = stdin._pendingWrite;
      stdin._pendingWrite = null;
      attachProcess.stdin.write(pending.chunk, pending.callback);
    }
    if (stdin._pendingFinal) {
      const done = stdin._pendingFinal;
      stdin._pendingFinal = null;
      attachProcess.stdin.end(done);
    }
  }

  function buildFacade() {
    facade = new EventEmitter();
    stdout = new PassThrough({ highWaterMark: 64 * 1024 });
    stdin = new Writable({
      highWaterMark: 64 * 1024,
      write(chunk, _encoding, callback) {
        if (!checkFrameBytes(chunk, 'input')) { callback(primaryError); return; }
        if (!attachProcess?.stdin) {
          stdin._pendingWrite = { chunk: Buffer.from(chunk), callback };
          return;
        }
        attachProcess.stdin.write(chunk, callback);
      },
      destroy(error, callback) {
        const pendingWrite = stdin._pendingWrite;
        const pendingFinal = stdin._pendingFinal;
        stdin._pendingWrite = null;
        stdin._pendingFinal = null;
        const pendingError = error ?? new Error('adapter closed before stdin attach');
        pendingWrite?.callback(pendingError);
        pendingFinal?.(pendingError);
        callback(error);
      },
      final(callback) {
        if (!attachProcess?.stdin) stdin._pendingFinal = callback;
        else attachProcess.stdin.end(callback);
      },
    });
    const setDefaultEncoding = stdin.setDefaultEncoding.bind(stdin);
    stdin.setDefaultEncoding = encoding => {
      const result = setDefaultEncoding(encoding);
      inputEncoding = encoding;
      return result;
    };
    const write = stdin.write.bind(stdin);
    const end = stdin.end.bind(stdin);
    // Reserve before Node queues chunks; _write records bytes exactly once when processing them.
    stdin.write = (chunk, encoding, callback) => {
      const admitted = admitInput(chunk, encoding, false);
      return write(admitted ? chunk : Buffer.alloc(0), encoding, callback);
    };
    stdin.end = (chunk, encoding, callback) => {
      const admitted = admitInput(chunk, encoding, true);
      return end(admitted ? chunk : null, encoding, callback);
    };
    stdin.on('error', error => markFailure(error));
    stdout.on('error', error => markFailure(error));
    stdout.on('drain', () => attachProcess?.stdout?.resume());
    Object.defineProperties(facade, {
      stdin: { enumerable: true, value: stdin },
      stdout: { enumerable: true, value: stdout },
      stdinWritable: { enumerable: true, value: stdin },
      stdoutReadable: { enumerable: true, value: stdout },
      killed: { enumerable: true, get: () => killed },
      exitCode: { enumerable: true, get: () => facade._exitCode ?? null },
    });
    facade._exitCode = null;
    facade.kill = signal => {
      if (facade._exitEmitted) return false;
      void signal; // SDK signals never cross into Docker; the owned container gets bounded TERM/KILL.
      void requestTermination().catch(error => markFailure(error));
      return true;
    };
    return facade;
  }

  function attachToContainer(id) {
    return new Promise((resolvePromise, reject) => {
      let child;
      try {
        const args = ['start', '--attach', '--interactive', id];
        assertDockerOperation(args, state);
        if (backend.real) invariant(socketIdentity() === socketId, 'local Docker socket changed');
        child = backend.attach(args, context());
        attachProcess = child;
      } catch (error) { reject(error); return; }
      const closeState = observeChildClose(child);
      attachCloseState = closeState;
      cliCloseStates.add(closeState);
      let settled = false;
      let total = 0;
      let diagnosticBytes = 0;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        void terminateClient(child, closeState, terminationOptions).then(closed => reject(new Error(
          closed ? 'Docker attach timed out' : 'Docker attach timeout; CLI close unconfirmed')));
      }, attachTimeoutMs);
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else resolvePromise(result);
      };
      child.once('error', error => finish(error));
      closeState.promise.then(result => finish(null, result));
      child.stdout?.on('data', chunk => {
        const bytes = Buffer.from(chunk);
        total += bytes.length;
        const bounded = checkFrameBytes(bytes, 'output');
        if (!bounded || total + diagnosticBytes > MAX_OUTPUT) {
          transportError('Docker attach output limit');
          void terminateClient(child, closeState, terminationOptions);
          return;
        }
        if (!stdout.write(bytes)) child.stdout.pause();
      });
      child.stdout?.on('error', error => finish(error));
      child.stderr?.on('data', chunk => {
        // Diagnostics from the daemon are bounded and never become SDK protocol frames.
        diagnosticBytes += Buffer.byteLength(chunk);
        if (total + diagnosticBytes > MAX_OUTPUT) {
          transportError('Docker attach diagnostic limit');
          void terminateClient(child, closeState, terminationOptions);
        }
      });
      child.stderr?.on('error', error => finish(error));
      flushStdin();
    });
  }

  async function runLifecycle() {
    let attachedExit;
    let failure;
    let finalExitCode = null;
    const cleanupErrors = [];
    configPath = mkdtempSync(join(ownedRoot, '.docker-config-'));
    try {
      const configInfo = lstatSync(configPath);
      invariant(realpathSync(configPath) === configPath && configInfo.isDirectory()
        && configInfo.uid === process.getuid() && (configInfo.mode & 0o777) === 0o700,
      'fresh Docker config directory ownership/mode mismatch');
      socketId = backend.real ? socketIdentity() : 'fake-control-plane';
      daemonBefore = await daemonIdentity();
      validateImage(await docker(['image', 'inspect', IMAGE]));
      const existing = listIds(await docker([
        'container', 'ls', '--all', '--no-trunc', '--filter', `name=^/${name}$`, '--format', '{{.ID}}',
      ]));
      invariant(existing.length === 0, 'owned container name already exists');
      if (killed) throw primaryError ?? new Error('adapter terminated before container creation');
      invariant(createHash('sha256').update(readFileSync(join(fixture, 'protocol-child.py'))).digest('hex') === FIXTURE_SHA256,
        'protocol child source changed before creation');
      creationAttempted = true;
      const created = (await docker(createArgs(name, fixture, mode, sessionId))).toString('utf8').trim();
      invariant(isContainerId(created), 'invalid created container identity');
      const createInspection = parseJson(await docker(['inspect', created]), 'invalid created container inspection');
      invariant(Array.isArray(createInspection) && createInspection.length === 1, 'ambiguous created container inspection');
      validateOwnership(createInspection[0], created, name);
      state.ownedId = created;
      setCidReady(created);
      validateInspect(createInspection[0], state, created, { beforeStart: true });
      if (killed) throw new Error('adapter terminated during container creation');
      attachedExit = await attachToContainer(created);
      stdout.end();
      const current = await inspect(created);
      if (current.Running) failure ??= new Error('Docker attach exited while the owned container remained running');
      if (!failure) {
        invariant(current.Running === false && current.Pid === 0 && Number.isInteger(current.ExitCode)
          && current.ExitCode >= 0, 'container exit status unavailable');
        invariant(Number.isInteger(attachedExit.code) && attachedExit.code === current.ExitCode,
          'Docker attach exit code disagrees with container exit status');
        finalExitCode = current.ExitCode;
        if (attachedExit.signal) failure = new Error('Docker attach client was signaled before completion');
      }
    } catch (error) {
      failure ??= primaryError ?? (error instanceof Error ? error : new Error(String(error)));
    } finally {
      const cleanupStage = async (label, action) => {
        try { return await action(); }
        catch (error) {
          cleanupErrors.push(`${label}: ${error instanceof Error ? error.message : String(error)}`);
          return undefined;
        }
      };
      if (creationAttempted && !state.ownedId) {
        const recovered = await cleanupStage('recovery', recoverOwned);
        if (recovered !== undefined) {
          setCidReady(recovered);
          if (!recovered) {
            await cleanupStage('create absence proof', async () => {
              const remaining = listIds(await docker([
                'container', 'ls', '--all', '--no-trunc', '--filter', `name=^/${name}$`, '--format', '{{.ID}}',
              ]));
              invariant(remaining.length === 0, 'owned container absence unconfirmed after failed create');
            });
          }
        }
      }
      if (!cidReadySet) setCidReady(state.ownedId);
      if (state.ownedId) {
        if (stopPromise) await cleanupStage('termination request', () => stopPromise);
        if (killed || failure) {
          await cleanupStage('direct owned stop', () => stopOwned(state.ownedId));
        }
        if (attachProcess && attachCloseState && !attachCloseState.seen) {
          await cleanupStage('attach CLI close', () => waitForClientClose(
            attachProcess, attachCloseState, attachCloseWaitMs, terminationOptions));
        }
        const cleanedExitCode = await cleanupStage('owned container cleanup', () => cleanupOwned(state.ownedId));
        if (cleanedExitCode !== undefined) finalExitCode = cleanedExitCode;
      }
      await cleanupStage('daemon readback', async () => {
        if (daemonBefore !== undefined) {
          daemonAfter = await daemonIdentity();
          invariant(daemonAfter === daemonBefore, 'Docker daemon identity changed');
        }
      });
      const attachCloseConfirmed = [...cliCloseStates].every(closeState => closeState.seen)
        && (!attachProcess || attachCloseState?.seen === true);
      if (configPath && attachCloseConfirmed) {
        await cleanupStage('config cleanup', async () => rmSync(configPath, { recursive: true, force: false }));
      } else if (configPath) {
        cleanupErrors.push('config retained because Docker CLI close was unconfirmed');
      }
      // Let native stream finish/error callbacks run before forced teardown.
      await new Promise(resolvePromise => process.nextTick(resolvePromise));
      if (stdin && !stdin.destroyed) stdin.destroy();
      if (stdout && !stdout.destroyed && !stdout.writableEnded) stdout.end();
    }
    failure ??= primaryError;
    if (cleanupErrors.length) {
      const cleanupFailure = new Error(`cleanup incomplete: ${cleanupErrors.join('; ')}`);
      failure = failure
        ? new AggregateError([failure, cleanupFailure], `${failure.message}; ${cleanupFailure.message}`)
        : cleanupFailure;
    }
    if (failure) throw failure;
    invariant(finalExitCode !== null, 'container exit code was not proven');
    return { name, containerId: state.ownedId, daemonBefore, daemonAfter, exitCode: finalExitCode,
      transportBytes: { input: inputBytes, output: outputBytes, total: transportBytes } };
  }

  function spawn(options) {
    invariant(!spawned, 'SDK process facade can only be spawned once');
    invariant(options && options.command === join(ownedRoot, 'NEVER-EXECUTED-claude')
      && options.cwd === ownedRoot, 'unexpected SDK command or working directory');
    checkUuidArg(options.args, sessionId);
    spawned = true;
    buildFacade();
    if (options.signal) {
      invariant(typeof options.signal.addEventListener === 'function', 'invalid SDK abort signal');
      // SDK controls its grace period; the signal is never forwarded to Docker or the container.
    }
    queueMicrotask(() => {
      if (!lifecycle) {
        lifecycle = runLifecycle().then(result => {
          facade._exitCode = result.exitCode;
          facade._exitEmitted = true;
          facade.emit('exit', result.exitCode, null);
          return result;
        }, error => {
          facade._exitCode = 1;
          facade._exitEmitted = true;
          if (!stdout.destroyed && !stdout.writableEnded) stdout.end();
          facade.emit('error', error);
          facade.emit('exit', 1, null);
          throw error;
        });
        lifecycle.catch(() => {});
      }
    });
    return facade;
  }

  function settle() {
    if (!spawned) return Promise.reject(new Error('SDK process was not spawned'));
    if (!settlePromise) {
      settlePromise = new Promise(resolvePromise => queueMicrotask(resolvePromise)).then(() => lifecycle);
    }
    return settlePromise;
  }

  return { spawn, settle };
}

function isAbsolute(value) {
  return typeof value === 'string' && value.startsWith('/');
}

export function createDockerAdapter(options) {
  return createAdapter(options, { ...createRealBackend(), real: true });
}

// Explicit offline-only seam for the sibling unit fixture; production callers use the fixed backend above.
export function createDockerAdapterWithFakeBackend(options, fakeBackend) {
  invariant(fakeBackend && typeof fakeBackend.command === 'function' && typeof fakeBackend.attach === 'function',
    'fake backend must implement command and attach');
  return createAdapter(options, { ...fakeBackend, real: false });
}

// Boolean-only probe for the offline test; it never exposes or invokes the captured process primitive.
export function spawnBindingProbeForTest(expected) {
  return { capturedMatches: nodeSpawn === expected, importedMatches: importedSpawn === expected };
}
