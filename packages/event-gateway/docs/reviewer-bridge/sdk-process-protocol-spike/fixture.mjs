// Offline protocol fixture: no native process, Docker, provider, or usable credential.
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import net from 'node:net';

let phase = 'startup';
let completed = false;
let diagnosticCount = 0;
function diagnostic(event, details = {}) {
  if (++diagnosticCount <= 100) console.error(JSON.stringify({ fixtureDiagnostic: true, event, phase, ...details }));
}
function mark(value) { phase = value; diagnostic('phase'); }
// A synthetic stream has no OS I/O handle. Keep this fixture alive while awaiting
// the real SDK's unref'ed cleanup timers, with an independent hard deadline.
const fixtureDeadline = setTimeout(() => {
  diagnostic('deadline');
  process.exitCode = 1;
  process.exit(1);
}, 15000);
process.once('exit', code => {
  if (!completed) diagnostic('premature-exit', { code });
});
try {
mark('guards-and-containment');
const counters = { subprocess: 0, fetch: 0, customSpawn: 0 };
for (const key of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  childProcess[key] = () => { counters.subprocess++; throw new Error('offline subprocess guard'); };
}
globalThis.fetch = () => { counters.fetch++; throw new Error('offline fetch guard'); };
syncBuiltinESMExports();
// Causal controls use guards only: never execute a native child or network request.
assert.throws(() => childProcess.spawn('/not-executed', []), /offline subprocess guard/);
assert.throws(() => globalThis.fetch('https://invalid.invalid'), /offline fetch guard/);
const baseline = { ...counters };

const scratch = process.env.HOME;
assert(scratch && process.env.TMPDIR === join(scratch, 'tmp'));
assert.equal(process.env.CLAUDE_CONFIG_DIR, join(scratch, 'claude'));
assert.equal(process.env.XDG_CONFIG_HOME, join(scratch, 'xdg'));
for (const name of Object.keys(process.env)) {
  assert(!/^(GH_|GITHUB_|ACTIONS_|ANTHROPIC_|AWS_|AZURE_|GOOGLE_|OTEL_)/.test(name));
  assert(!/^(DEBUG|DEBUG_SDK|NODE_OPTIONS|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)$/i.test(name));
}
assert.throws(() => readFileSync(process.argv[2]), error => ['EPERM', 'EACCES'].includes(error.code));
writeFileSync(join(scratch, 'write-probe'), 'owned scratch');
assert.equal(readFileSync(join(scratch, 'write-probe'), 'utf8'), 'owned scratch');
// This loopback attempt must be denied by the OS before it reaches a listener.
await new Promise((resolve, reject) => {
  const socket = net.connect({ host: '127.0.0.1', port: 9 });
  const timer = setTimeout(() => { socket.destroy(); reject(new Error('network denial probe timed out')); }, 1000);
  socket.once('connect', () => { clearTimeout(timer); socket.destroy(); reject(new Error('network unexpectedly allowed')); });
  socket.once('error', error => {
    clearTimeout(timer);
    try { assert(['EPERM', 'EACCES'].includes(error.code), `network denial was ${error.code}`); resolve(); }
    catch (failure) { reject(failure); }
  });
});

const hash = (value, algorithm = 'sha256') => createHash(algorithm).update(value).digest('hex');
assert.equal(hash(readFileSync(new URL('./frozen/sdk.mjs', import.meta.url))), '7b3577a1078660a3ec43471e6738c730ca1b172070ddcf3f9a9384bcb68bd3ca');
// Dynamic imports deliberately occur after environment checks and API guards.
mark('sdk-import');
const sdk = await import('./frozen/sdk.mjs');
mark('driver-import');
const { runReview, validateSnapshot } = await import('./frozen/reviewer-completion-driver.mjs');
const content = 'Synthetic café fixture.\n';
const buffer = Buffer.from(content);
const diff = 'Synthetic added-file diff; no real source.\n';
const manifest = {
  schema: 'knitli-reviewer-input:v1', repository: { id: 1, fullName: 'fixture/offline' }, pullRequest: 1,
  base: { repositoryId: 1, repository: 'fixture/offline', sha: '1'.repeat(40) },
  head: { repositoryId: 1, repository: 'fixture/offline', sha: '2'.repeat(40) },
  description: { title: 'Offline protocol fixture', body: 'Synthetic data only' }, mergeBase: '1'.repeat(40),
  scope: { kind: 'regular-utf8-text', comparison: 'merge-base-to-head', renameDetection: false,
    submodules: 'refused', historyDepth: 1, sourceExecution: false },
  files: [{ path: 'fixture.txt', status: 'added', before: null,
    after: { oid: hash(Buffer.concat([Buffer.from(`blob ${buffer.length}\0`), buffer]), 'sha1'),
      mode: '100644', bytes: buffer.length, sha256: hash(buffer) } }],
  diff: { bytes: Buffer.byteLength(diff), sha256: hash(diff) },
};
const bytes = Buffer.from(JSON.stringify({ manifest, manifestSha256: hash(JSON.stringify(manifest)),
  files: [{ path: 'fixture.txt', before: null, after: content }], diff }));
const digest = hash(bytes);
validateSnapshot(bytes, digest);
const model = 'claude-sonnet-4-6';

class FakeProcess extends EventEmitter {
  constructor(options, mode) {
    super();
    this.mode = mode;
    this.options = options;
    this.stdout = new PassThrough();
    this.killed = false;
    this.exitCode = null;
    this.exited = false;
    this.events = [];
    this.pending = new Map();
    this.request = 0;
    this.receivedBytes = 0;
    this.served = [];
    let input = '';
    this.stdin = new Writable({
      write: (chunk, encoding, done) => {
        try {
          this.receivedBytes += chunk.length;
          assert(this.receivedBytes <= 256 * 1024, 'fake input bound');
          input += chunk.toString();
          while (input.includes('\n')) {
            const end = input.indexOf('\n');
            const line = input.slice(0, end); input = input.slice(end + 1);
            if (line) queueMicrotask(() => this.receive(JSON.parse(line)));
          }
          done();
        } catch (error) { done(error); }
      },
      final: done => {
        this.record('stdin-eof');
        done();
        if (this.mode !== 'abort') queueMicrotask(() => this.finish(0, null));
      },
    });
    options.signal.addEventListener('abort', () => this.record('forwarded-abort'));
  }
  record(name) { this.events.push({ name, at: performance.now() }); diagnostic('fake-process', { mode: this.mode, name }); }
  emitFrame(value) {
    const raw = JSON.stringify(value) + '\n';
    assert(Buffer.byteLength(raw) <= 64 * 1024, 'fake output frame bound');
    // Exercise the actual SDK's newline framing across separate writes.
    const cut = Math.floor(raw.length / 2);
    this.stdout.write(raw.slice(0, cut));
    this.stdout.write(raw.slice(cut));
  }
  receive(message) {
    try {
      if (message.type === 'control_request' && message.request.subtype === 'initialize') {
        assert.deepEqual(message.request.sdkMcpServers, ['frozen']);
        this.emitFrame({ type: 'control_response', response: { subtype: 'success', request_id: message.request_id, response: {} } });
        this.initialized = true;
      } else if (message.type === 'user') {
        assert(this.initialized, 'initialize control request must precede prompt');
        this.work().catch(error => { this.emit('error', error); this.finish(1, null); });
      } else if (message.type === 'control_response') {
        const pending = this.pending.get(message.response.request_id);
        assert(pending, 'unexpected control response');
        this.pending.delete(message.response.request_id);
        clearTimeout(pending.timer);
        assert.equal(message.response.subtype, 'success');
        pending.resolve(message.response.response.mcp_response);
      } else {
        assert.fail(`unexpected SDK frame ${message.type}`);
      }
    } catch (error) { this.emit('error', error); this.finish(1, null); }
  }
  mcp(message) {
    const request_id = `offline-${++this.request}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(request_id); reject(new Error('fake MCP response timeout')); }, 1000);
      this.pending.set(request_id, { resolve, reject, timer });
      this.emitFrame({ type: 'control_request', request_id, request: { subtype: 'mcp_message', server_name: 'frozen', message } });
    });
  }
  async work() {
    const args = this.options.args;
    const session = args[args.indexOf('--session-id') + 1];
    this.emitFrame({ type: 'system', subtype: 'init', session_id: session, model, tools: ['mcp__frozen__read_next'] });
    if (this.mode === 'abort') return;
    if (this.mode === 'eof') { this.finish(0, null); return; }
    const initialized = await this.mcp({ jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'offline-fake-process', version: '1' } } });
    assert(initialized.result && !initialized.error, 'real MCP initialize');
    await this.mcp({ jsonrpc: '2.0', method: 'notifications/initialized' });
    if (this.mode === 'success') {
      let remaining;
      do {
        const response = await this.mcp({ jsonrpc: '2.0', id: 2 + this.served.length, method: 'tools/call',
          params: { name: 'read_next', arguments: {} } });
        assert(response.result && !response.error && !response.result.isError, 'real MCP tool result');
        const page = JSON.parse(response.result.content[0].text);
        assert.equal(page.snapshotSha256, digest);
        this.served.push(page);
        remaining = page.remaining;
      } while (remaining);
    }
    this.emitFrame({ type: 'result', subtype: 'success', is_error: false, terminal_reason: 'completed',
      permission_denials: [], session_id: session, uuid: randomUUID(), modelUsage: { [model]: {} },
      result: JSON.stringify({ schema: 'knitli-review-report:v1', snapshotSha256: digest, findings: [],
        limitations: ['Synthetic in-memory process; not a provider review'] }) });
  }
  finish(code, signal) {
    if (this.exited) return;
    this.exited = true;
    this.exitCode = code;
    this.record('exit');
    this.stdout.end();
    this.emit('exit', code, signal);
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(new Error('fake process exited')); }
    this.pending.clear();
  }
  kill(signal) {
    this.record(`kill:${signal}`);
    this.killed = true;
    this.finish(null, signal);
    return true;
  }
}

const results = [];
for (const mode of ['success', 'early-terminal', 'eof', 'abort']) {
  mark(`case:${mode}`);
  let fake;
  const promise = runReview({ bytes, expectedSha256: digest, sdk, runtimeDirectory: scratch,
    binaryPath: join(scratch, 'NEVER-EXECUTED-claude'), apiKey: 'offline-synthetic-not-a-credential', model,
    timeoutMs: mode === 'abort' ? 100 : 3000,
    spawnClaudeCodeProcess: options => {
      counters.customSpawn++;
      diagnostic('custom-spawn', { mode });
      assert.equal(options.command, join(scratch, 'NEVER-EXECUTED-claude'));
      assert.equal(options.cwd, scratch);
      assert(options.signal instanceof AbortSignal);
      assert.equal(options.env.ANTHROPIC_API_KEY, 'offline-synthetic-not-a-credential');
      assert(options.args.includes('--bare') && options.args.includes('--no-chrome'));
      return fake = new FakeProcess(options, mode);
    },
  });
  if (mode === 'success') {
    const result = await promise;
    assert.equal(result.coverage.pages, result.coverage.requiredPages);
    assert.equal(result.coverage.pages, 3);
    assert.deepEqual(fake.served.map(page => page.unit), ['manifest', 'diff', 'file:0:after']);
    assert(fake.exited && fake.exitCode === 0);
  } else {
    await assert.rejects(promise, mode === 'early-terminal' ? /refused: incomplete/ : mode === 'eof' ? /refused: missing_terminal/ : /refused: timeout/);
  }
  if (mode === 'abort') {
    await new Promise(resolve => setTimeout(resolve, 2200));
    const eof = fake.events.find(event => event.name === 'stdin-eof');
    const kill = fake.events.find(event => event.name === 'kill:SIGTERM');
    const forwarded = fake.events.find(event => event.name === 'forwarded-abort');
    assert(eof && kill && forwarded, 'SDK EOF/kill/forwarded-abort events required');
    assert(kill.at - eof.at >= 1800, 'SDK grace period preserved');
    assert(forwarded.at >= kill.at, 'forwarded abort follows graceful-close phase');
    assert(fake.exited);
  }
  diagnostic('case-passed', { mode });
  results.push({ mode, pages: fake.served.length, events: fake.events.map(event => event.name), passed: true });
}
assert.equal(counters.subprocess, baseline.subprocess, 'unexpected native/keychain subprocess');
assert.equal(counters.fetch, baseline.fetch, 'unexpected fetch');
assert.equal(counters.customSpawn, 4);
mark('complete');
completed = true;
console.log(JSON.stringify({ status: 'PASS', scope: 'Actual pinned SDK with in-memory fake process only',
  cases: results, containment: { outsideScratchReadDenied: true, loopbackNetworkDenied: true, scratchWrite: true },
  guards: { causalSubprocessRefusals: baseline.subprocess, causalFetchRefusals: baseline.fetch,
    unexpectedSubprocessCalls: counters.subprocess - baseline.subprocess, unexpectedFetchCalls: counters.fetch - baseline.fetch },
  nativeExecuted: false, dockerExecuted: false, providerCalled: false }));

} catch (error) {
  diagnostic('failure', { name: String(error?.name).slice(0, 80), message: String(error?.message).slice(0, 800) });
  process.exitCode = 1;
} finally {
  clearTimeout(fixtureDeadline);
}
