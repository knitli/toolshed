// Private, unexecuted integration candidate. Only the frozen adapter may spawn Docker.
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, lstatSync, realpathSync } from 'node:fs';
import net from 'node:net';
import { join } from 'node:path';
// This import must capture spawn by value before guards synchronize builtin exports.
import { createDockerAdapter } from '/private/tmp/reviewer-docker-sdk-adapter-20261017/adapter.mjs';

const counters = { subprocess: 0, fetch: 0, customSpawn: 0 };
const guard = () => { counters.subprocess++; throw new Error('non-adapter subprocess refused'); };
for (const key of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[key] = guard;
childProcess.ChildProcess = class GuardedChildProcess { constructor() { guard(); } };
globalThis.fetch = () => { counters.fetch++; throw new Error('fetch refused'); };
syncBuiltinESMExports();
let records = 0;
const diagnostic = (event, details = {}) => {
  if (++records <= 80) console.error(JSON.stringify({ event, ...details }));
};
const hash = (value, algorithm = 'sha256') => createHash(algorithm).update(value).digest('hex');
const scratch = process.argv[2];
const outcomes = [];
const containment = { outsideScratchReadDenied: false, scratchWrite: false, ipv4Denied: false, ipv6Denied: false, otherUnixDenied: false };
function requireNetworkDenial(options) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let done = false;
    const finish = error => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(() => finish(new Error('containment probe timeout')), 1000);
    socket.once('connect', () => finish(new Error('containment probe unexpectedly connected')));
    socket.on('error', error => {
      finish(['EPERM', 'EACCES'].includes(error.code) ? null : new Error(`containment denial was ${error.code}`));
    });
    try { socket.connect(options); }
    catch (error) { finish(['EPERM', 'EACCES'].includes(error.code) ? null : error); }
  });
}

let activeMode = 'preflight';
try {
  assert(scratch && scratch === process.env.HOME && realpathSync(scratch) === scratch);
  const info = lstatSync(scratch);
  assert(info.isDirectory() && info.uid === process.getuid() && (info.mode & 0o777) === 0o700);
  assert.equal(process.env.TMPDIR, join(scratch, 'tmp'));
  for (const key of Object.keys(process.env)) {
    assert(!/^(GH_|GITHUB_|ACTIONS_|ANTHROPIC_|AWS_|AZURE_|GOOGLE_|OTEL_|DOCKER_)/.test(key));
    assert(!/^(NODE_OPTIONS|NODE_PATH|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|DEBUG|DEBUG_SDK)$/i.test(key));
  }
  assert.throws(() => childProcess.spawn('/NEVER-EXECUTED'), /non-adapter subprocess refused/);
  assert.throws(() => globalThis.fetch('https://invalid.invalid'), /fetch refused/);
  const baseline = { ...counters };
  const canaryPath = process.argv[3];
  const deniedSocketPath = process.argv[4];
  const fixtureRoot = '/private/tmp/reviewer-docker-sdk-integration-20261017';
  assert(typeof canaryPath === 'string' && /^canary-[a-f0-9]{32}$/.test(canaryPath.slice(fixtureRoot.length + 1)) && canaryPath.startsWith(`${fixtureRoot}/`));
  assert(typeof deniedSocketPath === 'string' && /^forbidden-[a-f0-9]{32}\.sock$/.test(deniedSocketPath.slice(fixtureRoot.length + 1)) && deniedSocketPath.startsWith(`${fixtureRoot}/`));
  assert.throws(() => readFileSync(canaryPath), error => ['EPERM', 'EACCES'].includes(error.code));
  containment.outsideScratchReadDenied = true;
  const positivePath = join(scratch, 'containment-write-probe');
  writeFileSync(positivePath, 'owned scratch positive control', { flag: 'wx', mode: 0o600 });
  assert.equal(readFileSync(positivePath, 'utf8'), 'owned scratch positive control');
  containment.scratchWrite = true;
  await requireNetworkDenial({ host: '127.0.0.1', port: 9, family: 4 });
  containment.ipv4Denied = true;
  await requireNetworkDenial({ host: '::1', port: 9, family: 6 });
  containment.ipv6Denied = true;
  await requireNetworkDenial({ path: deniedSocketPath });
  containment.otherUnixDenied = true;
  diagnostic('containment-probes-passed', containment);

  const sdkPath = '/private/tmp/reviewer-sdk-process-protocol-20261017/frozen/sdk.mjs';
  const driverPath = '/private/tmp/reviewer-sdk-process-protocol-20261017/frozen/reviewer-completion-driver.mjs';
  assert.equal(hash(readFileSync(sdkPath)), '7b3577a1078660a3ec43471e6738c730ca1b172070ddcf3f9a9384bcb68bd3ca');
  assert.equal(hash(readFileSync(driverPath)), '4ff7c66588d16f33f67ca89670b5efe4540170bf5708d28cea7b19a2d0298eee');
  const sdk = await import(sdkPath);
  const { runReview, validateSnapshot } = await import(driverPath);
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


for (const mode of ['success', 'early-terminal', 'eof', 'abort']) {
  activeMode = mode;
  diagnostic('case-start', { mode });
  const sessionId = randomUUID();
  const adapter = createDockerAdapter({ root: scratch, mode, sessionId });
  let result, reviewError, settlement, settleError, initialized = false, spawned = false, observationError;
  const events = [];
  try {
    result = await runReview({ bytes, expectedSha256: digest, sdk, runtimeDirectory: scratch,
      binaryPath: join(scratch, 'NEVER-EXECUTED-claude'), apiKey: 'offline-synthetic-not-a-credential',
      model, sessionId, timeoutMs: mode === 'abort' ? 8000 : 12000,
      spawnClaudeCodeProcess(options) {
        counters.customSpawn++;
        assert(!spawned, 'one SDK process per case');
        assert.equal(options.env.ANTHROPIC_API_KEY, 'offline-synthetic-not-a-credential');
        const facade = adapter.spawn(options);
        spawned = true;
        let partial = '';
        facade.stdout.on('data', chunk => {
          try {
          partial += chunk.toString('utf8');
          assert(Buffer.byteLength(partial) <= 128 * 1024, 'observation bound');
          while (partial.includes('\n')) {
            const end = partial.indexOf('\n');
            const line = partial.slice(0, end); partial = partial.slice(end + 1);
            if (!line) continue;
            const message = JSON.parse(line);
            if (message.type === 'system' && message.subtype === 'init') initialized = true;
          }
          } catch (error) { observationError ??= error; partial = ''; }
        });
        facade.stdin.once('finish', () => events.push({ event: 'stdin-finish', at: performance.now() }));
        const kill = facade.kill.bind(facade);
        facade.kill = signal => { events.push({ event: 'kill', signal, at: performance.now() }); return kill(signal); };
        return facade;
      },
    });
  } catch (error) { reviewError = error; }
  finally {
    // Never classify a review outcome until authoritative adapter cleanup settles.
    try { settlement = await adapter.settle(); }
    catch (error) { settleError = error; }
  }
  const summary = { mode, initialized, spawned, settlement: settlement ?? null,
    reviewError: reviewError ? String(reviewError.message).slice(0, 1000) : null,
    settleError: settleError ? String(settleError.message).slice(0, 1000) : null, events };
  outcomes.push(summary);
  diagnostic('case-settled', summary);
  assert.ifError(settleError);
  assert.ifError(observationError);
  assert(spawned && initialized && settlement?.containerId && settlement.daemonBefore === settlement.daemonAfter);
  if (mode === 'success') {
    assert.ifError(reviewError);
    assert.equal(result.status, 'completed');
    assert.equal(result.coverage.pages, 3);
    assert.equal(result.coverage.pages, result.coverage.requiredPages);
    assert.equal(settlement.exitCode, 0);
  } else {
    assert(reviewError, 'negative case must reject');
    assert.match(reviewError.message, mode === 'early-terminal' ? /refused: incomplete/ : mode === 'eof' ? /refused: missing_terminal/ : /refused: timeout/);
    if (mode === 'abort') {
      const eof = events.find(event => event.event === 'stdin-finish');
      const killed = events.find(event => event.event === 'kill');
      assert(eof && killed && killed.at - eof.at >= 1800, 'SDK grace and owned kill required');
    }
  }
  summary.passed = true;
}
assert.equal(counters.subprocess, baseline.subprocess, 'SDK attempted forbidden subprocess');
assert.equal(counters.fetch, baseline.fetch, 'SDK attempted fetch');
assert.equal(counters.customSpawn, 4);
console.log(JSON.stringify({ status: 'PASS', scope: 'Actual SDK plus fixed Docker protocol fixture only',
  sdkVersion: '0.3.209', cases: outcomes, guards: counters, containment,
  nativeClaudeExecuted: false, providerCalled: false, dockerExecuted: true,
  independentDockerAbsenceReadback: 'required from root after launch' }));
} catch (error) {
  console.error(JSON.stringify({ status: 'FAIL', mode: activeMode,
    message: String(error?.message).slice(0, 2000), cases: outcomes, containment,
    independentDockerAbsenceReadback: 'required even on failure or launcher termination' }));
  process.exitCode = 1;
}
