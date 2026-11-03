import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('./device-profile-rollback.mjs', import.meta.url), 'utf8');
const API_URL = 'https://api.cloudflare.com/client/v4/accounts/5def525918a785eeda6decf66cf6b99b/devices/policy/425f0bec-8230-42a6-814d-0d0ea8e0a452';
const PROFILE_ID = '425f0bec-8230-42a6-814d-0d0ea8e0a452';
const NAME = 'event-proxy-canary-d2c4a7d2';
const MATCH = 'identity.email == "adam@knitli.com" and os.name == "mac" and os.version == "27.0.1"';
const TOKEN = 'test-secret-token-7e2c';
const START = 1_900_000_000_000;

async function harness(sourceText = source) {
  const state = { now: START, calls: [], networkCalls: [], fetch: async () => { throw new Error('unexpected fetch'); }, timeoutSignals: [], uuidCounter: 0 };
  state.workerFetch = (url, init = {}) => {
    state.calls.push([url, init]);
    const redirect = init.redirect ?? 'follow';
    if (redirect !== 'follow' && redirect !== 'manual') throw new TypeError('Invalid redirect mode');
    state.networkCalls.push([url, init]);
    return state.fetch(url, init);
  };
  class FakeDate extends Date { static now() { return state.now; } }
  class FakeAbortSignal { static timeout(ms) { const signal = { timeoutMs: ms }; state.timeoutSignals.push(signal); return signal; } }
  const context = vm.createContext({
    Response, Headers, TextEncoder, TextDecoder, URL, Date: FakeDate, Number, Object, Array, Set, JSON, Uint8Array, AbortSignal: FakeAbortSignal,
    fetch: (...args) => state.workerFetch(...args),
    crypto: { randomUUID: () => `00000000-0000-4000-8000-${String(++state.uuidCounter).padStart(12, '0')}` },
  });
  const module = new vm.SourceTextModule(sourceText, { context });
  await module.link((specifier) => { throw new Error(`unexpected import ${specifier}`); });
  await module.evaluate();
  return { state, worker: module.namespace.default };
}

function enabledProfile(overrides = {}) {
  return {
    policy_id: PROFILE_ID, name: NAME, match: MATCH, enabled: true,
    service_mode_v2: { mode: 'proxy', port: 40000 }, tunnel_protocol: 'masque',
    ...overrides,
  };
}
function disabledProfile(overrides = {}) { return { ...enabledProfile(), enabled: false, ...overrides }; }
function jsonResponse(result, status = 200, envelope = {}) {
  return new Response(JSON.stringify({ success: true, result, ...envelope }), { status, headers: { 'content-type': 'application/json' } });
}
function env(options = {}) {
  const { lease, kv, ...extra } = options;
  const token = Object.hasOwn(options, 'token') ? options.token : TOKEN;
  const writes = [];
  const STATUS = kv ?? { async put(key, value) { writes.push([key, value]); } };
  return { env: { CF_TOKEN: token, LEASE_SPEC: lease, STATUS, ...extra }, writes };
}
function lease(now = START, rollbackAtMs = now + 10_000, tokenExpiresAtMs = now + 15 * 60_000) {
  return JSON.stringify({ issuedAtMs: now, rollbackAtMs, tokenExpiresAtMs });
}
async function schedule(worker, environment, scheduledTime = START) {
  await worker.scheduled({ scheduledTime }, environment);
}
function commitKey(value) {
  const scheduleKey = Number.isSafeInteger(value.scheduledAtMs) ? value.scheduledAtMs : 'invalid';
  return `commits/${scheduleKey}/${value.observationId}`;
}
function receipt(writes, key) {
  const entry = [...writes].reverse().find(([k]) => key ? k === key : k.startsWith('commits/'));
  assert.ok(entry, `missing KV write ${key ?? 'commits/<schedule>/<id>'}`);
  return JSON.parse(entry[1]);
}
function assertReceiptShape(value, status) {
  assert.deepEqual(Object.keys(value).sort(), ['apiCalls', 'disabledVerified', 'kind', 'observationId', 'observedAtMs', 'profileId', 'rollbackAtMs', 'scheduledAtMs', 'status'].concat(value.failCode ? ['failCode'] : []).sort());
  assert.match(value.observationId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(value.kind, 'device_profile_rollback');
  assert.equal(value.profileId, PROFILE_ID);
  assert.equal(value.status, status);
  assert.equal(typeof value.observedAtMs, 'number');
  assert.equal(typeof value.apiCalls, 'number');
  assert.equal(typeof value.disabledVerified, 'boolean');
  if (value.failCode) assert.ok(['invalid_schedule', 'invalid_lease', 'api_network', 'api_status', 'api_body_large', 'api_body_invalid', 'api_body_read', 'api_shape', 'profile_drift', 'service_drift'].includes(value.failCode));
}

async function arm(h, { due = true, getProfile = enabledProfile(), patchProfile = disabledProfile(), readback = disabledProfile(), firstStatus = 200, patchStatus = 200, afterStatus = 200 } = {}) {
  const responses = [
    firstStatus === 404 ? new Response(null, { status: 404 }) : jsonResponse(getProfile, firstStatus),
    ...(getProfile?.enabled === false || firstStatus === 404 ? [] : [jsonResponse(patchProfile, patchStatus), jsonResponse(readback, afterStatus)]),
  ];
  h.state.fetch = async (url, init) => {
    const response = responses.shift();
    if (!response) throw new Error('unexpected extra API call');
    return response;
  };
  const rollbackAt = START + 10_000;
  const data = env({ lease: lease(START, rollbackAt) });
  h.state.now = due ? rollbackAt : rollbackAt - 1;
  return { data, rollbackAt };
}

test('scheduled-only worker has no HTTP fetch handler', async () => {
  const { worker } = await harness();
  assert.equal(typeof worker.scheduled, 'function');
  assert.equal('fetch' in worker, false);
});

test('unarmed run records status without API calls', async () => {
  const h = await harness();
  const data = env({ token: null, lease: undefined });
  await schedule(h.worker, data.env);
  const result = receipt(data.writes);
  assertReceiptShape(result, 'unarmed');
  assert.equal(result.apiCalls, 0);
  assert.equal(result.rollbackAtMs, null);
  assert.equal(h.state.calls.length, 0);
});

test('partial, malformed, and unsafe leases fail closed without API calls', async () => {
  const cases = [
    { token: TOKEN, lease: undefined },
    { token: null, lease: lease() },
    { token: TOKEN, lease: '{broken' },
    { token: TOKEN, lease: JSON.stringify({ issuedAtMs: START, rollbackAtMs: START + 10_000, tokenExpiresAtMs: START + 900_000, extra: true }) },
    { token: TOKEN, lease: JSON.stringify({ issuedAtMs: START + 31_000, rollbackAtMs: START + 40_000, tokenExpiresAtMs: START + 900_000 }) },
    { token: TOKEN, lease: JSON.stringify({ issuedAtMs: START, rollbackAtMs: START + 12 * 60_000 + 1, tokenExpiresAtMs: START + 20 * 60_000 }) },
    { token: TOKEN, lease: JSON.stringify({ issuedAtMs: START, rollbackAtMs: START + 10_000, tokenExpiresAtMs: START + 129_999 }) },
    { token: TOKEN, lease: JSON.stringify({ issuedAtMs: START, rollbackAtMs: START + 10_000, tokenExpiresAtMs: START + 20 * 60_000 + 1 }) },
    { token: TOKEN, lease: JSON.stringify({ issuedAtMs: START + 0.5, rollbackAtMs: START + 10_000, tokenExpiresAtMs: START + 900_000 }) },
  ];
  for (const item of cases) {
    const h = await harness();
    const data = env(item);
    await schedule(h.worker, data.env);
    assertReceiptShape(receipt(data.writes), 'invalid_lease');
    assert.equal(h.state.calls.length, 0);
  }
});

test('before deadline is armed and exactly at deadline attempts cleanup', async () => {
  const h = await harness();
  const before = env({ lease: lease(START, START + 10_000) });
  h.state.now = START + 9_999;
  await schedule(h.worker, before.env, START + 9_999);
  assertReceiptShape(receipt(before.writes), 'armed');
  assert.equal(h.state.calls.length, 0);

  const due = env({ lease: lease(START, START + 10_000) });
  h.state.now = START + 10_000;
  h.state.fetch = async () => jsonResponse(disabledProfile());
  await schedule(h.worker, due.env, START + 10_000);
  assertReceiptShape(receipt(due.writes), 'disabled');
  assert.equal(h.state.calls.length, 1);
  assert.equal(h.state.calls[0][1].method, 'GET');
});

test('all API attempts use the fixed profile, manual redirects, bounded timeout, and PATCH only enabled false', async () => {
  const h = await harness();
  const { data } = await arm(h);
  await schedule(h.worker, data.env, START);
  assertReceiptShape(receipt(data.writes), 'disabled');
  assert.deepEqual(h.state.calls.map(([url]) => url), [API_URL, API_URL, API_URL]);
  assert.deepEqual(h.state.calls.map(([, init]) => init.method), ['GET', 'PATCH', 'GET']);
  assert.equal(h.state.networkCalls.length, 3);
  for (const [, init] of h.state.calls) {
    assert.equal(init.redirect, 'manual');
    assert.equal(init.signal.timeoutMs, 5_000);
    assert.equal(init.headers.authorization, `Bearer ${TOKEN}`);
  }
  assert.deepEqual(JSON.parse(h.state.calls[1][1].body), { enabled: false });
  assert.equal(receipt(data.writes).apiCalls, 3);
  assert.equal(receipt(data.writes).disabledVerified, true);
  const committed = receipt(data.writes);
  const observationKey = `observations/${committed.observationId}`;
  assert.equal(receipt(data.writes, observationKey).scheduledAtMs, START);
  assert.deepEqual(data.writes.map(([key]) => key), [observationKey, commitKey(committed)]);
  assert.equal(data.writes[0][1], data.writes[1][1]);
});

test('pre-cleanup mutable drift still disables the pinned profile', async (t) => {
  const variations = [
    ['wrong policy_id refuses mutation', { policy_id: 'attacker' }, 'cleanup_failed', ['GET']],
    ['missing enabled boolean refuses mutation', { enabled: 'true' }, 'cleanup_failed', ['GET']],
    ['wrong name does not block rollback', { name: 'other' }, 'disabled', ['GET', 'PATCH', 'GET']],
    ['wrong match does not block rollback', { match: 'true' }, 'disabled', ['GET', 'PATCH', 'GET']],
    ['non-string match does not block rollback', { match: false }, 'disabled', ['GET', 'PATCH', 'GET']],
    ['wrong proxy mode does not block rollback', { service_mode_v2: { mode: 'warp', port: 40000 } }, 'disabled', ['GET', 'PATCH', 'GET']],
    ['wrong port does not block rollback', { service_mode_v2: { mode: 'proxy', port: 40001 } }, 'disabled', ['GET', 'PATCH', 'GET']],
    ['wrong tunnel protocol does not block rollback', { tunnel_protocol: 'wireguard' }, 'disabled', ['GET', 'PATCH', 'GET']],
  ];
  for (const [label, change, status, methods] of variations) {
    await t.test(label, async () => {
      const h = await harness();
      const profile = enabledProfile(change);
      const { data } = await arm(h, { getProfile: profile });
      await schedule(h.worker, data.env, START);
      const result = receipt(data.writes);
      assertReceiptShape(result, status);
      assert.equal(result.disabledVerified, status === 'disabled');
      assert.deepEqual(h.state.calls.map(([, init]) => init.method), methods);
      if (status === 'disabled') assert.deepEqual(JSON.parse(h.state.calls[1][1].body), { enabled: false });
    });
  }
});

test('already-disabled matching profile is idempotently verified without PATCH', async () => {
  const h = await harness();
  const data = env({ lease: lease(START - 10_000, START) });
  h.state.now = START;
  h.state.fetch = async () => jsonResponse(disabledProfile());
  await schedule(h.worker, data.env, START);
  assertReceiptShape(receipt(data.writes), 'disabled');
  assert.equal(receipt(data.writes).disabledVerified, true);
  assert.equal(h.state.calls.length, 1);
});

test('GET 404 records absent without mutation', async () => {
  const h = await harness();
  const { data } = await arm(h, { firstStatus: 404 });
  await schedule(h.worker, data.env, START);
  assertReceiptShape(receipt(data.writes), 'absent');
  assert.equal(receipt(data.writes).disabledVerified, false);
  assert.equal(h.state.calls.length, 1);
});

test('Workers fetch contract rejects redirect error before dispatch', async () => {
  const h = await harness();
  assert.throws(() => h.state.workerFetch(API_URL, { method: 'GET', redirect: 'error' }), TypeError);
  assert.equal(h.state.calls.length, 1);
  assert.equal(h.state.networkCalls.length, 0);
});

test('3xx response is canceled and rejected before API continuation', async () => {
  const h = await harness();
  const data = env({ lease: lease(START - 10_000, START) });
  let cancelled = false;
  h.state.now = START;
  h.state.fetch = async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
    status: 302, headers: { location: API_URL },
  });
  await schedule(h.worker, data.env, START);
  const result = receipt(data.writes);
  assertReceiptShape(result, 'cleanup_failed');
  assert.equal(result.failCode, 'api_status');
  assert.equal(result.apiCalls, 1);
  assert.equal(result.disabledVerified, false);
  assert.equal(h.state.calls.length, 1);
  assert.equal(h.state.networkCalls.length, 1);
  assert.deepEqual(h.state.networkCalls.map(([, init]) => init.method), ['GET']);
  assert.equal(cancelled, true);
});

test('malformed API envelopes fail closed', async (t) => {
  for (const [label, response] of [
    ['success false', new Response(JSON.stringify({ success: false, result: enabledProfile() }), { status: 200 })],
    ['missing result', new Response(JSON.stringify({ success: true }), { status: 200 })],
    ['invalid JSON', new Response('{', { status: 200 })],
  ]) {
    await t.test(label, async () => {
      const h = await harness();
      const data = env({ lease: lease(START - 10_000, START) });
      h.state.now = START;
      h.state.fetch = async () => response.clone();
      await schedule(h.worker, data.env, START);
      assertReceiptShape(receipt(data.writes), 'cleanup_failed');
      assert.equal(receipt(data.writes).disabledVerified, false);
      assert.equal(h.state.calls.length, 1);
    });
  }
});

test('oversized API response is cancelled and fails closed', async () => {
  const h = await harness();
  const data = env({ lease: lease(START - 10_000, START) });
  let cancelled = false;
  h.state.now = START;
  h.state.fetch = async () => {
    const chunks = [new Uint8Array(16 * 1024), new Uint8Array([1])];
    return { status: 200, body: { getReader: () => ({
      async read() { return chunks.length ? { done: false, value: chunks.shift() } : { done: true }; },
      async cancel() { cancelled = true; },
    }) } };
  };
  await schedule(h.worker, data.env, START);
  assertReceiptShape(receipt(data.writes), 'cleanup_failed');
  assert.equal(receipt(data.writes).failCode, 'api_body_large');
  assert.equal(cancelled, true);
  assert.equal(h.state.calls.length, 1);
});

test('PATCH response and final GET validate pinned identity and disabled boolean', async (t) => {
  const cases = [
    ['patch response wrong policy_id', { ...disabledProfile(), policy_id: 'wrong' }, disabledProfile(), 'cleanup_failed', ['GET', 'PATCH']],
    ['patch response nonboolean enabled', { ...disabledProfile(), enabled: 'false' }, disabledProfile(), 'cleanup_failed', ['GET', 'PATCH']],
    ['patch response mutable name drift', { ...disabledProfile(), name: 'changed' }, disabledProfile(), 'disabled', ['GET', 'PATCH', 'GET']],
    ['patch response mutable match drift', { ...disabledProfile(), match: 'true' }, disabledProfile(), 'disabled', ['GET', 'PATCH', 'GET']],
    ['patch response mutable service drift', { ...disabledProfile(), service_mode_v2: { mode: 'warp', port: 40001 } }, disabledProfile(), 'disabled', ['GET', 'PATCH', 'GET']],
    ['final GET still enabled', disabledProfile(), enabledProfile(), 'cleanup_failed', ['GET', 'PATCH', 'GET']],
    ['final GET profile absent', disabledProfile(), null, 'cleanup_failed', ['GET', 'PATCH', 'GET']],
    ['final GET wrong policy_id', disabledProfile(), { ...disabledProfile(), policy_id: 'wrong' }, 'cleanup_failed', ['GET', 'PATCH', 'GET']],
    ['final GET nonboolean enabled', disabledProfile(), { ...disabledProfile(), enabled: 'false' }, 'cleanup_failed', ['GET', 'PATCH', 'GET']],
    ['final GET mutable name drift is allowed', disabledProfile(), { ...disabledProfile(), name: 'changed' }, 'disabled', ['GET', 'PATCH', 'GET']],
    ['final GET mutable match drift is allowed', disabledProfile(), { ...disabledProfile(), match: false }, 'disabled', ['GET', 'PATCH', 'GET']],
    ['final GET mutable service drift is allowed', disabledProfile(), { ...disabledProfile(), tunnel_protocol: 'wireguard' }, 'disabled', ['GET', 'PATCH', 'GET']],
  ];
  for (const [label, patch, readback, status, expectedMethods] of cases) {
    await t.test(label, async () => {
      const h = await harness();
      const { data } = await arm(h, { patchProfile: patch, readback, afterStatus: label === 'final GET profile absent' ? 404 : 200 });
      await schedule(h.worker, data.env, START);
      const result = receipt(data.writes);
      assertReceiptShape(result, status);
      assert.equal(result.disabledVerified, status === 'disabled');
      assert.deepEqual(h.state.calls.map(([, init]) => init.method), expectedMethods);
    });
  }
});

test('expired credential is still attempted and authorization failure is not success', async () => {
  const h = await harness();
  const data = env({ lease: lease(START, START + 10_000, START + 12 * 60_000) });
  h.state.now = START + 13 * 60_000;
  h.state.fetch = async () => new Response(JSON.stringify({ success: false, errors: [{ message: 'unauthorized' }] }), { status: 403 });
  await schedule(h.worker, data.env, START + 13 * 60_000);
  assertReceiptShape(receipt(data.writes), 'cleanup_failed');
  assert.equal(receipt(data.writes).apiCalls, 1);
  assert.equal(h.state.calls.length, 1);
});

test('network error containing credentials is redacted and a later cron retries', async () => {
  const h = await harness();
  const data = env({ lease: lease(START - 10_000, START) });
  h.state.now = START;
  h.state.fetch = async () => { throw new Error(`fetch ${TOKEN} failed for adam@knitli.com`); };
  await schedule(h.worker, data.env, START);
  const failed = receipt(data.writes);
  assertReceiptShape(failed, 'cleanup_failed');
  assert.equal(failed.failCode, 'api_network');
  assert.equal(JSON.stringify(failed).includes(TOKEN), false);
  assert.equal(JSON.stringify(failed).includes('adam@knitli.com'), false);
  h.state.calls.length = 0;
  h.state.fetch = async () => jsonResponse(disabledProfile());
  await schedule(h.worker, data.env, START);
  assertReceiptShape(receipt(data.writes), 'disabled');
  assert.equal(h.state.calls.length, 1);
});

test('duplicate scheduled times get distinct observations and exact per-run commits', async () => {
  const h = await harness();
  h.state.now = START;
  let getCount = 0;
  h.state.fetch = async (url, init) => init.method === 'GET'
    ? jsonResponse(getCount++ % 2 === 0 ? enabledProfile() : disabledProfile())
    : jsonResponse(disabledProfile());
  const entries = new Map();
  const kv = { async put(key, value) { entries.set(key, value); } };
  const data = env({ lease: lease(START - 10_000, START), kv });

  await schedule(h.worker, data.env, START);
  const commits = () => [...entries].filter(([key]) => key.startsWith('commits/'));
  const first = JSON.parse(commits()[0][1]);
  const firstKey = `observations/${first.observationId}`;
  assert.equal(entries.get(firstKey), commits()[0][1]);
  await schedule(h.worker, data.env, START);
  const second = JSON.parse(commits()[1][1]);
  const secondKey = `observations/${second.observationId}`;

  assert.equal(first.scheduledAtMs, START);
  assert.equal(second.scheduledAtMs, START);
  assert.notEqual(first.observationId, second.observationId);
  assert.notEqual(firstKey, secondKey);
  assert.equal(entries.get(firstKey), JSON.stringify(first));
  assert.equal(entries.get(secondKey), commits()[1][1]);
  assert.equal(entries.get(secondKey), JSON.stringify(second));
  assert.deepEqual(commits().map(([key]) => key), [commitKey(first), commitKey(second)]);
  assert.equal(entries.has('latest'), false);
  assert.equal(h.state.calls.length, 6);
});

test('overlapping runs retain separate observation and commit pairs', async () => {
  const h = await harness();
  h.state.now = START + 30_000;
  const entries = new Map();
  const kv = { async put(key, value) { entries.set(key, value); } };
  const data = env({ lease: lease(START, START + 10_000), kv });
  let releaseOldGet;
  let markOldGetStarted;
  const oldGetStarted = new Promise((resolve) => { markOldGetStarted = resolve; });
  const oldGetGate = new Promise((resolve) => { releaseOldGet = resolve; });
  let getCount = 0;
  h.state.fetch = async (url, init) => {
    if (init.method === 'PATCH') return jsonResponse(disabledProfile());
    const index = getCount++;
    if (index === 0) {
      markOldGetStarted();
      await oldGetGate;
      return jsonResponse(enabledProfile());
    }
    return jsonResponse(index === 1 ? enabledProfile() : disabledProfile());
  };

  const oldScheduledAt = START + 10_000;
  const newScheduledAt = START + 20_000;
  const oldRun = schedule(h.worker, data.env, oldScheduledAt);
  await oldGetStarted;
  await schedule(h.worker, data.env, newScheduledAt);
  const commits = () => [...entries].filter(([key]) => key.startsWith('commits/'));
  const newer = JSON.parse(commits()[0][1]);
  const newerKey = `observations/${newer.observationId}`;
  assert.equal(newer.scheduledAtMs, newScheduledAt);
  assert.equal(entries.get(commits()[0][0]), entries.get(newerKey));

  releaseOldGet();
  await oldRun;
  const older = JSON.parse(commits()[1][1]);
  const olderKey = `observations/${older.observationId}`;
  assert.equal(older.scheduledAtMs, oldScheduledAt);
  assert.notEqual(older.observationId, newer.observationId);
  assert.equal(entries.get(commits()[1][0]), entries.get(olderKey));
  assert.equal(entries.get(olderKey), JSON.stringify(older));
  assert.equal(entries.get(newerKey), JSON.stringify(newer));
  assert.deepEqual(commits().map(([key]) => key), [commitKey(newer), commitKey(older)]);
  assert.equal(entries.has('latest'), false);
  assert.equal(h.state.calls.length, 6);
});

test('observation write failure preserves prior commits while due cleanup completes', async () => {
  const h = await harness();
  h.state.now = START;
  let getCount = 0;
  h.state.fetch = async (url, init) => init.method === 'GET'
    ? jsonResponse(getCount++ === 0 ? enabledProfile() : disabledProfile())
    : jsonResponse(disabledProfile());
  const keys = [];
  const priorCommitKey = 'commits/previous/previous-id';
  const values = new Map([[priorCommitKey, 'previous receipt']]);
  const kv = { async put(key, value) { keys.push(key); if (key.startsWith('observations/')) throw new Error('observation storage unavailable'); values.set(key, value); } };
  const data = env({ lease: lease(START - 10_000, START), kv });
  await assert.rejects(schedule(h.worker, data.env, START), /receipt_write_failed/);
  assert.deepEqual(h.state.calls.map(([, init]) => init.method), ['GET', 'PATCH', 'GET']);
  assert.equal(keys.length, 1);
  assert.match(keys[0], /^observations\/[0-9a-f-]{36}$/);
  assert.equal(values.get(priorCommitKey), 'previous receipt');
  assert.equal(values.has('latest'), false);
});

test('commit write failure leaves the completed observation available', async () => {
  const h = await harness();
  h.state.now = START;
  let getCount = 0;
  h.state.fetch = async (url, init) => init.method === 'GET'
    ? jsonResponse(getCount++ === 0 ? enabledProfile() : disabledProfile())
    : jsonResponse(disabledProfile());
  const keys = [];
  const priorCommitKey = 'commits/previous/previous-id';
  const values = new Map([[priorCommitKey, 'previous receipt']]);
  const kv = { async put(key, value) { keys.push(key); if (key.startsWith('commits/')) throw new Error('commit storage unavailable'); values.set(key, value); } };
  const data = env({ lease: lease(START - 10_000, START), kv });
  await assert.rejects(schedule(h.worker, data.env, START), /receipt_write_failed/);
  assert.deepEqual(h.state.calls.map(([, init]) => init.method), ['GET', 'PATCH', 'GET']);
  assert.equal(keys.length, 2);
  assert.match(keys[0], /^observations\/[0-9a-f-]{36}$/);
  const observation = JSON.parse(values.get(keys[0]));
  assert.equal(keys[1], commitKey(observation));
  assert.equal(values.get(priorCommitKey), 'previous receipt');
  assert.equal(values.has('latest'), false);
  assert.equal(observation.observationId, keys[0].slice('observations/'.length));
  assert.equal(observation.status, 'disabled');
});

test('invalid scheduled time is rejected without API calls', async () => {
  const h = await harness();
  for (const scheduledTime of [-1, START + 30_001, START - 24 * 60 * 60_000 - 1]) {
    const data = env({ lease: lease(START - 10_000, START) });
    h.state.now = START;
    await schedule(h.worker, data.env, scheduledTime);
    const result = receipt(data.writes);
    assertReceiptShape(result, 'invalid_schedule');
    assert.equal(result.scheduledAtMs, null);
    assert.equal(receipt(data.writes, `observations/${result.observationId}`).observationId, result.observationId);
    assert.deepEqual(data.writes.map(([key]) => key), [`observations/${result.observationId}`, commitKey(result)]);
    assert.equal(h.state.calls.length, 0);
  }
  const missing = env({ lease: lease(START - 10_000, START) });
  await h.worker.scheduled({}, missing.env);
  const missingResult = receipt(missing.writes);
  assertReceiptShape(missingResult, 'invalid_schedule');
  assert.equal(missingResult.scheduledAtMs, null);
  assert.equal(receipt(missing.writes, `observations/${missingResult.observationId}`).observationId, missingResult.observationId);
  assert.deepEqual(missing.writes.map(([key]) => key), [`observations/${missingResult.observationId}`, commitKey(missingResult)]);
  assert.equal(h.state.calls.length, 0);
});
