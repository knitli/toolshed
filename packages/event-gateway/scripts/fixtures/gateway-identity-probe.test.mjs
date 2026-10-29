import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = (await readFile(new URL('./gateway-identity-probe.mjs', import.meta.url), 'utf8'))
  .replace("const PROBE_EXPIRES_AT = '__PROBE_EXPIRES_AT__';", 'const PROBE_EXPIRES_AT = 2_000_000_000;');
const contextVm = vm.createContext({
  Response, Request, Headers, TextEncoder, URL, globalThis: { URL }, Date, Math, Number, Array, Object, RegExp,
});
const module = new vm.SourceTextModule(source, { context: contextVm });
await module.link((specifier) => {
  assert.equal(specifier, 'cloudflare:workers');
  return new vm.SyntheticModule(['WorkerEntrypoint'], function () {
    this.setExport('WorkerEntrypoint', class { });
  }, { context: contextVm });
});
await module.evaluate();
const { handleGatewayIdentityProbe, GatewayMiddleware, default: worker } = module.namespace;
const expiry = 2_000_000_000;
const required = '8a56504f-da96-41ee-8089-3713e2070e6f';
const request = (url = 'https://event-native-probe-83fc4c309835.knitli.workers.dev/probe', method = 'GET') => new Request(url, { method });
const context = (passed = [required]) => ({ devicePosture: async () => ({ checks: { passed } }) });

async function readResponse(response) {
  return { status: response.status, body: await response.text(), headers: Object.fromEntries(response.headers) };
}

test('valid posture returns only the fixed probe body and controlled headers', async () => {
  const response = await handleGatewayIdentityProbe(request(), context(), expiry, 1_900_000_000_000);
  assert.deepEqual(await readResponse(response), {
    status: 200,
    body: 'knitli-probe-v1\n',
    headers: { 'cache-control': 'no-store', 'x-knitli-probe-gateway': 'v1', 'x-knitli-probe-host': '1' },
  });
});

test('a valid guest posture response without the required check reports host 0', async () => {
  const response = await handleGatewayIdentityProbe(request(), context([]), expiry, 1_900_000_000_000);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-knitli-probe-host'), '0');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal((await handleGatewayIdentityProbe(request(), context(['11111111-1111-4111-8111-111111111111']), expiry, 1_900_000_000_000)).headers.get('x-knitli-probe-host'), '0');
});

test('invalid request target never reads trusted context', async () => {
  for (const req of [
    request('https://example.com/probe'),
    request('https://event-native-probe-83fc4c309835.knitli.workers.dev/probe?x=1'),
    request(undefined, 'POST'),
  ]) {
    const response = await handleGatewayIdentityProbe(req, { devicePosture() { throw new Error('must not run'); } }, expiry, 1_900_000_000_000);
    assert.equal(response.status, 404);
  }
});

test('missing, malformed, mismatched, and throwing trusted context fail closed', async () => {
  const cases = [
    undefined,
    {},
    { devicePosture: async () => ({ checks: { passed: ['not-a-uuid'] } }) },
    { host: 'attacker.example', devicePosture: async () => ({ checks: { passed: [] } }) },
    { sni: 'attacker.example', devicePosture: async () => ({ checks: { passed: [] } }) },
    { uri: '/other', devicePosture: async () => ({ checks: { passed: [] } }) },
    { devicePosture: async () => { throw new Error('private context secret'); } },
    Object.defineProperty({}, 'host', { get() { throw new Error('private host metadata'); } }),
  ];
  for (const trusted of cases) {
    const result = await readResponse(await handleGatewayIdentityProbe(request(), trusted, expiry, 1_900_000_000_000));
    assert.equal(result.status, 503);
    assert.equal(result.body, '');
    assert.deepEqual(result.headers, { 'cache-control': 'no-store' });
  }
});

test('expiry and invalid configured expiry are handled before context lookup', async () => {
  let calls = 0;
  const unread = { devicePosture() { calls++; throw new Error('must not run'); } };
  assert.equal((await handleGatewayIdentityProbe(request(), unread, expiry, expiry * 1000)).status, 410);
  assert.equal((await handleGatewayIdentityProbe(request(), unread, '__PROBE_EXPIRES_AT__', 1)).status, 503);
  assert.equal(calls, 0);
});

test('the entrypoint delegates to the pure helper and the default route stays closed', async () => {
  const instance = new GatewayMiddleware();
  const result = await readResponse(await instance.handle(request(), context(), expiry));
  assert.equal(result.status, 200);
  const fallback = await worker.fetch(request());
  assert.equal(fallback.status, 404);
  assert.equal(fallback.headers.get('cache-control'), 'no-store');
});
