// Disposable loopback transport; production HTTP parsing, proofs and authority stay in workerd.
import { createServer } from 'node:http';
import { createHash, randomUUID, timingSafeEqual, webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFile, readdir, realpath } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { join, resolve, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

console.log = (...args) => console.error(...args); // stdout is the private parent handshake.
const cloud = await realpath(process.env.FIXTURE_CLOUD_SOURCE);
const rootRequire = createRequire(join(cloud, 'package.json'));
const messagingRequire = createRequire(join(cloud, 'packages/gatekeeper-messaging/package.json'));
const { build } = rootRequire('esbuild');
const validateRpc = messagingRequire('capnweb-validate/esbuild');
const miniflareRequire = createRequire(join(resolve(process.env.FIXTURE_MINIFLARE), 'package.json'));
const alias = {
  'fixture-event-runtime': join(cloud, 'packages/event-runtime/src'),
  'fixture-messaging': join(cloud, 'packages/gatekeeper-messaging/src'),
};
for (const directory of await readdir(join(cloud, 'packages'), { withFileTypes: true })) {
  if (!directory.isDirectory()) continue;
  try {
    const path = join(cloud, 'packages', directory.name);
    const pkg = JSON.parse(await readFile(join(path, 'package.json'), 'utf8'));
    if (pkg.name) {
      alias[pkg.name] = path;
      for (const [subpath, target] of Object.entries(pkg.exports ?? {})) {
        const imported = typeof target === 'string' ? target : target.import;
        if (subpath.startsWith('./') && typeof imported === 'string') alias[`${pkg.name}/${subpath.slice(2)}`] = join(path, imported);
      }
    }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
const fixtureDirectory = dirname(fileURLToPath(import.meta.url));
const inputName = path => {
  const absolute = resolve(path);
  const dependency = absolute.split('/node_modules/.pnpm/')[1];
  if (dependency) return `dependency/${dependency}`;
  const local = relative(cloud, absolute);
  if (!local.startsWith('../')) return `cloud/${local}`;
  const fixture = relative(fixtureDirectory, absolute);
  if (!fixture.startsWith('../')) return `fixture/${fixture}`;
  throw new Error(`unapproved input location: ${absolute}`);
};
const bundle = await build({
  entryPoints: [fileURLToPath(new URL('./messaging-workerd-worker.ts', import.meta.url))],
  alias, write: false, metafile: true, minifyWhitespace: true, bundle: true, format: 'esm', platform: 'neutral', target: 'es2022',
  external: ['cloudflare:workers', 'node:*'], logLevel: 'warning',
  plugins: [validateRpc({ cwd: join(cloud, 'packages/gatekeeper-messaging'), tsconfig: join(cloud, 'packages/gatekeeper-messaging/tsconfig.json') })],
});
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const approvedHash = (actual, expected) => typeof expected === 'string' && actual.length === expected.length
  && timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
const inputs = Object.fromEntries(await Promise.all(Object.keys(bundle.metafile.inputs).map(async path => [inputName(path), sha256(await readFile(path))])));
const expected = JSON.parse(await readFile(new URL('./messaging-workerd-inputs.json', import.meta.url), 'utf8'));
if (Object.keys(inputs).length !== Object.keys(expected.inputs).length
    || Object.entries(inputs).some(([path, hash]) => !approvedHash(hash, expected.inputs[path]))) {
  throw new Error('unapproved compiled input set or hash');
}
// Pin the bytes actually executed, including plugin output, against source-read races.
if (!approvedHash(sha256(bundle.outputFiles[0].contents), expected.bundleSha256)) {
  throw new Error('unapproved compiled bundle');
}
let crash = null;
let activeClaim = null;
const requireActiveClaim = () => {
  if (!activeClaim || activeClaim.socket.destroyed || activeClaim.response.destroyed
      || activeClaim.response.headersSent || activeClaim.response.writableEnded)
    throw new Error('claim ended before crash injection');
  crash.requestOpenAtKill = true;
};
if (process.env.FIXTURE_ABRUPT_CLOUD_CRASH === 'reviewed') {
  const pins = JSON.parse(await readFile(new URL('./messaging-workerd-runtime.json', import.meta.url), 'utf8'));
  const workerd = miniflareRequire('workerd');
  if (process.platform !== pins.platform || process.arch !== pins.arch
      || process.env.MINIFLARE_WORKERD_PATH !== undefined
      || miniflareRequire('miniflare/package.json').version !== pins.miniflareVersion
      || workerd.version !== pins.workerdVersion
      || !approvedHash(sha256(await readFile(miniflareRequire.resolve('miniflare'))), pins.miniflareModuleSha256)
      || !approvedHash(sha256(await readFile(workerd.default)), pins.workerdSha256))
    throw new Error('unapproved crash runtime');
  const { OwnedWorkerdCrash } = await import('./messaging-workerd-crash.mjs');
  crash = new OwnedWorkerdCrash({ binary: workerd.default, binarySha256: pins.workerdSha256,
    persistencePath: join(process.env.HOME, 'durable-objects'),
    afterKill: evidence => writeFileSync(join(process.env.HOME, 'cloud-crash-injected'),
      JSON.stringify(evidence), { flag: 'wx', mode: 0o600, flush: true }) });
  crash.install();
}
// Capture the owned ChildProcess before Miniflare imports node:child_process.
const { Miniflare, convertV4MiniflareOptions } = miniflareRequire('miniflare');
const ed25519 = async () => {
  const pair = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  return {
    pair,
    publicJwk: await webcrypto.subtle.exportKey('jwk', pair.publicKey),
    privateJwk: await webcrypto.subtle.exportKey('jwk', pair.privateKey),
    pkcs8: Buffer.from(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey)),
  };
};
const agent = await ed25519(), transport = await ed25519(), receipt = await ed25519();
const access = await webcrypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
const accessJwk = { ...await webcrypto.subtle.exportKey('jwk', access.publicKey), kid: 'fixture-access', alg: 'RS256', use: 'sig' };
const thumbprint = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: agent.publicJwk.x })).digest('base64url');
const jwt = async (header, payload, key, algorithm) => {
  const data = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  return `${data}.${Buffer.from(await webcrypto.subtle.sign(algorithm, key, Buffer.from(data))).toString('base64url')}`;
};
const now = Math.floor(Date.now() / 1000);
const accessToken = await jwt({ alg: 'RS256', kid: accessJwk.kid, typ: 'JWT' },
  { iss: 'https://fixture.cloudflareaccess.com', aud: ['fixture-events'], email: 'b@knitli.com', sub: 'fixture-owner', iat: now, exp: now + 300 }, access.privateKey, 'RSASSA-PKCS1-v1_5');
const agentToken = await jwt({ alg: 'Ed25519', kid: thumbprint, typ: 'JWT' },
  { sub: 'b@knitli.com/ws', aud: 'https://events.test', iat: now, exp: now + 300 }, agent.pair.privateKey, 'Ed25519');
const receiptPublic = { ...receipt.publicJwk, kid: 'fixture-receipt' };
const secret = randomUUID();
let outboundCalls = 0;
const options = convertV4MiniflareOptions({
  ...(crash ? { unsafeHandleRuntimeRestart: () => crash.restarted() } : {}),
  resourcePersistencePath: join(process.env.HOME, 'durable-objects'),
  name: 'messaging-wire-fixture', modules: true, script: bundle.outputFiles[0].text,
  outboundService: async () => { outboundCalls++; return new Response(null, { status: 503 }); },
  compatibilityDate: '2026-10-05', compatibilityFlags: ['nodejs_compat'], host: '127.0.0.1', port: 0,
  bindings: {
    FIXTURE_SECRET: secret, FIXTURE_ACCESS_JWK: JSON.stringify(accessJwk), FIXTURE_AGENT_JWK: JSON.stringify(agent.publicJwk),
    RECEIPT_PUBLIC_KEYS: '', RECEIPT_KEYS: JSON.stringify({ current: receiptPublic.kid, keys: { [receiptPublic.kid]: { pkcs8: receipt.pkcs8.toString('base64'), publicJwk: receiptPublic } } }),
    EVENT_ENABLED: 'true', EVENT_NATIVE_BINDING_ENABLED: 'true', EVENT_MESSAGING_ACCEPT_ENABLED: 'true', EVENT_MESSAGING_DELIVERY_ENABLED: 'true',
    EVENT_NATIVE_BINDING_CANARY: JSON.stringify({ principal: 'b@knitli.com', agent: 'ws' }),
    MESSAGING_NAMESPACE: 'fixture-messaging', MESSAGE_NAMESPACE: 'fixture-messaging', ALLOWED_PRINCIPALS: '@knitli.com',
    ENROLL_PRINCIPALS: '@knitli.com', EVENT_HOST: 'events.test', MESSAGES_HOST: 'messages.test', MESSAGES_ADMIN_HOST: 'messages-admin.test',
    ACCESS_ISSUER: 'https://fixture.cloudflareaccess.com', ACCESS_EVENT_AUD: 'fixture-events', ACCESS_AUD: 'fixture-messages', ACCESS_ADMIN_AUD: 'fixture-admin',
    EVENT_TRANSPORT_KEY_ID: 'fixture-v2', EVENT_TRANSPORT_PRIVATE_KEY: transport.pkcs8.toString('base64url'),
  },
  serviceBindings: {
    ...(crash ? { FIXTURE_CRASH_BARRIER: async request => {
      const phase = new URL(request.url).pathname.slice(1);
      if (!['before-reserve', 'after-reserve'].includes(phase)) {
        crash.fail(new Error('unexpected Messaging reservation path'));
        return new Response(null, { status: 500 });
      }
      if (crash.phase === phase) requireActiveClaim();
      await crash.reach(phase);
      return new Response(null, { status: 204 });
    } } : {}),
    MESSAGE_AUTHORITY: { name: 'messaging-wire-fixture', entrypoint: 'FixtureEventAuthority' },
    EVENT_MESSAGE_CONSUMER: { name: 'messaging-wire-fixture', entrypoint: 'MessageConsumerAuthority' },
  },
  durableObjects: {
    MAILBOX: { className: 'FixtureMailbox', useSQLite: true },
    OWNER_REGISTRY: { className: 'FixtureRegistry', useSQLite: true },
    AGENT_COORDINATOR: { className: 'FixtureCoordinator', useSQLite: true },
  },
});
let mf = new Miniflare(options);
let restarting = null;
const paths = new Set(['/fixture/seed', '/fixture/read', '/fixture/change', '/fixture/restart', '/v1/dispatch/claim',
  ...(crash ? ['/fixture/arm-crash', '/fixture/crash-proof'] : [])]);
const server = createServer({ requestTimeout: 5000, headersTimeout: 5000, maxHeaderSize: 16384 }, async (req, res) => {
  let claim = null;
  try {
    if (req.method !== 'POST' || !paths.has(req.url) || req.headers['x-fixture-secret'] !== secret) {
      res.writeHead(403).end(); req.resume(); return;
    }
    const chunks = []; let length = 0;
    for await (const chunk of req) { length += chunk.length; if (length > 8192) { res.writeHead(413).end(); req.resume(); return; } chunks.push(chunk); }
    if (restarting || stopping) { res.writeHead(409).end(); return; }
    crash?.healthy();
    if (req.url === '/fixture/arm-crash') {
      const value = JSON.parse(Buffer.concat(chunks));
      if (Object.keys(value).join(',') !== 'phase') throw new Error('invalid crash arm input');
      crash.arm(value.phase);
      res.writeHead(200, { 'content-type': 'application/json' }).end('{"armed":true}');
      return;
    }
    if (req.url === '/fixture/crash-proof') {
      await crash.proof();
      const ready = await mf.dispatchFetch('https://events.test/fixture/read', {
        method: 'POST', headers: { 'x-fixture-secret': secret }, body: '{}', signal: AbortSignal.timeout(1000) });
      if (ready.status !== 200) throw new Error('replacement readiness failed');
      await ready.arrayBuffer();
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(await crash.proof()));
      return;
    }
    if (req.url === '/fixture/restart') {
      if (crash) throw new Error('orderly restart forbidden in abrupt crash case');
      restarting = (async () => {
        await mf.dispose();
        if (stopping) throw new Error('fixture stopping');
        mf = new Miniflare(options);
        await mf.ready;
      })();
      try { await restarting; } finally { restarting = null; }
      res.writeHead(200, { 'content-type': 'application/json' }).end('{"restarted":true}');
      return;
    }
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(', ') : value);
    if (crash && req.url === '/v1/dispatch/claim') {
      if (activeClaim) throw new Error('concurrent crash claim');
      claim = { socket: req.socket, response: res };
      activeClaim = claim;
    }
    const response = await mf.dispatchFetch(`https://events.test${req.url}`, { method: 'POST', headers, body: Buffer.concat(chunks) });
    if (req.url === '/v1/dispatch/claim' && crash?.phase === 'after-admission' && response.status === 200) {
      const admission = await response.json();
      if (admission.status !== 'admitted') throw new Error('crash admission barrier missed');
      crash.admission = admission;
      requireActiveClaim();
      await crash.reach('after-admission');
      req.socket.destroy(); return;
    }
    if (req.url === '/v1/dispatch/claim' && headers.get('x-fixture-drop-reply') === 'true' && response.status === 200) {
      await response.arrayBuffer(); req.socket.destroy(); return;
    }
    res.writeHead(response.status, { 'content-type': response.headers.get('content-type') ?? 'application/octet-stream' });
    if (req.url === '/fixture/read' && response.status === 200) {
      res.end(JSON.stringify({ ...await response.json(), outboundCalls }));
    } else res.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) { console.error(error); if (!res.headersSent) res.writeHead(502); res.end(); }
  finally { if (claim && activeClaim === claim) activeClaim = null; }
});
let stopping = false;
async function stop() {
  if (stopping) return; stopping = true;
  crash?.stop();
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  try { await restarting; } finally {
    try { await mf.dispose(); } finally { crash?.restore(); }
  }
}
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => void stop().then(() => process.exit(0)));
process.on('disconnect', () => void stop().then(() => process.exit(0)));
try {
  await mf.ready;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  process.stdout.write(`${JSON.stringify({ pid: process.pid, port: server.address().port, secret, accessToken, agentToken,
    agentPrivateJwk: agent.privateJwk, transportPublicKey: transport.publicJwk.x,
    bundle: { sha256: sha256(bundle.outputFiles[0].contents), inputs } })}\n`);
} catch (error) { console.error(error); await stop(); process.exitCode = 1; }
