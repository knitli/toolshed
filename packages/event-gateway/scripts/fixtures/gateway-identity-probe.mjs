import { WorkerEntrypoint } from 'cloudflare:workers';

const HOST = 'event-native-probe-83fc4c309835.knitli.workers.dev';
const TARGET_URL = `https://${HOST}/probe`;
const REQUIRED_CHECK = '8a56504f-da96-41ee-8089-3713e2070e6f';
const PROBE_EXPIRES_AT = '__PROBE_EXPIRES_AT__';
const BODY = new TextEncoder().encode('knitli-probe-v1\n');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const response = (status, hostMatch) => new Response(status === 200 ? BODY : null, {
  status,
  headers: {
    'cache-control': 'no-store',
    ...(status === 200 ? {
      'x-knitli-probe-gateway': 'v1',
      'x-knitli-probe-host': hostMatch ? '1' : '0',
    } : {}),
  },
});

function contextMatchesTarget(context) {
  for (const [key, expected] of [['sni', HOST], ['host', HOST]]) {
    if (key in context && context[key] !== expected) return false;
  }
  if ('uri' in context && context.uri !== '/probe' && context.uri !== TARGET_URL) return false;
  return true;
}

export async function handleGatewayIdentityProbe(request, context, expiresAt = PROBE_EXPIRES_AT, {
  now = Date.now,
  timeoutMs = 2_000,
  schedule = setTimeout,
  cancel = clearTimeout,
} = {}) {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) return response(503, false);
  if (Math.floor(now() / 1000) >= expiresAt) return response(410, false);

  let url;
  try { url = new globalThis.URL(request.url); } catch { return response(404, false); }
  if (request.method !== 'GET' || url.href !== TARGET_URL || url.search || url.hash) return response(404, false);
  try {
    if (!context || typeof context !== 'object' || !contextMatchesTarget(context)
        || typeof context.devicePosture !== 'function') return response(503, false);
    let timer;
    let timerScheduled = false;
    let posture;
    try {
      // shortcut: Promise.race bounds the response, not the Gateway lookup; upgrade if cancellation becomes available.
      posture = await Promise.race([
        Promise.resolve().then(() => context.devicePosture()),
        new Promise((_, reject) => {
          timer = schedule(() => reject(new Error('device_posture_timeout')), timeoutMs);
          timerScheduled = true;
        }),
      ]);
    } finally {
      if (timerScheduled) cancel(timer);
    }
    if (Math.floor(now() / 1000) >= expiresAt) return response(410, false);
    const passed = posture?.checks?.passed;
    if (!Array.isArray(passed) || passed.some((id) => typeof id !== 'string' || !UUID.test(id))) return response(503, false);
    return response(200, passed.includes(REQUIRED_CHECK));
  } catch {
    if (Math.floor(now() / 1000) >= expiresAt) return response(410, false);
    return response(503, false);
  }
}

export class GatewayMiddleware extends WorkerEntrypoint {
  handle(request, context) {
    return handleGatewayIdentityProbe(request, context);
  }
}

export default { fetch: () => new Response(null, { status: 404, headers: { 'cache-control': 'no-store' } }) };
