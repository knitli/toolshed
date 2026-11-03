const ACCOUNT_ID = '5def525918a785eeda6decf66cf6b99b';
const PROFILE_ID = '425f0bec-8230-42a6-814d-0d0ea8e0a452';
const PROFILE_NAME = 'event-proxy-canary-d2c4a7d2';
const PROFILE_MATCH = 'identity.email == "adam@knitli.com" and os.name == "mac" and os.version == "27.0.1"';
const API_URL = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/devices/policy/${PROFILE_ID}`;
const LEASE_KEYS = ['issuedAtMs', 'rollbackAtMs', 'tokenExpiresAtMs'];
const MAX_BODY_BYTES = 16 * 1024;
const MAX_RECEIPT_BYTES = 4 * 1024;
const MAX_FUTURE_SCHEDULE_MS = 30_000;
const MAX_PAST_SCHEDULE_MS = 24 * 60 * 60 * 1000;
const FAIL_CODES = new Set([
  'invalid_schedule', 'invalid_lease', 'api_network', 'api_status', 'api_body_large',
  'api_body_invalid', 'api_body_read', 'api_shape', 'profile_drift', 'service_drift',
]);

export const PINNED = Object.freeze({ accountId: ACCOUNT_ID, profileId: PROFILE_ID, name: PROFILE_NAME, match: PROFILE_MATCH });

function readLease(raw, now) {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  let lease;
  try { lease = JSON.parse(raw); } catch { return null; }
  if (!lease || typeof lease !== 'object' || Array.isArray(lease)) return null;
  const keys = Object.keys(lease).sort();
  if (keys.length !== LEASE_KEYS.length || keys.some((key, i) => key !== [...LEASE_KEYS].sort()[i])) return null;
  const { issuedAtMs, rollbackAtMs, tokenExpiresAtMs } = lease;
  if (![issuedAtMs, rollbackAtMs, tokenExpiresAtMs].every(Number.isSafeInteger)) return null;
  if (issuedAtMs > now + MAX_FUTURE_SCHEDULE_MS || rollbackAtMs <= issuedAtMs
      || rollbackAtMs - issuedAtMs > 12 * 60_000
      || tokenExpiresAtMs < rollbackAtMs + 2 * 60_000
      || tokenExpiresAtMs - issuedAtMs > 20 * 60_000) return null;
  return { issuedAtMs, rollbackAtMs, tokenExpiresAtMs };
}

function safeFail(code) {
  return { status: 'cleanup_failed', failCode: FAIL_CODES.has(code) ? code : 'api_status' };
}

async function readJsonResponse(response) {
  if (!response.body) return { ok: false, code: 'api_shape' };
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        return { ok: false, code: 'api_body_large' };
      }
      chunks.push(value);
    }
  } catch {
    try { await reader.cancel(); } catch {}
    return { ok: false, code: 'api_body_read' };
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!value || value.success !== true || !Object.hasOwn(value, 'result')) return { ok: false, code: 'api_shape' };
    return { ok: true, value: value.result };
  } catch { return { ok: false, code: 'api_body_invalid' }; }
}

async function callApi(method, token, calls) {
  calls.count += 1; // Counts fixed-URL request attempts, not confirmed network dispatches.
  let response;
  try {
    response = await fetch(API_URL, {
      method,
      redirect: 'manual',
      signal: AbortSignal.timeout(5_000),
      headers: { authorization: `Bearer ${token}`, accept: 'application/json', ...(method === 'PATCH' ? { 'content-type': 'application/json' } : {}) },
      ...(method === 'PATCH' ? { body: JSON.stringify({ enabled: false }) } : {}),
    });
  } catch { return { ok: false, code: 'api_network' }; }
  if (response.status >= 300 && response.status < 400) {
    try { await response.body?.cancel(); } catch { return { ok: false, code: 'api_body_read' }; }
    return { ok: false, code: 'api_status' };
  }
  if (method === 'GET' && response.status === 404) {
    try { await response.body?.cancel(); } catch { return { ok: false, code: 'api_body_read' }; }
    return { ok: true, absent: true };
  }
  if (response.status !== 200) {
    try { await response.body?.cancel(); } catch {}
    return { ok: false, code: 'api_status' };
  }
  return readJsonResponse(response);
}

function checkProfile(profile) {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)
      || profile.policy_id !== PROFILE_ID || typeof profile.enabled !== 'boolean') {
    return { ok: false, code: 'profile_drift' };
  }
  return { ok: true, profile };
}

async function writeReceipt(env, receipt) {
  const serialized = JSON.stringify(receipt);
  if (new TextEncoder().encode(serialized).byteLength >= MAX_RECEIPT_BYTES) throw new Error('receipt_write_failed');
  try {
    await env.STATUS.put(`observations/${receipt.observationId}`, serialized, { expirationTtl: 86_400 });
    const scheduleKey = Number.isSafeInteger(receipt.scheduledAtMs) ? receipt.scheduledAtMs : 'invalid';
    // Each commit pairs with one observation; there is no shared mutable latest pointer.
    await env.STATUS.put(`commits/${scheduleKey}/${receipt.observationId}`, serialized, { expirationTtl: 86_400 });
  } catch { throw new Error('receipt_write_failed'); }
}

async function runCleanup(token, calls) {
  const before = await callApi('GET', token, calls);
  if (!before.ok) return safeFail(before.code);
  if (before.absent) return { status: 'absent', disabledVerified: false };
  const known = checkProfile(before.value);
  if (!known.ok) return safeFail(known.code);
  if (!known.profile.enabled) return { status: 'disabled', disabledVerified: true };

  const patched = await callApi('PATCH', token, calls);
  if (!patched.ok) return safeFail(patched.code);
  const patchCheck = checkProfile(patched.value);
  if (!patchCheck.ok) return safeFail(patchCheck.code);

  const after = await callApi('GET', token, calls);
  if (!after.ok || after.absent) return safeFail(after.code ?? 'api_shape');
  const verified = checkProfile(after.value);
  if (!verified.ok) return safeFail(verified.code);
  if (verified.profile.enabled) return safeFail('api_status');
  return { status: 'disabled', disabledVerified: true };
}

export default {
  async scheduled(controller, env) {
    const observationId = crypto.randomUUID();
    const now = Date.now();
    const scheduledAtMs = controller?.scheduledTime;
    const scheduleValid = Number.isSafeInteger(scheduledAtMs) && scheduledAtMs >= 0
      && scheduledAtMs <= now + MAX_FUTURE_SCHEDULE_MS
      && scheduledAtMs >= now - MAX_PAST_SCHEDULE_MS;
    const hasToken = typeof env.CF_TOKEN === 'string' && env.CF_TOKEN.length > 0;
    const hasLease = env.LEASE_SPEC !== undefined && env.LEASE_SPEC !== null && env.LEASE_SPEC !== '';
    const calls = { count: 0 };
    let decision;
    let lease = null;

    if (!scheduleValid) decision = { status: 'invalid_schedule', failCode: 'invalid_schedule' };
    else if (!hasToken && !hasLease) decision = { status: 'unarmed' };
    else if (!hasToken || !hasLease || !(lease = readLease(env.LEASE_SPEC, now))) {
      decision = { status: 'invalid_lease', failCode: 'invalid_lease' };
    } else if (now < lease.rollbackAtMs) decision = { status: 'armed' };
    else decision = await runCleanup(env.CF_TOKEN, calls);

    const receipt = {
      kind: 'device_profile_rollback',
      observationId,
      profileId: PROFILE_ID,
      observedAtMs: now,
      scheduledAtMs: scheduleValid ? scheduledAtMs : null,
      status: decision.status,
      rollbackAtMs: lease?.rollbackAtMs ?? null,
      apiCalls: calls.count,
      disabledVerified: decision.disabledVerified === true,
      ...(decision.failCode ? { failCode: decision.failCode } : {}),
    };
    await writeReceipt(env, receipt);
  },
};
