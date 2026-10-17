// Dormant fixed API-only child. Importing this module does not perform I/O.
import dns from 'node:dns/promises';
import https from 'node:https';
import tls from 'node:tls';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const CA_SHA256 = '1decfbbd96de12a0ff0677ea34b95586e646a7fb4c32f6352d95af26a7408624';
export const HEADER_LIMIT = 32768;
const MAX_BODY = 3 * 1024 * 1024;
const fail = () => { throw new Error('https_refused'); };

// Conservative IPv4 special-purpose denial. Exceptions within these ranges are
// deliberately denied too. IPv6 and IPv4-mapped IPv6 are unsupported.
const DENIED = [
  [0x00000000, 8], [0x0a000000, 8], [0x64400000, 10],
  [0x7f000000, 8], [0xa9fe0000, 16], [0xac100000, 12],
  [0xc0000000, 24], [0xc0000200, 24], [0xc0586300, 24],
  [0xc0a80000, 16], [0xc6120000, 15], [0xc6336400, 24],
  [0xcb007100, 24], [0xe0000000, 4], [0xf0000000, 4],
];

export function publicIPv4(address) {
  if (typeof address !== 'string' || !/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(address)) return false;
  const octets = address.split('.').map(Number);
  if (octets.some(x => x > 255)) return false;
  const value = octets.reduce((a, b) => ((a << 8) | b) >>> 0, 0);
  return !DENIED.some(([base, bits]) => (value >>> (32 - bits)) === (base >>> (32 - bits)));
}

export function validateInput(input) {
  if (!input || typeof input !== 'object' || Object.keys(input).sort().join(',') !== 'headers,maximum,remainingMs,url') fail();
  if (typeof input.url !== 'string' || input.url.length > 8192 || input.url.includes('#') || /[^\x21-\x7e]/.test(input.url)) fail();
  const url = new URL(input.url);
  // No alternate authority spelling, explicit port, userinfo, fragment or host.
  if (!input.url.startsWith('https://api.github.com/') || url.origin !== 'https://api.github.com' || url.username || url.password || url.hash) fail();
  if (!Number.isSafeInteger(input.maximum) || input.maximum < 0 || input.maximum > MAX_BODY) fail();
  if (!Number.isFinite(input.remainingMs) || input.remainingMs <= 0 || input.remainingMs > 60000) fail();
  if (!input.headers || typeof input.headers !== 'object' || Array.isArray(input.headers)) fail();
  const seen = new Set();
  for (const [name, value] of Object.entries(input.headers)) {
    const lower = name.toLowerCase();
    if (!['accept', 'accept-encoding', 'authorization', 'x-github-api-version', 'user-agent'].includes(lower) || seen.has(lower)) fail();
    if (typeof value !== 'string' || value.length > 4096 || /[^\x20-\x7e]/.test(value)) fail();
    if (lower === 'accept-encoding' && value !== 'identity') fail();
    seen.add(lower);
  }
  return url;
}

export function responseHeaders(raw) {
  if (!Array.isArray(raw) || raw.length % 2 || raw.length > 128) fail();
  const headers = {};
  let bytes = 0;
  for (let i = 0; i < raw.length; i += 2) {
    const name = raw[i], value = raw[i + 1];
    if (typeof name !== 'string' || typeof value !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$/.test(name) || value.length > 8192 || /[\x00-\x08\x0a-\x1f\x7f]/.test(value)) fail();
    bytes += Buffer.byteLength(name) + Buffer.byteLength(value) + 4;
    const lower = name.toLowerCase();
    if (Object.hasOwn(headers, lower) || bytes > HEADER_LIMIT) fail();
    Object.defineProperty(headers, lower, { value, enumerable: true });
  }
  if (headers['content-encoding'] && headers['content-encoding'] !== 'identity') fail();
  if (headers['transfer-encoding'] && headers['transfer-encoding'] !== 'chunked') fail();
  if (headers['content-length'] !== undefined && (!/^(0|[1-9]\d{0,9})$/.test(headers['content-length']) || headers['transfer-encoding'])) fail();
  return headers;
}

// Dependency arguments are only for offline imports; the executable uses fixed
// built-ins, fixed bundled roots and no environment-driven configuration.
export async function exchange(input, lookup = dns.lookup, request = https.request) {
  const url = validateInput(input);
  if (createHash('sha256').update(JSON.stringify(tls.rootCertificates)).digest('hex') !== CA_SHA256) fail();
  const answers = await lookup(url.hostname, { family: 4, all: true, verbatim: true });
  if (!Array.isArray(answers) || !answers.length || answers.length > 32 || answers.some(x => x.family !== 4 || !publicIPv4(x.address))) fail();
  const address = answers[0].address;
  return await new Promise((resolve, reject) => {
    let req;
    const refuse = () => { req?.destroy(); reject(new Error('https_refused')); };
    req = request({
      protocol: 'https:', hostname: address, port: 443, family: 4,
      servername: url.hostname, method: 'GET', path: url.pathname + url.search,
      headers: { ...input.headers, Host: url.hostname, 'Accept-Encoding': 'identity' },
      agent: false, maxHeaderSize: HEADER_LIMIT, maxHeadersCount: 65,
      ca: tls.rootCertificates, rejectUnauthorized: true, minVersion: 'TLSv1.2',
      checkServerIdentity: (_host, cert) => tls.checkServerIdentity(url.hostname, cert),
      lookup: (_host, _options, callback) => callback(new Error('https_refused')),
    }, response => {
      try {
        if (!response.socket.authorized || response.socket.remoteAddress !== address) fail();
        const headers = responseHeaders(response.rawHeaders);
        if (!Number.isInteger(response.statusCode) || response.statusCode < 200 || response.statusCode > 599) fail();
        if (headers['content-length'] !== undefined && Number(headers['content-length']) > input.maximum) fail();
        const chunks = [];
        let size = 0;
        response.on('data', chunk => {
          size += chunk.length;
          if (size > input.maximum) { response.destroy(); refuse(); return; }
          chunks.push(chunk);
        });
        response.on('error', refuse);
        response.on('aborted', refuse);
        response.on('end', () => {
          if (!response.complete || (headers['content-length'] !== undefined && Number(headers['content-length']) !== size)) { refuse(); return; }
          resolve({ status: response.statusCode, headers, body: Buffer.concat(chunks, size) });
        });
      } catch { response.destroy(); refuse(); }
    });
    req.maxHeadersCount = 65;
    req.on('error', refuse);
    req.on('information', refuse);
    req.end();
  });
}

async function main() {
  let size = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 16384) fail();
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
  validateInput(input);
  const timeout = setTimeout(() => process.exit(2), Math.ceil(input.remainingMs));
  const result = await exchange(input);
  const metadata = Buffer.from(JSON.stringify({ status: result.status, headers: result.headers }));
  if (metadata.length > HEADER_LIMIT) fail();
  const length = Buffer.alloc(4);
  length.writeUInt32BE(metadata.length);
  process.stdout.write(length);
  process.stdout.write(metadata);
  process.stdout.end(result.body, () => { clearTimeout(timeout); });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => process.exit(2));
}
