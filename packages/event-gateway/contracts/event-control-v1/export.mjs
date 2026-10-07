// Export from an explicit OS checkout; never import Worker runtime modules.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { stripTypeScriptTypes } from 'node:module';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';

const [root, zodPath, check] = process.argv.slice(2);
if (!root || !zodPath || (check && check !== '--check')) throw Error('usage: export.mjs OS_ROOT ZOD_ESM_PATH [--check]');
const base = resolve(root, 'packages/event-runtime/src');
const names = ['contracts.ts', 'api.ts', 'registry.ts', 'coordinator.ts', 'coordinator-admission.ts', 'authority-client.ts', 'protocol.ts', 'policy.ts'];
// eslint-disable-next-line security/detect-non-literal-fs-filename -- Fixed source filenames under the operator-supplied local checkout.
const source = Object.fromEntries(names.map(name => [name, readFileSync(resolve(base, name), 'utf8')]));
const destination = dirname(fileURLToPath(import.meta.url));
const revision = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
// eslint-disable-next-line security/detect-non-literal-fs-filename -- Read package metadata beside the operator-supplied trusted Zod module.
const zodVersion = JSON.parse(readFileSync(resolve(dirname(zodPath), 'package.json'), 'utf8')).version;
// eslint-disable-next-line security/detect-object-injection -- Keys come only from the fixed source filename allowlist above.
const sources = Object.fromEntries(names.map(name => [`apps/os/packages/event-runtime/src/${name}`, createHash('sha256').update(source[name]).digest('hex')]));
if (check) {
  const pinned = JSON.parse(readFileSync(resolve(destination, 'manifest.json'), 'utf8'));
  if (revision !== pinned.revision || zodVersion !== pinned.zodVersion ||
      Object.keys(pinned.sources).length !== names.length ||
      // eslint-disable-next-line security/detect-object-injection -- Compare allowlisted source keys with the reviewed local manifest; never execute values.
      Object.entries(sources).some(([name, digest]) => pinned.sources[name] !== digest))
    throw Error('source pin mismatch before evaluation');
}
const dataModule = code => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(code, { mode: 'transform' })).toString('base64')}`;
const policy = dataModule(source['policy.ts']);
const zod = pathToFileURL(resolve(zodPath)).href;
const protocol = dataModule(source['protocol.ts'].replace('"zod"', JSON.stringify(zod)).replace('"./policy.js"', JSON.stringify(policy)));
// eslint-disable-next-line no-unsanitized/method -- Execute reviewed local schemas; --check verifies revision, source hashes and Zod version before this import.
const contracts = await import(dataModule(source['contracts.ts'].replace('"zod"', JSON.stringify(zod)).replace('"./protocol.ts"', JSON.stringify(protocol))));
const canonicalSource = source['registry.ts'].match(/export function canonicalNodeProof\([\s\S]*?\n\}/)[0];
// eslint-disable-next-line no-unsanitized/method -- Execute the reviewed pinned proof function after the same pre-evaluation checks; regeneration explicitly trusts local source.
const { canonicalNodeProof } = await import(dataModule(canonicalSource));
// eslint-disable-next-line security/detect-non-literal-fs-filename -- Fixed fixture filename within the explicitly supplied local checkout.
const original = JSON.parse(readFileSync(resolve(base, '../__tests__/fixtures/protocol-v1.json'), 'utf8')).validEnvelopes[0];
const nodeId = '00000000-0000-4000-8000-000000000001';
const permitId = '00000000-0000-4000-8000-000000000002';
const issuedAt = '2026-10-05T12:00:58.000Z';
const envelope = { ...original, issuedAt, expiresAt: '2026-10-05T12:01:58.000Z' };
const admitted = { status: 'admitted', permitId, nodeId, permitIssuedAt: issuedAt, permitExpiresAt: '2026-10-05T12:01:03.000Z', envelope };
contracts.DispatchClaimResultSchema.parse(admitted);
const claim = { deliveryId: original.deliveryId, attemptId: original.attemptId };
contracts.ClaimRequestSchema.parse(claim);
const body = JSON.stringify(claim);
const proof = { nodeId, nodeGeneration: 1, issuedAt, nonce: permitId };
const binding = { audience: 'https://events.example.com', method: 'POST', path: '/v1/dispatch/claim', bodySha256: createHash('sha256').update(body).digest('hex') };
const overBudget = { status: 'over_budget', budget: { used: 10, remaining: 0, limit: 10, windowMs: 3600000 } };
contracts.DispatchClaimResultSchema.parse(overBudget);
const noStart = { deliveryId: original.deliveryId, attemptId: original.attemptId, permitId,
  nodeGeneration: original.nodeGeneration, evidence: { type: 'native_terminal_no_start', receiptId: nodeId } };
const localNoStart = { ...noStart, evidence: { type: 'local_not_submitted' } };
contracts.DispatchNoStartRequestSchema.parse(noStart);
contracts.DispatchNoStartRequestSchema.parse(localNoStart);
const noStartResult = { ...noStart, nodeId, status: 'not_started' };
const localNoStartResult = { ...localNoStart, nodeId, status: 'not_started' };
contracts.DispatchNoStartResultSchema.parse(noStartResult);
contracts.DispatchNoStartResultSchema.parse(localNoStartResult);
const noStartBody = JSON.stringify(noStart);
const noStartBinding = { ...binding, path: '/v1/dispatch/settle-no-start',
  bodySha256: createHash('sha256').update(noStartBody).digest('hex') };
const fixture = { original, admitted, overBudget, claim,
  nodeProof: { principal: original.principal, binding, body, proof, canonical: canonicalNodeProof(original.principal, proof, binding) },
  noStart, localNoStart, noStartResult, localNoStartResult,
  noStartNodeProof: { principal: original.principal, binding: noStartBinding, body: noStartBody, proof,
    canonical: canonicalNodeProof(original.principal, proof, noStartBinding) } };
const json = value => JSON.stringify(value, null, 2) + '\n';
const fixtureText = json(fixture);
const manifest = {
  repository: 'knitli/knitli-site', revision, zodVersion, sources,
  fixturesSha256: createHash('sha256').update(fixtureText).digest('hex'),
};
for (const [name, content] of [['fixtures.json', fixtureText], ['manifest.json', json(manifest)]]) {
  const path = resolve(destination, name);
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Compare one of two fixed output filenames beside this exporter.
  if (check) { if (readFileSync(path, 'utf8') !== content) throw Error(`stale ${name}`); }
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Explicit regeneration writes only those two fixed files beside this exporter.
  else writeFileSync(path, content);
}
console.log(check ? 'control-plane contract matches source' : 'control-plane fixtures exported');
