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
const names = [
  'contracts.ts', 'api.ts', 'registry.ts', 'coordinator.ts', 'coordinator-admission.ts',
  'authority-client.ts', 'protocol.ts', 'policy.ts', 'native-admission-contract.ts',
  'native-runtime-store.ts',
];
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
// eslint-disable-next-line no-unsanitized/method -- Execute the reviewed pinned native DTO schemas only after the same pre-evaluation source-pin checks.
const nativeAdmissionSchemas = await import(dataModule(
  source['native-admission-contract.ts'].replace('"zod"', JSON.stringify(zod))));
const canonicalSource = source['registry.ts'].match(/export function canonicalNodeProof\([\s\S]*?\n\}/)[0];
// eslint-disable-next-line no-unsanitized/method -- Execute the reviewed pinned proof function after the same pre-evaluation checks; regeneration explicitly trusts local source.
const { canonicalNodeProof } = await import(dataModule(canonicalSource));
// eslint-disable-next-line security/detect-non-literal-fs-filename -- Fixed fixture filename within the explicitly supplied local checkout.
const corpus = JSON.parse(readFileSync(resolve(base, '../__tests__/fixtures/protocol-v1.json'), 'utf8'));
const original = corpus.validEnvelopes[0];
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
const nativeAckFixture = corpus.validAcknowledgments.find(ack => ack.nativeCorrelation.kind === 'native_turn_started');
if (!nativeAckFixture) throw Error('canonical native-start ACK fixture missing');
const nativeAck = { ...nativeAckFixture, acknowledgedAt: issuedAt,
  nativeCorrelation: { ...nativeAckFixture.nativeCorrelation, permitId } };
// eslint-disable-next-line no-unsanitized/method -- Same reviewed protocol module, after pre-evaluation source-pin checks above.
const { EventObservationAckSchema } = await import(protocol);
EventObservationAckSchema.parse(nativeAck);
const nativeAckBody = JSON.stringify(nativeAck);
const nativeAckBinding = { ...binding, path: '/v1/ack',
  bodySha256: createHash('sha256').update(nativeAckBody).digest('hex') };
const nativeObservedFixture = corpus.validAcknowledgments.find(ack => ack.nativeCorrelation.kind === 'native_input_recorded');
if (!nativeObservedFixture) throw Error('canonical native-input ACK fixture missing');
const nativeObservedAck = { ...nativeObservedFixture, acknowledgedAt: issuedAt,
  nativeCorrelation: { ...nativeObservedFixture.nativeCorrelation, permitId,
    turnId: nativeAck.nativeCorrelation.turnId } };
EventObservationAckSchema.parse(nativeObservedAck);
const nativeObservedBody = JSON.stringify(nativeObservedAck);
const nativeObservedBinding = { ...binding, path: '/v1/ack',
  bodySha256: createHash('sha256').update(nativeObservedBody).digest('hex') };
const nativeIds = {
  runtime: '00000000-0000-4000-8000-000000000003',
  sourceRuntime: '00000000-0000-4000-8000-000000000004',
  replacementRuntime: '00000000-0000-4000-8000-000000000005',
  attachChallenge: '00000000-0000-4000-8000-000000000006',
  renewChallenge: '00000000-0000-4000-8000-000000000007',
  transferChallenge: '00000000-0000-4000-8000-000000000008',
  client: '00000000-0000-4000-8000-000000000009',
  connection: '00000000-0000-4000-8000-000000000010',
  thread: '00000000-0000-4000-8000-000000000011',
  serverInstance: '00000000-0000-4000-8000-000000000012',
  challengeProofAttach: '00000000-0000-4000-8000-000000000013',
  challengeProofRenew: '00000000-0000-4000-8000-000000000014',
  challengeProofTransfer: '00000000-0000-4000-8000-000000000015',
  attachProof: '00000000-0000-4000-8000-000000000016',
  renewProof: '00000000-0000-4000-8000-000000000017',
  transferProof: '00000000-0000-4000-8000-000000000018',
};
const nativeIssuedAt = '2026-10-09T12:00:58.000Z';
const nativeObservedAt = '2026-10-09T12:00:58.100Z';
const nativeLeaseUntil = '2026-10-09T12:02:28.100Z';
const nativeBinding = {
  clientId: nativeIds.client,
  connectionId: nativeIds.connection,
  backendPid: 4321,
  threadId: nativeIds.thread,
  generation: 7,
  serverInstanceId: nativeIds.serverInstance,
  serverGeneration: 2,
};
const nativeWitness = {
  version: 2,
  nonce: 11,
  clientId: nativeIds.client,
  backendPid: 4321,
  connectionId: nativeIds.connection,
  threadId: nativeIds.thread,
  generation: 7,
  eligible: true,
  sequence: 23,
  cause: 'selection_changed',
  serverInstanceId: nativeIds.serverInstance,
  serverGeneration: 2,
  leaseMs: 500,
};
const nativeEvidence = { observedAt: nativeObservedAt, witness: nativeWitness };
const nativeChallengeRequests = {
  attach: { operation: 'attach', runtimeId: nativeIds.runtime, expectedRuntimeGeneration: null,
    expectedAttachmentGeneration: null, expectedNativeBinding: nativeBinding },
  renew: { operation: 'renew', runtimeId: nativeIds.runtime, expectedRuntimeGeneration: 1,
    expectedAttachmentGeneration: 1, expectedNativeBinding: nativeBinding },
  transfer: { operation: 'transfer', sourceRuntimeId: nativeIds.sourceRuntime,
    expectedSourceRuntimeGeneration: 2, expectedSourceAttachmentGeneration: 3,
    replacementRuntimeId: nativeIds.replacementRuntime, expectedReplacementRuntimeGeneration: 4,
    expectedReplacementAttachmentGeneration: 5, expectedNativeBinding: nativeBinding },
};
for (const request of Object.values(nativeChallengeRequests))
  nativeAdmissionSchemas.NativeRuntimeChallengeRequestSchema.parse(request);
const nativeChallengeResponses = Object.fromEntries(Object.entries({
  attach: nativeIds.attachChallenge, renew: nativeIds.renewChallenge, transfer: nativeIds.transferChallenge,
}).map(([operation, challengeId]) => [operation, {
  challengeId, issuedAt: nativeIssuedAt, expiresAt: new Date(Date.parse(nativeIssuedAt) + 30_000).toISOString(),
}]));
for (const response of Object.values(nativeChallengeResponses))
  nativeAdmissionSchemas.NativeRuntimeChallengeResponseSchema.parse(response);
const nativeCommitRequests = {
  attach: { challengeId: nativeIds.attachChallenge, runtimeId: nativeIds.runtime,
    expectedRuntimeGeneration: null, expectedAttachmentGeneration: null, nativeEvidence },
  renew: { challengeId: nativeIds.renewChallenge, runtimeId: nativeIds.runtime,
    expectedRuntimeGeneration: 1, expectedAttachmentGeneration: 1, nativeEvidence },
  transfer: { challengeId: nativeIds.transferChallenge, sourceRuntimeId: nativeIds.sourceRuntime,
    expectedSourceRuntimeGeneration: 2, expectedSourceAttachmentGeneration: 3,
    replacementRuntimeId: nativeIds.replacementRuntime, expectedReplacementRuntimeGeneration: 4,
    expectedReplacementAttachmentGeneration: 5, nativeEvidence },
};
nativeAdmissionSchemas.NativeRuntimeAttachRequestSchema.parse(nativeCommitRequests.attach);
nativeAdmissionSchemas.NativeRuntimeRenewRequestSchema.parse(nativeCommitRequests.renew);
nativeAdmissionSchemas.NativeRuntimeTransferRequestSchema.parse(nativeCommitRequests.transfer);
const nativeSuccessResponses = {
  attach: { status: 'attached', runtimeId: nativeIds.runtime, runtimeGeneration: 1, nodeId,
    nodeGeneration: 1, attachmentGeneration: 1, leaseUntil: nativeLeaseUntil, nativeBinding },
  renew: { status: 'renewed', runtimeId: nativeIds.runtime, runtimeGeneration: 1, nodeId,
    nodeGeneration: 1, attachmentGeneration: 1, leaseUntil: nativeLeaseUntil, nativeBinding },
  transfer: { status: 'transferred', sourceRuntimeId: nativeIds.sourceRuntime,
    sourceRuntimeGeneration: 3, sourceAttachmentGeneration: 4, runtimeId: nativeIds.replacementRuntime,
    runtimeGeneration: 4, nodeId, nodeGeneration: 1, attachmentGeneration: 6,
    leaseUntil: nativeLeaseUntil, nativeBinding },
};
nativeAdmissionSchemas.NativeRuntimeAttachResponseSchema.parse(nativeSuccessResponses.attach);
nativeAdmissionSchemas.NativeRuntimeRenewResponseSchema.parse(nativeSuccessResponses.renew);
nativeAdmissionSchemas.NativeRuntimeTransferResponseSchema.parse(nativeSuccessResponses.transfer);
const nativeErrors = [
  'invalid_request', 'invalid_json', 'duplicate_json_key', 'invalid_body', 'invalid',
  'denied', 'node_proof_required', 'node_denied', 'conflict', 'capacity',
  'coordinator_capacity', 'expired', 'native_binding_unqualified', 'request_timeout',
  'request_too_large', 'content_type', 'content_encoding', 'runtime_disabled',
  'authority_unavailable', 'registry_unavailable', 'unavailable', 'not_found',
  'method_not_allowed',
].map(error => {
  const value = { error };
  nativeAdmissionSchemas.NativeRuntimeAdmissionErrorSchema.parse(value);
  return value;
});
const nativeRejections = [
  { name: 'attach_partial_null_cas', schema: nativeAdmissionSchemas.NativeRuntimeChallengeRequestSchema,
    value: { ...nativeChallengeRequests.attach, expectedAttachmentGeneration: 1 } },
  { name: 'transfer_same_runtime', schema: nativeAdmissionSchemas.NativeRuntimeChallengeRequestSchema,
    value: { ...nativeChallengeRequests.transfer, replacementRuntimeId: nativeIds.sourceRuntime } },
  { name: 'ineligible_witness', schema: nativeAdmissionSchemas.NativeRuntimeAttachRequestSchema,
    value: { ...nativeCommitRequests.attach, nativeEvidence: { ...nativeEvidence,
      witness: { ...nativeWitness, eligible: false } } } },
  { name: 'wrong_witness_version', schema: nativeAdmissionSchemas.NativeRuntimeRenewRequestSchema,
    value: { ...nativeCommitRequests.renew, nativeEvidence: { ...nativeEvidence,
      witness: { ...nativeWitness, version: 3 } } } },
  { name: 'unsafe_witness_integer', schema: nativeAdmissionSchemas.NativeRuntimeRenewRequestSchema,
    value: { ...nativeCommitRequests.renew, nativeEvidence: { ...nativeEvidence,
      witness: { ...nativeWitness, sequence: Number.MAX_SAFE_INTEGER + 1 } } } },
  { name: 'unexpected_binding_field', schema: nativeAdmissionSchemas.NativeRuntimeChallengeRequestSchema,
    value: { ...nativeChallengeRequests.attach, expectedNativeBinding: { ...nativeBinding, enabled: true } } },
  { name: 'wrong_challenge_ttl', schema: nativeAdmissionSchemas.NativeRuntimeChallengeResponseSchema,
    value: {
      ...nativeChallengeResponses.attach,
      expiresAt: new Date(Date.parse(nativeIssuedAt) + 29_999).toISOString(),
    } },
];
for (const vector of nativeRejections) {
  if (vector.schema.safeParse(vector.value).success)
    throw Error('native admission rejection vector accepted: ' + vector.name);
}
const nativePrincipal = 'adam@knitli.com';
const nativeProof = (path, value, nonce) => {
  const body = JSON.stringify(value);
  const proof = { nodeId, nodeGeneration: 1, issuedAt: nativeObservedAt, nonce };
  const requestBinding = { audience: 'https://events.example.com', method: 'POST', path,
    bodySha256: createHash('sha256').update(body).digest('hex') };
  return { principal: nativePrincipal, agent: 'pilot-agent', binding: requestBinding, body, proof,
    canonical: canonicalNodeProof(nativePrincipal, proof, requestBinding) };
};
const nativeNodeProofs = {
  challengeAttach: nativeProof('/v1/runtimes/challenge', nativeChallengeRequests.attach,
    nativeIds.challengeProofAttach),
  challengeRenew: nativeProof('/v1/runtimes/challenge', nativeChallengeRequests.renew,
    nativeIds.challengeProofRenew),
  challengeTransfer: nativeProof('/v1/runtimes/challenge', nativeChallengeRequests.transfer,
    nativeIds.challengeProofTransfer),
  attach: nativeProof('/v1/runtimes/attach', nativeCommitRequests.attach, nativeIds.attachProof),
  renew: nativeProof('/v1/runtimes/renew', nativeCommitRequests.renew, nativeIds.renewProof),
  transfer: nativeProof('/v1/runtimes/transfer', nativeCommitRequests.transfer, nativeIds.transferProof),
};
const runtimeStatusRequest = { runtimeId: nativeIds.runtime };
nativeAdmissionSchemas.NativeRuntimeStatusRequestSchema.parse(runtimeStatusRequest);
const runtimeStatusResponses = {
  missing: { status: 'missing', runtimeId: nativeIds.runtime, observedAt: nativeObservedAt },
  expired: { ...nativeSuccessResponses.attach, status: 'present', observedAt: nativeObservedAt,
    runtimeGeneration: 7, attachmentGeneration: 9,
    leaseUntil: nativeIssuedAt, storedQualified: true },
  legacy: { ...nativeSuccessResponses.attach, status: 'present', observedAt: nativeObservedAt,
    runtimeGeneration: 3, attachmentGeneration: 4,
    leaseUntil: nativeIssuedAt, storedQualified: false, nativeBinding: null },
};
for (const value of Object.values(runtimeStatusResponses))
  nativeAdmissionSchemas.NativeRuntimeStatusResponseSchema.parse(value);
const runtimeStatusRejections = [
  { name: 'status_extra_request_field', request: true,
    value: { ...runtimeStatusRequest, qualified: true } },
  { name: 'status_invalid_runtime_id', request: true,
    value: { runtimeId: 'not-a-runtime' } },
  { name: 'status_qualified_without_binding',
    value: { ...runtimeStatusResponses.expired, nativeBinding: null } },
  { name: 'status_unsafe_runtime_generation',
    value: { ...runtimeStatusResponses.expired, runtimeGeneration: Number.MAX_SAFE_INTEGER + 1 } },
  { name: 'status_zero_attachment_generation',
    value: { ...runtimeStatusResponses.expired, attachmentGeneration: 0 } },
  { name: 'status_nonboolean_qualification',
    value: { ...runtimeStatusResponses.expired, storedQualified: 1 } },
  { name: 'status_extra_missing_field',
    value: { ...runtimeStatusResponses.missing, nativeBinding } },
  { name: 'status_invalid_snapshot_time',
    value: { ...runtimeStatusResponses.missing, observedAt: 'unknown' } },
  { name: 'status_invalid_binding',
    value: { ...runtimeStatusResponses.expired, nativeBinding: { ...nativeBinding, clientId: 'invalid' } } },
];
for (const vector of runtimeStatusRejections) {
  const schema = vector.request ? nativeAdmissionSchemas.NativeRuntimeStatusRequestSchema
    : nativeAdmissionSchemas.NativeRuntimeStatusResponseSchema;
  if (schema.safeParse(vector.value).success)
    throw Error('runtime status rejection vector accepted: ' + vector.name);
}
const runtimeStatus = { request: runtimeStatusRequest, responses: runtimeStatusResponses,
  rejections: runtimeStatusRejections,
  nodeProof: nativeProof('/v1/runtimes/status', runtimeStatusRequest, nativeIds.challengeProofAttach) };
const nativeAdmissionFixture = {
  runtimeStatus,
  ids: nativeIds,
  binding: nativeBinding,
  witness: nativeWitness,
  evidence: nativeEvidence,
  challengeRequests: nativeChallengeRequests,
  challengeResponses: nativeChallengeResponses,
  commitRequests: nativeCommitRequests,
  successResponses: nativeSuccessResponses,
  errors: nativeErrors,
  rejections: nativeRejections.map(({ name, value }) => ({ name, value })),
  nodeProofs: nativeNodeProofs,
};
const fixture = { original, admitted, overBudget, claim,
  nativeAck,
  nativeAckNodeProof: { principal: nativeAck.principal, binding: nativeAckBinding, body: nativeAckBody, proof,
    canonical: canonicalNodeProof(nativeAck.principal, proof, nativeAckBinding) },
  nativeObservedAck,
  nativeObservedAckNodeProof: { principal: nativeObservedAck.principal, binding: nativeObservedBinding,
    body: nativeObservedBody, proof,
    canonical: canonicalNodeProof(nativeObservedAck.principal, proof, nativeObservedBinding) },
  nodeProof: { principal: original.principal, binding, body, proof, canonical: canonicalNodeProof(original.principal, proof, binding) },
  noStart, localNoStart, noStartResult, localNoStartResult,
  nativeAdmission: nativeAdmissionFixture,
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
