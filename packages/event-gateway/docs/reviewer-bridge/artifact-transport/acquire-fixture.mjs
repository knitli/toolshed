// OFFLINE TEST ONLY: verifierStub is fabricated; this proves no signature or provider execution.
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {dirname, join} from 'node:path';
import {readdirSync, readFileSync} from 'node:fs';
const [source, directory, handoff, attestation, output, mode] = process.argv.slice(2);
const {acquireQualificationEvidence} = await import(pathToFileURL(join(source, 'scripts/reviewer-host-acquisition.mjs')));
const {REVIEW_WORKFLOW,QUALIFICATION_STEP,SEAL_STEP} = await import(pathToFileURL(join(source, 'scripts/reviewer-host-handoff.mjs')));
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
function verifierStub(bytes, policy) {
  const signer = `https://github.com/${REVIEW_WORKFLOW}@${policy.workflowSha}`;
  return [{ verificationResult: { mediaType: 'application/vnd.dev.sigstore.verificationresult+json;version=0.1',
    signature: { certificate: { issuer: 'https://token.actions.githubusercontent.com', subjectAlternativeName: signer,
      buildSignerURI: signer, buildSignerDigest: policy.workflowSha, runnerEnvironment: 'github-hosted',
      sourceRepositoryURI: `https://github.com/${policy.repository}`, sourceRepositoryIdentifier: String(policy.repositoryId),
      sourceRepositoryDigest: policy.sourceHeadSha, sourceRepositoryRef: 'refs/heads/main', sourceRepositoryVisibilityAtSigning: 'private',
      buildTrigger: 'workflow_dispatch', buildConfigURI: `https://github.com/${policy.repository}/.github/workflows/reviewer-host-qualification.yml@refs/heads/main`,
      buildConfigDigest: policy.sourceHeadSha,
      runInvocationURI: `https://github.com/${policy.repository}/actions/runs/${policy.runId}/attempts/${policy.runAttempt}` } },
    verifiedTimestamps: [{ type: 'Tlog', uri: 'https://fixture.invalid', timestamp: '2026-10-17T00:00:00Z' }],
    statement: { _type: 'https://in-toto.io/Statement/v1', predicateType: 'https://slsa.dev/provenance/v1',
      subject: [{ name: 'reviewer-host-handoff.json', digest: { sha256: hash(bytes) } }], predicate: {} } } }];
}

const policy = {repository:'knitli/knitli-site', repositoryId:1058277548, runId:'123', runAttempt:'2', workflowSha:'711e265cc280cad7c4a44ba6d2d72f40a1378fec', sourceHeadSha:'d'.repeat(40)};
const expectedHandoff = await readFile(handoff);
const expectedAttestation = await readFile(attestation);
assert.equal(expectedAttestation.toString(), '{"TEST_ONLY_TRUSTED_VERIFIER_STUB":true}');
let verifierCalls = 0;
let sourceCalls = 0;
let runReads = 0;
let acquisitionError;
let lateFailureInjected = false;
const run={id:123,run_attempt:2,repository:{id:1058277548,full_name:policy.repository,private:true},status:'completed',conclusion:'success',event:'workflow_dispatch',head_branch:'main',head_sha:policy.sourceHeadSha,path:'.github/workflows/reviewer-host-qualification.yml',referenced_workflows:[{path:`${REVIEW_WORKFLOW}@${policy.workflowSha}`,sha:policy.workflowSha}]};
const jobs=['77','88'].map((id,index)=>({id:index+10,run_id:123,status:'completed',conclusion:'success',check_run_url:`https://api.github.com/repos/${policy.repository}/check-runs/${id}`,head_sha:policy.sourceHeadSha,steps:[{name:index?SEAL_STEP:QUALIFICATION_STEP,number:1,status:'completed',conclusion:'success'}]}));
let result;
try {
result=await acquireQualificationEvidence({directory,outputPath:output,handoffBytes:await readFile(handoff),attestationBytes:await readFile(attestation),expected:policy,verify:async({handoffBytes,attestationBytes,policy})=>{
 verifierCalls++;
 assert.deepEqual(handoffBytes, expectedHandoff);
 assert.deepEqual(attestationBytes, expectedAttestation);
 // Reading the real bundle here proves acquisition occurs before transport cleanup.
 for (const name of ['completion.json','envelope.json','snapshot.json']) assert.ok((await readFile(join(directory,name))).length);
 return verifierStub(handoffBytes,policy);
},get:endpoint=>{
 sourceCalls++;
 const prefix=`repos/${policy.repository}/actions/runs/123/attempts/2`;
 if(endpoint===prefix) {
  runReads++;
  if (mode === 'throw' && runReads === 3) {
   const stages = readdirSync(dirname(output)).filter(name => name.startsWith('.host-acquisition-'));
   assert.equal(stages.length, 1);
   assert.ok(readFileSync(join(dirname(output), stages[0], 'evidence.json')).length);
   lateFailureInjected = true;
   throw Error('OFFLINE acquisition refusal after staging');
  }
  return structuredClone(run);
 }
 if(endpoint===prefix+'/jobs?per_page=100&page=1')return {total_count:2,jobs:structuredClone(jobs)};
 throw Error('Unexpected fixture endpoint');
}});
} catch (error) { acquisitionError = error; }
assert.equal(verifierCalls, 1);
assert.ok(sourceCalls > 0);
assert.equal(runReads, 3);
assert.equal(lateFailureInjected, mode === 'throw');
if (mode === 'throw') {
 assert.match(acquisitionError?.message ?? '', /acquisition_failed/);
 throw acquisitionError;
}
if (acquisitionError) throw acquisitionError;
assert.deepEqual(JSON.parse(await readFile(output)), result);
console.log(JSON.stringify({status:result.status,reason:result.execution.reason,provenance:result.provenance,roundCompletion:result.roundCompletion}));
