// Disposable fixture only: no production qualification or Access authority claim.
import { signedEventRequest } from 'fixture-event-runtime/delivery.ts';
import { eventFetch } from 'fixture-event-runtime/api.ts';
import { AgentCoordinator } from 'fixture-event-runtime/coordinator.ts';
import { OwnerRegistry, ownerRegistryName } from 'fixture-event-runtime/registry.ts';
import { coordinatorName, type EventApiEnvironment } from 'fixture-event-runtime/contracts.ts';
type Auth = { accessAssertion: string; agentToken: string };
type CoordinatorEnv = ConstructorParameters<typeof AgentCoordinator>[1];
type Authority = CoordinatorEnv['MESSAGE_AUTHORITY'];
type ActivationInput = Parameters<Authority['prepareSourceActivation']>[0];
type ActivationClaim = NonNullable<Parameters<Authority['nativeAttemptStatus']>[0]['activation']>;
type AttemptAuth = Auth & { attemptId: string; activation?: ActivationClaim };
type FixtureSetup = { runtimeId: string; nodeId: string; transportPrivateKey: string; subjectId?: string };
type CoordinatorContext = ConstructorParameters<typeof AgentCoordinator>[0];
type FixtureEnv = Omit<EventApiEnvironment, 'OWNER_REGISTRY' | 'AGENT_COORDINATOR'> & {
  FIXTURE_SECRET: string;
  MESSAGE_NAMESPACE: string;
  OWNER_REGISTRY: DurableObjectNamespace<FixtureRegistry>;
  AGENT_COORDINATOR: DurableObjectNamespace<FixtureCoordinator>;
};
const principal = 'qualification@example.com', agent = 'pilot';
const messageNamespace = 'fixture-message-namespace';
const threeSessionSubjects = new Set(['three-session-route-a','three-session-route-b','three-session-route-c',
  'three-session-c-busy-first','three-session-c-busy-second','three-session-c-after-attach']);
const fixtureManualSubjects = new Set(['fixture-manual-source', ...threeSessionSubjects]);
const reservations = new Map<string,{reservedAt:number;activation?:ActivationClaim}>();
const budget = () => ({ used: reservations.size, remaining: 10-reservations.size, limit: 10, windowMs: 3600000 });
const valid = (x:Auth) => x.accessAssertion === 'fixture-access' && x.agentToken === 'fixture-agent';
const exactObject = (value:unknown,keys:string[]) => value!==null&&typeof value==='object'&&!Array.isArray(value)
  &&[Object.prototype,null].includes(Object.getPrototypeOf(value))&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const sha256 = async (value:string) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),
  byte=>byte.toString(16).padStart(2,'0')).join('');
// This deterministic fixture digest checks source/snapshot binding only; it is not Messaging's production policy proof.
const policyFingerprint = 'b'.repeat(64);
async function validActivation(activation?:ActivationClaim) {
  if(activation===undefined)return true;
  if(!exactObject(activation,['version','principal','agent','agentIncarnation','source','verdict','policyFingerprint','snapshotDigest'])
    ||!exactObject(activation.source,['kind','subjectId','sourceStateVersion'])||!exactObject(activation.verdict,['allowed','reason'])
    ||activation.version!==1||activation.principal!==principal||activation.agent!==agent||activation.agentIncarnation!==1
    ||activation.source.kind!=='manual'||activation.verdict.allowed!==true||activation.verdict.reason!=='owner_direct'
    ||activation.policyFingerprint!==policyFingerprint)return false;
  const source={kind:'manual' as const,subjectId:activation.source.subjectId,sourceStateVersion:activation.source.sourceStateVersion};
  const result=await authority.prepareSourceActivation({namespace:messageNamespace,principal,agent,source});
  return result.status==='eligible'&&result.claim.source.kind==='manual'
    &&activation.source.subjectId===result.claim.source.subjectId&&activation.source.sourceStateVersion===result.claim.source.sourceStateVersion
    &&activation.snapshotDigest===result.claim.snapshotDigest;
}
const sameActivationSnapshot = (left:ActivationClaim,right:ActivationClaim) => left.version===right.version
  &&left.principal===right.principal&&left.agent===right.agent&&left.agentIncarnation===right.agentIncarnation
  &&left.source.kind==='manual'&&right.source.kind==='manual'
  &&left.source.subjectId===right.source.subjectId&&left.source.sourceStateVersion===right.source.sourceStateVersion
  &&left.verdict.allowed===right.verdict.allowed&&left.verdict.reason===right.verdict.reason
  &&left.policyFingerprint===right.policyFingerprint&&left.snapshotDigest===right.snapshotDigest;
const authority = {
  async registeredOwnerAgent() { return { status:'denied' }; },
  async currentAuth(x:Auth) { return valid(x) ? { status:'authorized', identity:{ principal,agent,keyThumbprint:'A'.repeat(43) } } : { status:'denied' }; },
  async prepareSourceActivation(input:ActivationInput) {
    const source=input?.source;
    const hasExpectedSnapshot=Object.hasOwn(input??{},'expectedSnapshot');
    if(!exactObject(input,hasExpectedSnapshot?['namespace','principal','agent','source','expectedSnapshot']:['namespace','principal','agent','source'])
      ||hasExpectedSnapshot&&(typeof input.expectedSnapshot!=='string'||!/^[0-9a-f]{64}$/.test(input.expectedSnapshot))
      ||!exactObject(source,['kind','subjectId','sourceStateVersion']))return { status:'invalid' } as const;
    if(input?.namespace!==messageNamespace||input.principal!==principal||input.agent!==agent||source?.kind!=='manual'
      ||!fixtureManualSubjects.has(source.subjectId)||typeof source.sourceStateVersion!=='string'||source.sourceStateVersion.length<1||source.sourceStateVersion.length>256)
      return { status:'denied' } as const;
    const snapshotDigest=await sha256(JSON.stringify([messageNamespace,principal,agent,1,source.kind,source.subjectId,
      source.sourceStateVersion,policyFingerprint]));
    if(hasExpectedSnapshot&&input.expectedSnapshot!==snapshotDigest)return { status:'changed' } as const;
    const claim:ActivationClaim={version:1,principal,agent,agentIncarnation:1,
      source:{kind:'manual',subjectId:source.subjectId,sourceStateVersion:source.sourceStateVersion},
      verdict:{allowed:true,reason:'owner_direct'},policyFingerprint,snapshotDigest};
    return { status:'eligible',claim } as const;
  },
  async nativeAttemptStatus(x:AttemptAuth) {
    if(!valid(x))return { status:'denied' } as const;
    const prior=reservations.get(x.attemptId);
    if(prior) {
      if(!!prior.activation!==!!x.activation||(prior.activation&&x.activation&&!sameActivationSnapshot(prior.activation,x.activation)))
        return { status:'denied' } as const;
      return {status:'reserved',attemptId:x.attemptId,reservedAt:prior.reservedAt,budget:budget()} as const;
    }
    return {status:'unknown',attemptId:x.attemptId,reservedAt:null,budget:budget()} as const;
  },
  async reserveNativeAttempt(x:AttemptAuth) {
    if(!valid(x))return { status:'denied' } as const;
    const previous=reservations.get(x.attemptId);
    if(previous) {
      if(!!previous.activation!==!!x.activation||(previous.activation&&x.activation&&!sameActivationSnapshot(previous.activation,x.activation)))
        return { status:'denied' } as const;
      return {status:'reserved',attemptId:x.attemptId,reservedAt:previous.reservedAt,idempotent:true,budget:budget()} as const;
    }
    if(!x.activation||!await validActivation(x.activation))return { status:'denied' } as const;
    const reservedAt=Date.now();reservations.set(x.attemptId,{reservedAt,activation:x.activation});
    return {status:'reserved',attemptId:x.attemptId,reservedAt,idempotent:false,budget:budget()} as const;
  },
};
async function fixtureAuthorityCheck(namespace:string) {
  const input:ActivationInput={namespace,principal,agent,source:{kind:'manual',subjectId:'fixture-manual-source',sourceStateVersion:'fixture-source-v1'}};
  const validClaim=await authority.prepareSourceActivation(input);
  const wrongScope=await authority.prepareSourceActivation({...input,principal:'other@example.com'});
  const reorderedSource=await authority.prepareSourceActivation({...input,source:{sourceStateVersion:'fixture-source-v1',subjectId:'fixture-manual-source',kind:'manual'}});
  const freshSnapshot=validClaim.status==='eligible'
    ? await authority.prepareSourceActivation({...input,expectedSnapshot:validClaim.claim.snapshotDigest}) : {status:'invalid'} as const;
  const stale=await authority.prepareSourceActivation({...input,expectedSnapshot:'0'.repeat(64)});
  const undefinedSnapshot=await authority.prepareSourceActivation({...input,expectedSnapshot:undefined});
  const changedSource=validClaim.status==='eligible'
    ? await authority.prepareSourceActivation({...input,source:{kind:'manual',subjectId:'fixture-manual-source',sourceStateVersion:'fixture-source-v2'},expectedSnapshot:validClaim.claim.snapshotDigest}) : {status:'invalid'} as const;
  if(validClaim.status!=='eligible'||wrongScope.status!=='denied'||reorderedSource.status!=='eligible'
    ||reorderedSource.claim.snapshotDigest!==validClaim.claim.snapshotDigest||freshSnapshot.status!=='eligible'
    ||stale.status!=='changed'||undefinedSnapshot.status!=='invalid'||changedSource.status!=='changed')
    throw new Error('fixture_activation_contract');
  const attempt:AttemptAuth={accessAssertion:'fixture-access',agentToken:'fixture-agent',attemptId:crypto.randomUUID(),activation:validClaim.claim};
  try {
    const validStatus=await authority.nativeAttemptStatus(attempt);
    const {activation:_activation,...unboundAttempt}=attempt;
    const optionalStatus=await authority.nativeAttemptStatus(unboundAttempt);
    const budgetBefore=budget().used;
    const unboundReserve=await authority.reserveNativeAttempt(unboundAttempt);
    const unboundAfter=await authority.nativeAttemptStatus(unboundAttempt);
    const invalidReserve=await authority.reserveNativeAttempt({...attempt,attemptId:crypto.randomUUID(),activation:{...validClaim.claim,principal:'other@example.com'}});
    const boundAfterInvalid=await authority.nativeAttemptStatus(attempt);
    const budgetAfterInvalid=budget().used;
    const validReserve=await authority.reserveNativeAttempt(attempt);
    const replayReserve=await authority.reserveNativeAttempt(attempt);
    const missingReplay=await authority.reserveNativeAttempt(unboundAttempt);
    const invalidStatus=await authority.nativeAttemptStatus({...attempt,activation:{...validClaim.claim,principal:'other@example.com'}});
    const reorderedClaim=await authority.nativeAttemptStatus({...attempt,activation:{...validClaim.claim,
      source:{sourceStateVersion:'fixture-source-v1',subjectId:'fixture-manual-source',kind:'manual'}}});
    const reservedStatus=await authority.nativeAttemptStatus(attempt);
    if(validStatus.status!=='unknown'||optionalStatus.status!=='unknown'||unboundReserve.status!=='denied'||unboundAfter.status!=='unknown'
      ||boundAfterInvalid.status!=='unknown'||budgetAfterInvalid!==budgetBefore||invalidReserve.status!=='denied'
      ||validReserve.status!=='reserved'||replayReserve.status!=='reserved'||!replayReserve.idempotent
      ||replayReserve.reservedAt!==validReserve.reservedAt||replayReserve.budget.used!==validReserve.budget.used
      ||missingReplay.status!=='denied'||invalidStatus.status!=='denied'||reorderedClaim.status!=='reserved'||reservedStatus.status!=='reserved')
      throw new Error('fixture_attempt_authority_contract');
    return {validClaim:validClaim.status,wrongScope:wrongScope.status,reorderedSource:reorderedSource.status,
      freshSnapshot:freshSnapshot.status,staleSnapshot:stale.status,undefinedSnapshot:undefinedSnapshot.status,changedSource:changedSource.status,
      validStatus:validStatus.status,optionalStatus:optionalStatus.status,unboundReserve:unboundReserve.status,
      boundAfterInvalid:boundAfterInvalid.status,validReserve:validReserve.status,replayReserve:replayReserve.status,
      replayIdempotent:replayReserve.idempotent,missingReplay:missingReplay.status,invalidStatus:invalidStatus.status,
      invalidReserve:invalidReserve.status,reorderedClaim:reorderedClaim.status,reservedStatus:reservedStatus.status};
  } finally { reservations.delete(attempt.attemptId); }
}
const metadata = { metrics:{ backlogCount:0,backlogBytes:0 } };
const queue = { async send(){return {metadata};}, async sendBatch(){return {metadata};}, async metrics(){return metadata.metrics;} };
export class FixtureCoordinator extends AgentCoordinator {
  readonly #threeSession: boolean;
  constructor(ctx:CoordinatorContext,env:CoordinatorEnv & {FIXTURE_THREE_SESSION_CANARY?:string}) {
    super(ctx,{...env,MESSAGE_AUTHORITY:authority as unknown as CoordinatorEnv['MESSAGE_AUTHORITY'],DELIVERY_QUEUE:queue as unknown as CoordinatorEnv['DELIVERY_QUEUE']});
    this.#threeSession=env.FIXTURE_THREE_SESSION_CANARY==='true';
  }
  async fixtureSetup(x:FixtureSetup) {
    if(!this.#threeSession)return this.#setup(x);
    return this.ctx.blockConcurrencyWhile(async()=>{
      if(!threeSessionSubjects.has(x.subjectId??''))throw new Error('fixture_manual_subject_refused');
      const original=this.env.EVENT_MANUAL_CANARY;
      const scope=JSON.parse(original??'');
      // Sequential synthetic deployment scopes retain the one broker deadline.
      this.env.EVENT_MANUAL_CANARY=JSON.stringify({...scope,subjectId:x.subjectId});
      try{return await this.#setup(x);}
      finally{this.env.EVENT_MANUAL_CANARY=original;}
    });
  }
  async #setup(x:FixtureSetup) {
    await this.setEnabled({enabled:true});
    const job={principal,agent,...await this.publishManual({runtimeId:x.runtimeId,subjectId:x.subjectId??'fixture-manual-source'})};
    const transport=await this.claimTransport(job);
    if(!transport) throw new Error('fixture_transport_claim_refused');
    const req=await signedEventRequest({EVENT_TRANSPORT_PRIVATE_KEY:x.transportPrivateKey,EVENT_TRANSPORT_KEY_ID:'fixture-transport',
      MESH:{async fetch(){throw new Error('fixture_no_mesh');}}}, {nodeId:x.nodeId,meshIp:'100.96.0.1',meshPort:8789},transport.envelope);
    return {...transport,signedDelivery:{body:await req.text(),headers:Object.fromEntries(req.headers)}};
  }
  async fixtureAdmission() {
    await this.status();
    return Object.fromEntries(['runtimes','native_runtime_bindings'].map(t=>[t,this.ctx.storage.sql.exec(`SELECT * FROM ${t}`).toArray()]));
  }
  async fixtureAlarm() { await this.alarm(); }
  async fixtureRead() {
    await this.status();
    const tables=['attempts','deliveries','native_claims','native_correlations','manual_sources','slot_intents','no_start_settlements'];
    return Object.fromEntries(tables.map(t=>[t,this.ctx.storage.sql.exec(`SELECT * FROM ${t}`).toArray()]));
  }
}
export class FixtureRegistry extends OwnerRegistry {
  async fixtureRead() { await this.status(); return this.ctx.storage.sql.exec('SELECT * FROM slots').toArray(); }
}
export default { async fetch(request:Request,env:FixtureEnv) {
  if (request.headers.get('x-fixture-secret')!==env.FIXTURE_SECRET) return new Response(null,{status:403});
  const path=new URL(request.url).pathname;
  const registry=env.OWNER_REGISTRY.getByName(ownerRegistryName(principal));
  const coordinator=env.AGENT_COORDINATOR.getByName(coordinatorName(principal,agent));
  if(path==='/fixture/authority-contract') return Response.json(await fixtureAuthorityCheck(env.MESSAGE_NAMESPACE));
  if(path==='/fixture/challenge') return Response.json(await registry.createChallenge(await request.json()));
  if(path==='/fixture/admission') return Response.json(await coordinator.fixtureAdmission());
  if(path==='/fixture/setup') return Response.json(await coordinator.fixtureSetup(await request.json()));
  if(path==='/fixture/read') return Response.json({cloud:await coordinator.fixtureRead(),slots:await registry.fixtureRead(),budget:budget()});
  if(path==='/fixture/alarm') { await coordinator.fixtureAlarm(); return Response.json({ok:true}); }
  // Explicit mock Access edge: only our exact synthetic token is forwarded as assertion.
  if(request.headers.get('cf-access-token')==='fixture-access') {
    const headers=new Headers(request.headers); headers.set('cf-access-jwt-assertion','fixture-access');
    request=new Request(request,{headers});
  }
  return eventFetch(request,{...env,MESSAGE_AUTHORITY:authority as unknown as EventApiEnvironment['MESSAGE_AUTHORITY']});
} };
