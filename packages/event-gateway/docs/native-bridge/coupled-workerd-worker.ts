// Disposable fixture only: no production qualification or Access authority claim.
import { signedEventRequest } from 'fixture-event-runtime/delivery.ts';
import { eventFetch } from 'fixture-event-runtime/api.ts';
import { AgentCoordinator } from 'fixture-event-runtime/coordinator.ts';
import { OwnerRegistry, ownerRegistryName } from 'fixture-event-runtime/registry.ts';
import { coordinatorName, type EventApiEnvironment } from 'fixture-event-runtime/contracts.ts';
type Auth = { accessAssertion: string; agentToken: string };
type AttemptAuth = Auth & { attemptId: string };
type FixtureSetup = { runtimeId: string; nodeId: string; transportPrivateKey: string };
type CoordinatorContext = ConstructorParameters<typeof AgentCoordinator>[0];
type CoordinatorEnv = ConstructorParameters<typeof AgentCoordinator>[1];
type FixtureEnv = Omit<EventApiEnvironment, 'OWNER_REGISTRY' | 'AGENT_COORDINATOR'> & {
  FIXTURE_SECRET: string;
  OWNER_REGISTRY: DurableObjectNamespace<FixtureRegistry>;
  AGENT_COORDINATOR: DurableObjectNamespace<FixtureCoordinator>;
};
const principal = 'qualification@example.com', agent = 'pilot';
const reservations = new Set<string>();
const budget = () => ({ used: reservations.size, remaining: 10-reservations.size, limit: 10, windowMs: 3600000 });
const valid = (x:Auth) => x.accessAssertion === 'fixture-access' && x.agentToken === 'fixture-agent';
const authority = {
  async registeredOwnerAgent() { return { status:'denied' }; },
  async currentAuth(x:Auth) { return valid(x) ? { status:'authorized', identity:{ principal,agent,keyThumbprint:'A'.repeat(43) } } : { status:'denied' }; },
  async nativeAttemptStatus(x:AttemptAuth) { return valid(x) ? { status:reservations.has(x.attemptId)?'reserved':'unknown', attemptId:x.attemptId,reservedAt:null,budget:budget() } : { status:'denied' }; },
  async reserveNativeAttempt(x:AttemptAuth) { if (!valid(x)) return { status:'denied' }; const idempotent=reservations.has(x.attemptId); reservations.add(x.attemptId); return { status:'reserved',attemptId:x.attemptId,reservedAt:Date.now(),idempotent,budget:budget() }; },
};
const metadata = { metrics:{ backlogCount:0,backlogBytes:0 } };
const queue = { async send(){return {metadata};}, async sendBatch(){return {metadata};}, async metrics(){return metadata.metrics;} };
export class FixtureCoordinator extends AgentCoordinator {
  constructor(ctx:CoordinatorContext,env:CoordinatorEnv) { super(ctx,{...env,MESSAGE_AUTHORITY:authority as unknown as CoordinatorEnv['MESSAGE_AUTHORITY'],DELIVERY_QUEUE:queue as unknown as CoordinatorEnv['DELIVERY_QUEUE']}); }
  async fixtureSetup(x:FixtureSetup) {
    this.ctx.storage.sql.exec('INSERT INTO runtimes VALUES (?,1,?,1,1,?,1)',x.runtimeId,x.nodeId,Date.now()+90000);
    await this.setEnabled({enabled:true});
    const job={principal,agent,...await this.publishManual({runtimeId:x.runtimeId,subjectId:'fixture-manual-source'})};
    const transport=await this.claimTransport(job);
    if(!transport) throw new Error('fixture_transport_claim_refused');
    const req=await signedEventRequest({EVENT_TRANSPORT_PRIVATE_KEY:x.transportPrivateKey,EVENT_TRANSPORT_KEY_ID:'fixture-transport',
      MESH:{async fetch(){throw new Error('fixture_no_mesh');}}}, {nodeId:x.nodeId,meshIp:'100.96.0.1',meshPort:8789},transport.envelope);
    return {...transport,signedDelivery:{body:await req.text(),headers:Object.fromEntries(req.headers)}};
  }
  async fixtureAlarm() { await this.alarm(); }
  async fixtureRead() {
    const tables=['attempts','deliveries','native_claims','native_correlations','manual_sources','slot_intents','no_start_settlements'];
    return Object.fromEntries(tables.map(t=>[t,this.ctx.storage.sql.exec(`SELECT * FROM ${t}`).toArray()]));
  }
}
export class FixtureRegistry extends OwnerRegistry {
  async fixtureRead() { return this.ctx.storage.sql.exec('SELECT * FROM slots').toArray(); }
}
export default { async fetch(request:Request,env:FixtureEnv) {
  if (request.headers.get('x-fixture-secret')!==env.FIXTURE_SECRET) return new Response(null,{status:403});
  const path=new URL(request.url).pathname;
  const registry=env.OWNER_REGISTRY.getByName(ownerRegistryName(principal));
  const coordinator=env.AGENT_COORDINATOR.getByName(coordinatorName(principal,agent));
  if(path==='/fixture/challenge') return Response.json(await registry.createChallenge(await request.json()));
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
