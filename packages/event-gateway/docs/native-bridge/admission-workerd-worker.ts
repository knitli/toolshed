// Disposable admission proof: synthetic Access/Messaging, real registry and coordinator.
import { eventFetch } from 'fixture-event-runtime/api.ts';
import { AgentCoordinator } from 'fixture-event-runtime/coordinator.ts';
import { OwnerRegistry, ownerRegistryName } from 'fixture-event-runtime/registry.ts';
import { coordinatorName, type EventApiEnvironment } from 'fixture-event-runtime/contracts.ts';
const principal = 'qualification@example.com', agent = 'pilot';
const authority = {
  async currentAuth(x: {accessAssertion:string;agentToken:string}) {
    return x.accessAssertion === 'fixture-access' && x.agentToken === 'fixture-agent'
      ? {status:'authorized',identity:{principal,agent,keyThumbprint:'A'.repeat(43)}} : {status:'denied'};
  },
};
export class AdmissionCoordinator extends AgentCoordinator {
  constructor(ctx:ConstructorParameters<typeof AgentCoordinator>[0],env:ConstructorParameters<typeof AgentCoordinator>[1]) {
    super(ctx,{...env,MESSAGE_AUTHORITY:authority as unknown as typeof env.MESSAGE_AUTHORITY});
  }
  async fixtureRead() {
    return Object.fromEntries(['runtimes','native_runtime_bindings','native_runtime_challenges'].map(table =>
      [table,this.ctx.storage.sql.exec(`SELECT * FROM ${table}`).toArray()]));
  }
}
export { OwnerRegistry };
type Env = EventApiEnvironment & {FIXTURE_SECRET:string;AGENT_COORDINATOR:DurableObjectNamespace<AdmissionCoordinator>};
export default {async fetch(request:Request, env:Env) {
  if(request.headers.get('x-fixture-secret') !== env.FIXTURE_SECRET) return new Response(null,{status:403});
  const path = new URL(request.url).pathname;
  if(path === '/fixture/challenge') return Response.json(await env.OWNER_REGISTRY.getByName(ownerRegistryName(principal)).createChallenge(await request.json()));
  if(path === '/fixture/read') return Response.json(await env.AGENT_COORDINATOR.getByName(coordinatorName(principal,agent)).fixtureRead());
  const headers = new Headers(request.headers);
  if(headers.get('cf-access-token') === 'fixture-access') headers.set('cf-access-jwt-assertion','fixture-access');
  return eventFetch(new Request(request,{headers}),{...env,
    EVENT_NATIVE_BINDING_ENABLED: headers.get('x-fixture-gate-disabled') === 'true' ? 'false' : 'true',
    EVENT_NATIVE_BINDING_CANARY: headers.get('x-fixture-canary-mismatch') === 'true' ? JSON.stringify({principal:'other@example.com',agent}) : env.EVENT_NATIVE_BINDING_CANARY,
    MESSAGE_AUTHORITY:authority as unknown as EventApiEnvironment['MESSAGE_AUTHORITY']});
}};
