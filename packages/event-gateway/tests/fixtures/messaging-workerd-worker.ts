// Disposable local proof: approved state is seeded; admission and reservation use production methods.
import { eventFetch } from 'fixture-event-runtime/api.ts';
import { AgentCoordinator } from 'fixture-event-runtime/coordinator.ts';
import { OwnerRegistry, ownerRegistryName } from 'fixture-event-runtime/registry.ts';
import { coordinatorName, type EventApiEnvironment } from 'fixture-event-runtime/contracts.ts';
import { signedEventRequest, type TransportEnvironment } from 'fixture-event-runtime/delivery.ts';
import { Mailbox } from 'gatekeeper-messaging/src/mailbox.ts';
import { EventAuthority } from 'gatekeeper-messaging/src/event-authority.ts';
import type { EventAuthorityAttemptV1, EventMessageAttemptV1 } from 'gatekeeper-messaging/src/event-authority-contract.ts';
import { canonicalMessagePublication } from 'gatekeeper-messaging/src/event-bridge.ts';
import { mailboxName, detach, NO_FLAGS } from 'gatekeeper-messaging/src/model.ts';
export { MessageConsumerAuthority } from 'fixture-event-runtime/message-consumer-authority.ts';

const principal = 'b@knitli.com', sender = 'a@knitli.com', agent = 'ws', namespace = 'fixture-messaging';
type Seed = { nodeId: string; runtimeId: string };
type FixtureEnv = Omit<EventApiEnvironment, 'OWNER_REGISTRY' | 'AGENT_COORDINATOR'> & TransportEnvironment & {
  FIXTURE_SECRET: string;
  FIXTURE_AGENT_JWK: string;
  MAILBOX: DurableObjectNamespace<FixtureMailbox>;
  OWNER_REGISTRY: DurableObjectNamespace<FixtureRegistry>;
  AGENT_COORDINATOR: DurableObjectNamespace<FixtureCoordinator>;
};
const consumerOf = ({ nodeId, runtimeId }: Seed) => ({ nodeId, runtimeId, nodeGeneration: 1,
  runtimeGeneration: 1, attachmentGeneration: 1, consumerGeneration: 1 });

export class FixtureEventAuthority extends EventAuthority {
  private readonly crashBarrier?: Fetcher;

  constructor(ctx: ExecutionContext, env: ConstructorParameters<typeof EventAuthority>[1] & {
    FIXTURE_ACCESS_JWK: string; FIXTURE_CRASH_BARRIER?: Fetcher;
  }) {
    super(ctx, env, { now: () => Math.floor(Date.now() / 1000),
      fetch: async () => Response.json({ keys: [JSON.parse(env.FIXTURE_ACCESS_JWK)] }) });
    this.crashBarrier = env.FIXTURE_CRASH_BARRIER;
  }

  override async reserveMessageAttempt(input: EventMessageAttemptV1) {
    if (this.crashBarrier) await this.crashBarrier.fetch('https://barrier.invalid/before-reserve');
    const result = await super.reserveMessageAttempt(input);
    // The Mailbox RPC response crossed its storage output gate; no pre-crash read or flush is added.
    if (this.crashBarrier && result.status === 'reserved')
      await this.crashBarrier.fetch('https://barrier.invalid/after-reserve');
    return result;
  }

  override async reserveNativeAttempt(input: EventAuthorityAttemptV1) {
    if (this.crashBarrier) {
      await this.crashBarrier.fetch('https://barrier.invalid/generic-fallback');
      throw new Error('unexpected_generic_reservation');
    }
    return super.reserveNativeAttempt(input);
  }

  override async nativeAttemptStatus(input: EventAuthorityAttemptV1) {
    if (this.crashBarrier) {
      await this.crashBarrier.fetch('https://barrier.invalid/generic-fallback');
      throw new Error('unexpected_generic_status');
    }
    return super.nativeAttemptStatus(input);
  }
}

export class FixtureRegistry extends OwnerRegistry {
  async fixtureSeed(input: Seed, publicKey: JsonWebKey) {
    await this.admitCoordinator({ agent });
    this.ctx.storage.sql.exec('INSERT INTO nodes VALUES (?,1,0,?)', input.nodeId,
      JSON.stringify({ nodeId: input.nodeId, agents: [agent],
        publicKey: { kty: 'OKP', crv: 'Ed25519', x: publicKey.x }, meshIp: '100.96.0.1', meshPort: 8789 }));
  }
}

export class FixtureMailbox extends Mailbox {
  async fixtureAgent(publicKey?: JsonWebKey) {
    this.registerAgent(agent, 'external');
    if (!publicKey) return null;
    const thumbprint = await this.addAgentKey(agent, publicKey);
    this.ctx.storage.sql.exec("UPDATE agent_keys SET state='active' WHERE thumbprint=?", thumbprint);
    this.ctx.storage.sql.exec("UPDATE agents SET activation_mode='granted',activation_transports='[\"event\"]' WHERE name='ws'");
    return thumbprint;
  }

  fixturePublication(input: Seed, messageId: string, thumbprint: string) {
    const sql = this.ctx.storage.sql;
    const incarnation = sql.exec<{ created_at: number }>("SELECT created_at FROM agents WHERE name='ws'").one().created_at;
    const consumer = consumerOf(input), operationId = crypto.randomUUID();
    sql.exec("INSERT INTO message_wake_routes VALUES ('ws','event',1,?)", JSON.stringify(consumer));
    sql.exec("INSERT INTO message_route_operations VALUES (?,'ws',?,?,?,?)", operationId, incarnation,
      JSON.stringify({ operationId, namespace, principal, agent, agentCreatedAt: incarnation,
        expectedGeneration: 0, owner: 'event', consumer, keyThumbprint: thumbprint }),
      JSON.stringify({ previous: { owner: 'os', generation: 0, consumer: null },
        route: { owner: 'event', generation: 1, consumer } }), Date.now());
    const publication = canonicalMessagePublication(sql, { namespace, principal, admitted: () => true }, agent, messageId, Date.now());
    if (!publication) throw new Error('fixture_publication_missing');
    return publication;
  }

  fixtureRead() {
    return { budget: this.ctx.storage.kv.get('wake-budget:ws') ?? null,
      message_attempts: this.ctx.storage.sql.exec('SELECT attempt_id FROM message_wake_attempts').toArray() };
  }

  fixtureChange(kind: string) {
    if (kind === 'route') this.ctx.storage.sql.exec("UPDATE message_wake_routes SET generation=generation+1 WHERE agent='ws'");
    else if (kind === 'key') this.ctx.storage.sql.exec("UPDATE agent_keys SET state='provisional' WHERE agent='ws'");
    else if (kind === 'source') this.ctx.storage.sql.exec("UPDATE grants SET revoked_at=1 WHERE direction='in'");
    else throw new Error('invalid_fixture_change');
  }
}

export class FixtureCoordinator extends AgentCoordinator {
  constructor(ctx: DurableObjectState, env: ConstructorParameters<typeof AgentCoordinator>[1]) {
    super(ctx, { ...env, DELIVERY_QUEUE: {
      send: async () => ({ metadata: { metrics: { backlogCount: 0, backlogBytes: 0 } } }),
      sendBatch: async () => { throw new Error('unexpected_fixture_queue_batch'); },
      metrics: async () => { throw new Error('unexpected_fixture_queue_metrics'); },
    } });
  }

  // Fixture controls scheduling; the production alarm is invoked explicitly after publication.
  override async alarm() {}

  async fixtureSeed(input: Seed, thumbprint: string) {
    await this.setEnabled({ enabled: true });
    const attachment = { clientId: crypto.randomUUID(), connectionId: crypto.randomUUID(), backendPid: 1234,
      threadId: crypto.randomUUID(), generation: 1, serverInstanceId: crypto.randomUUID(), serverGeneration: 1 };
    this.ctx.storage.sql.exec('INSERT INTO runtimes VALUES (?,?,?,?,?,?,?)', input.runtimeId, 1, input.nodeId, 1, 1, Date.now() + 600_000, 1);
    this.ctx.storage.sql.exec('INSERT INTO native_runtime_bindings VALUES (?,?,?,?,?,?)', input.runtimeId,
      attachment.clientId, thumbprint, JSON.stringify(attachment), 1, 1);
    return attachment;
  }

  fixtureRotateConsumer() {
    this.ctx.storage.sql.exec('UPDATE runtimes SET attachment_generation=attachment_generation+1');
  }

  async fixturePublish(publication: unknown) {
    await this.publishMessage(publication);
    this.ctx.storage.sql.exec('UPDATE message_publications SET next_at=0');
    await super.alarm();
    const deliveryId = this.ctx.storage.sql.exec<{ delivery_id: string }>('SELECT delivery_id FROM deliveries').one().delivery_id;
    const transport = await this.claimTransport({ principal, agent, deliveryId });
    await this.ctx.storage.deleteAlarm();
    if (transport?.envelope.schemaVersion !== 2) throw new Error('fixture_v2_transport_missing');
    return transport;
  }

  fixtureRead() {
    return {
      attempts: this.ctx.storage.sql.exec('SELECT attempt_id,state,permit_id,reservation_state FROM attempts').toArray(),
      native_claims: this.ctx.storage.sql.exec('SELECT attempt_id,state,permit_id FROM native_claims').toArray(),
      deliveries: this.ctx.storage.sql.exec('SELECT delivery_id,state FROM deliveries').toArray(),
      slot_intents: this.ctx.storage.sql.exec('SELECT delivery_id FROM slot_intents').toArray(),
    };
  }
}

export default { async fetch(request: Request, env: FixtureEnv) {
  if (request.headers.get('x-fixture-secret') !== env.FIXTURE_SECRET) return new Response(null, { status: 403 });
  const path = new URL(request.url).pathname;
  const mailbox = env.MAILBOX.getByName(mailboxName(namespace, principal));
  const coordinator = env.AGENT_COORDINATOR.getByName(coordinatorName(principal, agent));
  if (path === '/fixture/seed') {
    const input = await request.json() as Seed;
    for (const value of [input.nodeId, input.runtimeId]) if (typeof value !== 'string' || !/^[0-9a-f-]{36}$/.test(value))
      return Response.json({ error: 'invalid_fixture_seed' }, { status: 400 });
    const publicKey = JSON.parse(env.FIXTURE_AGENT_JWK) as JsonWebKey;
    const senderMailbox = env.MAILBOX.getByName(mailboxName(namespace, sender));
    await senderMailbox.fixtureAgent();
    const thumbprint = await mailbox.fixtureAgent(publicKey);
    if (thumbprint === null) throw new Error('fixture_key_missing');
    for (const [from, to] of [[sender, principal], [principal, sender]]) {
      const fromMailbox = env.MAILBOX.getByName(mailboxName(namespace, from));
      const toMailbox = env.MAILBOX.getByName(mailboxName(namespace, to));
      await fromMailbox.grant({ agent, to: `${to}/${agent}`, mode: 'standing', expiresAt: null });
      await toMailbox.offer({ agent, from: `${from}/${agent}`, expiresAt: null });
      const offer = (await toMailbox.grants()).find(g => g.direction === 'in' && g.peer === `${from}/${agent}`);
      if (!offer) throw new Error('fixture_offer_missing');
      await toMailbox.acceptOffer(offer.id, null);
    }
    await env.OWNER_REGISTRY.getByName(ownerRegistryName(principal)).fixtureSeed(input, publicKey);
    const attachment = await coordinator.fixtureSeed(input, thumbprint);
    const message = detach(await senderMailbox.issue({ id: crypto.randomUUID(), kind: 'request', parentId: null,
      sender: { principal: sender, agent, client: 'os', endpoint: 'fixture-sender' }, recipient: `${principal}/${agent}`,
      subject: 'Fixture message', body: 'private reservation body', taskType: null, expiresAt: null,
      idempotencyKey: null, requestDigest: `digest-${crypto.randomUUID()}`, attested: [sender, principal],
      attestedFlags: NO_FLAGS, applied: 'send' }));
    await mailbox.deliver(message);
    const publication = await mailbox.fixturePublication(input, message.id, thumbprint);
    const transport = await coordinator.fixturePublish(publication);
    const signed = await signedEventRequest(env, transport.destination, transport.envelope);
    return Response.json({ envelope: transport.envelope, body: await signed.text(), attachment,
      signature: signed.headers.get('x-event-signature'), audience: signed.headers.get('x-event-audience'),
      keyId: signed.headers.get('x-event-key-id') });
  }
  if (path === '/fixture/read') return Response.json({ ...await mailbox.fixtureRead(), ...await coordinator.fixtureRead() });
  if (path === '/fixture/change') {
    const { kind } = await request.json() as { kind: string };
    if (kind === 'consumer') await coordinator.fixtureRotateConsumer();
    else await mailbox.fixtureChange(kind);
    return Response.json({ changed: true });
  }
  const headers = new Headers(request.headers);
  const assertion = headers.get('cf-access-token');
  if (assertion) headers.set('cf-access-jwt-assertion', assertion);
  return eventFetch(new Request(request, { headers }), env);
} };
