import { z } from "zod";
import {
  EVENT_CLOCK_SKEW_MS,
  EVENT_FRESHNESS_LIFETIME_MS,
  EVENT_PROTOCOL_VERSION,
  MAX_PROTOCOL_MESSAGE_BYTES,
} from "./policy.js";

const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const UUID_V4_OR_V7_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DELIVERY_ID_PATTERN = /^dly_[0-9a-f]{64}$/;
const EVENT_REFERENCE_PATTERN =
  /^ref_[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINCIPAL_PATTERN =
  /^(?=[^@]{1,64}@)[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const AGENT_PATTERN = /^[a-z0-9-]{1,32}$/;
const OPAQUE_TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const NATIVE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REPOSITORY_ID_PATTERN = /^[1-9][0-9]{0,19}$/;
const CANONICAL_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const uuidV4OrV7Schema = z.string().regex(UUID_V4_OR_V7_PATTERN);
const deliveryIdSchema = z.string().regex(DELIVERY_ID_PATTERN);
const eventReferenceSchema = z.string().regex(EVENT_REFERENCE_PATTERN);
const principalSchema = z.string().max(254).regex(PRINCIPAL_PATTERN);
const agentSchema = z.string().regex(AGENT_PATTERN);
const opaqueTokenSchema = z.string().regex(OPAQUE_TOKEN_PATTERN);
const nativeIdSchema = z.string().regex(NATIVE_ID_PATTERN);
const generationSchema = z
  .number()
  .int()
  .min(1)
  .max(MAX_SAFE_INTEGER);
const timestampSchema = z.iso.datetime({ precision: 3 });

const manualSubjectSchema = z.strictObject({
  kind: z.literal("manual"),
  subjectId: opaqueTokenSchema,
});

const githubSubjectSchema = z.strictObject({
  kind: z.literal("github_pr"),
  repositoryId: z.string().regex(REPOSITORY_ID_PATTERN),
  pullRequestNumber: generationSchema,
});

const commonEnvelopeShape = {
  schemaVersion: z.literal(EVENT_PROTOCOL_VERSION),
  eventId: uuidV4OrV7Schema,
  canonicalSubject: z.union([manualSubjectSchema, githubSubjectSchema]),
  sourceStateVersion: opaqueTokenSchema,
  policyRevision: generationSchema,
  observedAt: timestampSchema,
  principal: principalSchema,
  agent: agentSchema,
  eventReference: eventReferenceSchema,
  runtimeId: uuidV4OrV7Schema,
  nodeGeneration: generationSchema,
  runtimeGeneration: generationSchema,
  attachmentGeneration: generationSchema,
  deliveryId: deliveryIdSchema,
  attemptId: uuidV4OrV7Schema,
  issuedAt: timestampSchema,
  expiresAt: timestampSchema,
  candidateGeneration: generationSchema.optional(),
  consumerGeneration: generationSchema.optional(),
};

const manualEnvelopeSchema = z.strictObject({
  ...commonEnvelopeShape,
  source: z.literal("manual"),
  canonicalSubject: manualSubjectSchema,
  eventKind: z.literal("manual"),
  reasonCode: z.literal("owner_canary"),
});

const githubEnvelopeBase = {
  ...commonEnvelopeShape,
  source: z.literal("github"),
  canonicalSubject: githubSubjectSchema,
};

const githubAttentionEnvelopeSchema = z.strictObject({
  ...githubEnvelopeBase,
  eventKind: z.literal("attention"),
  reasonCode: z.enum([
    "review_requested",
    "review_submitted",
    "review_comment",
  ]),
});

const githubCiEnvelopeSchema = z.strictObject({
  ...githubEnvelopeBase,
  eventKind: z.literal("ci"),
  reasonCode: z.enum(["check_failed", "status_failed"]),
});

const githubTerminalEnvelopeSchema = z.strictObject({
  ...githubEnvelopeBase,
  eventKind: z.literal("terminal"),
  reasonCode: z.enum(["pull_request_closed", "pull_request_merged"]),
});

const githubCompletionEnvelopeSchema = z.strictObject({
  ...githubEnvelopeBase,
  candidateGeneration: generationSchema,
  eventKind: z.literal("completion"),
  reasonCode: z.enum([
    "round_complete",
    "round_complete_with_waivers",
  ]),
});

/**
 * Closed metadata-only v1 envelope. Subject/reference values are identifiers;
 * prompt text, reviewer text, URLs, local paths, PIDs, and native session IDs
 * are not part of this wire contract.
 */
export const EventEnvelopeSchema = z.union([
  manualEnvelopeSchema,
  githubAttentionEnvelopeSchema,
  githubCiEnvelopeSchema,
  githubTerminalEnvelopeSchema,
  githubCompletionEnvelopeSchema,
]);

const commonAcknowledgmentShape = {
  schemaVersion: z.literal(EVENT_PROTOCOL_VERSION),
  eventId: uuidV4OrV7Schema,
  deliveryId: deliveryIdSchema,
  attemptId: uuidV4OrV7Schema,
  principal: principalSchema,
  agent: agentSchema,
  runtimeId: uuidV4OrV7Schema,
  nodeGeneration: generationSchema,
  runtimeGeneration: generationSchema,
  attachmentGeneration: generationSchema,
  consumerGeneration: generationSchema.optional(),
  deliveredSourceStateVersion: opaqueTokenSchema,
  acknowledgedAt: timestampSchema,
};

const submittedAcknowledgmentSchema = z.strictObject({
  ...commonAcknowledgmentShape,
  status: z.literal("submitted"),
  nativeCorrelation: z.union([
    z.strictObject({
      kind: z.literal("queued"),
      submissionId: nativeIdSchema,
    }),
    z.strictObject({
      kind: z.literal("native_turn_started"),
      permitId: uuidV4OrV7Schema,
      turnId: uuidV4OrV7Schema,
    }),
  ]),
});

const nativeInputRecordedCorrelationSchema = z.strictObject({
  kind: z.literal("native_input_recorded"),
  permitId: uuidV4OrV7Schema,
  turnId: uuidV4OrV7Schema,
  itemId: uuidV4OrV7Schema.meta({ "x-distinct-from": "turnId" }),
}).refine(correlation => correlation.itemId !== correlation.turnId, {
  message: "itemId must differ from turnId",
});

const observedAcknowledgmentSchema = z.strictObject({
  ...commonAcknowledgmentShape,
  status: z.literal("observed"),
  nativeCorrelation: z.union([
    z.strictObject({
      kind: z.literal("turn"),
      submissionId: nativeIdSchema,
      turnId: nativeIdSchema,
    }),
    nativeInputRecordedCorrelationSchema,
  ]),
});

/**
 * A queue receipt or direct native-turn registration is `submitted`; it does
 * not prove input observation. `observed` is either a queue-correlated turn or
 * the input-recorded item bound to an already registered native turn. The
 * version is the one delivered to this runtime, never a mutable watermark.
 */
export const EventObservationAckSchema = z.union([
  submittedAcknowledgmentSchema,
  observedAcknowledgmentSchema,
]);

export const EventProtocolMessageSchema = z.union([
  EventEnvelopeSchema,
  EventObservationAckSchema,
]);

/** JSON Schema artifact is checked against protocol.schema.json in tests. */
export const EVENT_PROTOCOL_JSON_SCHEMA = z.toJSONSchema(
  EventProtocolMessageSchema,
  { target: "draft-2020-12" },
);

export type EventEnvelopeV1 = z.infer<typeof EventEnvelopeSchema>;
export type EventObservationAckV1 = z.infer<typeof EventObservationAckSchema>;
export type EventProtocolMessageV1 = z.infer<
  typeof EventProtocolMessageSchema
>;
export type EventSource = EventEnvelopeV1["source"];
export type EventKind = EventEnvelopeV1["eventKind"];
export type EventReasonCode = EventEnvelopeV1["reasonCode"];
export type EventCanonicalSubject = EventEnvelopeV1["canonicalSubject"];
export type EventPrincipal = EventEnvelopeV1["principal"];
export type EventAgent = EventEnvelopeV1["agent"];
export type EventReference = EventEnvelopeV1["eventReference"];

export type EventProtocolErrorCode =
  | "message_too_large"
  | "invalid_json"
  | "duplicate_json_key"
  | "invalid_envelope"
  | "invalid_acknowledgment"
  | "stale_message"
  | "invalid_delivery_identity";

export class EventProtocolError extends Error {
  constructor(readonly code: EventProtocolErrorCode) {
    super(code);
    this.name = "EventProtocolError";
  }
}

export function isUuidV4OrV7(value: string): boolean {
  return UUID_V4_OR_V7_PATTERN.test(value);
}

export function isDeliveryId(value: string): boolean {
  return DELIVERY_ID_PATTERN.test(value);
}

function canonicalTimestampMs(value: string): number | null {
  if (!CANONICAL_TIMESTAMP_PATTERN.test(value)) return null;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return null;
  return new Date(timestamp).toISOString() === value ? timestamp : null;
}

function envelopeIsFresh(envelope: EventEnvelopeV1, nowMs: number): boolean {
  const issuedAt = canonicalTimestampMs(envelope.issuedAt);
  const expiresAt = canonicalTimestampMs(envelope.expiresAt);
  const observedAt = canonicalTimestampMs(envelope.observedAt);
  if (issuedAt === null || expiresAt === null || observedAt === null) {
    return false;
  }

  return (
    Number.isFinite(nowMs) &&
    expiresAt > issuedAt &&
    expiresAt - issuedAt <= EVENT_FRESHNESS_LIFETIME_MS &&
    issuedAt <= nowMs + EVENT_CLOCK_SKEW_MS &&
    nowMs <= expiresAt + EVENT_CLOCK_SKEW_MS &&
    observedAt <= issuedAt + EVENT_CLOCK_SKEW_MS &&
    observedAt <= nowMs + EVENT_CLOCK_SKEW_MS
  );
}

function acknowledgmentTimeIsValid(
  acknowledgment: EventObservationAckV1,
  nowMs: number,
): boolean {
  const acknowledgedAt = canonicalTimestampMs(acknowledgment.acknowledgedAt);
  return (
    acknowledgedAt !== null &&
    Number.isFinite(nowMs) &&
    acknowledgedAt <= nowMs + EVENT_CLOCK_SKEW_MS
  );
}

function encodedJsonSize(value: unknown): number | null {
  try {
    const json = JSON.stringify(value);
    return typeof json === "string"
      ? new TextEncoder().encode(json).byteLength
      : null;
  } catch {
    return null;
  }
}

/** Type guard for already-decoded values; wire callers should use the parser. */
export function validateEventEnvelope(
  value: unknown,
  nowMs = Date.now(),
): value is EventEnvelopeV1 {
  const result = EventEnvelopeSchema.safeParse(value);
  return (
    result.success &&
    (encodedJsonSize(value) ?? Infinity) <= MAX_PROTOCOL_MESSAGE_BYTES &&
    envelopeIsFresh(result.data, nowMs)
  );
}

/** Type guard for already-decoded values; wire callers should use the parser. */
export function validateEventObservationAck(
  value: unknown,
  nowMs = Date.now(),
): value is EventObservationAckV1 {
  const result = EventObservationAckSchema.safeParse(value);
  return (
    result.success &&
    (encodedJsonSize(value) ?? Infinity) <= MAX_PROTOCOL_MESSAGE_BYTES &&
    acknowledgmentTimeIsValid(result.data, nowMs)
  );
}

function scanJsonString(json: string, start: number): number {
  let offset = start + 1;
  while (offset < json.length) {
    const char = json[offset];
    if (char === "\\") {
      offset += 2;
      continue;
    }
    if (char === '"') return offset + 1;
    offset += 1;
  }
  return json.length;
}

/** Called after JSON.parse has established syntactic validity. */
function hasDuplicateObjectKeys(json: string): boolean {
  let offset = 0;

  const skipWhitespace = (): void => {
    while (/\s/.test(json[offset] ?? "")) offset += 1;
  };

  const scanStringValue = (): string => {
    const start = offset;
    offset = scanJsonString(json, offset);
    return JSON.parse(json.slice(start, offset)) as string;
  };

  const scanValue = (depth: number): boolean => {
    if (depth > 32) throw new EventProtocolError("invalid_json");
    skipWhitespace();
    const character = json[offset];

    if (character === '"') {
      scanStringValue();
      return false;
    }

    if (character === "[") {
      offset += 1;
      skipWhitespace();
      if (json[offset] === "]") {
        offset += 1;
        return false;
      }
      while (offset < json.length) {
        if (scanValue(depth + 1)) return true;
        skipWhitespace();
        if (json[offset] === "]") {
          offset += 1;
          return false;
        }
        offset += 1;
      }
      return false;
    }

    if (character === "{") {
      offset += 1;
      skipWhitespace();
      const keys = new Set<string>();
      if (json[offset] === "}") {
        offset += 1;
        return false;
      }
      while (offset < json.length) {
        const key = scanStringValue();
        if (keys.has(key)) return true;
        keys.add(key);
        skipWhitespace();
        offset += 1; // colon
        if (scanValue(depth + 1)) return true;
        skipWhitespace();
        if (json[offset] === "}") {
          offset += 1;
          return false;
        }
        offset += 1; // comma
        skipWhitespace();
      }
      return false;
    }

    while (offset < json.length && !/[\s,\]}]/.test(json[offset] ?? "")) {
      offset += 1;
    }
    return false;
  };

  return scanValue(0);
}

function decodeProtocolJson(json: string): unknown {
  if (
    json.length > MAX_PROTOCOL_MESSAGE_BYTES ||
    new TextEncoder().encode(json).byteLength > MAX_PROTOCOL_MESSAGE_BYTES
  ) {
    throw new EventProtocolError("message_too_large");
  }

  let value: unknown;
  try {
    value = JSON.parse(json) as unknown;
  } catch {
    throw new EventProtocolError("invalid_json");
  }

  if (hasDuplicateObjectKeys(json)) {
    throw new EventProtocolError("duplicate_json_key");
  }
  return value;
}

/**
 * Parse and validate envelope bytes without accepting duplicate keys. Signature
 * verification is external. Before persistence or deduplication, callers must
 * also await matchesDeliveryId() and verify current authority/destination state.
 */
export function parseEventEnvelope(
  json: string,
  nowMs = Date.now(),
): EventEnvelopeV1 {
  const parsed = EventEnvelopeSchema.safeParse(decodeProtocolJson(json));
  if (!parsed.success) throw new EventProtocolError("invalid_envelope");
  if (!envelopeIsFresh(parsed.data, nowMs)) {
    throw new EventProtocolError("stale_message");
  }
  return parsed.data;
}

/** Parse an authenticated runtime acknowledgment without accepting duplicate keys. */
export function parseEventObservationAck(
  json: string,
  nowMs = Date.now(),
): EventObservationAckV1 {
  const parsed = EventObservationAckSchema.safeParse(decodeProtocolJson(json));
  if (!parsed.success) {
    throw new EventProtocolError("invalid_acknowledgment");
  }
  if (!acknowledgmentTimeIsValid(parsed.data, nowMs)) {
    throw new EventProtocolError("stale_message");
  }
  return parsed.data;
}

export type EventDeliveryIdentityV1 = Pick<
  EventEnvelopeV1,
  | "eventId"
  | "runtimeId"
  | "nodeGeneration"
  | "runtimeGeneration"
  | "attachmentGeneration"
  | "consumerGeneration"
>;

const deliveryIdentitySchema = z.strictObject({
  eventId: uuidV4OrV7Schema,
  runtimeId: uuidV4OrV7Schema,
  nodeGeneration: generationSchema,
  runtimeGeneration: generationSchema,
  attachmentGeneration: generationSchema,
  consumerGeneration: generationSchema.optional(),
});

/**
 * Stable across transport retries; changes for any destination generation.
 * Attempt IDs and freshness timestamps are intentionally excluded.
 */
export async function deriveDeliveryId(
  identity: EventDeliveryIdentityV1,
): Promise<string> {
  const parsed = deliveryIdentitySchema.safeParse({
    eventId: identity.eventId,
    runtimeId: identity.runtimeId,
    nodeGeneration: identity.nodeGeneration,
    runtimeGeneration: identity.runtimeGeneration,
    attachmentGeneration: identity.attachmentGeneration,
    consumerGeneration: identity.consumerGeneration,
  });
  if (!parsed.success) {
    throw new EventProtocolError("invalid_delivery_identity");
  }

  const semanticIdentity = JSON.stringify([
    EVENT_PROTOCOL_VERSION,
    parsed.data.eventId,
    parsed.data.runtimeId,
    parsed.data.nodeGeneration,
    parsed.data.runtimeGeneration,
    parsed.data.attachmentGeneration,
    parsed.data.consumerGeneration ?? null,
  ]);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(semanticIdentity),
  );
  const hex = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return `dly_${hex}`;
}

export async function matchesDeliveryId(
  envelope: EventEnvelopeV1,
): Promise<boolean> {
  if (!isDeliveryId(envelope.deliveryId)) return false;
  try {
    return envelope.deliveryId === await deriveDeliveryId(envelope);
  } catch {
    return false;
  }
}

/** Confirms an acknowledgment describes this exact delivery attempt. */
export function acknowledgmentMatchesDelivery(
  envelope: EventEnvelopeV1,
  acknowledgment: EventObservationAckV1,
): boolean {
  return (
    acknowledgment.eventId === envelope.eventId &&
    acknowledgment.deliveryId === envelope.deliveryId &&
    acknowledgment.attemptId === envelope.attemptId &&
    acknowledgment.principal === envelope.principal &&
    acknowledgment.agent === envelope.agent &&
    acknowledgment.runtimeId === envelope.runtimeId &&
    acknowledgment.nodeGeneration === envelope.nodeGeneration &&
    acknowledgment.runtimeGeneration === envelope.runtimeGeneration &&
    acknowledgment.attachmentGeneration === envelope.attachmentGeneration &&
    acknowledgment.consumerGeneration === envelope.consumerGeneration &&
    acknowledgment.deliveredSourceStateVersion ===
      envelope.sourceStateVersion
  );
}

/**
 * Call only with the destination envelope freshly reread from the authoritative
 * coordinator and confirmed as its current authorized attachment. A historical
 * envelope may be used to record an ACK, but cannot settle a replacement's
 * watermark. Older delivered source versions remain historical observations.
 */
export function acknowledgmentAdvancesCurrentWatermark(
  currentDestinationEnvelope: EventEnvelopeV1,
  acknowledgment: EventObservationAckV1,
  currentSourceStateVersion: string,
): boolean {
  return (
    acknowledgmentMatchesDelivery(
      currentDestinationEnvelope,
      acknowledgment,
    ) &&
    acknowledgment.status === "observed" &&
    acknowledgment.deliveredSourceStateVersion === currentSourceStateVersion
  );
}
