/**
 * Frozen pilot limits for Event Runtime protocol v1.
 * Changes to authority or delivery policy require a new policy revision.
 */
export const EVENT_POLICY_V1 = Object.freeze({
  protocolVersion: 1,
  initialPolicyRevision: 1,

  maxProtocolMessageBytes: 4 * 1024,
  freshnessLifetimeMs: 60_000,
  clockSkewMs: 30_000,

  runtimeLeaseMs: 90_000,
  runtimeRenewalMs: 30_000,
  dispatchStartWindowMs: 5_000,
  nativeRpcDeadlineMs: 10_000,
  meshRequestDeadlineMs: 8_000,
  listenerHeaderAndBodyDeadlineMs: 5_000,

  maxWatchesPerAgent: 32,
  maxRuntimesPerAgent: 8,
  pilotAdmittedSessionsPerAgent: 3,
  automaticWakeAttemptsPerAgent: 10,
  automaticWakeWindowMs: 60 * 60 * 1_000,

  maxPendingDeliveriesPerAgent: 1_000,
  maxPendingDeliveriesPerNode: 1_000,
  deliveryTransportRetryHorizonMs: 24 * 60 * 60 * 1_000,
  terminalDeduplicationRetentionMs: 7 * 24 * 60 * 60 * 1_000,
  localStorageLimitBytes: 64 * 1024 * 1024,

  nativeHistoryMaxPages: 10,
  nativeHistoryPageSize: 50,

  githubIngressMaxBodyBytes: 256 * 1024,
  githubReconcileIntervalMs: 5 * 60 * 1_000,
  githubReconcileJitterMs: 30_000,
  githubStaleAfterMs: 10 * 60 * 1_000,

  recoveryBackoffInitialMs: 5_000,
  recoveryBackoffMaxMs: 15 * 60 * 1_000,

  queueConsumerBatchSize: 10,
  queueConsumerConcurrency: 1,
  queueInfrastructureRetries: 5,
  queueRetentionMs: 24 * 60 * 60 * 1_000,
} as const);

export type EventPolicyV1 = typeof EVENT_POLICY_V1;

export const EVENT_PROTOCOL_VERSION = EVENT_POLICY_V1.protocolVersion;
export const EVENT_INITIAL_POLICY_REVISION =
  EVENT_POLICY_V1.initialPolicyRevision;
export const MAX_PROTOCOL_MESSAGE_BYTES =
  EVENT_POLICY_V1.maxProtocolMessageBytes;
export const EVENT_FRESHNESS_LIFETIME_MS =
  EVENT_POLICY_V1.freshnessLifetimeMs;
export const EVENT_CLOCK_SKEW_MS = EVENT_POLICY_V1.clockSkewMs;
