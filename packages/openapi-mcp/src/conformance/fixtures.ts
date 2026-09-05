import type {
  CandidateRef,
  CatalogId,
  ManifestEnvelope,
  ManifestTrust,
  OperationRecordV4,
  ReleaseId,
  SchemaRecordV4,
  StoredRecord,
  TypedOperationId,
  TypedSchemaId,
} from "../runtime/index.ts";

export interface RuntimeConformanceFixture {
  readonly catalogId: CatalogId;
  readonly releaseA: ReleaseId;
  readonly releaseB: ReleaseId;
  readonly operationId: TypedOperationId;
  readonly missingOperationId: TypedOperationId;
  readonly schemaIds: readonly TypedSchemaId[];
  readonly searchQuery: string;
  readonly api: string;
  readonly expectedCandidates: readonly CandidateRef[];
  readonly envelopeA: ManifestEnvelope;
  readonly envelopeB: ManifestEnvelope;
  readonly trust: ManifestTrust;
  readonly operationA: StoredRecord<OperationRecordV4>;
  readonly operationB: StoredRecord<OperationRecordV4>;
  readonly schemasA: readonly StoredRecord<SchemaRecordV4>[];
  readonly schemasB: readonly StoredRecord<SchemaRecordV4>[];
}

const catalogId = "conformance" as CatalogId;
const releaseA = "release-a" as ReleaseId;
const releaseB = "release-b" as ReleaseId;
const operationId = "operation:conformance:get-item" as TypedOperationId;
const itemSchemaId =
  "schema:conformance:#/components/schemas/Item" as TypedSchemaId;
const tagSchemaId =
  "schema:conformance:#/components/schemas/Tag" as TypedSchemaId;

const envelopeA: ManifestEnvelope = {
  manifestJson:
    '{"allowedOrigins":["https://api.example.invalid"],"catalogId":"conformance","compiledAt":"2026-09-04T00:00:00.000Z","compilerVersion":"fixture-v1","contract":1,"format":4,"generation":1,"issuer":"conformance.example","keyId":"fixture-key","policyId":"fixture-policy","records":{"operation:conformance:get-item":"8eeb54ce7802f5e33d8cdfd0c2c59965f9867a18b3c5dbc81082fd3b8b9d5753","schema:conformance:#/components/schemas/Item":"e10267890d908b2db1fac5cb17b139c08f9cd8bf887600d8aec9e80156f42d66","schema:conformance:#/components/schemas/Tag":"5c28908d43c68938ba560687c098e8339f93564471043f7aefe4bdc2fb42a1dd"},"releaseId":"release-a","source":{"contentSha256":"0000000000000000000000000000000000000000000000000000000000000000","referenceGraphDigest":"1111111111111111111111111111111111111111111111111111111111111111","revision":"release-a","uri":"https://specs.example.invalid/conformance.json"}}',
  signature: {
    algorithm: "Ed25519",
    keyId: "fixture-key",
    signature:
      "ol9usPjzs-FujMZnOP8uSwCrSxnQc1LLuaMZp2oJXMJU0vFLX3tlLEfFNr6mzaF83ZU2xUlyUpoAzMQPlo5YBw",
  },
};

const envelopeB: ManifestEnvelope = {
  manifestJson:
    '{"allowedOrigins":["https://api.example.invalid"],"catalogId":"conformance","compiledAt":"2026-09-04T00:00:00.000Z","compilerVersion":"fixture-v1","contract":1,"format":4,"generation":2,"issuer":"conformance.example","keyId":"fixture-key","policyId":"fixture-policy","records":{"operation:conformance:get-item":"ab223e9204df8dbb2dd94982f10080db4517efc7b181fa02b3999b6657b893cd","schema:conformance:#/components/schemas/Item":"8416a81dbe1c8fe3ef459701d787384cc63f55953103a28bf1b384760cf59273","schema:conformance:#/components/schemas/Tag":"5c28908d43c68938ba560687c098e8339f93564471043f7aefe4bdc2fb42a1dd"},"releaseId":"release-b","source":{"contentSha256":"0000000000000000000000000000000000000000000000000000000000000000","referenceGraphDigest":"1111111111111111111111111111111111111111111111111111111111111111","revision":"release-b","uri":"https://specs.example.invalid/conformance.json"}}',
  signature: {
    algorithm: "Ed25519",
    keyId: "fixture-key",
    signature:
      "t2vi58Ars0_amzBA2NfBlb7NzEM6Bl7v5n5tFu437b1hxDSx6YxnuV7TFEDcvXJY06Fj_GEWE0cjExU6fJE_Cg",
  },
};

function operation(
  summary: string,
  logicalDigest: string,
): StoredRecord<OperationRecordV4> {
  return {
    id: operationId,
    logicalDigest: logicalDigest as never,
    record: {
      id: operationId,
      api: "conformance",
      operationId: "get-item",
      method: "POST",
      path: "/items",
      origin: "https://api.example.invalid",
      summary,
      deprecated: false,
      parameters: [],
      requestBody: {
        required: true,
        content: [
          {
            mediaType: "application/json" as never,
            schemaId: itemSchemaId,
            encoding: [],
          },
        ],
      },
      schemaIds: [itemSchemaId],
      advisory: {},
    } as unknown as OperationRecordV4,
  };
}

function schemas(
  title: string,
  itemDigest: string,
): readonly StoredRecord<SchemaRecordV4>[] {
  return [
    {
      id: itemSchemaId,
      logicalDigest: itemDigest as never,
      record: {
        id: itemSchemaId,
        schema: {
          properties: { tag: { $ref: tagSchemaId } },
          title,
          type: "object",
        },
      },
    },
    {
      id: tagSchemaId,
      logicalDigest:
        "5c28908d43c68938ba560687c098e8339f93564471043f7aefe4bdc2fb42a1dd" as never,
      record: {
        id: tagSchemaId,
        schema: { type: "string" },
      },
    },
  ];
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) return value;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && "value" in descriptor) deepFreeze(descriptor.value);
  }
  return Object.freeze(value);
}

/**
 * Stable, cryptographically valid public fixture for every store adapter.
 * The matching private key is deliberately not included.
 */
export const RUNTIME_CONFORMANCE_FIXTURE: RuntimeConformanceFixture =
  deepFreeze({
    catalogId,
    releaseA,
    releaseB,
    operationId,
    missingOperationId: "operation:conformance:missing" as TypedOperationId,
    schemaIds: Object.freeze([itemSchemaId, tagSchemaId]),
    searchQuery: "item",
    api: "conformance",
    expectedCandidates: Object.freeze([
      { catalogId, releaseId: releaseA, operationId },
      { catalogId, releaseId: releaseB, operationId },
    ]),
    envelopeA: Object.freeze(envelopeA),
    envelopeB: Object.freeze(envelopeB),
    trust: Object.freeze({
      releaseKeys: Object.freeze([
        Object.freeze({
          issuer: "conformance.example",
          keyId: "fixture-key",
          publicKey:
            "MCowBQYDK2VwAyEAQujfB1nZVWKU0z212f9rLQ8SanSmrjKOv7Ah40_oMQU",
        }),
      ]),
      rollbackKeys: Object.freeze([]),
    }),
    operationA: Object.freeze(
      operation(
        "release a",
        "8eeb54ce7802f5e33d8cdfd0c2c59965f9867a18b3c5dbc81082fd3b8b9d5753",
      ),
    ),
    operationB: Object.freeze(
      operation(
        "release b",
        "ab223e9204df8dbb2dd94982f10080db4517efc7b181fa02b3999b6657b893cd",
      ),
    ),
    schemasA: Object.freeze(
      schemas(
        "release a",
        "e10267890d908b2db1fac5cb17b139c08f9cd8bf887600d8aec9e80156f42d66",
      ),
    ),
    schemasB: Object.freeze(
      schemas(
        "release b",
        "8416a81dbe1c8fe3ef459701d787384cc63f55953103a28bf1b384760cf59273",
      ),
    ),
  });
