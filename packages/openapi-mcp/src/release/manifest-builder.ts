import type {
  CatalogId,
  ManifestEnvelope,
  ReleaseId,
  ReleaseManifestV4,
  Sha256,
  TypedRecordId,
} from "../runtime/types.ts";
import {
  ARTIFACT_FORMAT_VERSION,
  RUNTIME_CONTRACT_VERSION,
} from "../runtime/versions.ts";
import { signReleaseManifestV4 } from "../sign.ts";

export interface ManifestBuilderInput {
  catalogId: CatalogId;
  releaseId: ReleaseId;
  generation: number;
  issuer: string;
  keyId: string;
  policyId: string;
  allowedOrigins: readonly string[];
  compiledAt: string;
  compilerVersion: string;
  sourceUri: string;
  sourceRevision: string;
  sourceContentSha256: Sha256;
  referenceGraphDigest: Sha256;
  records: Readonly<Record<TypedRecordId, Sha256>>;
}

export function buildReleaseManifestV4(
  input: ManifestBuilderInput,
): ReleaseManifestV4 {
  return {
    format: ARTIFACT_FORMAT_VERSION,
    contract: RUNTIME_CONTRACT_VERSION,
    catalogId: input.catalogId,
    releaseId: input.releaseId,
    generation: input.generation,
    issuer: input.issuer,
    keyId: input.keyId,
    policyId: input.policyId,
    allowedOrigins: [...input.allowedOrigins].sort(),
    compiledAt: input.compiledAt,
    compilerVersion: input.compilerVersion,
    source: {
      uri: input.sourceUri,
      revision: input.sourceRevision,
      contentSha256: input.sourceContentSha256,
      referenceGraphDigest: input.referenceGraphDigest,
    },
    records: Object.fromEntries(
      Object.entries(input.records).sort(([left], [right]) =>
        left < right ? -1 : left > right ? 1 : 0,
      ),
    ) as Readonly<Record<TypedRecordId, Sha256>>,
  };
}

export function buildManifestEnvelopeV4(
  manifest: ReleaseManifestV4,
  privateKeyPem: string,
): ManifestEnvelope {
  const signed = signReleaseManifestV4(manifest, manifest.keyId, privateKeyPem);
  return { manifestJson: signed.manifestJson, signature: signed.signature };
}
