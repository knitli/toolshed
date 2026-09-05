import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import { canonicalJson } from "./runtime/strict-json.ts";
import type {
  JsonValue,
  ManifestSignature,
  ReleaseManifestV4,
} from "./runtime/types.ts";

function manifestSignatureDomain(format: 4 | 5): string {
  return `knitli.openapi-mcp.release-manifest.v${format}\0`;
}

/** Ed25519 keypair, PEM encoded. The public key ships in plugin source. */
export function generateKeypair(): {
  publicKeyPem: string;
  privateKeyPem: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
  };
}

/** Signs the artifact's exact bytes. Returns a base64 signature. */
export async function signArtifact(
  path: string,
  privateKeyPem: string,
): Promise<string> {
  const bytes = await readFile(path);
  const key = createPrivateKey(privateKeyPem);
  return sign(null, bytes, key).toString("base64");
}

/**
 * Verifies an artifact against a public key. Returns false rather than
 * throwing on malformed input — callers treat any failure identically.
 */
export async function verifyArtifact(
  path: string,
  signatureB64: string,
  publicKeyPem: string,
): Promise<boolean> {
  try {
    const bytes = await readFile(path);
    const key = createPublicKey(publicKeyPem);
    return verify(null, bytes, key, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

/** Sign canonical v4/v5 manifest JSON under its versioned domain separator. */
export function signReleaseManifestV4(
  manifest: ReleaseManifestV4,
  keyId: string,
  privateKeyPem: string,
): { manifestJson: string; signature: ManifestSignature } {
  const manifestJson = canonicalJson(manifest as unknown as JsonValue);
  const payload = Buffer.concat([
    Buffer.from(manifestSignatureDomain(manifest.format), "utf8"),
    Buffer.from(manifestJson, "utf8"),
  ]);
  const signature = sign(
    null,
    payload,
    createPrivateKey(privateKeyPem),
  ).toString("base64url");
  return {
    manifestJson,
    signature: { algorithm: "Ed25519", keyId, signature },
  };
}

/** Derive the unpadded base64url SPKI used by the Worker-safe trust contract. */
export function deriveReleasePublicKeyV4(privateKeyPem: string): string {
  return createPublicKey(createPrivateKey(privateKeyPem))
    .export({ type: "spki", format: "der" })
    .toString("base64url");
}
