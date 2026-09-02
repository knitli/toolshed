import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { readFile } from "node:fs/promises";

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
