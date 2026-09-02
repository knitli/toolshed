import { afterEach, describe, expect, test } from "bun:test";
import { unlinkSync } from "node:fs";
import { generateKeypair, signArtifact, verifyArtifact } from "../src/sign";

const FILE = `${import.meta.dir}/tmp-sign.bin`;
afterEach(() => {
  try { unlinkSync(FILE); } catch { /* already gone */ }
});

describe("artifact signing", () => {
  test("a signature made with the private key verifies with the public key", async () => {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    await Bun.write(FILE, "artifact bytes");
    const sig = await signArtifact(FILE, privateKeyPem);
    expect(await verifyArtifact(FILE, sig, publicKeyPem)).toBe(true);
  });

  test("verification fails when the file is modified", async () => {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    await Bun.write(FILE, "artifact bytes");
    const sig = await signArtifact(FILE, privateKeyPem);
    await Bun.write(FILE, "tampered bytes");
    expect(await verifyArtifact(FILE, sig, publicKeyPem)).toBe(false);
  });

  test("verification fails against a different key", async () => {
    const a = generateKeypair();
    const b = generateKeypair();
    await Bun.write(FILE, "artifact bytes");
    const sig = await signArtifact(FILE, a.privateKeyPem);
    expect(await verifyArtifact(FILE, sig, b.publicKeyPem)).toBe(false);
  });

  test("a malformed signature returns false rather than throwing", async () => {
    const { publicKeyPem } = generateKeypair();
    await Bun.write(FILE, "artifact bytes");
    expect(await verifyArtifact(FILE, "not-base64!!", publicKeyPem)).toBe(false);
  });
});
