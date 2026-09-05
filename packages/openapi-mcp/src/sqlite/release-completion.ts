import {
  type BigIntStats,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import { OpenApiMcpError } from "../runtime/errors.ts";
import type {
  JsonObject,
  ManifestEnvelope,
  RuntimeLimits,
} from "../runtime/index.ts";
import { canonicalJson, parseJsonStrict } from "../runtime/strict-json.ts";

export function releaseFileIdentity(path: string): BigIntStats {
  const value = lstatSync(path, { bigint: true });
  if (!value.isFile() || value.isSymbolicLink())
    throw new OpenApiMcpError("MANIFEST_INVALID");
  return value;
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.birthtimeNs === right.birthtimeNs
  );
}

function sameSnapshot(left: BigIntStats, right: BigIntStats): boolean {
  return (
    sameFile(left, right) &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function readCompleteSidecar(
  path: string,
  maximum: number,
): { text: string; identity: BigIntStats } {
  const before = releaseFileIdentity(path);
  if (before.size > BigInt(maximum) || !constants.O_NOFOLLOW) throw new Error();
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameSnapshot(before, opened) || !opened.isFile()) throw new Error();
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let count = 0;
    while (count < bytes.length) {
      const read = readSync(fd, bytes, count, bytes.length - count, null);
      if (read === 0) break;
      count += read;
    }
    const after = fstatSync(fd, { bigint: true });
    const named = releaseFileIdentity(path);
    if (
      count !== Number(before.size) ||
      !sameSnapshot(before, after) ||
      !sameSnapshot(before, named)
    )
      throw new Error();
    return {
      text: new TextDecoder("utf-8", { fatal: true }).decode(
        bytes.subarray(0, count),
      ),
      identity: before,
    };
  } finally {
    closeSync(fd);
  }
}

/** Filesystem completion is local ingress policy, never a portable semantic-store requirement. */
export function verifyReleaseCompletion(
  path: string,
  payload: BigIntStats,
  envelope: ManifestEnvelope,
  limits: RuntimeLimits,
): void {
  try {
    if (
      !path.endsWith(".sqlite") ||
      !sameFile(payload, releaseFileIdentity(path))
    )
      throw new Error();
    const stem = path.slice(0, -".sqlite".length);
    const manifest = readCompleteSidecar(
      `${stem}.manifest.json`,
      limits.maxManifestBytes,
    );
    const signatureFile = readCompleteSidecar(
      `${stem}.manifest.sig`,
      16 * 1024,
    );
    const signature = parseJsonStrict(signatureFile.text, {
      maxBytes: 16 * 1024,
      maxDepth: 4,
      maxKeys: 8,
    });
    if (
      manifest.text !== envelope.manifestJson ||
      canonicalJson(signature) !==
        canonicalJson(envelope.signature as unknown as JsonObject)
    )
      throw new Error();
    if (
      !sameSnapshot(
        manifest.identity,
        releaseFileIdentity(`${stem}.manifest.json`),
      ) ||
      !sameSnapshot(
        signatureFile.identity,
        releaseFileIdentity(`${stem}.manifest.sig`),
      )
    )
      throw new Error();
    if (!sameFile(payload, releaseFileIdentity(path))) throw new Error();
  } catch {
    throw new OpenApiMcpError(
      "MANIFEST_INVALID",
      "Release publication is incomplete or mismatched",
    );
  }
}
