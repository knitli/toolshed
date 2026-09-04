import { createHash } from "node:crypto";
import { type BigIntStats, constants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import { basename, dirname, join, relative, sep } from "node:path";
import type { ManifestEnvelope, ReleaseManifestV4 } from "../runtime/types.ts";

export interface CompiledReleasePaths {
  readonly directory: string;
  readonly sqlite: string;
  readonly signature: string;
  readonly manifest: string;
}

export interface CompiledRelease {
  readonly manifest: ReleaseManifestV4;
  readonly envelope: ManifestEnvelope;
  readonly paths: CompiledReleasePaths;
}

type StageFileKind = "sqlite" | "signature" | "manifest";
type StageFileRecord<T> = Readonly<Record<StageFileKind, T>>;

interface CompiledState {
  outDir: string;
  paths: CompiledReleasePaths;
  consumed: boolean;
  digests: StageFileRecord<string>;
  sizes: StageFileRecord<number>;
  ownership: CompiledReleaseOwnership;
}

export interface PathIdentity {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly birthtimeNs: bigint;
}

export interface CompiledReleaseOwnership {
  readonly directory: PathIdentity;
  readonly sqlite: PathIdentity;
  readonly signature: PathIdentity;
  readonly manifest: PathIdentity;
}

const compiledStates = new WeakMap<object, CompiledState>();

/** Package-private construction gate; intentionally absent from the compiler barrel. */
export function registerCompiledRelease(
  compiled: CompiledRelease,
  outDir: string,
  digests: StageFileRecord<string>,
  sizes: StageFileRecord<number>,
  ownership: CompiledReleaseOwnership,
): CompiledRelease {
  compiledStates.set(compiled, {
    outDir,
    paths: { ...compiled.paths },
    consumed: false,
    digests: { ...digests },
    sizes: { ...sizes },
    ownership: {
      directory: { ...ownership.directory },
      sqlite: { ...ownership.sqlite },
      signature: { ...ownership.signature },
      manifest: { ...ownership.manifest },
    },
  });
  return compiled;
}

function stateFor(compiled: CompiledRelease): CompiledState {
  const state = compiledStates.get(compiled);
  if (!state || state.consumed)
    throw new Error("compiled release is invalid or already consumed");
  return state;
}

export function pathIdentityFromStats(stat: {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly birthtimeNs: bigint;
}): PathIdentity {
  if (stat.birthtimeNs <= 0n)
    throw new Error("path identity requires a nonzero birthtimeNs");
  return {
    dev: stat.dev,
    ino: stat.ino,
    birthtimeNs: stat.birthtimeNs,
  };
}

export function samePathIdentity(
  left: PathIdentity,
  right: PathIdentity,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.birthtimeNs === right.birthtimeNs
  );
}

export async function capturePathIdentity(
  path: string,
  kind: "directory" | "file",
): Promise<PathIdentity> {
  const metadata = await lstat(path, { bigint: true });
  const validKind =
    kind === "directory" ? metadata.isDirectory() : metadata.isFile();
  if (!validKind || metadata.isSymbolicLink())
    throw new Error(`compiler-created ${kind} is unsafe`);
  if (kind === "file" && metadata.nlink !== 1n)
    throw new Error("compiler-created file must have one link");
  return pathIdentityFromStats(metadata);
}

async function ownedMetadata(
  path: string,
  identity: PathIdentity,
): Promise<BigIntStats | null> {
  const metadata = await lstat(path, { bigint: true }).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  });
  return metadata && samePathIdentity(pathIdentityFromStats(metadata), identity)
    ? metadata
    : null;
}

async function requireOwnedFile(
  path: string,
  identity: PathIdentity,
  label: string,
  requireSingleLink = true,
): Promise<void> {
  const metadata = await ownedMetadata(path, identity);
  if (
    !metadata?.isFile() ||
    metadata.isSymbolicLink() ||
    (requireSingleLink && metadata.nlink !== 1n)
  )
    throw new Error(`${label} identity or ownership was lost`);
}

async function requireOwnedDirectory(
  path: string,
  identity: PathIdentity,
  label: string,
): Promise<void> {
  const metadata = await ownedMetadata(path, identity);
  if (!metadata?.isDirectory() || metadata.isSymbolicLink())
    throw new Error(`${label} identity or ownership was lost`);
}

async function removeOwnedFile(
  path: string,
  identity: PathIdentity,
): Promise<boolean> {
  const metadata = await ownedMetadata(path, identity);
  if (!metadata?.isFile() || metadata.isSymbolicLink()) return false;
  await unlink(path);
  return true;
}

export async function cleanupOwnedStage(
  paths: CompiledReleasePaths,
  ownership: Partial<CompiledReleaseOwnership>,
): Promise<void> {
  for (const kind of ["manifest", "signature", "sqlite"] as const) {
    const identity = ownership[kind];
    if (identity)
      await removeOwnedFile(paths[kind], identity).catch(() => false);
  }
  if (!ownership.directory) return;
  const directory = await ownedMetadata(paths.directory, ownership.directory);
  if (!directory?.isDirectory() || directory.isSymbolicLink()) return;
  await rmdir(paths.directory).catch(() => {});
}

async function hashOwnedStageFile(
  path: string,
  identity: PathIdentity,
  expectedSize: number,
  beforeOpen: () => void | Promise<void>,
  beforeRead: () => void | Promise<void>,
): Promise<string> {
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0)
    throw new Error("compiled release staged file size is invalid");
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0)
    throw new Error("compiled release validation requires O_NOFOLLOW support");
  await requireOwnedFile(path, identity, "compiled release staged file");
  await beforeOpen();
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
  } catch {
    throw new Error("compiled release staged file could not be opened safely");
  }
  try {
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      !samePathIdentity(pathIdentityFromStats(before), identity) ||
      before.size !== BigInt(expectedSize)
    )
      throw new Error(
        "compiled release staged content was modified or identity was lost",
      );
    await requireOwnedFile(path, identity, "compiled release staged file");
    await beforeRead();

    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, expectedSize) || 1);
    let total = 0;
    while (total < expectedSize) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.byteLength, expectedSize - total),
        null,
      );
      if (bytesRead === 0)
        throw new Error(
          "compiled release staged content was modified: early EOF",
        );
      digest.update(buffer.subarray(0, bytesRead));
      total += bytesRead;
    }
    const growthProbe = new Uint8Array(1);
    const { bytesRead: extraBytes } = await handle.read(
      growthProbe,
      0,
      1,
      null,
    );
    if (extraBytes !== 0)
      throw new Error(
        "compiled release staged content was modified: exceeds recorded size",
      );
    const after = await handle.stat({ bigint: true });
    if (
      !after.isFile() ||
      after.nlink !== 1n ||
      !samePathIdentity(pathIdentityFromStats(after), identity) ||
      after.size !== BigInt(expectedSize)
    )
      throw new Error(
        "compiled release staged content was modified or identity was lost",
      );
    await requireOwnedFile(path, identity, "compiled release staged file");
    return digest.digest("hex");
  } finally {
    await handle.close();
  }
}

async function validateStage(
  compiled: CompiledRelease,
  state: CompiledState,
  checkpoint: Checkpoint,
): Promise<void> {
  const root = await realpath(state.outDir);
  if (compiled.paths.directory !== state.paths.directory)
    throw new Error("compiled release staged directory was substituted");
  await requireOwnedDirectory(
    state.paths.directory,
    state.ownership.directory,
    "compiled release stage",
  );
  const directory = await realpath(state.paths.directory);
  if (dirname(directory) !== root || relative(root, directory).includes(sep))
    throw new Error("compiled release stage is outside its output directory");
  for (const kind of ["sqlite", "signature", "manifest"] as const) {
    const path = state.paths[kind];
    if (compiled.paths[kind] !== path || dirname(path) !== directory)
      throw new Error("compiled release staged path was substituted");
    await requireOwnedFile(
      path,
      state.ownership[kind],
      "compiled release staged file",
    );
    const digest = await hashOwnedStageFile(
      path,
      state.ownership[kind],
      state.sizes[kind],
      () => checkpoint(`before-${kind}-validation-open`),
      () => checkpoint(`before-${kind}-validation-read`),
    );
    await requireOwnedFile(
      path,
      state.ownership[kind],
      "compiled release staged file",
    );
    if (digest !== state.digests[kind])
      throw new Error("compiled release staged content was modified");
  }
  if (
    basename(state.paths.sqlite) !== `${compiled.manifest.releaseId}.sqlite` ||
    basename(state.paths.signature) !==
      `${compiled.manifest.releaseId}.manifest.sig` ||
    basename(state.paths.manifest) !==
      `${compiled.manifest.releaseId}.manifest.json`
  )
    throw new Error(
      "compiled release staged names disagree with its release ID",
    );
}

async function syncFile(path: string, identity: PathIdentity): Promise<void> {
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat({ bigint: true });
    if (
      !metadata.isFile() ||
      !samePathIdentity(pathIdentityFromStats(metadata), identity)
    )
      throw new Error("compiled release staged file identity was lost");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await requireOwnedFile(path, identity, "compiled release staged file");
}

async function syncOwnedDirectory(
  path: string,
  identity: PathIdentity,
): Promise<void> {
  await requireOwnedDirectory(path, identity, "release target directory");
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const metadata = await handle.stat({ bigint: true });
    if (
      !metadata.isDirectory() ||
      !samePathIdentity(pathIdentityFromStats(metadata), identity)
    )
      throw new Error(
        "release target directory identity or ownership was lost",
      );
    await handle.sync();
  } finally {
    await handle.close();
  }
  await requireOwnedDirectory(path, identity, "release target directory");
}

async function requirePromotedTargets(
  targets: ReadonlyMap<string, PathIdentity>,
): Promise<void> {
  for (const [path, identity] of targets)
    await requireOwnedFile(path, identity, "published target");
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function requireLock(
  path: string,
  identity: PathIdentity,
): Promise<void> {
  const metadata = await ownedMetadata(path, identity);
  if (
    !metadata?.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.nlink !== 1n ||
    (metadata.mode & 0o777n) !== 0o600n
  )
    throw new Error("release publication lock identity or ownership was lost");
}

export type PublishCheckpoint =
  | "before-sqlite-validation-open"
  | "before-signature-validation-open"
  | "before-manifest-validation-open"
  | "before-sqlite-validation-read"
  | "before-signature-validation-read"
  | "before-manifest-validation-read"
  | "payload-published"
  | "signature-published"
  | "manifest-published";

type Checkpoint = (checkpoint: PublishCheckpoint) => void | Promise<void>;

export async function publishReleaseWithCheckpoint(
  compiled: CompiledRelease,
  target: { readonly directory: string },
  checkpoint: Checkpoint = () => {},
): Promise<void> {
  const state = stateFor(compiled);
  state.consumed = true;
  const createdTargets = new Map<string, PathIdentity>();
  let lockHandle: Awaited<ReturnType<typeof open>> | undefined;
  let lockIdentity: PathIdentity | undefined;
  let lockPath: string | undefined;
  let targetDirectory: string | undefined;
  let targetDirectoryIdentity: PathIdentity | undefined;
  try {
    await validateStage(compiled, state, checkpoint);
    await mkdir(target.directory, { recursive: false }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    });
    targetDirectory = await realpath(target.directory);
    targetDirectoryIdentity = await capturePathIdentity(
      targetDirectory,
      "directory",
    );
    await requireOwnedDirectory(
      targetDirectory,
      targetDirectoryIdentity,
      "release target directory",
    );
    lockPath = join(
      targetDirectory,
      `.${compiled.manifest.releaseId}.publish.lock`,
    );
    if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0)
      throw new Error("release publication requires O_NOFOLLOW support");
    const flags =
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_WRONLY |
      constants.O_NOFOLLOW;
    lockHandle = await open(lockPath, flags, 0o600).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === "EEXIST")
        throw new Error(
          "release publication lock already exists; publication is in progress or requires operator cleanup",
        );
      throw error;
    });
    await requireOwnedDirectory(
      targetDirectory,
      targetDirectoryIdentity,
      "release target directory",
    );
    const lockStat = await lockHandle.stat({ bigint: true });
    if (
      !lockStat.isFile() ||
      lockStat.nlink !== 1n ||
      (lockStat.mode & 0o777n) !== 0o600n
    )
      throw new Error("release publication lock is unsafe");
    lockIdentity = pathIdentityFromStats(lockStat);
    await requireLock(lockPath, lockIdentity);

    const targets = [
      join(targetDirectory, `${compiled.manifest.releaseId}.sqlite`),
      join(targetDirectory, `${compiled.manifest.releaseId}.manifest.sig`),
      join(targetDirectory, `${compiled.manifest.releaseId}.manifest.json`),
    ];
    if ((await Promise.all(targets.map(exists))).some(Boolean))
      throw new Error("release target already exists");

    const sources = [
      state.paths.sqlite,
      state.paths.signature,
      state.paths.manifest,
    ];
    const identities = [
      state.ownership.sqlite,
      state.ownership.signature,
      state.ownership.manifest,
    ];
    const checkpoints: PublishCheckpoint[] = [
      "payload-published",
      "signature-published",
      "manifest-published",
    ];
    for (let index = 0; index < sources.length; index += 1) {
      const source = sources[index] as string;
      const destination = targets[index] as string;
      const identity = identities[index] as PathIdentity;
      await requireLock(lockPath, lockIdentity);
      await requireOwnedDirectory(
        targetDirectory,
        targetDirectoryIdentity,
        "release target directory",
      );
      await syncFile(source, identity);
      await requirePromotedTargets(createdTargets);
      try {
        await link(source, destination);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST")
          throw new Error("release target already exists", { cause: error });
        throw error;
      }
      const destinationMetadata = await lstat(destination, { bigint: true });
      if (
        !destinationMetadata.isFile() ||
        destinationMetadata.isSymbolicLink() ||
        !samePathIdentity(pathIdentityFromStats(destinationMetadata), identity)
      )
        throw new Error("published target identity is unsafe");
      createdTargets.set(destination, identity);
      await requireOwnedDirectory(
        targetDirectory,
        targetDirectoryIdentity,
        "release target directory",
      );
      await requireLock(lockPath, lockIdentity);
      if (!(await removeOwnedFile(source, identity)))
        throw new Error("compiled release staged file identity was lost");
      await syncOwnedDirectory(targetDirectory, targetDirectoryIdentity);
      await checkpoint(checkpoints[index]);
      await requireOwnedDirectory(
        targetDirectory,
        targetDirectoryIdentity,
        "release target directory",
      );
      await requirePromotedTargets(createdTargets);
      await requireLock(lockPath, lockIdentity);
    }
  } catch (error) {
    const targetDirectoryOwned =
      targetDirectory && targetDirectoryIdentity
        ? await ownedMetadata(targetDirectory, targetDirectoryIdentity).then(
            (metadata) => metadata?.isDirectory() === true,
            () => false,
          )
        : false;
    if (targetDirectoryOwned) {
      for (const [path, identity] of [...createdTargets.entries()].reverse())
        await removeOwnedFile(path, identity).catch(() => false);
      if (createdTargets.size > 0)
        await syncOwnedDirectory(
          targetDirectory as string,
          targetDirectoryIdentity as PathIdentity,
        ).catch(() => {});
    }
    throw error;
  } finally {
    await lockHandle?.close().catch(() => {});
    if (
      lockPath &&
      lockIdentity &&
      targetDirectory &&
      targetDirectoryIdentity &&
      (await ownedMetadata(targetDirectory, targetDirectoryIdentity).then(
        (metadata) => metadata?.isDirectory() === true,
        () => false,
      ))
    ) {
      await removeOwnedFile(lockPath, lockIdentity).catch(() => false);
      await syncOwnedDirectory(targetDirectory, targetDirectoryIdentity).catch(
        () => {},
      );
    }
    await cleanupOwnedStage(state.paths, state.ownership);
  }
}

export async function publishRelease(
  compiled: CompiledRelease,
  target: { readonly directory: string },
): Promise<void> {
  await publishReleaseWithCheckpoint(compiled, target);
}

export async function discardCompiledRelease(
  compiled: CompiledRelease,
): Promise<void> {
  const state = stateFor(compiled);
  state.consumed = true;
  await cleanupOwnedStage(state.paths, state.ownership);
}
