import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
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

interface CompiledState {
  outDir: string;
  paths: CompiledReleasePaths;
  consumed: boolean;
  digests: Readonly<Record<"sqlite" | "signature" | "manifest", string>>;
}

const compiledStates = new WeakMap<object, CompiledState>();

/** Package-private construction gate; intentionally absent from the compiler barrel. */
export function registerCompiledRelease(
  compiled: CompiledRelease,
  outDir: string,
  digests: Readonly<Record<"sqlite" | "signature" | "manifest", string>>,
): CompiledRelease {
  compiledStates.set(compiled, {
    outDir,
    paths: { ...compiled.paths },
    consumed: false,
    digests: { ...digests },
  });
  return compiled;
}

function stateFor(compiled: CompiledRelease): CompiledState {
  const state = compiledStates.get(compiled);
  if (!state || state.consumed)
    throw new Error("compiled release is invalid or already consumed");
  return state;
}

async function validateStage(
  compiled: CompiledRelease,
  state: CompiledState,
): Promise<void> {
  const root = await realpath(state.outDir);
  const directory = await realpath(state.paths.directory);
  if (compiled.paths.directory !== state.paths.directory)
    throw new Error("compiled release staged directory was substituted");
  if (dirname(directory) !== root || relative(root, directory).includes(sep))
    throw new Error("compiled release stage is outside its output directory");
  for (const [kind, path] of Object.entries(state.paths)) {
    if (kind === "directory") continue;
    if (
      compiled.paths[kind as keyof CompiledReleasePaths] !== path ||
      dirname(path) !== directory
    )
      throw new Error("compiled release staged path was substituted");
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1)
      throw new Error("compiled release staged file is unsafe");
    const digest = createHash("sha256")
      .update(await readFile(path))
      .digest("hex");
    if (digest !== state.digests[kind as "sqlite" | "signature" | "manifest"])
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

async function syncFile(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
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

export type PublishCheckpoint =
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
  const createdTargets: string[] = [];
  let lockHandle: Awaited<ReturnType<typeof open>> | undefined;
  let lockIdentity: { dev: number | bigint; ino: number | bigint } | undefined;
  let lockPath: string | undefined;
  try {
    await validateStage(compiled, state);
    await mkdir(target.directory, { recursive: false }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    });
    const targetDirectory = await realpath(target.directory);
    lockPath = join(
      targetDirectory,
      `.${compiled.manifest.releaseId}.publish.lock`,
    );
    const flags =
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_WRONLY |
      (constants.O_NOFOLLOW ?? 0);
    lockHandle = await open(lockPath, flags, 0o600).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === "EEXIST")
        throw new Error(
          "release publication lock already exists; publication is in progress or requires operator cleanup",
        );
      throw error;
    });
    const lockStat = await lockHandle.stat();
    if (
      !lockStat.isFile() ||
      lockStat.nlink !== 1 ||
      (lockStat.mode & 0o777) !== 0o600
    )
      throw new Error("release publication lock is unsafe");
    lockIdentity = { dev: lockStat.dev, ino: lockStat.ino };

    const targets = [
      join(targetDirectory, `${compiled.manifest.releaseId}.sqlite`),
      join(targetDirectory, `${compiled.manifest.releaseId}.manifest.sig`),
      join(targetDirectory, `${compiled.manifest.releaseId}.manifest.json`),
    ];
    if ((await Promise.all(targets.map(exists))).some(Boolean))
      throw new Error("release target already exists");

    for (const path of [
      state.paths.sqlite,
      state.paths.signature,
      state.paths.manifest,
    ])
      await syncFile(path);
    const sources = [
      state.paths.sqlite,
      state.paths.signature,
      state.paths.manifest,
    ];
    const checkpoints: PublishCheckpoint[] = [
      "payload-published",
      "signature-published",
      "manifest-published",
    ];
    for (let index = 0; index < sources.length; index += 1) {
      await rename(sources[index], targets[index]);
      createdTargets.push(targets[index]);
      await syncDirectory(targetDirectory);
      await checkpoint(checkpoints[index]);
    }
  } catch (error) {
    for (const path of createdTargets.reverse())
      await unlink(path).catch(() => {});
    if (createdTargets.length > 0)
      await syncDirectory(target.directory).catch(() => {});
    throw error;
  } finally {
    await lockHandle?.close().catch(() => {});
    if (lockPath && lockIdentity) {
      const current = await lstat(lockPath).catch(() => null);
      if (
        current &&
        current.dev === lockIdentity.dev &&
        current.ino === lockIdentity.ino
      )
        await unlink(lockPath).catch(() => {});
      await syncDirectory(target.directory).catch(() => {});
    }
    await rm(state.paths.directory, { recursive: true, force: true }).catch(
      () => {},
    );
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
  await rm(state.paths.directory, { recursive: true, force: true });
}
