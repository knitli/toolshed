import { constants, type Stats } from "node:fs";
import {
  type FileHandle,
  link,
  lstat,
  open,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import {
  canonicalJson,
  canonicalJsonBounded,
  parseJsonStrict,
} from "../runtime/strict-json.ts";
import type {
  CatalogId,
  GenerationState,
  GenerationStore,
  GenerationTransition,
  JsonObject,
  Sha256,
} from "../runtime/types.ts";

interface StateEntry {
  catalogId: CatalogId;
  issuer: string;
  state: GenerationState;
}

interface StoreLocation {
  target: string;
  parent: string;
  lock: string;
  recovery: string;
}

interface LockMetadata {
  version: 1;
  pid: number;
  createdAtEpochMs: number;
  token: string;
}

interface LockLease {
  location: StoreLocation;
  claim: string;
  handle: FileHandle;
  metadata: LockMetadata;
}

const pathQueues = new Map<string, Promise<void>>();
const digestPattern = /^[0-9a-f]{64}$/;
const identityPattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const stateKeys = [
  "activeGeneration",
  "activeManifestDigest",
  "consumedRollbackAuthorizationIds",
  "highestGeneration",
  "highestManifestDigest",
  "revision",
];
const lockKeys = ["createdAtEpochMs", "pid", "token", "version"];
const lockTimeoutMs = 2_000;
const deadLockMinimumAgeMs = 100;
const lockPollMs = 10;

function failure(message: string, cause?: unknown): Error {
  return new Error(`Generation state ${message}`, { cause });
}

function exactObject(
  value: unknown,
  expected: readonly string[],
  label: string,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw failure(`${label} is invalid`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype)
    throw failure(`${label} prototype is invalid`);
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string"))
    throw failure(`${label} shape is invalid`);
  const keys = (actual as string[]).sort();
  const wanted = [...expected].sort();
  if (
    keys.length !== wanted.length ||
    keys.some((key, index) => key !== wanted[index])
  )
    throw failure(`${label} shape is invalid`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      throw failure(`${label} properties are invalid`);
  }
  return value as Record<string, unknown>;
}

function integer(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function requireIdentity(catalogId: CatalogId, issuer: string): void {
  if (
    typeof catalogId !== "string" ||
    catalogId.length === 0 ||
    catalogId.length > 128 ||
    catalogId === "." ||
    catalogId === ".." ||
    !identityPattern.test(catalogId) ||
    typeof issuer !== "string" ||
    issuer.length === 0 ||
    issuer.length > 256 ||
    /[^\x21-\x7e]/.test(issuer)
  )
    throw failure("entry identity is invalid");
}

function decodeState(value: unknown): GenerationState {
  const object = exactObject(value, stateKeys, "entry state");
  if (
    !integer(object.revision) ||
    !integer(object.highestGeneration) ||
    !integer(object.activeGeneration) ||
    typeof object.highestManifestDigest !== "string" ||
    !digestPattern.test(object.highestManifestDigest) ||
    typeof object.activeManifestDigest !== "string" ||
    !digestPattern.test(object.activeManifestDigest) ||
    !Array.isArray(object.consumedRollbackAuthorizationIds) ||
    object.consumedRollbackAuthorizationIds.some(
      (id) =>
        typeof id !== "string" ||
        id.length === 0 ||
        id.length > 128 ||
        !identityPattern.test(id),
    ) ||
    new Set(object.consumedRollbackAuthorizationIds).size !==
      object.consumedRollbackAuthorizationIds.length ||
    object.activeGeneration > object.highestGeneration ||
    (object.activeGeneration === object.highestGeneration &&
      object.activeManifestDigest !== object.highestManifestDigest)
  )
    throw failure("entry state invariants are invalid");
  return {
    revision: object.revision,
    highestGeneration: object.highestGeneration,
    highestManifestDigest: object.highestManifestDigest as Sha256,
    activeGeneration: object.activeGeneration,
    activeManifestDigest: object.activeManifestDigest as Sha256,
    consumedRollbackAuthorizationIds: [
      ...object.consumedRollbackAuthorizationIds,
    ] as string[],
  };
}

function decodeFile(text: string): StateEntry[] {
  let value: unknown;
  try {
    value = parseJsonStrict(text, {
      maxBytes: 16 * 1024 * 1024,
      maxDepth: 8,
      maxKeys: 1_000_000,
    });
  } catch (error) {
    throw failure("file is corrupt", error);
  }
  const root = exactObject(value, ["entries", "version"], "file");
  if (root.version !== 1 || !Array.isArray(root.entries))
    throw failure("file version or entries are invalid");
  const seen = new Set<string>();
  return root.entries.map((rawEntry) => {
    const entry = exactObject(
      rawEntry,
      ["catalogId", "issuer", "state"],
      "entry",
    );
    if (typeof entry.catalogId !== "string" || typeof entry.issuer !== "string")
      throw failure("entry identity is invalid");
    requireIdentity(entry.catalogId as CatalogId, entry.issuer);
    const identity = `${entry.catalogId}\0${entry.issuer}`;
    if (seen.has(identity)) throw failure("file has duplicate entries");
    seen.add(identity);
    return {
      catalogId: entry.catalogId as CatalogId,
      issuer: entry.issuer,
      state: decodeState(entry.state),
    };
  });
}

function cloneState(state: GenerationState): GenerationState {
  return {
    ...state,
    consumedRollbackAuthorizationIds: [
      ...state.consumedRollbackAuthorizationIds,
    ],
  };
}

function sameLedger(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((identity, index) => identity === right[index])
  );
}

function requireLegalTransition(
  current: GenerationState | null,
  next: GenerationState,
): void {
  if (current === null) {
    if (
      next.revision !== 0 ||
      next.activeGeneration !== next.highestGeneration ||
      next.activeManifestDigest !== next.highestManifestDigest ||
      next.consumedRollbackAuthorizationIds.length !== 0
    )
      throw failure("transition is not a legal creation");
    return;
  }
  if (next.revision !== current.revision + 1)
    throw failure("transition revision is invalid");
  const higherNormal =
    next.highestGeneration > current.highestGeneration &&
    next.activeGeneration === next.highestGeneration &&
    next.activeManifestDigest === next.highestManifestDigest &&
    sameLedger(
      next.consumedRollbackAuthorizationIds,
      current.consumedRollbackAuthorizationIds,
    );
  const rollback =
    next.highestGeneration === current.highestGeneration &&
    next.highestManifestDigest === current.highestManifestDigest &&
    next.activeGeneration < next.highestGeneration &&
    next.consumedRollbackAuthorizationIds.length ===
      current.consumedRollbackAuthorizationIds.length + 1 &&
    current.consumedRollbackAuthorizationIds.every(
      (identity, index) =>
        next.consumedRollbackAuthorizationIds[index] === identity,
    );
  if (!higherNormal && !rollback)
    throw failure("transition is not a legal normal admission or rollback");
}

async function serialized<T>(
  path: string,
  operation: () => Promise<T>,
): Promise<T> {
  const prior = pathQueues.get(path) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((resolveGate) => {
    release = resolveGate;
  });
  const current = prior.catch(() => undefined).then(() => gate);
  pathQueues.set(path, current);
  await prior.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release();
    if (pathQueues.get(path) === current) pathQueues.delete(path);
  }
}

function assertPrivateRegular(metadata: Stats, label: string): void {
  if (!metadata.isFile() || metadata.isSymbolicLink())
    throw failure(`${label} must be a regular non-symlink file`);
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid())
    throw failure(`${label} has the wrong owner`);
  if ((metadata.mode & 0o077) !== 0)
    throw failure(`${label} must not be group or world accessible`);
}

function decodeLock(text: string): LockMetadata {
  const value = parseJsonStrict(text, {
    maxBytes: 4096,
    maxDepth: 2,
    maxKeys: 4,
  });
  const object = exactObject(value, lockKeys, "lock");
  if (
    object.version !== 1 ||
    !Number.isSafeInteger(object.pid) ||
    (object.pid as number) <= 0 ||
    !integer(object.createdAtEpochMs) ||
    typeof object.token !== "string" ||
    !/^[0-9a-f-]{36}$/.test(object.token)
  )
    throw failure("lock metadata is invalid");
  return object as unknown as LockMetadata;
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    return true;
  }
}

async function readLock(path: string): Promise<{
  metadata: LockMetadata;
  stats: Stats;
}> {
  const before = await lstat(path);
  assertPrivateRegular(before, "lock");
  const handle = await open(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const stats = await handle.stat();
    assertPrivateRegular(stats, "lock");
    if (stats.dev !== before.dev || stats.ino !== before.ino)
      throw failure("lock changed while opening");
    return { metadata: decodeLock(await handle.readFile("utf8")), stats };
  } finally {
    await handle.close();
  }
}

function sameLock(
  left: Awaited<ReturnType<typeof readLock>>,
  right: Awaited<ReturnType<typeof readLock>>,
): boolean {
  return (
    left.stats.dev === right.stats.dev &&
    left.stats.ino === right.stats.ino &&
    left.metadata.version === right.metadata.version &&
    left.metadata.pid === right.metadata.pid &&
    left.metadata.createdAtEpochMs === right.metadata.createdAtEpochMs &&
    left.metadata.token === right.metadata.token
  );
}

async function writeClaim(
  location: StoreLocation,
): Promise<{ claim: string; handle: FileHandle; metadata: LockMetadata }> {
  const token = crypto.randomUUID();
  const claim = join(
    location.parent,
    `.${basename(location.target)}.${process.pid}.${token}.claim`,
  );
  const handle = await open(
    claim,
    constants.O_CREAT |
      constants.O_EXCL |
      constants.O_RDWR |
      (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  const metadata: LockMetadata = {
    version: 1,
    pid: process.pid,
    createdAtEpochMs: Date.now(),
    token,
  };
  try {
    assertPrivateRegular(await handle.stat(), "claim");
    await handle.writeFile(
      `${canonicalJson(metadata as unknown as JsonObject)}\n`,
    );
    await handle.sync();
    return { claim, handle, metadata };
  } catch (error) {
    await handle.close();
    try {
      await unlink(claim);
    } catch {}
    throw error;
  }
}

async function tryInstallClaim(
  location: StoreLocation,
  claim: string,
): Promise<boolean> {
  try {
    await lstat(location.recovery);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  try {
    await link(claim, location.lock);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw failure("lock cannot be installed", error);
  }
}

async function clearStaleRecovery(location: StoreLocation): Promise<void> {
  let observed: Awaited<ReturnType<typeof readLock>>;
  try {
    observed = await readLock(location.recovery);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (
    processIsAlive(observed.metadata.pid) ||
    Date.now() - observed.metadata.createdAtEpochMs < deadLockMinimumAgeMs
  )
    return;
  let current: Awaited<ReturnType<typeof readLock>>;
  try {
    current = await readLock(location.recovery);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!sameLock(current, observed) || processIsAlive(current.metadata.pid))
    return;
  try {
    await unlink(location.recovery);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function tryRecoverDeadLock(
  location: StoreLocation,
  claim: string,
): Promise<boolean> {
  try {
    await lstat(location.recovery);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  let observed: Awaited<ReturnType<typeof readLock>>;
  try {
    observed = await readLock(location.lock);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
  if (
    processIsAlive(observed.metadata.pid) ||
    Date.now() - observed.metadata.createdAtEpochMs < deadLockMinimumAgeMs
  )
    return false;
  try {
    await link(location.lock, location.recovery);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw failure("dead lock cannot be claimed for recovery", error);
  }
  try {
    const [current, recovery] = await Promise.all([
      readLock(location.lock),
      readLock(location.recovery),
    ]);
    if (
      !sameLock(current, observed) ||
      !sameLock(recovery, observed) ||
      processIsAlive(current.metadata.pid)
    )
      return false;
    const recoveryHandle = await open(
      location.recovery,
      constants.O_WRONLY | constants.O_TRUNC | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const opened = await recoveryHandle.stat();
      assertPrivateRegular(opened, "recovery lock");
      if (
        opened.dev !== recovery.stats.dev ||
        opened.ino !== recovery.stats.ino
      )
        throw failure("recovery lock changed while opening");
      const claimMetadata = await readLock(claim);
      await recoveryHandle.writeFile(
        `${canonicalJson(claimMetadata.metadata as unknown as JsonObject)}\n`,
      );
      await recoveryHandle.sync();
      const adopted = await readLock(location.lock);
      if (
        adopted.stats.dev !== opened.dev ||
        adopted.stats.ino !== opened.ino ||
        adopted.metadata.token !== claimMetadata.metadata.token ||
        adopted.metadata.pid !== claimMetadata.metadata.pid
      )
        throw failure("dead lock ownership changed during recovery");
    } finally {
      await recoveryHandle.close();
    }
    await unlink(location.lock);
    try {
      await link(claim, location.lock);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
      throw error;
    }
    return true;
  } finally {
    try {
      await unlink(location.recovery);
    } catch {}
  }
}

async function acquireLock(location: StoreLocation): Promise<LockLease> {
  const claim = await writeClaim(location);
  const deadline = Date.now() + lockTimeoutMs;
  try {
    while (Date.now() <= deadline) {
      await clearStaleRecovery(location);
      if (
        (await tryInstallClaim(location, claim.claim)) ||
        (await tryRecoverDeadLock(location, claim.claim))
      )
        return { location, ...claim };
      await new Promise<void>((resolveDelay) =>
        setTimeout(resolveDelay, lockPollMs),
      );
    }
    throw failure("lock contention exceeded its bounded deadline");
  } catch (error) {
    await claim.handle.close();
    try {
      await unlink(claim.claim);
    } catch {}
    throw error;
  }
}

async function releaseLock(lease: LockLease): Promise<void> {
  try {
    const [lock, claim] = await Promise.all([
      readLock(lease.location.lock),
      lease.handle.stat(),
    ]);
    if (
      lock.stats.dev !== claim.dev ||
      lock.stats.ino !== claim.ino ||
      lock.metadata.token !== lease.metadata.token
    )
      throw failure("lock ownership changed before release");
    await unlink(lease.location.lock);
    const parent = await open(lease.location.parent, constants.O_RDONLY);
    try {
      await parent.sync();
    } finally {
      await parent.close();
    }
  } finally {
    await lease.handle.close();
    try {
      await unlink(lease.claim);
    } catch {}
  }
}

/** Node-only durable, user-private compare-and-swap generation storage. */
export class FileGenerationStore implements GenerationStore {
  readonly #requestedPath: string;

  constructor(path: string) {
    if (typeof path !== "string" || path.length === 0)
      throw failure("path is invalid");
    this.#requestedPath = resolve(path);
  }

  async get(
    catalogId: CatalogId,
    issuer: string,
  ): Promise<GenerationState | null> {
    requireIdentity(catalogId, issuer);
    const location = await this.#location();
    return serialized(location.target, async () => {
      const entries = await this.#read(location.target);
      const state = entries.find(
        (entry) => entry.catalogId === catalogId && entry.issuer === issuer,
      )?.state;
      return state ? cloneState(state) : null;
    });
  }

  async accept(
    catalogId: CatalogId,
    issuer: string,
    transition: GenerationTransition,
  ): Promise<GenerationState | null> {
    requireIdentity(catalogId, issuer);
    const location = await this.#location();
    return serialized(location.target, async () => {
      const lease = await acquireLock(location);
      try {
        const entries = await this.#read(location.target);
        const index = entries.findIndex(
          (entry) => entry.catalogId === catalogId && entry.issuer === issuer,
        );
        const current = index < 0 ? null : entries[index].state;
        if ((current?.revision ?? null) !== transition.expectedRevision)
          return null;
        const next = decodeState(transition.next);
        requireLegalTransition(current, next);
        const replacement: StateEntry = { catalogId, issuer, state: next };
        if (index < 0) entries.push(replacement);
        else entries[index] = replacement;
        entries.sort((left, right) =>
          `${left.catalogId}\0${left.issuer}`.localeCompare(
            `${right.catalogId}\0${right.issuer}`,
          ),
        );
        await this.#persist(location, entries);
        return cloneState(next);
      } finally {
        await releaseLock(lease);
      }
    });
  }

  async #location(): Promise<StoreLocation> {
    const parent = await realpath(dirname(this.#requestedPath));
    const metadata = await lstat(parent);
    if (!metadata.isDirectory() || metadata.isSymbolicLink())
      throw failure("parent must be a real directory");
    if (
      typeof process.getuid === "function" &&
      metadata.uid !== process.getuid()
    )
      throw failure("parent has the wrong owner");
    if ((metadata.mode & 0o022) !== 0)
      throw failure("parent must not be group or world writable");
    const target = join(parent, basename(this.#requestedPath));
    return {
      target,
      parent,
      lock: join(parent, `.${basename(target)}.lock`),
      recovery: join(parent, `.${basename(target)}.lock.recovery`),
    };
  }

  async #read(target: string): Promise<StateEntry[]> {
    let metadata: Stats;
    try {
      metadata = await lstat(target);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw failure("cannot be inspected", error);
    }
    assertPrivateRegular(metadata, "file");
    if (metadata.size > 16 * 1024 * 1024)
      throw failure("file exceeds its byte limit");
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        target,
        constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
      );
      const opened = await handle.stat();
      assertPrivateRegular(opened, "file");
      if (opened.dev !== metadata.dev || opened.ino !== metadata.ino)
        throw failure("file changed while opening");
      return decodeFile(await handle.readFile("utf8"));
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.startsWith("Generation state")
      )
        throw error;
      throw failure("cannot be read", error);
    } finally {
      await handle?.close();
    }
  }

  async #persist(
    location: StoreLocation,
    entries: readonly StateEntry[],
  ): Promise<void> {
    const temporary = join(
      location.parent,
      `.${basename(location.target)}.${process.pid}.${crypto.randomUUID()}.tmp`,
    );
    let handle: FileHandle | undefined;
    let renamed = false;
    try {
      handle = await open(
        temporary,
        constants.O_CREAT |
          constants.O_EXCL |
          constants.O_WRONLY |
          (constants.O_NOFOLLOW ?? 0),
        0o600,
      );
      const payload = canonicalJsonBounded(
        { version: 1, entries } as unknown as JsonObject,
        { maxBytes: 16 * 1024 * 1024, maxDepth: 8, maxNodes: 1_000_000 },
      );
      await handle.writeFile(payload, "utf8");
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporary, location.target);
      renamed = true;
      const parent = await open(location.parent, constants.O_RDONLY);
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
    } catch (error) {
      try {
        await handle?.close();
      } catch {}
      if (!renamed) {
        try {
          await unlink(temporary);
        } catch {}
      }
      throw failure(
        renamed
          ? "replacement was installed but parent sync failed; retry admission to reconcile active state"
          : "cannot be persisted atomically",
        error,
      );
    }
  }
}
