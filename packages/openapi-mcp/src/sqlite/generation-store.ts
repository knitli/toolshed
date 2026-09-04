import { type BigIntStats, constants, type Stats } from "node:fs";
import {
  type FileHandle,
  link,
  lstat,
  open,
  readdir,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
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
  mutex: string;
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
const mutexMarker = "knitli.openapi-mcp.generation-mutex.v1";
const mutexTable = "knitli_generation_mutex";
const mutexTimeoutMs = 2_000;
const mutexInitializationGraceMs = 500;
const maximumMutexBytes = 1024 * 1024;
const maximumStateBytes = 16 * 1024 * 1024;

class MutexLinkCountError extends Error {
  constructor(label: string) {
    super(`Generation state ${label} must have exactly one link`);
  }
}

/** Stable bounded failure when another process retains the generation mutex. */
export class GenerationStoreContentionError extends Error {
  constructor() {
    super("Generation state mutex contention exceeded its bounded deadline");
    this.name = "GenerationStoreContentionError";
  }
}

function failure(message: string, cause?: unknown): Error {
  return new Error(`Generation state ${message}`, { cause });
}

function mutexFailure(message: string): Error {
  return failure(`mutex ${message}`);
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
      maxBytes: maximumStateBytes,
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

function assertPrivateRegular(
  metadata: Stats,
  label: string,
  requireSingleLink = false,
): void {
  if (!metadata.isFile() || metadata.isSymbolicLink())
    throw failure(`${label} must be a regular non-symlink file`);
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid())
    throw failure(`${label} has wrong owner`);
  if ((metadata.mode & 0o077) !== 0)
    throw failure(`${label} must not be group or world accessible`);
  if (requireSingleLink && metadata.nlink !== 1)
    throw new MutexLinkCountError(label);
}

function sameFile(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertPrivateStateFile(metadata: BigIntStats): void {
  if (!metadata.isFile() || metadata.isSymbolicLink())
    throw failure("file must be a regular non-symlink file");
  if (
    typeof process.getuid === "function" &&
    metadata.uid !== BigInt(process.getuid())
  )
    throw failure("file has wrong owner");
  if ((metadata.mode & 0o077n) !== 0n)
    throw failure("file must not be group or world accessible");
}

function sameStateSnapshot(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function readStateBytes(
  handle: FileHandle,
  expectedSize: number,
): Promise<string> {
  const bytes = Buffer.allocUnsafe(expectedSize || 1);
  let total = 0;
  while (total < expectedSize) {
    const { bytesRead } = await handle.read(
      bytes,
      total,
      Math.min(64 * 1024, expectedSize - total),
      null,
    );
    if (bytesRead === 0) throw failure("file changed while reading");
    total += bytesRead;
  }
  const probe = new Uint8Array(1);
  const { bytesRead: trailingBytes } = await handle.read(probe, 0, 1, null);
  if (trailingBytes !== 0) throw failure("file changed while reading");
  return bytes.subarray(0, expectedSize).toString("utf8");
}

function sqliteRows(database: DatabaseSync, sql: string): unknown[] {
  return database.prepare(sql).all();
}

function validateMutexSchema(database: DatabaseSync): void {
  const version = database.prepare("PRAGMA user_version").get() as
    | Record<string, unknown>
    | undefined;
  const tables = sqliteRows(
    database,
    "SELECT name, type FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
  ) as Record<string, unknown>[];
  const columns = sqliteRows(
    database,
    `PRAGMA table_info(${mutexTable})`,
  ) as Record<string, unknown>[];
  const rows = sqliteRows(
    database,
    `SELECT singleton, format, marker FROM ${mutexTable}`,
  ) as Record<string, unknown>[];
  const integrity = database.prepare("PRAGMA integrity_check").get() as
    | Record<string, unknown>
    | undefined;
  if (
    version?.user_version !== 1 ||
    tables.length !== 1 ||
    tables[0]?.name !== mutexTable ||
    tables[0]?.type !== "table" ||
    columns.length !== 3 ||
    columns[0]?.name !== "singleton" ||
    columns[0]?.type !== "INTEGER" ||
    columns[0]?.pk !== 1 ||
    columns[1]?.name !== "format" ||
    columns[1]?.type !== "INTEGER" ||
    columns[1]?.notnull !== 1 ||
    columns[2]?.name !== "marker" ||
    columns[2]?.type !== "TEXT" ||
    columns[2]?.notnull !== 1 ||
    rows.length !== 1 ||
    rows[0]?.singleton !== 1 ||
    rows[0]?.format !== 1 ||
    rows[0]?.marker !== mutexMarker ||
    integrity?.integrity_check !== "ok"
  )
    throw mutexFailure("database schema or marker is invalid");
}

async function requireNoMutexSidecars(mutex: string): Promise<void> {
  for (const suffix of ["-journal", "-wal", "-shm"] as const) {
    try {
      const metadata = await lstat(`${mutex}${suffix}`);
      assertPrivateRegular(metadata, `mutex ${suffix} sidecar`, true);
      throw mutexFailure(`${suffix} sidecar is unexpected`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

async function validateMutexMetadata(mutex: string): Promise<Stats> {
  let before: Stats;
  try {
    before = await lstat(mutex);
    assertPrivateRegular(before, "mutex database", true);
    if (before.size > maximumMutexBytes)
      throw mutexFailure("database exceeds its byte limit");
    await requireNoMutexSidecars(mutex);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") throw error;
    if ((error as Error).message?.startsWith("Generation state")) throw error;
    throw mutexFailure("database cannot be inspected");
  }
  return before;
}

function regexEscape(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function clearMutexInitializerAlias(
  location: StoreLocation,
): Promise<void> {
  const final = await lstat(location.mutex);
  const namePattern = new RegExp(
    `^\\.${regexEscape(basename(location.target))}\\.\\d+\\.` +
      "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.mutex-init$",
    "i",
  );
  let removed = false;
  for (const name of await readdir(location.parent)) {
    if (!namePattern.test(name)) continue;
    const candidate = join(location.parent, name);
    let metadata: Stats;
    try {
      metadata = await lstat(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    assertPrivateRegular(metadata, "mutex initializer");
    if (!sameFile(final, metadata)) continue;
    let finalImmediatelyBefore: Stats;
    let aliasImmediatelyBefore: Stats;
    try {
      finalImmediatelyBefore = await lstat(location.mutex);
      aliasImmediatelyBefore = await lstat(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    if (
      !sameFile(final, finalImmediatelyBefore) ||
      !sameFile(finalImmediatelyBefore, aliasImmediatelyBefore)
    )
      continue;
    try {
      await unlink(candidate);
      removed = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  if (removed) {
    const parent = await open(location.parent, constants.O_RDONLY);
    try {
      await parent.sync();
    } finally {
      await parent.close();
    }
  }
}

async function initializeMutex(location: StoreLocation): Promise<void> {
  const observationDeadline = Date.now() + mutexInitializationGraceMs;
  while (true) {
    try {
      await validateMutexMetadata(location.mutex);
      return;
    } catch (error) {
      if (
        error instanceof MutexLinkCountError &&
        Date.now() < observationDeadline
      ) {
        await clearMutexInitializerAlias(location);
        await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, 5));
        continue;
      }
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      break;
    }
  }

  const temporary = join(
    location.parent,
    `.${basename(location.target)}.${process.pid}.${crypto.randomUUID()}.mutex-init`,
  );
  let handle: FileHandle | undefined;
  let database: DatabaseSync | undefined;
  try {
    handle = await open(
      temporary,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_RDWR |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    assertPrivateRegular(await handle.stat(), "mutex initializer", true);
    await handle.close();
    handle = undefined;
    database = new DatabaseSync(temporary, { timeout: mutexTimeoutMs });
    database.exec(
      `PRAGMA journal_mode=DELETE;
       PRAGMA synchronous=FULL;
       CREATE TABLE ${mutexTable} (
         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
         format INTEGER NOT NULL CHECK (format = 1),
         marker TEXT NOT NULL CHECK (marker = '${mutexMarker}')
       ) WITHOUT ROWID;
       INSERT INTO ${mutexTable}(singleton, format, marker)
       VALUES (1, 1, '${mutexMarker}');
       PRAGMA user_version=1;`,
    );
    database.close();
    database = undefined;
    handle = await open(
      temporary,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    assertPrivateRegular(await handle.stat(), "mutex initializer", true);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await requireNoMutexSidecars(temporary);

    try {
      await link(temporary, location.mutex);
      try {
        await unlink(temporary);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      const parent = await open(location.parent, constants.O_RDONLY);
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  } catch {
    throw mutexFailure("database cannot be initialized");
  } finally {
    try {
      database?.close();
    } catch {}
    try {
      await handle?.close();
    } catch {}
    try {
      await unlink(temporary);
    } catch {}
  }
  const installationDeadline = Date.now() + mutexInitializationGraceMs;
  while (true) {
    try {
      await validateMutexMetadata(location.mutex);
      return;
    } catch (error) {
      if (
        error instanceof MutexLinkCountError &&
        Date.now() < installationDeadline
      ) {
        await clearMutexInitializerAlias(location);
        await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, 5));
        continue;
      }
      throw error;
    }
  }
}

async function openMutex(location: StoreLocation): Promise<DatabaseSync> {
  await initializeMutex(location);
  const before = await validateMutexMetadata(location.mutex);
  let database: DatabaseSync | undefined;
  try {
    // DatabaseSync has no fd constructor. A canonical 0700 parent prevents an
    // untrusted path swap between these inode checks and the path-based open.
    database = new DatabaseSync(location.mutex, { timeout: mutexTimeoutMs });
    const after = await lstat(location.mutex);
    assertPrivateRegular(after, "mutex database", true);
    if (!sameFile(before, after))
      throw mutexFailure("database changed while opening");
    await requireNoMutexSidecars(location.mutex);
    return database;
  } catch (error) {
    try {
      database?.close();
    } catch {}
    if (isSqliteBusy(error)) throw new GenerationStoreContentionError();
    if ((error as Error).message?.startsWith("Generation state")) throw error;
    throw mutexFailure("database is corrupt or inaccessible");
  }
}

function isSqliteBusy(error: unknown): boolean {
  const candidate = error as { errcode?: unknown };
  if (typeof candidate?.errcode !== "number") return false;
  const primaryCode = candidate.errcode & 0xff;
  return primaryCode === 5 || primaryCode === 6;
}

function beginExclusive(database: DatabaseSync): void {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      database.exec("BEGIN EXCLUSIVE");
      return;
    } catch (error) {
      if (isSqliteBusy(error)) throw new GenerationStoreContentionError();
      // Bun/macOS may transiently surface SQLITE_IOERR_LOCK on the first lock
      // syscall after a prior connection closes. Retry once; only a subsequent
      // canonical BUSY/LOCKED result is classified as contention.
      if (attempt === 0 && (error as { errcode?: unknown }).errcode === 3850)
        continue;
      throw mutexFailure("exclusive transaction cannot be acquired");
    }
  }
}

function requireValidOpenMutex(database: DatabaseSync): void {
  try {
    validateMutexSchema(database);
  } catch (error) {
    if (isSqliteBusy(error)) throw new GenerationStoreContentionError();
    if ((error as Error).message?.startsWith("Generation state")) throw error;
    throw mutexFailure("database is corrupt or inaccessible");
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
      const database = await openMutex(location);
      let transactionOpen = false;
      try {
        beginExclusive(database);
        transactionOpen = true;
        requireValidOpenMutex(database);
        const entries = await this.#read(location.target);
        const state = entries.find(
          (entry) => entry.catalogId === catalogId && entry.issuer === issuer,
        )?.state;
        database.exec("COMMIT");
        transactionOpen = false;
        return state ? cloneState(state) : null;
      } catch (error) {
        if (transactionOpen) {
          try {
            database.exec("ROLLBACK");
          } catch {}
        }
        throw error;
      } finally {
        try {
          database.close();
        } catch {}
      }
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
      const database = await openMutex(location);
      let transactionOpen = false;
      try {
        beginExclusive(database);
        transactionOpen = true;
        requireValidOpenMutex(database);
        const entries = await this.#read(location.target);
        const index = entries.findIndex(
          (entry) => entry.catalogId === catalogId && entry.issuer === issuer,
        );
        const current = index < 0 ? null : entries[index].state;
        if ((current?.revision ?? null) !== transition.expectedRevision) {
          database.exec("COMMIT");
          transactionOpen = false;
          return null;
        }
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
        database.exec("COMMIT");
        transactionOpen = false;
        return cloneState(next);
      } catch (error) {
        if (transactionOpen) {
          try {
            database.exec("ROLLBACK");
          } catch {}
        }
        throw error;
      } finally {
        try {
          database.close();
        } catch {}
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
      throw failure("parent has wrong owner");
    if ((metadata.mode & 0o077) !== 0)
      throw failure("parent must be owner-only (0700)");
    const target = join(parent, basename(this.#requestedPath));
    return {
      target,
      parent,
      mutex: join(parent, `.${basename(target)}.mutex.sqlite3`),
    };
  }

  async #read(target: string): Promise<StateEntry[]> {
    let metadata: BigIntStats;
    try {
      metadata = await lstat(target, { bigint: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw failure("cannot be read", error);
    }
    assertPrivateStateFile(metadata);
    if (metadata.size > BigInt(maximumStateBytes))
      throw failure("file is too large");
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        target,
        constants.O_RDONLY |
          (constants.O_NOFOLLOW ?? 0) |
          (constants.O_NONBLOCK ?? 0),
      );
      const opened = await handle.stat({ bigint: true });
      assertPrivateStateFile(opened);
      if (!sameStateSnapshot(opened, metadata))
        throw failure("file changed while opening");
      const text = await readStateBytes(handle, Number(metadata.size));
      const after = await handle.stat({ bigint: true });
      assertPrivateStateFile(after);
      if (!sameStateSnapshot(after, opened))
        throw failure("file changed while reading");
      const current = await lstat(target, { bigint: true });
      assertPrivateStateFile(current);
      if (!sameStateSnapshot(current, opened))
        throw failure("file pathname changed while reading");
      return decodeFile(text);
    } catch (error) {
      if ((error as Error).message?.startsWith("Generation state")) throw error;
      throw failure("cannot be read", error);
    } finally {
      await handle?.close();
    }
  }

  async #persist(
    location: StoreLocation,
    entries: StateEntry[],
  ): Promise<void> {
    const temporary = join(
      location.parent,
      `.${basename(location.target)}.${process.pid}.${crypto.randomUUID()}.tmp`,
    );
    let handle: FileHandle | undefined;
    let renamed = false;
    try {
      const payload = canonicalJsonBounded(
        { version: 1, entries } as unknown as JsonObject,
        {
          maxBytes: maximumStateBytes,
          maxDepth: 8,
          maxNodes: 1_000_000,
        },
      );
      handle = await open(
        temporary,
        constants.O_CREAT |
          constants.O_EXCL |
          constants.O_WRONLY |
          (constants.O_NOFOLLOW ?? 0),
        0o600,
      );
      assertPrivateRegular(await handle.stat(), "temporary file", true);
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
