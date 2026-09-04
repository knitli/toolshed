import { constants, type Stats } from "node:fs";
import { type FileHandle, lstat, open, rename, unlink } from "node:fs/promises";
import { basename, dirname } from "node:path";
import { canonicalJson, parseJsonStrict } from "../runtime/strict-json.ts";
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

const pathQueues = new Map<string, Promise<void>>();
const digestPattern = /^[0-9a-f]{64}$/;
const stateKeys = [
  "activeGeneration",
  "activeManifestDigest",
  "consumedRollbackAuthorizationIds",
  "highestGeneration",
  "highestManifestDigest",
  "revision",
];

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
      (id) => typeof id !== "string" || id.length === 0 || id.length > 128,
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
    if (
      typeof entry.catalogId !== "string" ||
      typeof entry.issuer !== "string" ||
      entry.catalogId.length === 0 ||
      entry.issuer.length === 0
    ) {
      throw failure("entry identity is invalid");
    }
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

async function serialized<T>(
  path: string,
  operation: () => Promise<T>,
): Promise<T> {
  const prior = pathQueues.get(path) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
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

/** Node-only durable, user-private compare-and-swap generation storage. */
export class FileGenerationStore implements GenerationStore {
  readonly #path: string;

  constructor(path: string) {
    if (typeof path !== "string" || path.length === 0)
      throw failure("path is invalid");
    this.#path = path;
  }

  async get(
    catalogId: CatalogId,
    issuer: string,
  ): Promise<GenerationState | null> {
    return serialized(this.#path, async () => {
      const entries = await this.#read();
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
    return serialized(this.#path, async () => {
      const entries = await this.#read();
      const index = entries.findIndex(
        (entry) => entry.catalogId === catalogId && entry.issuer === issuer,
      );
      const current = index < 0 ? null : entries[index].state;
      if ((current?.revision ?? null) !== transition.expectedRevision)
        return null;
      const next = decodeState(transition.next);
      if (next.revision !== (current === null ? 0 : current.revision + 1))
        throw failure("transition revision is invalid");
      const replacement: StateEntry = { catalogId, issuer, state: next };
      if (index < 0) entries.push(replacement);
      else entries[index] = replacement;
      entries.sort((left, right) =>
        `${left.catalogId}\0${left.issuer}`.localeCompare(
          `${right.catalogId}\0${right.issuer}`,
        ),
      );
      await this.#persist(entries);
      return cloneState(next);
    });
  }

  async #read(): Promise<StateEntry[]> {
    let metadata: Stats;
    try {
      metadata = await lstat(this.#path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw failure("cannot be inspected", error);
    }
    if (metadata.isSymbolicLink() || !metadata.isFile())
      throw failure("must be a regular non-symlink file");
    if (
      typeof process.getuid === "function" &&
      metadata.uid !== process.getuid()
    )
      throw failure("has the wrong owner");
    if ((metadata.mode & 0o077) !== 0)
      throw failure("must not be group or world accessible");
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        this.#path,
        constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
      );
      const opened = await handle.stat();
      if (
        !opened.isFile() ||
        opened.dev !== metadata.dev ||
        opened.ino !== metadata.ino
      )
        throw failure("changed while opening");
      if (
        typeof process.getuid === "function" &&
        opened.uid !== process.getuid()
      )
        throw failure("has the wrong owner");
      if ((opened.mode & 0o077) !== 0)
        throw failure("must not be group or world accessible");
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

  async #persist(entries: readonly StateEntry[]): Promise<void> {
    const directory = dirname(this.#path);
    const temporary = `${directory}/.${basename(this.#path)}.${process.pid}.${crypto.randomUUID()}.tmp`;
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        temporary,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      const payload = canonicalJson({
        version: 1,
        entries,
      } as unknown as JsonObject);
      await handle.writeFile(`${payload}\n`, "utf8");
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporary, this.#path);
      const parent = await open(directory, constants.O_RDONLY);
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
    } catch (error) {
      try {
        await handle?.close();
      } catch {}
      try {
        await unlink(temporary);
      } catch {}
      throw failure("cannot be persisted atomically", error);
    }
  }
}
