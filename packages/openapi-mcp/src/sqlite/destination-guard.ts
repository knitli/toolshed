import { lookup as systemLookup } from "node:dns/promises";
import type { LookupFunction } from "node:net";
import { BlockList, isIP } from "node:net";
import { OpenApiMcpError } from "../runtime/errors.ts";

export interface DestinationGuardOptions {
  readonly allowedOrigins: readonly string[];
  /** Trusted resolver only; every returned address still passes public policy. */
  readonly lookup?: (
    hostname: string,
    options: { all: true; verbatim: true },
  ) => Promise<readonly { address: string; family: number }[]>;
  readonly now?: () => number;
  readonly ttlMs?: number;
}

export interface ApprovedDestination {
  readonly origin: string;
  readonly expiresAt: number;
  readonly lookup: LookupFunction;
}

const deniedV4 = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const)
  deniedV4.addSubnet(network, prefix, "ipv4");
const publicV6 = new BlockList();
publicV6.addSubnet("2000::", 3, "ipv6");
const deniedV6 = new BlockList();
for (const [network, prefix] of [
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20],
] as const)
  deniedV6.addSubnet(network, prefix, "ipv6");

function denied(): OpenApiMcpError {
  return new OpenApiMcpError(
    "DESTINATION_DENIED",
    "Destination is not permitted",
  );
}

/** Conservative IANA special-purpose policy, including all mapped/translation IPv6. */
function isPublic(address: string, family: number): boolean {
  if (isIP(address) !== family || address.includes("%")) return false;
  if (family === 4) return !deniedV4.check(address, "ipv4");
  return (
    family === 6 &&
    publicV6.check(address, "ipv6") &&
    !deniedV6.check(address, "ipv6")
  );
}

export class NodeDestinationGuard {
  readonly #origins: ReadonlySet<string>;
  readonly #resolve: NonNullable<DestinationGuardOptions["lookup"]>;
  readonly #now: () => number;
  readonly #ttl: number;

  constructor(options: DestinationGuardOptions) {
    this.#origins = new Set(
      options.allowedOrigins.map((value) => {
        const url = new URL(value);
        if (
          url.protocol !== "https:" ||
          url.username ||
          url.password ||
          url.search ||
          url.hash ||
          url.pathname !== "/"
        )
          throw denied();
        return url.origin;
      }),
    );
    this.#resolve = options.lookup ?? systemLookup;
    this.#now = options.now ?? Date.now;
    this.#ttl = options.ttlMs ?? 30_000;
    if (!Number.isSafeInteger(this.#ttl) || this.#ttl < 1 || this.#ttl > 30_000)
      throw new RangeError("Destination TTL must only lower 30000ms");
  }

  async authorize(
    value: URL,
    signal?: AbortSignal,
  ): Promise<ApprovedDestination> {
    const url = new URL(value.href);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      !this.#origins.has(url.origin)
    )
      throw denied();
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    const issuedAt = this.#now();
    if (!Number.isFinite(issuedAt)) throw denied();
    const expiresAt = issuedAt + this.#ttl;
    let answers: readonly { address: string; family: number }[];
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let abort: (() => void) | undefined;
    try {
      if (signal?.aborted) throw denied();
      const family = isIP(hostname);
      answers = family
        ? [{ address: hostname, family }]
        : await Promise.race([
            this.#resolve(hostname, { all: true, verbatim: true }),
            new Promise<never>((_, reject) => {
              timeout = setTimeout(() => reject(denied()), this.#ttl);
            }),
            new Promise<never>((_, reject) => {
              abort = () => reject(denied());
              signal?.addEventListener("abort", abort, { once: true });
            }),
          ]);
    } catch {
      throw denied();
    } finally {
      clearTimeout(timeout);
      if (abort) signal?.removeEventListener("abort", abort);
    }
    if (
      !Array.isArray(answers) ||
      answers.length === 0 ||
      answers.length > 64 ||
      this.#now() >= expiresAt
    )
      throw denied();
    const pinned = answers.map(({ address, family }) => {
      if (!isPublic(address, family)) throw denied();
      return Object.freeze({ address, family });
    });
    const lookup: LookupFunction = (requested, options, callback) => {
      const time = this.#now();
      if (
        requested !== hostname ||
        !Number.isFinite(time) ||
        time >= expiresAt
      ) {
        callback(denied(), "", 0);
        return;
      }
      const eligible = pinned.filter(
        (answer) => !options.family || answer.family === Number(options.family),
      );
      const first = eligible[0];
      if (!first) {
        callback(denied(), "", 0);
        return;
      }
      if (options.all)
        callback(
          null,
          eligible.map((answer) => ({ ...answer })),
        );
      else callback(null, first.address, first.family);
    };
    return Object.freeze({ origin: url.origin, expiresAt, lookup });
  }
}
