// Real Node 24 / Undici integration. Run explicitly with node --test; Bun mocks
// cannot establish the socket, TLS, decoding, or implicit retry guarantees here.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { channel } from "node:diagnostics_channel";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { createServer as createProbeServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mock, test } from "node:test";
import tls from "node:tls";
import { gzipSync } from "node:zlib";
import { sha256 } from "../src/runtime/digest.ts";
import { digestCredentialProfile } from "../src/sqlite/auth.ts";
import { createLocalDispatchBoundary } from "../src/sqlite/guarded-fetch.ts";
import {
  authorizer,
  credential,
  prepared,
  profile,
} from "./helpers/dispatch-fixtures.ts";

test("Node 24 real guarded TLS HTTP dispatch", async (t) => {
  assert.match(process.version, /^v24\./);
  const dir = mkdtempSync(join(tmpdir(), "guarded-dispatch-node-"));
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      join(dir, "key.pem"),
      "-out",
      join(dir, "cert.pem"),
      "-days",
      "1",
      "-subj",
      "/CN=api.example.test",
      "-addext",
      "subjectAltName=DNS:api.example.test",
    ],
    { stdio: "ignore" },
  );
  const cert = readFileSync(join(dir, "cert.pem"));
  const key = readFileSync(join(dir, "key.pem"));
  const requests: {
    url: string;
    authorization: string | undefined;
    bytes: number;
    apiKey: string | string[] | undefined;
  }[] = [];
  let handler = (_req, res) => res.end("ok");
  const server = createServer({ key, cert }, async (req, res) => {
    let bytes = 0;
    for await (const chunk of req) bytes += chunk.length;
    requests.push({
      url: req.url ?? "/",
      authorization: req.headers.authorization,
      bytes,
      apiKey: req.headers["x-fixture-key"],
    });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const probe = createProbeServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const refusedPort = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  const originalConnect = tls.connect;
  let constructions = 0;
  let requestConstructions = 0;
  let credentialConstructions = 0;
  const requestCreated = (message: unknown) => {
    requestConstructions++;
    const headers = (message as { request: { headers: unknown } }).request
      .headers;
    if (String(headers).includes("fixture-secret")) credentialConstructions++;
  };
  const creationChannel = channel("undici:request:create");
  creationChannel.subscribe(requestCreated);
  let pinnedLookups = 0;
  let trustFixture = true;
  let refuseConnection = false;
  mock.method(tls, "connect", (options, callback) => {
    constructions++;
    assert.equal(options.servername, "api.example.test");
    assert.notEqual(options.rejectUnauthorized, false);
    const lookup = options.lookup;
    assert.equal(typeof lookup, "function");
    return originalConnect(
      {
        ...options,
        port: refuseConnection ? refusedPort : port,
        ca: trustFixture ? cert : undefined,
        // This test-only socket seam rewrites ONLY the address returned by the
        // real pinned lookup. Production still rejects every loopback fixture.
        lookup(hostname, lookupOptions, done) {
          lookup(hostname, lookupOptions, (error, address, family) => {
            if (error) {
              done(error);
              return;
            }
            pinnedLookups++;
            assert.equal(address, "8.8.8.8");
            assert.equal(family, 4);
            done(null, "127.0.0.1", 4);
          });
        },
      },
      callback,
    );
  });
  t.after(async () => {
    creationChannel.unsubscribe(requestCreated);
    mock.restoreAll();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  });
  const snapshot = await credential();
  function pair(limits = {}) {
    const auth = authorizer();
    return {
      ...createLocalDispatchBoundary(auth, {
        profile,
        limits,
        allowsManifestOrigin: (context) =>
          context.manifestDigest === "b".repeat(64) &&
          context.origin === "https://api.example.test",
        lookup: async () => [{ address: "8.8.8.8", family: 4 }],
      }),
      auth,
    };
  }
  async function action(boundary, input?) {
    const call = input ?? (await prepared());
    const plan = await boundary.transport.prepareDispatch(call, snapshot);
    const decision = await boundary.auth.authorize(call, snapshot.binding, {
      kind: "initial",
    });
    const permit = await boundary.broker.consume(
      decision,
      call,
      snapshot.binding,
    );
    return { plan, permit };
  }
  async function read(boundary, url = "/widgets") {
    const call = await prepared({
      method: "GET",
      body: null,
      safety: "read",
      actionKind: null,
      cardinality: null,
      relativeUrl: url,
    });
    const plan = await boundary.transport.prepareDispatch(call, snapshot);
    return boundary.transport.dispatchRead(plan);
  }
  await t.test(
    "read invokes pinned DNS and preserves hostname TLS and auth",
    async () => {
      handler = (_req, res) => res.end("ok");
      const result = await read(pair());
      assert.equal(result.kind, "success");
      assert.equal(new TextDecoder().decode(result.body), "ok");
      assert.equal(requests.at(-1)?.authorization, "Bearer fixture-secret");
      assert.ok(pinnedLookups > 0);
      assert.ok(requestConstructions > 0);
      assert.ok(credentialConstructions > 0);
    },
  );
  await t.test(
    "API key placement is profile-bound and injected only after preflight",
    async () => {
      handler = (_req, res) => res.end("ok");
      for (const placement of ["header", "query"] as const) {
        const name = placement === "header" ? "x-fixture-key" : "api_key";
        const configured = {
          ...profile,
          auth: {
            type: "api-key-env" as const,
            env: "FIXTURE_KEY",
            placement,
            name,
          },
        };
        const resolved = await credential({
          profileDigest: await digestCredentialProfile(configured),
          slotsDigest: await sha256("knitli.openapi-mcp.credential-slots.v1", [
            { placement, name },
          ]),
        });
        const keyed = {
          ...resolved,
          credential: {
            type: "api-key" as const,
            placement,
            name,
            value: "fixture-secret",
          },
        };
        const boundary = createLocalDispatchBoundary(authorizer(), {
          profile: configured,
          allowsManifestOrigin: () => true,
          lookup: async () => [{ address: "8.8.8.8", family: 4 }],
        });
        const call = await prepared({
          method: "GET",
          body: null,
          safety: "read",
          actionKind: null,
          cardinality: null,
          credentialProfileDigest: keyed.binding.profileDigest,
          reservedSlotsDigest: keyed.binding.slotsDigest,
        });
        const before = requestConstructions;
        for (const patch of [
          { name: "different_key" },
          { placement: placement === "header" ? "query" : "header" },
        ]) {
          await assert.rejects(
            boundary.transport.prepareDispatch(call, {
              ...keyed,
              credential: { ...keyed.credential, ...patch },
            }),
            { code: "AUTH_PROFILE_INVALID" },
          );
        }
        const plan = await boundary.transport.prepareDispatch(call, keyed);
        assert.equal(requestConstructions, before);
        keyed.credential.value = "changed-after-preflight";
        assert.equal(
          (await boundary.transport.dispatchRead(plan)).kind,
          "success",
        );
        if (placement === "header")
          assert.equal(requests.at(-1)?.apiKey, "fixture-secret");
        else
          assert.equal(
            new URL(
              requests.at(-1)?.url ?? "",
              "https://api.example.test",
            ).searchParams.get("api_key"),
            "fixture-secret",
          );
      }
    },
  );
  await t.test(
    "structural, copied and wrong-call permits construct zero HTTP requests or sockets",
    async () => {
      const boundary = pair();
      const { plan, permit } = await action(boundary);
      const before = constructions;
      const beforeRequests = requestConstructions;
      const beforeCredentials = credentialConstructions;
      for (const forged of [{}, { ...permit }])
        await assert.rejects(boundary.transport.dispatchAction(plan, forged), {
          code: "ACTION_DENIED",
        });
      const other = await action(
        boundary,
        await prepared({ relativeUrl: "/different" }),
      );
      await assert.rejects(
        boundary.transport.dispatchAction(other.plan, permit),
        { code: "ACTION_DENIED" },
      );
      assert.equal(constructions, before);
      assert.equal(requestConstructions, beforeRequests);
      assert.equal(credentialConstructions, beforeCredentials);
    },
  );
  await t.test(
    "concurrent permit reuse and plan replay send exactly one action",
    async () => {
      handler = (_req, res) => res.end("done");
      const boundary = pair();
      const { plan, permit } = await action(boundary);
      const anotherPlan = await boundary.transport.prepareDispatch(
        await prepared(),
        snapshot,
      );
      const before = requests.length;
      const results = await Promise.allSettled([
        boundary.transport.dispatchAction(plan, permit),
        boundary.transport.dispatchAction(anotherPlan, permit),
      ]);
      assert.equal(
        results.filter((value) => value.status === "fulfilled").length,
        1,
      );
      assert.equal(requests.length - before, 1);
      await assert.rejects(boundary.transport.dispatchAction(plan, permit), {
        code: "ACTION_DENIED",
      });
    },
  );
  await t.test(
    "action disconnect after body has outcome unknown and never retries",
    async () => {
      handler = (req) => req.socket.destroy();
      const boundary = pair();
      const { plan, permit } = await action(boundary);
      const before = requests.length;
      await assert.rejects(boundary.transport.dispatchAction(plan, permit), {
        code: "UPSTREAM_OUTCOME_UNKNOWN",
        retryable: false,
      });
      assert.equal(requests.length - before, 1);
      assert.equal(requests.at(-1)?.bytes, 5);
    },
  );
  await t.test("action timeout after write sends once", async () => {
    handler = () => {};
    const boundary = pair({ requestDeadlineMs: 80 });
    const { plan, permit } = await action(boundary);
    const before = requests.length;
    await assert.rejects(boundary.transport.dispatchAction(plan, permit), {
      code: "UPSTREAM_OUTCOME_UNKNOWN",
    });
    assert.equal(requests.length - before, 1);
  });
  await t.test(
    "close cancels an active action with unknown outcome and no replay",
    async () => {
      let wrote: () => void;
      const started = new Promise<void>((resolve) => {
        wrote = resolve;
      });
      handler = () => wrote();
      const boundary = pair();
      assert.equal(typeof boundary.close, "function");
      const { plan, permit } = await action(boundary);
      const before = requests.length;
      const pending = boundary.transport.dispatchAction(plan, permit);
      const rejected = assert.rejects(pending, {
        code: "UPSTREAM_OUTCOME_UNKNOWN",
      });
      await started;
      await boundary.close();
      await rejected;
      assert.equal(requests.length - before, 1);
    },
  );
  await t.test(
    "manifest policy rechecks redirects and continuation before their DNS or second request",
    async () => {
      for (const continuation of [false, true]) {
        let checks = 0;
        let dns = 0;
        const boundary = createLocalDispatchBoundary(authorizer(), {
          profile,
          allowsManifestOrigin: (context) => {
            assert.deepEqual(Object.keys(context).sort(), [
              "catalogId",
              "manifestDigest",
              "origin",
              "releaseId",
            ]);
            assert.equal(Object.isFrozen(context), true);
            return ++checks === 1;
          },
          lookup: async () => {
            dns++;
            return [{ address: "8.8.8.8", family: 4 }];
          },
        });
        handler = (_req, res) => {
          res.writeHead(
            continuation ? 200 : 302,
            continuation
              ? { link: '</next>; rel="next"' }
              : { location: "/next" },
          );
          res.end("page");
        };
        const before = requests.length;
        await assert.rejects(read(boundary), { code: "DESTINATION_DENIED" });
        assert.equal(checks, 2);
        assert.equal(dns, 1);
        assert.equal(requests.length - before, 1);
      }
    },
  );
  await t.test(
    "TLS chain verification rejects untrusted fixture before HTTP",
    async () => {
      trustFixture = false;
      const before = requests.length;
      try {
        await assert.rejects(read(pair()), { code: "UPSTREAM_ERROR" });
      } finally {
        trustFixture = true;
      }
      assert.equal(requests.length, before);
    },
  );
  await t.test(
    "positively refused connections allow two read retries and zero action retries",
    async () => {
      refuseConnection = true;
      try {
        let before = constructions;
        await assert.rejects(read(pair()), { code: "UPSTREAM_ERROR" });
        assert.equal(constructions - before, 3);
        const boundary = pair();
        const { plan, permit } = await action(boundary);
        before = constructions;
        await assert.rejects(boundary.transport.dispatchAction(plan, permit), {
          code: "UPSTREAM_ERROR",
        });
        assert.equal(constructions - before, 1);
      } finally {
        refuseConnection = false;
      }
    },
  );
  await t.test(
    "cross-origin and downgrade redirects never send a second request",
    async () => {
      for (const location of [
        "https://evil.test/secret?token=fixture-secret",
        "http://api.example.test/next",
      ]) {
        handler = (_req, res) => {
          res.writeHead(302, { location });
          res.end();
        };
        const before = requests.length;
        assert.deepEqual(await read(pair()), {
          kind: "redirect-blocked",
          location: null,
        });
        assert.equal(requests.length - before, 1);
      }
    },
  );
  await t.test(
    "actions block same-origin redirects without replay",
    async () => {
      handler = (_req, res) => {
        res.writeHead(307, { location: "/next" });
        res.end();
      };
      const boundary = pair();
      const { plan, permit } = await action(boundary);
      const before = requests.length;
      assert.deepEqual(await boundary.transport.dispatchAction(plan, permit), {
        kind: "redirect-blocked",
        location: null,
      });
      assert.equal(requests.length - before, 1);
    },
  );
  await t.test(
    "reads retain auth through three redirects and block fourth",
    async () => {
      handler = (req, res) => {
        const n = Number(req.url.slice(1)) || 0;
        if (n < 3) res.writeHead(302, { location: `/${n + 1}` });
        res.end("ok");
      };
      let before = requests.length;
      assert.equal((await read(pair(), "/0")).kind, "success");
      assert.equal(requests.length - before, 4);
      assert.ok(
        requests
          .slice(before)
          .every((value) => value.authorization === "Bearer fixture-secret"),
      );
      handler = (_req, res) => {
        res.writeHead(302, { location: "/forever" });
        res.end();
      };
      before = requests.length;
      assert.equal((await read(pair())).kind, "redirect-blocked");
      assert.equal(requests.length - before, 4);
    },
  );
  await t.test(
    "eligible read retries stop at three attempts; action statuses send once",
    async () => {
      for (const status of [429, 502, 503, 504]) {
        handler = (_req, res) => {
          res.writeHead(status, { "retry-after": "0" });
          res.end("retry");
        };
        let before = requests.length;
        assert.equal((await read(pair())).statusCode, status);
        assert.equal(requests.length - before, 3);
        const boundary = pair();
        const { plan, permit } = await action(boundary);
        before = requests.length;
        assert.equal(
          (await boundary.transport.dispatchAction(plan, permit)).statusCode,
          status,
        );
        assert.equal(requests.length - before, 1);
      }
      handler = (_req, res) => {
        res.writeHead(500);
        res.end();
      };
      const before = requests.length;
      await read(pair());
      assert.equal(requests.length - before, 1);
    },
  );
  await t.test(
    "content length and streamed decompressed bytes are independently bounded",
    async () => {
      handler = (_req, res) => {
        res.writeHead(200, { "content-length": "1000" });
        res.flushHeaders();
        res.write("a");
      };
      await assert.rejects(read(pair({ maxResponseBytes: 100 })), {
        code: "RESPONSE_LIMIT_EXCEEDED",
      });
      const compressed = gzipSync(Buffer.alloc(10_000, "a"));
      assert.ok(compressed.length < 100);
      handler = (_req, res) => {
        res.writeHead(200, {
          "content-encoding": "gzip",
          "content-length": compressed.length,
        });
        res.end(compressed);
      };
      await assert.rejects(read(pair({ maxResponseBytes: 100 })), {
        code: "RESPONSE_LIMIT_EXCEEDED",
      });
      handler = (_req, res) => {
        res.writeHead(200, { "content-encoding": "unknown" });
        res.end("encoded");
      };
      await assert.rejects(read(pair()), { code: "UPSTREAM_ERROR" });
      handler = (_req, res) => {
        res.writeHead(200, { "content-encoding": "gzip, identity" });
        res.end(compressed);
      };
      await assert.rejects(read(pair({ maxResponseBytes: 100 })), {
        code: "UPSTREAM_ERROR",
      });
    },
  );
  await t.test(
    "HEAD Content-Length describes GET bytes and does not exhaust an empty-body budget",
    async () => {
      handler = (_req, res) => {
        res.writeHead(200, {
          "content-length": "1000000",
          "content-encoding": "gzip",
        });
        res.end();
      };
      const boundary = pair({ maxResponseBytes: 10 });
      const call = await prepared({
        method: "HEAD",
        body: null,
        safety: "read",
        actionKind: null,
        cardinality: null,
      });
      const plan = await boundary.transport.prepareDispatch(call, snapshot);
      const result = await boundary.transport.dispatchRead(plan);
      assert.equal(result.kind, "success");
      assert.equal(result.body.byteLength, 0);
    },
  );
  await t.test(
    "body stall and excessive Retry-After share the original deadline",
    async () => {
      handler = (_req, res) => {
        res.writeHead(200);
        res.write("a");
      };
      await assert.rejects(read(pair({ requestDeadlineMs: 80 })), {
        code: "UPSTREAM_ERROR",
      });
      handler = (_req, res) => {
        res.writeHead(503, { "retry-after": "100" });
        res.end();
      };
      const before = requests.length;
      const result = await read(pair({ requestDeadlineMs: 80 }));
      assert.equal(result.statusCode, 503);
      assert.equal(requests.length - before, 1);
    },
  );
  await t.test(
    "Link next yields opaque proof, hides authenticated URLs and rejects cumulative overflow",
    async () => {
      handler = (_req, res) => {
        res.writeHead(200, {
          link: '</widgets?cursor=private>; rel="next", </first>; rel="first"',
          "set-cookie": "secret=yes",
        });
        res.end("page");
      };
      const boundary = pair({ maxPaginationBytes: 7 });
      const result = await read(boundary);
      assert.equal(typeof result.pageToken, "string");
      assert.equal(result.headers.link, undefined);
      assert.equal(result.headers["set-cookie"], undefined);
      const state = await boundary.paginationTokenCodec.decode(
        result.pageToken,
      );
      assert.equal(state.nextRelativeUrl, "/widgets?cursor=private");
      assert.equal(state.pageCount, 1);
      assert.equal(state.cumulativeBytes, 4);
      const call = await prepared({
        method: "GET",
        body: null,
        safety: "read",
        actionKind: null,
        cardinality: null,
        relativeUrl: state.nextRelativeUrl,
        pageToken: result.pageToken,
      });
      const plan = await boundary.transport.prepareDispatch(call, snapshot);
      handler = (_req, res) => res.end("page");
      await assert.rejects(boundary.transport.dispatchRead(plan), {
        code: "PAGINATION_LIMIT_EXCEEDED",
      });
    },
  );
  await t.test(
    "page count and continuation destination policy fail closed; JSON keys are not extractors",
    async () => {
      handler = (_req, res) => {
        res.writeHead(200, { link: '</next>; rel="next"' });
        res.end("page");
      };
      await assert.rejects(read(pair({ maxPages: 1 })), {
        code: "PAGINATION_LIMIT_EXCEEDED",
      });
      handler = (_req, res) => {
        res.writeHead(200, { link: '<https://evil.test/next>; rel="next"' });
        res.end("page");
      };
      await assert.rejects(read(pair()), { code: "DESTINATION_DENIED" });
      handler = (_req, res) => res.end('{"nextLink":"https://evil.test/next"}');
      assert.equal((await read(pair())).pageToken, undefined);
    },
  );
});
