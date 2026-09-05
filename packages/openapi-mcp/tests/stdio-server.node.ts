// Isolated real Node/Undici transport fixture; every socket is redirected to
// the local TLS server only after asserting the production pinned lookup.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mock, test } from "node:test";
import tls from "node:tls";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  InMemoryTransport,
  type JSONRPCMessage,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { encodeOperationRef } from "../src/runtime/references.ts";
import { createLocalDispatchBoundary } from "../src/sqlite/guarded-fetch.ts";
import {
  createOpenApiMcpServer,
  createStdioActionAuthorizer,
} from "../src/stdio/server.ts";
import { credential, prepared, profile } from "./helpers/dispatch-fixtures.ts";

interface WireResponse {
  result: {
    resultType?: string;
    requestState?: unknown;
    isError?: boolean;
    content?: readonly { text?: string }[];
  };
}

test("stdio helper consumes real transport plans and permits exactly once under concurrent replay", async () => {
  const directory = mkdtempSync(join(tmpdir(), "stdio-node-tls-"));
  let https: ReturnType<typeof createServer> | undefined;
  let handle: ReturnType<typeof serveStdio> | undefined;
  let boundary: ReturnType<typeof createLocalDispatchBoundary> | undefined;
  try {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        join(directory, "key.pem"),
        "-out",
        join(directory, "cert.pem"),
        "-days",
        "1",
        "-subj",
        "/CN=api.example.test",
        "-addext",
        "subjectAltName=DNS:api.example.test",
      ],
      { stdio: "ignore" },
    );
    const cert = readFileSync(join(directory, "cert.pem"));
    const key = readFileSync(join(directory, "key.pem"));
    let upstreamActions = 0;
    let disconnectAfterAction = false;
    https = createServer({ key, cert }, async (request, response) => {
      for await (const _chunk of request) {
        /* drain */
      }
      upstreamActions++;
      assert.equal(request.headers.authorization, "Bearer fixture-secret");
      if (disconnectAfterAction) {
        request.socket.destroy();
        return;
      }
      response.end("fixture-secret: untrusted response");
    });
    const listeningServer = https;
    await new Promise<void>((resolve) =>
      listeningServer.listen(0, "127.0.0.1", resolve),
    );
    const port = (https.address() as { port: number }).port;
    const original = tls.connect;
    mock.method(tls, "connect", (options, callback) => {
      assert.equal(options.servername, "api.example.test");
      assert.equal(options.rejectUnauthorized, true);
      return original(
        {
          ...options,
          port,
          ca: cert,
          lookup(hostname, lookupOptions, done) {
            options.lookup(
              hostname,
              lookupOptions,
              (error, address, family) => {
                assert.equal(error, null);
                assert.equal(address, "8.8.8.8");
                assert.equal(family, 4);
                done(null, "127.0.0.1", 4);
              },
            );
          },
        },
        callback,
      );
    });
    const call = await prepared();
    const snapshot = await credential();
    const authorizer = createStdioActionAuthorizer();
    boundary = createLocalDispatchBoundary(authorizer, {
      profile,
      allowsManifestOrigin: (context) =>
        context.catalogId === call.catalogId &&
        context.releaseId === call.releaseId &&
        context.manifestDigest === call.manifestDigest &&
        context.origin === call.origin,
      lookup: async () => [{ address: "8.8.8.8", family: 4 }],
    });
    const transport = boundary.transport;
    let dispatchInvocations = 0;
    let replayFailures = 0;
    const replayStatuses: string[] = [];
    const [wire, serverTransport] = InMemoryTransport.createLinkedPair();
    handle = serveStdio(
      () =>
        createOpenApiMcpServer({
          searchRuntime: {
            async search() {
              return { operations: [], warnings: [] };
            },
          },
          authorizer,
          routes: [
            {
              catalogId: call.catalogId,
              releaseId: call.releaseId,
              apiNamespaces: ["fixture"],
              credentials: {
                async resolve() {
                  return { status: "ready", snapshot };
                },
              },
              runtime: {
                async search() {
                  return { operations: [], warnings: [] };
                },
                async prepareAction() {
                  return call;
                },
                async prepareRead() {
                  return call;
                },
                async revalidate(value) {
                  return value;
                },
              },
              boundary: {
                ...boundary!,
                transport: {
                  ...transport,
                  async dispatchAction(plan, permit) {
                    dispatchInvocations++;
                    const first = transport.dispatchAction(plan, permit);
                    const replay = transport.dispatchAction(plan, permit).then(
                      () => "accepted",
                      () => "rejected",
                    );
                    const result = await first;
                    replayStatuses.push(await replay);
                    replayFailures++;
                    replayStatuses.push(
                      await transport.dispatchAction(plan, permit).then(
                        () => "accepted",
                        () => "rejected",
                      ),
                    );
                    replayFailures++;
                    return result;
                  },
                },
              },
            },
          ],
        }),
      { transport: serverTransport },
    );
    const pending = new Map<number, (value: WireResponse) => void>();
    wire.onmessage = (message: JSONRPCMessage) => {
      if ("id" in message) {
        pending.get(message.id as number)?.(message as unknown as WireResponse);
        pending.delete(message.id as number);
      }
    };
    await wire.start();
    let id = 0;
    async function request(
      method: string,
      params: Record<string, unknown> = {},
    ) {
      const next = ++id;
      const result = new Promise<WireResponse>((resolve) =>
        pending.set(next, resolve),
      );
      await wire.send({
        jsonrpc: "2.0",
        id: next,
        method,
        params: {
          ...params,
          _meta: {
            [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
            [CLIENT_INFO_META_KEY]: { name: "local-tls-test", version: "1" },
            [CLIENT_CAPABILITIES_META_KEY]: { elicitation: { form: {} } },
          },
        },
      } as JSONRPCMessage);
      return result;
    }
    await request("server/discover");
    const operation = encodeOperationRef({
      catalogId: call.catalogId,
      releaseId: call.releaseId,
      manifestDigest: call.manifestDigest,
      operationId: call.operationId,
    });
    const args = { name: "action", arguments: { operation, arguments: {} } };
    const first = await request("tools/call", args);
    assert.equal(first.result.resultType, "input_required");
    assert.equal(upstreamActions, 0);
    const result = await request("tools/call", {
      ...args,
      requestState: first.result.requestState,
      inputResponses: {
        confirm: { action: "accept", content: { confirm: true } },
      },
    });
    assert.notEqual(result.result.isError, true);
    assert.equal(dispatchInvocations, 1);
    assert.deepEqual(replayStatuses, ["rejected", "rejected"]);
    assert.equal(replayFailures, 2);
    assert.equal(upstreamActions, 1);
    assert.doesNotMatch(JSON.stringify(result), /fixture-secret/);
    disconnectAfterAction = true;
    const uncertain = await request("tools/call", args);
    assert.equal(uncertain.result.resultType, "input_required");
    const unknown = await request("tools/call", {
      ...args,
      requestState: uncertain.result.requestState,
      inputResponses: {
        confirm: { action: "accept", content: { confirm: true } },
      },
    });
    assert.equal(unknown.result.isError, true);
    const unknownText = unknown.result.content?.[0]?.text;
    assert.ok(typeof unknownText === "string");
    assert.deepEqual(JSON.parse(unknownText), {
      code: "UPSTREAM_OUTCOME_UNKNOWN",
      message: "UPSTREAM_OUTCOME_UNKNOWN",
      retryable: false,
      details: { preparedCallDigest: call.preparedCallDigest },
    });
    assert.equal(upstreamActions, 2);
    assert.equal(dispatchInvocations, 2);
    assert.doesNotMatch(JSON.stringify(unknown), /fixture-secret|api\.example/);
  } finally {
    await boundary?.close();
    await handle?.close();
    mock.restoreAll();
    if (https) {
      const closingServer = https;
      closingServer.closeAllConnections();
      await new Promise<void>((resolve) =>
        closingServer.close(() => resolve()),
      );
    }
    rmSync(directory, { recursive: true, force: true });
  }
});
