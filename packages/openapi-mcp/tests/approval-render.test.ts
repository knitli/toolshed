import { describe, expect, test } from "bun:test";
import { digestCredentialAuthorizationBinding } from "../src/runtime/credential-binding.ts";
import {
  createPreparedCall,
  type PreparedCallInput,
} from "../src/runtime/prepared-call.ts";
import type {
  CredentialAuthorizationBinding,
  PreparedCall,
  Sha256,
} from "../src/runtime/types.ts";
import { renderApproval } from "../src/stdio/render.ts";

const digest = (character: string): Sha256 => character.repeat(64) as Sha256;

async function preparedCall(
  overrides: Partial<PreparedCallInput> = {},
): Promise<PreparedCall> {
  return await createPreparedCall({
    version: 2,
    catalogId: "catalog" as PreparedCall["catalogId"],
    releaseId: "release-1" as PreparedCall["releaseId"],
    operationId: "operation:catalog:createWidget",
    operationDigest: digest("a"),
    manifestDigest: digest("b"),
    credentialProfileId: "operator-profile",
    credentialProfileDigest: digest("c"),
    reservedSlotsDigest: digest("d"),
    method: "POST",
    origin: "https://api.example.test",
    relativeUrl: "/widgets",
    headers: {},
    body: null,
    normalizedArguments: {
      body: { name: "safe" },
      query: { limit: 1 },
    },
    safety: "action",
    actionKind: "create",
    cardinality: { kind: "single" },
    ...overrides,
  });
}

async function credentialBinding(
  overrides: Partial<CredentialAuthorizationBinding> = {},
): Promise<CredentialAuthorizationBinding> {
  const payload = {
    profileId: "operator-profile",
    profileDigest: digest("c"),
    grantId: "grant_identifier_1",
    audience: "https://api.example.test",
    scopes: Object.freeze(["widgets:write"]),
    slotsDigest: digest("d"),
    ...overrides,
  };
  return Object.freeze({
    ...payload,
    bindingDigest: await digestCredentialAuthorizationBinding(payload),
  });
}

describe("renderApproval", () => {
  test("renders identity and credential authority as fixed-label quoted data", async () => {
    const valid = await preparedCall();
    const call = {
      ...valid,
      catalogId: "```\n# APPROVED<script>" as PreparedCall["catalogId"],
    } as PreparedCall;
    const validBinding = await credentialBinding();
    const binding = {
      ...validBinding,
      profileId: "profile`] <admin>\u202e",
      audience: "https://evil.test/\n# APPROVED<script>",
      scopes: Object.freeze(["write` **everything**\u0085"]),
    } as CredentialAuthorizationBinding;

    const presentation = renderApproval(call, binding);

    expect(presentation.message).toContain('Catalog: "');
    expect(presentation.message).toContain("\\u000A");
    expect(presentation.message).toContain("\\u202E");
    expect(presentation.message).toContain("\\u0085");
    expect(presentation.message).not.toContain("\n# APPROVED");
    expect(presentation.message).not.toContain("<script>");
    expect(presentation.message).not.toContain("```");
    expect(presentation.credentialProfile).toBe(
      "profile\\u0060\\u005D\\u0020\\u003Cadmin\\u003E\\u202E",
    );
    expect(presentation.audience).toBe(
      "https\\u003A\\u002F\\u002Fevil\\u002Etest\\u002F\\u000A\\u0023\\u0020APPROVED\\u003Cscript\\u003E",
    );
    expect(presentation.scopes).toEqual([
      "write\\u0060\\u0020\\u002A\\u002Aeverything\\u002A\\u002A\\u0085",
    ]);
    expect(presentation.credentialBindingDigest).toBe(binding.bindingDigest);
    expect(presentation.preparedCallDigest).toBe(call.preparedCallDigest);
    expect(Object.isFrozen(presentation)).toBe(true);
    expect(Object.isFrozen(presentation.scopes)).toBe(true);
  });

  test("never truncates exact digests or identity fields", async () => {
    const call = await preparedCall();
    const binding = await credentialBinding();

    const presentation = renderApproval(call, binding);

    expect(presentation.message).toContain(call.preparedCallDigest);
    expect(presentation.message).toContain(binding.bindingDigest);
    expect(presentation.message).toContain(call.operationDigest);
    expect(presentation.message).toContain(call.manifestDigest);
    expect(presentation.message).toContain(call.credentialProfileDigest);
    expect(presentation.message).toContain(call.reservedSlotsDigest);
    expect(Buffer.byteLength(presentation.message, "utf8")).toBeLessThanOrEqual(
      16 * 1024,
    );
  });

  test("denies when escaped identity and credential authority cannot fit", async () => {
    const valid = await preparedCall();
    const binding = await credentialBinding();
    const expanded = {
      ...valid,
      relativeUrl: `/${"\u202e".repeat(3_000)}`,
    } as PreparedCall;

    expect(() => renderApproval(expanded, binding)).toThrow(
      expect.objectContaining({ code: "ACTION_DENIED" }),
    );
  });

  test("summarizes bodies structurally and bounds other argument values", async () => {
    const secret = `RAW-SECRET-${"x".repeat(8_000)}`;
    const valid = await preparedCall();
    const call = {
      ...valid,
      normalizedArguments: {
        path: { widgetId: "w-7" },
        query: { description: secret },
        headers: { "x-note": "short" },
        body: {
          password: secret,
          rows: Array.from({ length: 250 }, (_, index) => ({ index, secret })),
        },
      },
    } as PreparedCall;

    const presentation = renderApproval(call, await credentialBinding());

    expect(presentation.message).not.toContain(secret);
    expect(presentation.normalizedArguments).not.toContain("RAW-SECRET");
    expect(presentation.normalizedArguments).toContain("Body structure");
    expect(presentation.normalizedArguments).toContain("250 items");
    expect(presentation.normalizedArguments).toContain("password");
    expect(
      Buffer.byteLength(presentation.normalizedArguments, "utf8"),
    ).toBeLessThanOrEqual(2_048);
    expect(Buffer.byteLength(presentation.message, "utf8")).toBeLessThanOrEqual(
      16 * 1024,
    );
  });

  test("shows the complete canonical policy activation scope", async () => {
    const activation = {
      policyDigest: digest("f"),
      expiresAt: 2_000_000_000_000,
      template: {
        version: 1,
        arguments: {
          kind: "object",
          properties: {
            body: {
              kind: "object",
              properties: { role: { kind: "exact", value: "admin<script>" } },
            },
          },
        },
      },
    };

    const presentation = renderApproval(
      await preparedCall(),
      await credentialBinding(),
      activation,
    );

    expect(presentation.message).toContain("POLICY ACTIVATION WARNING");
    expect(presentation.message).toContain(
      "Complete canonical template constraints",
    );
    expect(presentation.message).toContain("admin\\u003Cscript\\u003E");
    expect(presentation.message).toContain(activation.policyDigest);
    expect(presentation.message).toContain(String(activation.expiresAt));
    expect(presentation.policyActivation).toEqual({
      policyDigest: activation.policyDigest,
      expiresAt: activation.expiresAt,
    });
    expect(Object.isFrozen(presentation.policyActivation)).toBe(true);
  });

  test("denies policy activation when full constraints cannot be displayed", async () => {
    const call = await preparedCall();
    const binding = await credentialBinding();
    expect(() =>
      renderApproval(call, binding, {
        policyDigest: digest("f"),
        expiresAt: 2_000_000_000_000,
        template: {
          arguments: {
            kind: "exact",
            value: "\u202e".repeat(4_000),
          },
        },
      }),
    ).toThrow(expect.objectContaining({ code: "ACTION_DENIED" }));
  });
});
