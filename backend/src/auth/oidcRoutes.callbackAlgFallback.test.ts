import crypto from "crypto";
import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const discoverMock = vi.fn();
const callbackMock = vi.fn();
const clientConfigs: Record<string, unknown>[] = [];
const issuerMetadata = {
  token_endpoint_auth_methods_supported: ["client_secret_basic"],
  id_token_signing_alg_values_supported: ["HS256", "RS256"],
};

vi.mock("openid-client", () => {
  const issuer = {
    issuer: "https://issuer.example",
    metadata: issuerMetadata,
  } as any;

  class MockClient {
    issuer = issuer;

    constructor(config: Record<string, unknown>) {
      clientConfigs.push({ ...config });
    }

    callbackParams(req: { query: unknown }) {
      return req.query;
    }

    callback(...args: unknown[]) {
      return callbackMock(...args);
    }

    authorizationUrl() {
      return "https://issuer.example/auth";
    }
  }

  issuer.Client = MockClient;
  discoverMock.mockResolvedValue(issuer);

  return {
    Issuer: {
      discover: discoverMock,
    },
    generators: {
      state: () => "state-fixed",
      nonce: () => "nonce-fixed",
      codeVerifier: () => "verifier-fixed",
      codeChallenge: () => "challenge-fixed",
    },
  };
});

const base64UrlEncode = (value: Buffer | string): string => {
  const buffer = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
};

const signFlowPayload = (encodedPayload: string, secret: string): string =>
  base64UrlEncode(
    crypto.createHmac("sha256", secret).update(encodedPayload, "utf8").digest()
  );

const makeFlowCookie = (
  secret: string,
  overrides: Partial<{
    state: string;
    nonce: string;
    codeVerifier: string;
    returnTo: string;
    expiresAt: number;
  }> = {}
) => {
  const payload = {
    state: "state-fixed",
    nonce: "nonce-fixed",
    codeVerifier: "verifier-fixed",
    returnTo: "/",
    expiresAt: Date.now() + 60_000,
    ...overrides,
  };
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = signFlowPayload(encodedPayload, secret);
  return `${encodedPayload}.${signature}`;
};

const createPrismaMock = () => {
  const user = {
    id: "user-1",
    username: null,
    email: "alice@example.com",
    name: "Alice",
    role: "USER",
    mustResetPassword: false,
    isActive: true,
  };

  const tx = {
    authIdentity: {
      findUnique: vi.fn(async () => null),
      update: vi.fn(async () => ({})),
      create: vi.fn(async () => ({})),
    },
    user: {
      findUnique: vi.fn(async () => user),
      count: vi.fn(async () => 1),
      create: vi.fn(async () => user),
    },
    collection: {
      findFirst: vi.fn(async () => ({ id: "trash:user-1" })),
      create: vi.fn(async () => ({})),
    },
  };

  return {
    $transaction: vi.fn(async (runner: (arg: typeof tx) => Promise<unknown>) =>
      runner(tx)
    ),
    refreshToken: {
      create: vi.fn(async () => ({})),
    },
  };
};

const createApp = async (idTokenAlgOverride: string | null) => {
  const { registerOidcRoutes } = await import("./oidcRoutes");
  const app = express();
  const router = express.Router();
  app.use(router);
  registerOidcRoutes({
    router,
    prisma: createPrismaMock() as any,
    ensureAuthEnabled: vi.fn(async () => true),
    ensureSystemConfig: vi.fn(async () => ({
      id: "default",
      oidcJitProvisioningEnabled: true,
    })),
    sanitizeText: (input: unknown) => String(input ?? ""),
    generateTokens: vi.fn(() => ({
      accessToken: "access-token",
      refreshToken: "refresh-token",
    })),
    setAuthCookies: vi.fn(),
    getRefreshTokenExpiresAt: () => new Date(Date.now() + 60_000),
    isMissingRefreshTokenTableError: () => false,
    config: {
      authMode: "oidc_enforced",
      jwtSecret: "test-secret",
      enableRefreshTokenRotation: false,
      enableAuditLogging: false,
      oidc: {
        enabled: true,
        enforced: true,
        providerName: "Test OIDC",
        issuerUrl: "https://issuer.example",
        clientId: "client-id",
        clientSecret: "client-secret",
        redirectUri: "https://app.example/api/auth/oidc/callback",
        idTokenSignedResponseAlg: idTokenAlgOverride,
        tokenEndpointAuthMethod: null,
        scopes: "openid email profile",
        emailClaim: "email",
        emailVerifiedClaim: "email_verified",
        requireEmailVerified: true,
        jitProvisioning: true,
        firstUserAdmin: true,
      },
    },
  });
  return app;
};

describe("OIDC callback alg mismatch fallback", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clientConfigs.length = 0;
    issuerMetadata.id_token_signing_alg_values_supported = ["HS256", "RS256"];
  });

  it("retries once with observed HS alg when default expected alg mismatches", async () => {
    let callCount = 0;
    callbackMock.mockImplementation(async () => {
      callCount += 1;
      if (callCount === 1) {
        throw new Error("unexpected JWT alg received, expected RS256, got: HS256");
      }
      return {
        claims: () => ({
          sub: "subject-1",
          email: "alice@example.com",
          email_verified: true,
        }),
      };
    });

    const app = await createApp(null);
    const response = await request(app)
      .get("/oidc/callback?code=test-code&state=state-fixed")
      .set("Cookie", [
        `anydash-oidc-flow=${makeFlowCookie("test-secret")}`,
      ]);

    expect(response.status).toBe(302);
    expect(response.headers.location).toBe("/");
    expect(callbackMock).toHaveBeenCalledTimes(2);
    expect(clientConfigs[0]?.id_token_signed_response_alg).toBe("RS256");
    expect(clientConfigs[1]?.id_token_signed_response_alg).toBe("HS256");
  });

  it("does not retry when id token alg is explicitly configured", async () => {
    callbackMock.mockRejectedValue(
      new Error("unexpected JWT alg received, expected RS256, got: HS256")
    );

    const app = await createApp("RS256");
    const response = await request(app)
      .get("/oidc/callback?code=test-code&state=state-fixed")
      .set("Cookie", [
        `anydash-oidc-flow=${makeFlowCookie("test-secret")}`,
      ]);

    expect(response.status).toBe(302);
    expect(response.headers.location).toContain("oidcError=callback_failed");
    expect(callbackMock).toHaveBeenCalledTimes(1);
    expect(clientConfigs).toHaveLength(1);
  });
});
