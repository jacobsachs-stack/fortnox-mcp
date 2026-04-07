import { Response } from "express";
import * as jose from "jose";
import crypto from "crypto";
import {
  OAuthServerProvider,
  AuthorizationParams,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import {
  OAuthClientInformationFull,
  OAuthTokens,
  OAuthTokenRevocationRequest,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { ITokenStorage } from "./storage/types.js";
import { DatabaseTokenProvider } from "./databaseProvider.js";
import { FORTNOX_SCOPES } from "./credentials.js";
import { Redis } from "@upstash/redis";

// JWT configuration
const JWT_ALGORITHM = "HS256";
const ACCESS_TOKEN_EXPIRES_IN = 3600; // 1 hour
const REFRESH_TOKEN_EXPIRES_IN = 90 * 24 * 3600; // 90 days

// Links MCP <-> Fortnox OAuth
interface PendingAuthorization {
  mcpClient: OAuthClientInformationFull;
  mcpParams: AuthorizationParams;
  codeChallenge: string;
  createdAt: number;
}

interface IssuedCode {
  userId: string;
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  scopes: string[];
  createdAt: number;
}

// Redis-backed clients store — survives cold starts
class RedisClientsStore implements OAuthRegisteredClientsStore {
  constructor(private redis: Redis) {}

  async getClient(
    clientId: string
  ): Promise<OAuthClientInformationFull | undefined> {
    const data = await this.redis.get<OAuthClientInformationFull>(
      `mcp:client:${clientId}`
    );
    return data ?? undefined;
  }

  async registerClient(
    client: Omit<
      OAuthClientInformationFull,
      "client_id" | "client_id_issued_at"
    >
  ): Promise<OAuthClientInformationFull> {
    const clientId = `client_${crypto.randomUUID()}`;
    const fullClient: OAuthClientInformationFull = {
      ...client,
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    await this.redis.set(`mcp:client:${clientId}`, fullClient, {
      ex: 90 * 24 * 3600,
    });
    return fullClient;
  }
}

export class FortnoxProxyOAuthProvider implements OAuthServerProvider {
  private redis: Redis;
  private jwtSecret: Uint8Array;
  private serverUrl: string;
  private tokenProvider: DatabaseTokenProvider;
  private _clientsStore: RedisClientsStore;

  constructor(
    jwtSecret: string,
    serverUrl: string,
    tokenStorage: ITokenStorage
  ) {
    this.redis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL!,
      token: process.env.UPSTASH_REDIS_REST_TOKEN!,
    });
    this.jwtSecret = new TextEncoder().encode(jwtSecret);
    this.serverUrl = serverUrl;
    this.tokenProvider = new DatabaseTokenProvider(tokenStorage);
    this._clientsStore = new RedisClientsStore(this.redis);
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const state = crypto.randomUUID();
    const codeChallenge = params.codeChallenge ?? "";

    const pending: PendingAuthorization = {
      mcpClient: client,
      mcpParams: params,
      codeChallenge,
      createdAt: Date.now(),
    };

    // Persist with 10-minute TTL — survives serverless cold starts
    await this.redis.set(`mcp:pending:${state}`, pending, { ex: 10 * 60 });

    const fortnoxAuthUrl = new URL("https://apps.fortnox.se/oauth-v1/auth");
    fortnoxAuthUrl.searchParams.set(
      "client_id",
      process.env.FORTNOX_CLIENT_ID!
    );
    fortnoxAuthUrl.searchParams.set(
      "redirect_uri",
      `${this.serverUrl}/oauth/fortnox/callback`
    );
    fortnoxAuthUrl.searchParams.set("scope", FORTNOX_SCOPES.join(" "));
    fortnoxAuthUrl.searchParams.set("state", state);
    fortnoxAuthUrl.searchParams.set("response_type", "code");
    fortnoxAuthUrl.searchParams.set("access_type", "offline");

    res.redirect(fortnoxAuthUrl.toString());
  }

  // Called by /oauth/fortnox/callback route after Fortnox redirects back
  async handleFortnoxCallback(
    code: string,
    state: string
  ): Promise<{ redirectUri: string; code: string; state?: string }> {
    // Look up pending authorization
    const pending = await this.redis.get<PendingAuthorization>(
      `mcp:pending:${state}`
    );
    if (!pending) {
      throw new Error("Invalid or expired OAuth state");
    }

    // Remove from pending (single use)
    await this.redis.del(`mcp:pending:${state}`);

    // Generate a unique user ID based on client ID and a random component
    const userId = `${pending.mcpClient.client_id}:${crypto.randomUUID()}`;

    // Exchange Fortnox code for tokens and store them
    await this.tokenProvider.exchangeAuthorizationCode(
      code,
      `${this.serverUrl}/oauth/fortnox/callback`,
      userId
    );

    // Issue our own MCP authorization code
    const mcpAuthCode = crypto.randomUUID();
    const issued: IssuedCode = {
      userId,
      clientId: pending.mcpClient.client_id,
      codeChallenge: pending.codeChallenge,
      redirectUri: pending.mcpParams.redirectUri,
      scopes: pending.mcpParams.scopes || [],
      createdAt: Date.now(),
    };

    // Persist with 5-minute TTL
    await this.redis.set(`mcp:code:${mcpAuthCode}`, issued, { ex: 5 * 60 });

    return {
      redirectUri: pending.mcpParams.redirectUri,
      code: mcpAuthCode,
      state: pending.mcpParams.state,
    };
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const issued = await this.redis.get<IssuedCode>(
      `mcp:code:${authorizationCode}`
    );
    if (!issued) {
      throw new Error("Invalid authorization code");
    }
    return issued.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    _redirectUri?: string,
    _resource?: URL
  ): Promise<OAuthTokens> {
    const issued = await this.redis.get<IssuedCode>(
      `mcp:code:${authorizationCode}`
    );
    if (!issued) {
      throw new Error("Invalid authorization code");
    }

    // Verify client matches
    if (issued.clientId !== client.client_id) {
      throw new Error("Authorization code was not issued to this client");
    }

    // Delete code — single use
    await this.redis.del(`mcp:code:${authorizationCode}`);

    return this.issueTokens(issued.userId, client.client_id, issued.scopes);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[]
  ): Promise<OAuthTokens> {
    // Check if revoked
    const isRevoked = await this.redis.exists(`mcp:revoked:${refreshToken}`);
    if (isRevoked) {
      throw new Error("Refresh token has been revoked");
    }

    let payload: jose.JWTPayload;
    try {
      const result = await jose.jwtVerify(refreshToken, this.jwtSecret);
      payload = result.payload;
    } catch {
      throw new Error("Invalid refresh token");
    }

    if (payload["client_id"] !== client.client_id) {
      throw new Error("Refresh token was not issued to this client");
    }

    const userId = payload.sub as string;
    const scopes = ((payload["scope"] as string) ?? "")
      .split(" ")
      .filter(Boolean);

    // Revoke the old refresh token
    await this.redis.set(`mcp:revoked:${refreshToken}`, 1, {
      ex: REFRESH_TOKEN_EXPIRES_IN,
    });

    return this.issueTokens(userId, client.client_id, scopes);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    // Check if revoked
    const isRevoked = await this.redis.exists(`mcp:revoked:${token}`);
    if (isRevoked) {
      throw new Error("Access token has been revoked");
    }

    let payload: jose.JWTPayload;
    try {
      const result = await jose.jwtVerify(token, this.jwtSecret);
      payload = result.payload;
    } catch {
      throw new Error("Invalid access token");
    }

    return {
      token,
      clientId: payload["client_id"] as string,
      scopes: ((payload["scope"] as string) ?? "").split(" ").filter(Boolean),
      expiresAt: payload.exp,
    };
  }

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    await this.redis.set(`mcp:revoked:${request.token}`, 1, {
      ex: REFRESH_TOKEN_EXPIRES_IN,
    });
  }

  // Expose the underlying Fortnox token provider (used by MCP tool handlers)
  getTokenProvider(): DatabaseTokenProvider {
    return this.tokenProvider;
  }

  // Helper: sign and return access + refresh token pair
  private async issueTokens(
    userId: string,
    clientId: string,
    scopes: string[]
  ): Promise<OAuthTokens> {
    const now = Math.floor(Date.now() / 1000);
    const scope = scopes.length > 0 ? scopes.join(" ") : FORTNOX_SCOPES.join(" ");

    const accessToken = await new jose.SignJWT({
      sub: userId,
      client_id: clientId,
      scope,
    })
      .setProtectedHeader({ alg: JWT_ALGORITHM })
      .setIssuedAt(now)
      .setExpirationTime(now + ACCESS_TOKEN_EXPIRES_IN)
      .sign(this.jwtSecret);

    const refreshToken = await new jose.SignJWT({
      sub: userId,
      client_id: clientId,
      scope,
      token_type: "refresh",
    })
      .setProtectedHeader({ alg: JWT_ALGORITHM })
      .setIssuedAt(now)
      .setExpirationTime(now + REFRESH_TOKEN_EXPIRES_IN)
      .sign(this.jwtSecret);

    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_EXPIRES_IN,
      refresh_token: refreshToken,
      scope,
    };
  }
}

// Extract the userId (JWT sub claim) from a verified AuthInfo token.
// The token has already been verified by requireBearerAuth, so we just decode.
export function getUserIdFromAuth(auth: AuthInfo): string {
  const claims = jose.decodeJwt(auth.token);
  return claims.sub as string;
}
