import axios, { AxiosError } from "axios";
import { FORTNOX_OAUTH_URL, TOKEN_REFRESH_BUFFER_MS } from "../constants.js";
import { ITokenProvider, TokenInfo, AuthRequiredError } from "./types.js";
import { ITokenStorage } from "./storage/types.js";
import { getFortnoxCredentials } from "./credentials.js";

// Token provider for remote mode (multi-user with database storage)
export class DatabaseTokenProvider implements ITokenProvider {
  private clientId: string;
  private clientSecret: string;
  private storage: ITokenStorage;
  private refreshPromises: Map<string, Promise<string>> = new Map();

  constructor(storage: ITokenStorage) {
    const { clientId, clientSecret } = getFortnoxCredentials();
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.storage = storage;
  }

  async getAccessToken(userId?: string): Promise<string> {
    if (!userId) {
      throw new AuthRequiredError();
    }
    const tokens = await this.storage.get(userId);
    if (!tokens) {
      throw new AuthRequiredError(userId);
    }
    const needsRefresh = Date.now() >= tokens.expiresAt - TOKEN_REFRESH_BUFFER_MS;
    if (needsRefresh || !tokens.accessToken) {
      if (!this.refreshPromises.has(userId)) {
        const promise = this.refreshAccessToken(userId, tokens).finally(() => {
          this.refreshPromises.delete(userId);
        });
        this.refreshPromises.set(userId, promise);
      }
      return this.refreshPromises.get(userId)!;
    }
    return tokens.accessToken;
  }

  isAuthenticated(userId?: string): boolean {
    return !!userId;
  }

  getTokenInfo(userId?: string): TokenInfo | null {
    return null;
  }

  async getTokenInfoAsync(userId: string): Promise<TokenInfo | null> {
    return this.storage.get(userId);
  }

  async storeTokens(userId: string, tokens: TokenInfo): Promise<void> {
    await this.storage.set(userId, tokens);
  }

  async deleteTokens(userId: string): Promise<void> {
    await this.storage.delete(userId);
  }

  async exchangeAuthorizationCode(
    code: string,
    redirectUri: string,
    userId: string
  ): Promise<TokenInfo> {
    const tokenUrl = `${FORTNOX_OAUTH_URL}/token`;
    const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");

    console.log('[TokenExchange] Starting, redirectUri:', redirectUri);

    try {
      const response = await axios.post(
        tokenUrl,
        new URLSearchParams({
          grant_type: "authorization_code",
          code: code,
          redirect_uri: redirectUri
        }),
        {
          adapter: "http",
          headers: {
            "Authorization": `Basic ${auth}`,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          timeout: 15000
        }
      );

      const tokens: TokenInfo = {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        expiresAt: Date.now() + response.data.expires_in * 1000,
        scope: response.data.scope
      };

      await this.storeTokens(userId, tokens);
      console.log('[TokenExchange] Success');
      return tokens;
    } catch (error) {
      console.error('[TokenExchange] Error:', error?.constructor?.name, error instanceof Error ? error.message : String(error));
      if (error instanceof Error && (error as any).cause) {
        console.error('[TokenExchange] Cause:', (error as any).cause);
      }
      if (error instanceof AxiosError) {
        console.error('[TokenExchange] HTTP status:', error.response?.status, JSON.stringify(error.response?.data));
      }
      throw this.handleAuthError(error, "Failed to exchange authorization code");
    }
  }

  private async refreshAccessToken(userId: string, tokens: TokenInfo): Promise<string> {
    if (!tokens.refreshToken) {
      throw new Error("No refresh token available");
    }

    const tokenUrl = `${FORTNOX_OAUTH_URL}/token`;
    const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");

    try {
      const response = await axios.post(
        tokenUrl,
        new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: tokens.refreshToken
        }),
        {
          adapter: "http",
          headers: {
            "Authorization": `Basic ${auth}`,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          timeout: 15000
        }
      );

      const newTokens: TokenInfo = {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        expiresAt: Date.now() + response.data.expires_in * 1000,
        scope: response.data.scope
      };

      await this.storeTokens(userId, newTokens);
      return newTokens.accessToken;
    } catch (error) {
      await this.storage.delete(userId);
      throw this.handleAuthError(error, "Failed to refresh access token");
    }
  }

  getAuthorizationUrl(redirectUri: string, scopes: string[], state?: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(" "),
      response_type: "code",
      access_type: "offline"
    });

    if (state) {
      params.set("state", state);
    }

    return `${FORTNOX_OAUTH_URL}/auth?${params.toString()}`;
  }

  private handleAuthError(error: unknown, context: string): Error {
    if (error instanceof AxiosError) {
      const status = error.response?.status;
      const data = error.response?.data;

      if (status === 401) {
        return new Error(`${context}: Invalid credentials.`);
      }

      if (status === 400) {
        const errorDesc = data?.error_description || data?.error || "Bad request";
        return new Error(`${context}: ${errorDesc}.`);
      }

      const cause = (error as any).cause instanceof Error ? (error as any).cause.message : '';
      return new Error(`${context}: HTTP ${status ?? 'network'} - ${JSON.stringify(data) || cause || error.message}`);
    }

    const causeMsg = (error instanceof Error && (error as any).cause)
      ? ' cause=' + ((error as any).cause instanceof Error ? (error as any).cause.message : String((error as any).cause))
      : '';
    return new Error(`${context}: ${error instanceof Error ? error.message : String(error)}${causeMsg}`);
  }
}
