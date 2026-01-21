import axios, { type AxiosInstance, type AxiosError } from 'axios';
import type { TokenResponse, OpenIDConfiguration, UserInfoResponse } from '@oauth2/shared-types';
import {
    generateCodeVerifier,
    generateCodeChallenge,
    generateState,
    generateNonce,
    createLogger,
} from '@oauth2/shared-utils';
import config from '../config/index.js';

const logger = createLogger({ name: 'oauth-service' });

// Session token data
export interface TokenData {
    accessToken: string;
    refreshToken?: string;
    idToken?: string;
    expiresAt: number;
    scope: string;
}

// User data from ID token or userinfo
export interface UserData {
    sub: string;
    email?: string;
    name?: string;
    picture?: string;
}

/**
 * OAuth Service - Handles all OAuth 2.0 flows with PKCE
 */
export class OAuthService {
    private httpClient: AxiosInstance;
    private discoveryDocument: OpenIDConfiguration | null = null;
    private discoveryFetchedAt: number = 0;
    private readonly discoveryTtl = 300000; // 5 minutes

    constructor() {
        this.httpClient = axios.create({
            timeout: 10000,
            headers: {
                'Accept': 'application/json',
            },
        });
    }

    /**
     * Get OpenID Connect discovery document (cached)
     */
    async getDiscoveryDocument(): Promise<OpenIDConfiguration> {
        const now = Date.now();

        if (this.discoveryDocument && now - this.discoveryFetchedAt < this.discoveryTtl) {
            return this.discoveryDocument;
        }

        try {
            const response = await this.httpClient.get<OpenIDConfiguration>(
                `${config.oauth.authServerUrl}/.well-known/openid-configuration`
            );
            this.discoveryDocument = response.data;
            this.discoveryFetchedAt = now;
            logger.debug('Discovery document fetched');
            return this.discoveryDocument;
        } catch (error) {
            logger.error({ error }, 'Failed to fetch discovery document');
            throw error;
        }
    }

    /**
     * Generate authorization URL with PKCE parameters
     */
    generateAuthorizationRequest(): {
        url: string;
        codeVerifier: string;
        state: string;
        nonce: string;
    } {
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = generateCodeChallenge(codeVerifier);
        const state = generateState();
        const nonce = generateNonce();

        const url = new URL(`${config.oauth.authServerPublicUrl}/authorize`);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('client_id', config.oauth.clientId);
        url.searchParams.set('redirect_uri', config.oauth.redirectUri);
        url.searchParams.set('scope', config.oauth.scopes);
        url.searchParams.set('state', state);
        url.searchParams.set('code_challenge', codeChallenge);
        url.searchParams.set('code_challenge_method', 'S256');
        url.searchParams.set('nonce', nonce);

        logger.debug({ clientId: config.oauth.clientId }, 'Generated authorization request');

        return {
            url: url.toString(),
            codeVerifier,
            state,
            nonce,
        };
    }

    /**
     * Exchange authorization code for tokens
     */
    async exchangeCodeForTokens(code: string, codeVerifier: string): Promise<TokenResponse> {
        try {
            const response = await this.httpClient.post<TokenResponse>(
                `${config.oauth.authServerUrl}/token`,
                new URLSearchParams({
                    grant_type: 'authorization_code',
                    code,
                    redirect_uri: config.oauth.redirectUri,
                    client_id: config.oauth.clientId,
                    client_secret: config.oauth.clientSecret,
                    code_verifier: codeVerifier,
                }).toString(),
                {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                }
            );

            logger.info('Tokens obtained successfully');
            return response.data;
        } catch (error) {
            const axiosError = error as AxiosError<{ error: string; error_description?: string }>;
            logger.error(
                { error: axiosError.response?.data },
                'Token exchange failed'
            );
            throw error;
        }
    }

    /**
     * Refresh access token using refresh token
     */
    async refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
        try {
            const response = await this.httpClient.post<TokenResponse>(
                `${config.oauth.authServerUrl}/token`,
                new URLSearchParams({
                    grant_type: 'refresh_token',
                    refresh_token: refreshToken,
                    client_id: config.oauth.clientId,
                    client_secret: config.oauth.clientSecret,
                }).toString(),
                {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                }
            );

            logger.info('Tokens refreshed successfully');
            return response.data;
        } catch (error) {
            logger.warn({ error }, 'Token refresh failed');
            throw error;
        }
    }

    /**
     * Revoke a token
     */
    async revokeToken(token: string, tokenTypeHint?: 'access_token' | 'refresh_token'): Promise<void> {
        try {
            await this.httpClient.post(
                `${config.oauth.authServerUrl}/revoke`,
                new URLSearchParams({
                    token,
                    client_id: config.oauth.clientId,
                    client_secret: config.oauth.clientSecret,
                    ...(tokenTypeHint && { token_type_hint: tokenTypeHint }),
                }).toString(),
                {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                }
            );
            logger.info({ tokenTypeHint }, 'Token revoked');
        } catch (error) {
            logger.warn({ error }, 'Token revocation failed (may be expected)');
        }
    }

    /**
     * Get user info from auth server
     */
    async getUserInfo(accessToken: string): Promise<UserInfoResponse> {
        const response = await this.httpClient.get<UserInfoResponse>(
            `${config.oauth.authServerUrl}/userinfo`,
            {
                headers: { Authorization: `Bearer ${accessToken}` },
            }
        );
        return response.data;
    }

    /**
     * Call a protected API endpoint
     */
    async callProtectedApi<T>(accessToken: string, endpoint: string): Promise<T> {
        const response = await this.httpClient.get<T>(
            `${config.oauth.resourceServerUrl}${endpoint}`,
            {
                headers: { Authorization: `Bearer ${accessToken}` },
            }
        );
        return response.data;
    }

    /**
     * Check if token is expired or about to expire
     */
    isTokenExpired(expiresAt: number, bufferSeconds: number = 60): boolean {
        return Date.now() >= expiresAt - bufferSeconds * 1000;
    }

    /**
     * Parse ID token claims (basic parsing, no validation)
     */
    parseIdToken(idToken: string): Record<string, unknown> {
        try {
            const [, payload] = idToken.split('.');
            if (!payload) throw new Error('Invalid token format');
            return JSON.parse(Buffer.from(payload, 'base64url').toString());
        } catch {
            return {};
        }
    }
}

export const oauthService = new OAuthService();
