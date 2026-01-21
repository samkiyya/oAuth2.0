import { ObjectId } from 'mongodb';
import type { TokenResponse, OAuthClient, User, GrantType } from '@oauth2/shared-types';
import { OAuthErrors } from '@oauth2/shared-utils';
import { tokenRepository } from '../repositories/token.repository.js';
import { userRepository } from '../repositories/user.repository.js';
import { keyService } from './key.service.js';
import { clientService } from './client.service.js';
import config from '../config/index.js';
import { logger, logSecurityEvent } from '../utils/logger.js';
import { cache, RedisKeys } from '../config/redis.js';

/**
 * Token Service - Handles token issuance, refresh, and revocation
 */
export class TokenService {
    /**
     * Issue tokens for authorization code exchange
     */
    async issueTokensForAuthCode(params: {
        userId: ObjectId;
        clientId: string;
        scope: string;
        nonce?: string;
    }): Promise<TokenResponse> {
        const user = await userRepository.findById(params.userId);
        if (!user) {
            throw OAuthErrors.invalidGrant('User not found');
        }

        const client = await clientService.getClient(params.clientId);
        const scopes = params.scope.split(' ').filter(Boolean);

        return this.issueTokens(user, client, scopes, params.nonce);
    }

    /**
     * Issue tokens (access token, refresh token, optionally ID token)
     */
    async issueTokens(
        user: User,
        client: OAuthClient,
        scopes: string[],
        nonce?: string
    ): Promise<TokenResponse> {
        const scope = scopes.join(' ');

        // Generate access token
        const { token: accessToken, jti, expiresAt } = await keyService.signAccessToken({
            sub: user._id.toString(),
            clientId: client.clientId,
            scope,
            userId: user._id,
        });

        // Record access token for revocation tracking
        await tokenRepository.recordAccessToken({
            jti,
            userId: user._id,
            clientId: client.clientId,
            scope,
            expiresIn: client.accessTokenLifetime * 1000,
        });

        const response: TokenResponse = {
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: client.accessTokenLifetime,
            scope,
        };

        // Generate refresh token if offline_access scope is requested
        if (scopes.includes('offline_access')) {
            const refreshToken = await tokenRepository.createRefreshToken({
                userId: user._id,
                clientId: client.clientId,
                scope,
                expiresIn: client.refreshTokenLifetime * 1000,
            });
            response.refresh_token = refreshToken;
        }

        // Generate ID token if openid scope is requested
        if (scopes.includes('openid')) {
            const idToken = await keyService.signIdToken({
                sub: user._id.toString(),
                clientId: client.clientId,
                nonce,
                authTime: Math.floor(Date.now() / 1000),
                accessToken,
                requestedScopes: scopes,
                profile: {
                    name: user.profile.name,
                    email: user.email,
                    emailVerified: user.emailVerified,
                    picture: user.profile.picture,
                },
            });
            response.id_token = idToken;
        }

        logSecurityEvent(logger, {
            event: 'tokens_issued',
            success: true,
            userId: user._id.toString(),
            clientId: client.clientId,
            details: { scopes, hasRefreshToken: !!response.refresh_token, hasIdToken: !!response.id_token },
        });

        return response;
    }

    /**
     * Refresh access token using refresh token
     */
    async refreshTokens(
        refreshToken: string,
        clientId: string,
        requestedScope?: string
    ): Promise<TokenResponse> {
        // Find the refresh token
        const tokenRecord = await tokenRepository.findRefreshToken(refreshToken);

        if (!tokenRecord) {
            throw OAuthErrors.invalidGrant('Invalid or expired refresh token');
        }

        // Validate client
        if (tokenRecord.clientId !== clientId) {
            logSecurityEvent(logger, {
                event: 'refresh_token_client_mismatch',
                success: false,
                clientId,
                details: { expectedClientId: tokenRecord.clientId },
            });
            throw OAuthErrors.invalidGrant('Refresh token was issued to a different client');
        }

        // Get user
        const user = await userRepository.findById(tokenRecord.userId);
        if (!user) {
            throw OAuthErrors.invalidGrant('User not found');
        }

        // Get client
        const client = await clientService.getClient(clientId);

        // Determine scope (can only request subset of original scope)
        let scopes = tokenRecord.scope.split(' ');
        if (requestedScope) {
            const requestedScopes = requestedScope.split(' ');
            const originalScopes = new Set(scopes);

            // Verify all requested scopes were in original grant
            for (const scope of requestedScopes) {
                if (!originalScopes.has(scope)) {
                    throw OAuthErrors.invalidScope(`Scope '${scope}' was not in original grant`);
                }
            }
            scopes = requestedScopes;
        }

        // Rotate refresh token (OAuth 2.1 requirement)
        const rotation = await tokenRepository.rotateRefreshToken(refreshToken, {
            userId: tokenRecord.userId,
            clientId,
            scope: scopes.join(' '),
            expiresIn: client.refreshTokenLifetime * 1000,
        });

        if (!rotation) {
            // Token was already used - potential replay attack
            logSecurityEvent(logger, {
                event: 'refresh_token_replay_detected',
                success: false,
                userId: tokenRecord.userId.toString(),
                clientId,
                details: { family: tokenRecord.family },
            });

            // Revoke entire token family
            await tokenRepository.revokeTokenFamily(tokenRecord.family);
            throw OAuthErrors.invalidGrant('Refresh token already used');
        }

        // Issue new tokens
        const { token: accessToken, jti } = await keyService.signAccessToken({
            sub: user._id.toString(),
            clientId: client.clientId,
            scope: scopes.join(' '),
            userId: user._id,
        });

        // Record access token
        await tokenRepository.recordAccessToken({
            jti,
            userId: user._id,
            clientId: client.clientId,
            scope: scopes.join(' '),
            expiresIn: client.accessTokenLifetime * 1000,
        });

        const response: TokenResponse = {
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: client.accessTokenLifetime,
            refresh_token: rotation.newToken,
            scope: scopes.join(' '),
        };

        // Generate new ID token if openid scope
        if (scopes.includes('openid')) {
            const idToken = await keyService.signIdToken({
                sub: user._id.toString(),
                clientId: client.clientId,
                accessToken,
                requestedScopes: scopes,
                profile: {
                    name: user.profile.name,
                    email: user.email,
                    emailVerified: user.emailVerified,
                    picture: user.profile.picture,
                },
            });
            response.id_token = idToken;
        }

        logSecurityEvent(logger, {
            event: 'tokens_refreshed',
            success: true,
            userId: user._id.toString(),
            clientId,
        });

        return response;
    }

    /**
     * Issue tokens for client credentials grant
     */
    async issueClientCredentialsToken(
        client: OAuthClient,
        requestedScope?: string
    ): Promise<TokenResponse> {
        // Validate scope
        const scopes = requestedScope ? requestedScope.split(' ') : client.allowedScopes.filter(s => s !== 'openid');
        const scope = scopes.join(' ');

        // Generate access token (no user, client is the subject)
        const { token: accessToken, jti } = await keyService.signAccessToken({
            sub: client.clientId,
            clientId: client.clientId,
            scope,
            userId: new ObjectId(), // Placeholder, client credentials don't have a user
        });

        logSecurityEvent(logger, {
            event: 'client_credentials_token_issued',
            success: true,
            clientId: client.clientId,
            details: { scopes },
        });

        return {
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: client.accessTokenLifetime,
            scope,
        };
    }

    /**
     * Revoke a token
     */
    async revokeToken(
        token: string,
        tokenTypeHint?: 'access_token' | 'refresh_token',
        clientId?: string
    ): Promise<void> {
        // Try as refresh token first (more common)
        if (!tokenTypeHint || tokenTypeHint === 'refresh_token') {
            const revoked = await tokenRepository.revokeRefreshToken(token);
            if (revoked) {
                logSecurityEvent(logger, {
                    event: 'refresh_token_revoked',
                    success: true,
                    clientId,
                });
                return;
            }
        }

        // Try as access token (by JTI - would need to decode first)
        // For simplicity, we'll add to a blacklist in Redis
        if (!tokenTypeHint || tokenTypeHint === 'access_token') {
            try {
                // Decode token to get JTI (without verification, just to extract claims)
                const parts = token.split('.');
                if (parts.length === 3) {
                    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());
                    if (payload.jti) {
                        // Add to blacklist with TTL matching token expiration
                        const ttl = Math.max(0, (payload.exp ?? 0) - Math.floor(Date.now() / 1000));
                        if (ttl > 0) {
                            await cache.set(RedisKeys.tokenBlacklist(payload.jti), true, ttl);
                            await tokenRepository.revokeAccessToken(payload.jti);

                            logSecurityEvent(logger, {
                                event: 'access_token_revoked',
                                success: true,
                                clientId,
                                details: { jti: payload.jti },
                            });
                        }
                    }
                }
            } catch {
                // Token could not be decoded, ignore
            }
        }

        // Per RFC 7009, always return success even if token wasn't found
    }

    /**
     * Introspect a token
     */
    async introspectToken(
        token: string,
        tokenTypeHint?: 'access_token' | 'refresh_token'
    ): Promise<{
        active: boolean;
        scope?: string;
        client_id?: string;
        username?: string;
        token_type?: string;
        exp?: number;
        iat?: number;
        sub?: string;
        aud?: string;
        iss?: string;
        jti?: string;
    }> {
        const inactiveResponse = { active: false };

        // Check if it's a refresh token
        if (!tokenTypeHint || tokenTypeHint === 'refresh_token') {
            const refreshTokenRecord = await tokenRepository.findRefreshToken(token);
            if (refreshTokenRecord) {
                const user = await userRepository.findById(refreshTokenRecord.userId);
                return {
                    active: true,
                    scope: refreshTokenRecord.scope,
                    client_id: refreshTokenRecord.clientId,
                    username: user?.email,
                    token_type: 'refresh_token',
                    exp: Math.floor(refreshTokenRecord.expiresAt.getTime() / 1000),
                    iat: Math.floor(refreshTokenRecord.issuedAt.getTime() / 1000),
                    sub: refreshTokenRecord.userId.toString(),
                };
            }
        }

        // Check if it's an access token (JWT)
        if (!tokenTypeHint || tokenTypeHint === 'access_token') {
            try {
                const parts = token.split('.');
                if (parts.length === 3) {
                    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());

                    // Check expiration
                    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
                        return inactiveResponse;
                    }

                    // Check blacklist
                    if (payload.jti) {
                        const isBlacklisted = await cache.exists(RedisKeys.tokenBlacklist(payload.jti));
                        if (isBlacklisted) {
                            return inactiveResponse;
                        }

                        const isRevoked = await tokenRepository.isAccessTokenRevoked(payload.jti);
                        if (isRevoked) {
                            return inactiveResponse;
                        }
                    }

                    return {
                        active: true,
                        scope: payload.scope,
                        client_id: payload.client_id ?? payload.aud,
                        token_type: 'Bearer',
                        exp: payload.exp,
                        iat: payload.iat,
                        sub: payload.sub,
                        aud: payload.aud,
                        iss: payload.iss,
                        jti: payload.jti,
                    };
                }
            } catch {
                return inactiveResponse;
            }
        }

        return inactiveResponse;
    }
}

export const tokenService = new TokenService();
