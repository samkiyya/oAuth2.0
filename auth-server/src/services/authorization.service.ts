import { ObjectId } from 'mongodb';
import type { User, OAuthClient, AuthorizationCode } from '@oauth2/shared-types';
import { OAuthErrors, verifyCodeChallenge } from '@oauth2/shared-utils';
import { tokenRepository } from '../repositories/token.repository.js';
import { consentRepository } from '../repositories/consent.repository.js';
import config from '../config/index.js';
import { logger, logSecurityEvent } from '../utils/logger.js';

export interface AuthorizationParams {
    responseType: string;
    clientId: string;
    redirectUri: string;
    scope: string;
    state?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    nonce?: string;
    prompt?: string;
}

/**
 * Authorization Service - Handles OAuth authorization flow
 */
export class AuthorizationService {
    /**
     * Validate authorization request parameters
     */
    validateAuthorizationRequest(params: AuthorizationParams): void {
        // Validate response_type
        if (params.responseType !== 'code') {
            throw OAuthErrors.invalidRequest('Only response_type=code is supported');
        }

        // PKCE is required (OAuth 2.1)
        if (!params.codeChallenge) {
            throw OAuthErrors.invalidRequest('code_challenge is required');
        }

        // Only S256 is allowed (OAuth 2.1)
        if (params.codeChallengeMethod && params.codeChallengeMethod !== 'S256') {
            throw OAuthErrors.invalidRequest('Only code_challenge_method=S256 is supported');
        }
    }

    /**
     * Check if user has already consented to the requested scopes
     */
    async hasConsent(userId: ObjectId, clientId: string, scopes: string[]): Promise<boolean> {
        return consentRepository.hasConsent(userId, clientId, scopes);
    }

    /**
     * Record user consent
     */
    async recordConsent(userId: ObjectId, clientId: string, scopes: string[]): Promise<void> {
        await consentRepository.upsertConsent(userId, clientId, scopes);

        logSecurityEvent(logger, {
            event: 'consent_granted',
            success: true,
            userId: userId.toString(),
            clientId,
            details: { scopes },
        });
    }

    /**
     * Generate authorization code
     */
    async generateAuthorizationCode(
        user: User,
        client: OAuthClient,
        params: AuthorizationParams
    ): Promise<string> {
        const code = await tokenRepository.createAuthorizationCode({
            clientId: client.clientId,
            userId: user._id,
            redirectUri: params.redirectUri,
            scope: params.scope,
            codeChallenge: params.codeChallenge,
            codeChallengeMethod: params.codeChallengeMethod ?? 'S256',
            nonce: params.nonce,
            state: params.state,
            expiresIn: config.oauth.authorizationCodeExpiresIn,
        });

        logSecurityEvent(logger, {
            event: 'authorization_code_issued',
            success: true,
            userId: user._id.toString(),
            clientId: client.clientId,
            details: { scope: params.scope },
        });

        return code;
    }

    /**
     * Exchange authorization code for tokens
     */
    async exchangeCode(
        code: string,
        clientId: string,
        redirectUri: string,
        codeVerifier?: string
    ): Promise<AuthorizationCode> {
        // Find and consume the authorization code
        const authCode = await tokenRepository.consumeAuthorizationCode(code);

        if (!authCode) {
            // Check if code was already used (replay attack)
            const wasUsed = await tokenRepository.isCodeUsed(code);
            if (wasUsed) {
                logSecurityEvent(logger, {
                    event: 'authorization_code_replay',
                    success: false,
                    clientId,
                    details: { reason: 'code_already_used' },
                });
                // Revoke all tokens in the family (security measure)
                throw OAuthErrors.invalidGrant('Authorization code already used');
            }
            throw OAuthErrors.invalidGrant('Invalid or expired authorization code');
        }

        // Validate client_id matches
        if (authCode.clientId !== clientId) {
            throw OAuthErrors.invalidGrant('client_id mismatch');
        }

        // Validate redirect_uri matches
        if (authCode.redirectUri !== redirectUri) {
            throw OAuthErrors.invalidGrant('redirect_uri mismatch');
        }

        // Verify PKCE code_verifier
        if (authCode.codeChallenge) {
            if (!codeVerifier) {
                throw OAuthErrors.invalidRequest('code_verifier is required');
            }

            const method = (authCode.codeChallengeMethod ?? 'S256') as 'S256' | 'plain';
            if (!verifyCodeChallenge(codeVerifier, authCode.codeChallenge, method)) {
                logSecurityEvent(logger, {
                    event: 'pkce_verification_failed',
                    success: false,
                    userId: authCode.userId.toString(),
                    clientId,
                });
                throw OAuthErrors.invalidGrant('PKCE verification failed');
            }
        }

        logSecurityEvent(logger, {
            event: 'authorization_code_exchanged',
            success: true,
            userId: authCode.userId.toString(),
            clientId,
        });

        return authCode;
    }

    /**
     * Revoke user consent for a client
     */
    async revokeConsent(userId: ObjectId, clientId: string): Promise<void> {
        await consentRepository.revokeConsent(userId, clientId);
        await tokenRepository.revokeUserClientTokens(userId, clientId);

        logSecurityEvent(logger, {
            event: 'consent_revoked',
            success: true,
            userId: userId.toString(),
            clientId,
        });
    }
}

export const authorizationService = new AuthorizationService();
