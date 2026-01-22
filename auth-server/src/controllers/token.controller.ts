import type { Request, Response, NextFunction } from 'express';
import type { GrantType } from '@oauth2/shared-types';
import { tokenRequestSchema, revocationRequestSchema, introspectionRequestSchema } from '@oauth2/shared-utils';
import { clientService } from '../services/client.service.js';
import { authorizationService } from '../services/authorization.service.js';
import { tokenService } from '../services/token.service.js';
import { deviceTokenExchange } from './device.controller.js';
import { OAuthErrors } from '@oauth2/shared-utils';

const DEVICE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * Token endpoint
 * POST /token
 */
export async function token(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        // Extract client credentials from header or body
        let clientId = req.body.client_id as string | undefined;
        let clientSecret = req.body.client_secret as string | undefined;

        // Check Authorization header for client_secret_basic
        const authHeader = req.headers.authorization;
        if (authHeader?.startsWith('Basic ')) {
            const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
            const [headerClientId, headerSecret] = credentials.split(':');
            clientId = headerClientId ?? clientId;
            clientSecret = headerSecret ?? clientSecret;
        }

        if (!clientId) {
            throw OAuthErrors.invalidClient('client_id is required');
        }

        const grantType = req.body.grant_type as GrantType;

        // Handle Device Authorization Grant specially
        if (grantType === DEVICE_GRANT_TYPE) {
            const deviceCode = req.body.device_code as string;
            if (!deviceCode) {
                throw OAuthErrors.invalidRequest('device_code is required');
            }

            const result = await deviceTokenExchange(deviceCode, clientId);

            switch (result.status) {
                case 'success':
                    res.json(result.tokens);
                    return;
                case 'authorization_pending':
                    res.status(400).json({
                        error: 'authorization_pending',
                        error_description: 'The authorization request is still pending',
                    });
                    return;
                case 'slow_down':
                    res.status(400).json({
                        error: 'slow_down',
                        error_description: 'Polling too frequently',
                    });
                    return;
                case 'access_denied':
                    res.status(400).json({
                        error: 'access_denied',
                        error_description: 'The user denied the authorization request',
                    });
                    return;
                case 'expired_token':
                    res.status(400).json({
                        error: 'expired_token',
                        error_description: 'The device code has expired',
                    });
                    return;
            }
        }

        // Validate request body for other grant types
        const validation = tokenRequestSchema.safeParse({
            ...req.body,
            client_id: clientId,
            client_secret: clientSecret,
        });

        if (!validation.success) {
            const firstError = validation.error.errors[0];
            throw OAuthErrors.invalidRequest(firstError?.message ?? 'Invalid request');
        }

        const tokenRequest = validation.data;

        // Handle different grant types
        switch (tokenRequest.grant_type) {
            case 'authorization_code': {
                const client = await clientService.validateClient(clientId, clientSecret);
                clientService.validateGrantType(client, 'authorization_code');

                const authCode = await authorizationService.exchangeCode(
                    tokenRequest.code,
                    clientId,
                    tokenRequest.redirect_uri,
                    tokenRequest.code_verifier
                );

                const tokens = await tokenService.issueTokensForAuthCode({
                    userId: authCode.userId,
                    clientId: authCode.clientId,
                    scope: authCode.scope,
                    nonce: authCode.nonce,
                });

                res.json(tokens);
                break;
            }

            case 'refresh_token': {
                const client = await clientService.validateClient(clientId, clientSecret);
                clientService.validateGrantType(client, 'refresh_token');

                const tokens = await tokenService.refreshTokens(
                    tokenRequest.refresh_token,
                    clientId,
                    tokenRequest.scope
                );

                res.json(tokens);
                break;
            }

            case 'client_credentials': {
                if (!clientSecret) {
                    throw OAuthErrors.invalidClient('client_secret is required for client_credentials grant');
                }

                const client = await clientService.validateClient(clientId, clientSecret);
                clientService.validateGrantType(client, 'client_credentials');

                const tokens = await tokenService.issueClientCredentialsToken(client, tokenRequest.scope);

                res.json(tokens);
                break;
            }

            default:
                throw OAuthErrors.unsupportedGrantType((tokenRequest as any).grant_type);
        }
    } catch (error) {
        next(error);
    }
}

/**
 * Token revocation endpoint
 * POST /revoke
 */
export async function revoke(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        // Extract client credentials
        let clientId = req.body.client_id as string | undefined;
        let clientSecret = req.body.client_secret as string | undefined;

        const authHeader = req.headers.authorization;
        if (authHeader?.startsWith('Basic ')) {
            const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
            const [headerClientId, headerSecret] = credentials.split(':');
            clientId = headerClientId ?? clientId;
            clientSecret = headerSecret ?? clientSecret;
        }

        // Validate client (optional but recommended)
        if (clientId) {
            await clientService.validateClient(clientId, clientSecret);
        }

        // Validate request
        const validation = revocationRequestSchema.safeParse(req.body);
        if (!validation.success) {
            throw OAuthErrors.invalidRequest('Invalid revocation request');
        }

        const { token, token_type_hint } = validation.data;

        // Revoke the token
        await tokenService.revokeToken(token, token_type_hint, clientId);

        // Always return 200 OK (per RFC 7009)
        res.status(200).end();
    } catch (error) {
        // Per RFC 7009, invalid tokens should still return 200
        if (error instanceof Error && 'error' in error) {
            const oauthError = error as { error: string };
            if (oauthError.error === 'invalid_token') {
                res.status(200).end();
                return;
            }
        }
        next(error);
    }
}

/**
 * Token introspection endpoint
 * POST /introspect
 */
export async function introspect(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        // Extract client credentials (required for introspection)
        let clientId = req.body.client_id as string | undefined;
        let clientSecret = req.body.client_secret as string | undefined;

        const authHeader = req.headers.authorization;
        if (authHeader?.startsWith('Basic ')) {
            const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
            const [headerClientId, headerSecret] = credentials.split(':');
            clientId = headerClientId ?? clientId;
            clientSecret = headerSecret ?? clientSecret;
        }

        if (!clientId) {
            throw OAuthErrors.invalidClient('Client authentication required for introspection');
        }

        await clientService.validateClient(clientId, clientSecret);

        // Validate request
        const validation = introspectionRequestSchema.safeParse(req.body);
        if (!validation.success) {
            throw OAuthErrors.invalidRequest('Invalid introspection request');
        }

        const { token, token_type_hint } = validation.data;

        // Introspect the token
        const introspectionResult = await tokenService.introspectToken(token, token_type_hint);

        res.json(introspectionResult);
    } catch (error) {
        next(error);
    }
}
