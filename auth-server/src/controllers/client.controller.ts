import type { Request, Response, NextFunction } from 'express';
import { clientRegistrationSchema } from '@oauth2/shared-utils';
import { clientService } from '../services/client.service.js';
import { OAuthErrors } from '@oauth2/shared-utils';

/**
 * Dynamic Client Registration endpoint
 * POST /register
 */
export async function registerClient(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        // Validate request
        const validation = clientRegistrationSchema.safeParse(req.body);
        if (!validation.success) {
            throw OAuthErrors.invalidRequest(validation.error.errors[0]?.message ?? 'Invalid request');
        }

        const registrationResponse = await clientService.registerClient(validation.data);

        res.status(201).json(registrationResponse);
    } catch (error) {
        next(error);
    }
}

/**
 * Get client configuration
 * GET /register/:clientId
 */
export async function getClientConfiguration(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const { clientId } = req.params;

        // In production, this should require authentication
        const client = await clientService.getClient(clientId);

        res.json({
            client_id: client.clientId,
            client_name: client.clientName,
            redirect_uris: client.redirectUris,
            grant_types: client.allowedGrantTypes,
            response_types: ['code'],
            token_endpoint_auth_method: client.tokenEndpointAuthMethod,
            logo_uri: client.logoUri,
            policy_uri: client.policyUri,
            tos_uri: client.tosUri,
        });
    } catch (error) {
        next(error);
    }
}

/**
 * Rotate client secret
 * POST /register/:clientId/rotate
 */
export async function rotateClientSecret(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const { clientId } = req.params;
        const currentSecret = req.body.client_secret as string | undefined;

        // Verify current secret before rotation
        if (currentSecret) {
            await clientService.validateClient(clientId, currentSecret);
        } else {
            throw OAuthErrors.invalidClient('Current client_secret is required');
        }

        const result = await clientService.rotateClientSecret(clientId);

        res.json({
            client_id: result.clientId,
            client_secret: result.clientSecret,
        });
    } catch (error) {
        next(error);
    }
}
