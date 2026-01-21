import type { OAuthClient, RegisterClientInput, RegisterClientResponse, GrantType } from '@oauth2/shared-types';
import { OAuthErrors, NotFoundError } from '@oauth2/shared-utils';
import { clientRepository } from '../repositories/client.repository.js';
import { logger, logSecurityEvent } from '../utils/logger.js';

/**
 * Client Service - Business logic for OAuth client management
 */
export class ClientService {
    /**
     * Validate client credentials
     */
    async validateClient(clientId: string, clientSecret?: string): Promise<OAuthClient> {
        const client = await clientRepository.findByClientId(clientId);

        if (!client) {
            logSecurityEvent(logger, {
                event: 'client_authentication',
                success: false,
                clientId,
                details: { reason: 'client_not_found' },
            });
            throw OAuthErrors.invalidClient('Client not found');
        }

        // If client has a secret, verify it
        if (client.clientSecretHash && client.clientType === 'confidential') {
            if (!clientSecret) {
                logSecurityEvent(logger, {
                    event: 'client_authentication',
                    success: false,
                    clientId,
                    details: { reason: 'secret_required' },
                });
                throw OAuthErrors.invalidClient('Client secret required');
            }

            const isValid = await clientRepository.verifySecret(client, clientSecret);
            if (!isValid) {
                logSecurityEvent(logger, {
                    event: 'client_authentication',
                    success: false,
                    clientId,
                    details: { reason: 'invalid_secret' },
                });
                throw OAuthErrors.invalidClient('Invalid client credentials');
            }
        }

        logSecurityEvent(logger, {
            event: 'client_authentication',
            success: true,
            clientId,
        });

        return client;
    }

    /**
     * Validate client for authorization request (no secret required)
     */
    async validateClientForAuthorization(clientId: string): Promise<OAuthClient> {
        const client = await clientRepository.findByClientId(clientId);

        if (!client) {
            throw OAuthErrors.invalidClient('Client not found');
        }

        return client;
    }

    /**
     * Validate redirect URI for client
     */
    validateRedirectUri(client: OAuthClient, redirectUri: string): void {
        if (!clientRepository.isValidRedirectUri(client, redirectUri)) {
            throw OAuthErrors.invalidRequest(`Invalid redirect_uri: ${redirectUri}`);
        }
    }

    /**
     * Validate scope for client
     */
    validateScope(client: OAuthClient, scope: string): string[] {
        const requestedScopes = scope ? scope.split(' ').filter(Boolean) : [];

        if (!clientRepository.isValidScope(client, requestedScopes)) {
            throw OAuthErrors.invalidScope('One or more requested scopes are not allowed');
        }

        return requestedScopes;
    }

    /**
     * Validate grant type for client
     */
    validateGrantType(client: OAuthClient, grantType: GrantType): void {
        if (!clientRepository.isValidGrantType(client, grantType)) {
            throw OAuthErrors.unauthorizedClient(`Client is not authorized for grant type: ${grantType}`);
        }
    }

    /**
     * Register a new client (Dynamic Client Registration)
     */
    async registerClient(input: RegisterClientInput): Promise<RegisterClientResponse> {
        const { client, secret } = await clientRepository.create(input);

        logSecurityEvent(logger, {
            event: 'client_registered',
            success: true,
            clientId: client.clientId,
            details: { clientName: input.client_name },
        });

        return {
            client_id: client.clientId,
            client_secret: secret,
            client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
            client_secret_expires_at: 0, // Never expires, but can be rotated
            client_name: client.clientName,
            redirect_uris: client.redirectUris,
            grant_types: client.allowedGrantTypes,
            response_types: ['code'],
            token_endpoint_auth_method: client.tokenEndpointAuthMethod,
        };
    }

    /**
     * Get client by ID
     */
    async getClient(clientId: string): Promise<OAuthClient> {
        const client = await clientRepository.findByClientId(clientId);
        if (!client) {
            throw new NotFoundError('Client', clientId);
        }
        return client;
    }

    /**
     * Rotate client secret
     */
    async rotateClientSecret(clientId: string): Promise<{ clientId: string; clientSecret: string }> {
        const result = await clientRepository.rotateSecret(clientId);
        if (!result) {
            throw new NotFoundError('Client', clientId);
        }

        logSecurityEvent(logger, {
            event: 'client_secret_rotated',
            success: true,
            clientId,
        });

        return {
            clientId: result.client.clientId,
            clientSecret: result.secret,
        };
    }

    /**
     * Delete client
     */
    async deleteClient(clientId: string): Promise<void> {
        const deleted = await clientRepository.delete(clientId);
        if (!deleted) {
            throw new NotFoundError('Client', clientId);
        }

        logSecurityEvent(logger, {
            event: 'client_deleted',
            success: true,
            clientId,
        });
    }
}

export const clientService = new ClientService();
