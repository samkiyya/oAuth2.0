import { ObjectId } from 'mongodb';
import type { OAuthClient, RegisterClientInput, GrantType, TokenEndpointAuthMethod } from '@oauth2/shared-types';
import { getCollections } from '../config/database.js';
import { hashPassword, verifyPassword } from '../utils/password.js';
import { generateSecureRandomString } from '@oauth2/shared-utils';

/**
 * Client Repository - Data access layer for OAuth clients
 */
export class ClientRepository {
    private get collection() {
        return getCollections().clients;
    }

    /**
     * Find client by client_id
     */
    async findByClientId(clientId: string): Promise<OAuthClient | null> {
        return this.collection.findOne({ clientId });
    }

    /**
     * Find client by ID
     */
    async findById(id: string | ObjectId): Promise<OAuthClient | null> {
        const _id = typeof id === 'string' ? new ObjectId(id) : id;
        return this.collection.findOne({ _id });
    }

    /**
     * Create a new client
     */
    async create(input: RegisterClientInput): Promise<{ client: OAuthClient; secret?: string }> {
        const clientId = generateSecureRandomString(16);
        const clientSecret = generateSecureRandomString(32);
        const clientSecretHash = await hashPassword(clientSecret);
        const now = new Date();

        const client: Omit<OAuthClient, '_id'> = {
            clientId,
            clientSecretHash,
            clientName: input.client_name,
            clientType: 'confidential',
            redirectUris: input.redirect_uris,
            postLogoutRedirectUris: [],
            allowedScopes: input.scope?.split(' ') ?? ['openid', 'profile', 'email'],
            allowedGrantTypes: (input.grant_types ?? ['authorization_code', 'refresh_token']) as GrantType[],
            tokenEndpointAuthMethod: (input.token_endpoint_auth_method ?? 'client_secret_post') as TokenEndpointAuthMethod,
            logoUri: input.logo_uri,
            policyUri: input.policy_uri,
            tosUri: input.tos_uri,
            contacts: input.contacts,
            accessTokenLifetime: 900, // 15 minutes
            refreshTokenLifetime: 604800, // 7 days
            idTokenLifetime: 3600, // 1 hour
            createdAt: now,
            updatedAt: now,
        };

        const result = await this.collection.insertOne(client as OAuthClient);
        return {
            client: { ...client, _id: result.insertedId } as OAuthClient,
            secret: clientSecret,
        };
    }

    /**
     * Verify client secret
     */
    async verifySecret(client: OAuthClient, secret: string): Promise<boolean> {
        if (!client.clientSecretHash) {
            return client.clientType === 'public';
        }
        return verifyPassword(secret, client.clientSecretHash);
    }

    /**
     * Check if redirect URI is valid for client
     */
    isValidRedirectUri(client: OAuthClient, redirectUri: string): boolean {
        return client.redirectUris.includes(redirectUri);
    }

    /**
     * Check if scope is allowed for client
     */
    isValidScope(client: OAuthClient, requestedScopes: string[]): boolean {
        return requestedScopes.every((scope) => client.allowedScopes.includes(scope));
    }

    /**
     * Check if grant type is allowed for client
     */
    isValidGrantType(client: OAuthClient, grantType: GrantType): boolean {
        return client.allowedGrantTypes.includes(grantType);
    }

    /**
     * Update client
     */
    async update(
        clientId: string,
        updates: Partial<Omit<OAuthClient, '_id' | 'clientId' | 'createdAt'>>
    ): Promise<OAuthClient | null> {
        const result = await this.collection.findOneAndUpdate(
            { clientId },
            {
                $set: {
                    ...updates,
                    updatedAt: new Date(),
                },
            },
            { returnDocument: 'after' }
        );

        return result;
    }

    /**
     * Rotate client secret
     */
    async rotateSecret(clientId: string): Promise<{ client: OAuthClient; secret: string } | null> {
        const newSecret = generateSecureRandomString(32);
        const newSecretHash = await hashPassword(newSecret);

        const client = await this.collection.findOneAndUpdate(
            { clientId },
            {
                $set: {
                    clientSecretHash: newSecretHash,
                    updatedAt: new Date(),
                },
            },
            { returnDocument: 'after' }
        );

        if (!client) {
            return null;
        }

        return { client, secret: newSecret };
    }

    /**
     * Delete client
     */
    async delete(clientId: string): Promise<boolean> {
        const result = await this.collection.deleteOne({ clientId });
        return result.deletedCount === 1;
    }

    /**
     * List all clients
     */
    async listAll(): Promise<OAuthClient[]> {
        return this.collection.find({}).toArray();
    }
}

export const clientRepository = new ClientRepository();
