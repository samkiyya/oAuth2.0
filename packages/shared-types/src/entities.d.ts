import type { ObjectId } from 'mongodb';
import type { GrantType, TokenEndpointAuthMethod } from './oauth.js';
/**
 * User entity stored in database
 */
export interface User {
    _id: ObjectId;
    email: string;
    username?: string;
    passwordHash: string;
    profile: UserProfile;
    emailVerified: boolean;
    mfaEnabled: boolean;
    mfaSecret?: string;
    lastLoginAt?: Date;
    failedLoginAttempts: number;
    lockedUntil?: Date;
    createdAt: Date;
    updatedAt: Date;
}
/**
 * User profile information
 */
export interface UserProfile {
    name?: string;
    givenName?: string;
    familyName?: string;
    picture?: string;
    locale?: string;
    zoneinfo?: string;
}
/**
 * User creation input
 */
export interface CreateUserInput {
    email: string;
    username?: string;
    password: string;
    profile?: Partial<UserProfile>;
}
/**
 * User update input
 */
export interface UpdateUserInput {
    email?: string;
    username?: string;
    profile?: Partial<UserProfile>;
}
/**
 * OAuth 2.0 Client entity
 */
export interface OAuthClient {
    _id: ObjectId;
    clientId: string;
    clientSecretHash?: string;
    clientName: string;
    clientDescription?: string;
    clientType: 'confidential' | 'public';
    redirectUris: string[];
    postLogoutRedirectUris?: string[];
    allowedScopes: string[];
    allowedGrantTypes: GrantType[];
    tokenEndpointAuthMethod: TokenEndpointAuthMethod;
    logoUri?: string;
    policyUri?: string;
    tosUri?: string;
    contacts?: string[];
    defaultMaxAge?: number;
    requireAuthTime?: boolean;
    accessTokenLifetime: number;
    refreshTokenLifetime: number;
    idTokenLifetime: number;
    createdAt: Date;
    updatedAt: Date;
}
/**
 * Client registration input
 */
export interface RegisterClientInput {
    client_name: string;
    redirect_uris: string[];
    grant_types?: GrantType[];
    response_types?: string[];
    scope?: string;
    token_endpoint_auth_method?: TokenEndpointAuthMethod;
    logo_uri?: string;
    policy_uri?: string;
    tos_uri?: string;
    contacts?: string[];
}
/**
 * Client registration response
 */
export interface RegisterClientResponse {
    client_id: string;
    client_secret?: string;
    client_id_issued_at: number;
    client_secret_expires_at?: number;
    client_name: string;
    redirect_uris: string[];
    grant_types: GrantType[];
    response_types: string[];
    token_endpoint_auth_method: TokenEndpointAuthMethod;
}
/**
 * Authorization code entity
 */
export interface AuthorizationCode {
    _id: ObjectId;
    code: string;
    codeHash: string;
    clientId: string;
    userId: ObjectId;
    redirectUri: string;
    scope: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    nonce?: string;
    state?: string;
    expiresAt: Date;
    usedAt?: Date;
    createdAt: Date;
}
/**
 * Refresh token entity
 */
export interface RefreshToken {
    _id: ObjectId;
    tokenHash: string;
    userId: ObjectId;
    clientId: string;
    scope: string;
    issuedAt: Date;
    expiresAt: Date;
    revokedAt?: Date;
    rotatedFromId?: ObjectId;
    family: string;
    createdAt: Date;
}
/**
 * Access token record (for revocation tracking)
 */
export interface AccessTokenRecord {
    _id: ObjectId;
    jti: string;
    userId: ObjectId;
    clientId: string;
    scope: string;
    issuedAt: Date;
    expiresAt: Date;
    revokedAt?: Date;
}
/**
 * User consent entity
 */
export interface UserConsent {
    _id: ObjectId;
    userId: ObjectId;
    clientId: string;
    scopes: string[];
    grantedAt: Date;
    updatedAt: Date;
}
/**
 * Signing key entity for key rotation
 */
export interface SigningKey {
    _id: ObjectId;
    kid: string;
    algorithm: 'RS256' | 'ES256';
    publicKey: string;
    privateKey: string;
    status: 'active' | 'rotated' | 'revoked';
    createdAt: Date;
    rotatedAt?: Date;
    expiresAt?: Date;
}
//# sourceMappingURL=entities.d.ts.map