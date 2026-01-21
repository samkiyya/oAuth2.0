import * as jose from 'jose';
import { ObjectId } from 'mongodb';
import type { SigningKey, AccessTokenClaims, IDTokenClaims } from '@oauth2/shared-types';
import { generateSecureRandomString, generateTokenId, generateTokenHash } from '@oauth2/shared-utils';
import { getCollections } from '../config/database.js';
import { cache, RedisKeys } from '../config/redis.js';
import config from '../config/index.js';
import { logger } from '../utils/logger.js';

const JWKS_CACHE_TTL = 300; // 5 minutes

/**
 * Key Service - Manages cryptographic keys for JWT signing
 */
export class KeyService {
    private get collection() {
        return getCollections().signingKeys;
    }

    /**
     * Get or create the active signing key
     */
    async getActiveKey(): Promise<SigningKey> {
        let key = await this.collection.findOne({ status: 'active' });

        if (!key) {
            logger.info('No active signing key found, generating new key...');
            key = await this.generateKey();
        }

        return key;
    }

    /**
     * Generate a new RSA key pair
     */
    async generateKey(): Promise<SigningKey> {
        const kid = generateSecureRandomString(8);

        // Generate RSA key pair
        const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
            modulusLength: 2048,
        });

        const publicKeyPem = await jose.exportSPKI(publicKey);
        const privateKeyPem = await jose.exportPKCS8(privateKey);

        const now = new Date();
        const key: Omit<SigningKey, '_id'> = {
            kid,
            algorithm: 'RS256',
            publicKey: publicKeyPem,
            privateKey: privateKeyPem,
            status: 'active',
            createdAt: now,
        };

        // Mark any existing active keys as rotated
        await this.collection.updateMany(
            { status: 'active' },
            { $set: { status: 'rotated', rotatedAt: now } }
        );

        const result = await this.collection.insertOne(key as SigningKey);
        logger.info({ kid }, 'Generated new signing key');

        // Invalidate JWKS cache
        await cache.del(RedisKeys.jwksCache());

        return { ...key, _id: result.insertedId } as SigningKey;
    }

    /**
     * Get the JWKS (JSON Web Key Set)
     */
    async getJWKS(): Promise<jose.JSONWebKeySet> {
        // Try cache first
        const cached = await cache.get<jose.JSONWebKeySet>(RedisKeys.jwksCache());
        if (cached) {
            return cached;
        }

        // Get all non-revoked keys (active + recently rotated)
        const keys = await this.collection
            .find({ status: { $in: ['active', 'rotated'] } })
            .toArray();

        const jwks: jose.JSONWebKeySet = {
            keys: await Promise.all(
                keys.map(async (key) => {
                    const publicKey = await jose.importSPKI(key.publicKey, key.algorithm);
                    const jwk = await jose.exportJWK(publicKey);
                    return {
                        ...jwk,
                        kid: key.kid,
                        use: 'sig',
                        alg: key.algorithm,
                    };
                })
            ),
        };

        // Cache the JWKS
        await cache.set(RedisKeys.jwksCache(), jwks, JWKS_CACHE_TTL);

        return jwks;
    }

    /**
     * Sign an access token JWT
     */
    async signAccessToken(claims: {
        sub: string;
        clientId: string;
        scope: string;
        userId: ObjectId;
    }): Promise<{ token: string; jti: string; expiresAt: Date }> {
        const key = await this.getActiveKey();
        const privateKey = await jose.importPKCS8(key.privateKey, key.algorithm);
        const jti = generateTokenId();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + this.parseExpiresIn(config.jwt.accessTokenExpiresIn));

        const token = await new jose.SignJWT({
            scope: claims.scope,
            client_id: claims.clientId,
        } satisfies Partial<AccessTokenClaims>)
            .setProtectedHeader({ alg: key.algorithm, kid: key.kid, typ: 'at+jwt' })
            .setIssuer(config.server.issuer)
            .setSubject(claims.sub)
            .setAudience(claims.clientId)
            .setIssuedAt()
            .setExpirationTime(config.jwt.accessTokenExpiresIn)
            .setJti(jti)
            .sign(privateKey);

        return { token, jti, expiresAt };
    }

    /**
     * Sign an ID token JWT
     */
    async signIdToken(claims: {
        sub: string;
        clientId: string;
        nonce?: string;
        authTime?: number;
        accessToken?: string;
        code?: string;
        profile?: {
            name?: string;
            email?: string;
            emailVerified?: boolean;
            picture?: string;
        };
        requestedScopes: string[];
    }): Promise<string> {
        const key = await this.getActiveKey();
        const privateKey = await jose.importPKCS8(key.privateKey, key.algorithm);

        const payload: Record<string, unknown> = {};

        // Add profile claims if profile scope is requested
        if (claims.requestedScopes.includes('profile') && claims.profile) {
            if (claims.profile.name) payload['name'] = claims.profile.name;
            if (claims.profile.picture) payload['picture'] = claims.profile.picture;
        }

        // Add email claims if email scope is requested
        if (claims.requestedScopes.includes('email') && claims.profile) {
            if (claims.profile.email) payload['email'] = claims.profile.email;
            if (claims.profile.emailVerified !== undefined) {
                payload['email_verified'] = claims.profile.emailVerified;
            }
        }

        // Add nonce if provided
        if (claims.nonce) {
            payload['nonce'] = claims.nonce;
        }

        // Add auth_time
        if (claims.authTime) {
            payload['auth_time'] = claims.authTime;
        }

        // Add at_hash if access token is provided
        if (claims.accessToken) {
            payload['at_hash'] = generateTokenHash(claims.accessToken, key.algorithm);
        }

        // Add c_hash if code is provided
        if (claims.code) {
            payload['c_hash'] = generateTokenHash(claims.code, key.algorithm);
        }

        const token = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: key.algorithm, kid: key.kid, typ: 'JWT' })
            .setIssuer(config.server.issuer)
            .setSubject(claims.sub)
            .setAudience(claims.clientId)
            .setIssuedAt()
            .setExpirationTime(config.jwt.idTokenExpiresIn)
            .sign(privateKey);

        return token;
    }

    /**
     * Rotate keys (create new, mark old as rotated)
     */
    async rotateKeys(): Promise<SigningKey> {
        return this.generateKey();
    }

    /**
     * Parse expiration time string to milliseconds
     */
    private parseExpiresIn(expiresIn: string): number {
        const match = expiresIn.match(/^(\d+)([smhd])$/);
        if (!match) {
            return 900000; // Default 15 minutes
        }

        const value = parseInt(match[1]!, 10);
        const unit = match[2];

        switch (unit) {
            case 's':
                return value * 1000;
            case 'm':
                return value * 60 * 1000;
            case 'h':
                return value * 60 * 60 * 1000;
            case 'd':
                return value * 24 * 60 * 60 * 1000;
            default:
                return 900000;
        }
    }
}

export const keyService = new KeyService();
