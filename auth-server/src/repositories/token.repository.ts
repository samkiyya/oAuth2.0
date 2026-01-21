import { ObjectId } from 'mongodb';
import type { AuthorizationCode, RefreshToken, AccessTokenRecord } from '@oauth2/shared-types';
import { getCollections } from '../config/database.js';
import { hashToken, generateSecureRandomString, generateTokenFamily } from '@oauth2/shared-utils';

/**
 * Token Repository - Data access layer for authorization codes, refresh tokens, and access tokens
 */
export class TokenRepository {
    private get authCodes() {
        return getCollections().authorizationCodes;
    }

    private get refreshTokens() {
        return getCollections().refreshTokens;
    }

    private get accessTokens() {
        return getCollections().accessTokens;
    }

    // ==================== Authorization Codes ====================

    /**
     * Create authorization code
     */
    async createAuthorizationCode(data: {
        clientId: string;
        userId: ObjectId;
        redirectUri: string;
        scope: string;
        codeChallenge?: string;
        codeChallengeMethod?: string;
        nonce?: string;
        state?: string;
        expiresIn: number;
    }): Promise<string> {
        const code = generateSecureRandomString(32);
        const codeHash = hashToken(code);
        const now = new Date();

        const authCode: Omit<AuthorizationCode, '_id'> = {
            code: '', // We don't store the plain code
            codeHash,
            clientId: data.clientId,
            userId: data.userId,
            redirectUri: data.redirectUri,
            scope: data.scope,
            codeChallenge: data.codeChallenge,
            codeChallengeMethod: data.codeChallengeMethod,
            nonce: data.nonce,
            state: data.state,
            expiresAt: new Date(now.getTime() + data.expiresIn),
            createdAt: now,
        };

        await this.authCodes.insertOne(authCode as AuthorizationCode);
        return code;
    }

    /**
     * Find and consume authorization code (single use)
     */
    async consumeAuthorizationCode(code: string): Promise<AuthorizationCode | null> {
        const codeHash = hashToken(code);
        const now = new Date();

        const authCode = await this.authCodes.findOneAndUpdate(
            {
                codeHash,
                expiresAt: { $gt: now },
                usedAt: { $exists: false },
            },
            {
                $set: { usedAt: now },
            },
            { returnDocument: 'before' }
        );

        return authCode;
    }

    /**
     * Check if code was already used (replay detection)
     */
    async isCodeUsed(code: string): Promise<boolean> {
        const codeHash = hashToken(code);
        const authCode = await this.authCodes.findOne({ codeHash });
        return authCode?.usedAt !== undefined;
    }

    /**
     * Delete expired authorization codes
     */
    async cleanupExpiredCodes(): Promise<number> {
        const result = await this.authCodes.deleteMany({
            expiresAt: { $lt: new Date() },
        });
        return result.deletedCount;
    }

    // ==================== Refresh Tokens ====================

    /**
     * Create refresh token
     */
    async createRefreshToken(data: {
        userId: ObjectId;
        clientId: string;
        scope: string;
        expiresIn: number;
        family?: string;
        rotatedFromId?: ObjectId;
    }): Promise<string> {
        const token = generateSecureRandomString(48);
        const tokenHash = hashToken(token);
        const now = new Date();

        const refreshToken: Omit<RefreshToken, '_id'> = {
            tokenHash,
            userId: data.userId,
            clientId: data.clientId,
            scope: data.scope,
            family: data.family ?? generateTokenFamily(),
            rotatedFromId: data.rotatedFromId,
            issuedAt: now,
            expiresAt: new Date(now.getTime() + data.expiresIn),
            createdAt: now,
        };

        await this.refreshTokens.insertOne(refreshToken as RefreshToken);
        return token;
    }

    /**
     * Find refresh token by token string
     */
    async findRefreshToken(token: string): Promise<RefreshToken | null> {
        const tokenHash = hashToken(token);
        return this.refreshTokens.findOne({
            tokenHash,
            expiresAt: { $gt: new Date() },
            revokedAt: { $exists: false },
        });
    }

    /**
     * Rotate refresh token (create new, mark old as rotated)
     */
    async rotateRefreshToken(
        oldToken: string,
        data: {
            userId: ObjectId;
            clientId: string;
            scope: string;
            expiresIn: number;
        }
    ): Promise<{ newToken: string; oldTokenRecord: RefreshToken } | null> {
        const oldTokenHash = hashToken(oldToken);
        const now = new Date();

        // Find and revoke old token
        const oldTokenRecord = await this.refreshTokens.findOneAndUpdate(
            {
                tokenHash: oldTokenHash,
                expiresAt: { $gt: now },
                revokedAt: { $exists: false },
            },
            {
                $set: { revokedAt: now },
            },
            { returnDocument: 'before' }
        );

        if (!oldTokenRecord) {
            return null;
        }

        // Create new token in the same family
        const newToken = await this.createRefreshToken({
            ...data,
            family: oldTokenRecord.family,
            rotatedFromId: oldTokenRecord._id,
        });

        return { newToken, oldTokenRecord };
    }

    /**
     * Revoke refresh token
     */
    async revokeRefreshToken(token: string): Promise<boolean> {
        const tokenHash = hashToken(token);
        const result = await this.refreshTokens.updateOne(
            { tokenHash },
            { $set: { revokedAt: new Date() } }
        );
        return result.modifiedCount === 1;
    }

    /**
     * Revoke all tokens in a family (token theft detection)
     */
    async revokeTokenFamily(family: string): Promise<number> {
        const result = await this.refreshTokens.updateMany(
            { family, revokedAt: { $exists: false } },
            { $set: { revokedAt: new Date() } }
        );
        return result.modifiedCount;
    }

    /**
     * Revoke all refresh tokens for a user
     */
    async revokeAllUserTokens(userId: ObjectId): Promise<number> {
        const result = await this.refreshTokens.updateMany(
            { userId, revokedAt: { $exists: false } },
            { $set: { revokedAt: new Date() } }
        );
        return result.modifiedCount;
    }

    /**
     * Revoke all refresh tokens for a user-client combination
     */
    async revokeUserClientTokens(userId: ObjectId, clientId: string): Promise<number> {
        const result = await this.refreshTokens.updateMany(
            { userId, clientId, revokedAt: { $exists: false } },
            { $set: { revokedAt: new Date() } }
        );
        return result.modifiedCount;
    }

    // ==================== Access Tokens ====================

    /**
     * Record access token (for revocation tracking)
     */
    async recordAccessToken(data: {
        jti: string;
        userId: ObjectId;
        clientId: string;
        scope: string;
        expiresIn: number;
    }): Promise<void> {
        const now = new Date();

        const record: Omit<AccessTokenRecord, '_id'> = {
            jti: data.jti,
            userId: data.userId,
            clientId: data.clientId,
            scope: data.scope,
            issuedAt: now,
            expiresAt: new Date(now.getTime() + data.expiresIn),
        };

        await this.accessTokens.insertOne(record as AccessTokenRecord);
    }

    /**
     * Check if access token is revoked
     */
    async isAccessTokenRevoked(jti: string): Promise<boolean> {
        const record = await this.accessTokens.findOne({ jti });
        return record?.revokedAt !== undefined;
    }

    /**
     * Revoke access token by JTI
     */
    async revokeAccessToken(jti: string): Promise<boolean> {
        const result = await this.accessTokens.updateOne(
            { jti },
            { $set: { revokedAt: new Date() } }
        );
        return result.modifiedCount === 1;
    }

    /**
     * Revoke all access tokens for a user
     */
    async revokeAllUserAccessTokens(userId: ObjectId): Promise<number> {
        const result = await this.accessTokens.updateMany(
            { userId, revokedAt: { $exists: false } },
            { $set: { revokedAt: new Date() } }
        );
        return result.modifiedCount;
    }
}

export const tokenRepository = new TokenRepository();
