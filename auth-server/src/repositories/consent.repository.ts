import { ObjectId } from 'mongodb';
import type { UserConsent } from '@oauth2/shared-types';
import { getCollections } from '../config/database.js';

/**
 * Consent Repository - Data access layer for user consents
 */
export class ConsentRepository {
    private get collection() {
        return getCollections().consents;
    }

    /**
     * Find consent for user-client combination
     */
    async findConsent(userId: ObjectId, clientId: string): Promise<UserConsent | null> {
        return this.collection.findOne({ userId, clientId });
    }

    /**
     * Create or update consent
     */
    async upsertConsent(userId: ObjectId, clientId: string, scopes: string[]): Promise<UserConsent> {
        const now = new Date();

        const result = await this.collection.findOneAndUpdate(
            { userId, clientId },
            {
                $set: {
                    scopes,
                    updatedAt: now,
                },
                $setOnInsert: {
                    grantedAt: now,
                },
            },
            {
                upsert: true,
                returnDocument: 'after',
            }
        );

        return result!;
    }

    /**
     * Check if user has consented to all requested scopes
     */
    async hasConsent(userId: ObjectId, clientId: string, requestedScopes: string[]): Promise<boolean> {
        const consent = await this.findConsent(userId, clientId);
        if (!consent) {
            return false;
        }
        return requestedScopes.every((scope) => consent.scopes.includes(scope));
    }

    /**
     * Revoke consent
     */
    async revokeConsent(userId: ObjectId, clientId: string): Promise<boolean> {
        const result = await this.collection.deleteOne({ userId, clientId });
        return result.deletedCount === 1;
    }

    /**
     * Revoke all consents for a user
     */
    async revokeAllUserConsents(userId: ObjectId): Promise<number> {
        const result = await this.collection.deleteMany({ userId });
        return result.deletedCount;
    }

    /**
     * List all consents for a user
     */
    async listUserConsents(userId: ObjectId): Promise<UserConsent[]> {
        return this.collection.find({ userId }).toArray();
    }
}

export const consentRepository = new ConsentRepository();
