import { ObjectId } from 'mongodb';
import type { User, CreateUserInput, UpdateUserInput } from '@oauth2/shared-types';
import { getCollections } from '../config/database.js';
import { hashPassword, verifyPassword } from '../utils/password.js';

/**
 * User Repository - Data access layer for users
 */
export class UserRepository {
    private get collection() {
        return getCollections().users;
    }

    /**
     * Find user by ID
     */
    async findById(id: string | ObjectId): Promise<User | null> {
        const _id = typeof id === 'string' ? new ObjectId(id) : id;
        return this.collection.findOne({ _id });
    }

    /**
     * Find user by email
     */
    async findByEmail(email: string): Promise<User | null> {
        return this.collection.findOne({ email: email.toLowerCase() });
    }

    /**
     * Find user by username
     */
    async findByUsername(username: string): Promise<User | null> {
        return this.collection.findOne({ username });
    }

    /**
     * Create a new user
     */
    async create(input: CreateUserInput): Promise<User> {
        const passwordHash = await hashPassword(input.password);
        const now = new Date();

        const user: Omit<User, '_id'> = {
            email: input.email.toLowerCase(),
            username: input.username,
            passwordHash,
            profile: {
                name: input.profile?.name,
                givenName: input.profile?.givenName,
                familyName: input.profile?.familyName,
                picture: input.profile?.picture,
                locale: input.profile?.locale,
                zoneinfo: input.profile?.zoneinfo,
            },
            emailVerified: false,
            mfaEnabled: false,
            failedLoginAttempts: 0,
            createdAt: now,
            updatedAt: now,
        };

        const result = await this.collection.insertOne(user as User);
        return { ...user, _id: result.insertedId } as User;
    }

    /**
     * Update user
     */
    async update(id: string | ObjectId, input: UpdateUserInput): Promise<User | null> {
        const _id = typeof id === 'string' ? new ObjectId(id) : id;

        const updateDoc: Record<string, unknown> = {
            updatedAt: new Date(),
        };

        if (input.email) {
            updateDoc.email = input.email.toLowerCase();
        }
        if (input.username) {
            updateDoc.username = input.username;
        }
        if (input.profile) {
            Object.entries(input.profile).forEach(([key, value]) => {
                if (value !== undefined) {
                    updateDoc[`profile.${key}`] = value;
                }
            });
        }

        const result = await this.collection.findOneAndUpdate(
            { _id },
            { $set: updateDoc },
            { returnDocument: 'after' }
        );

        return result;
    }

    /**
     * Update password
     */
    async updatePassword(id: string | ObjectId, newPassword: string): Promise<boolean> {
        const _id = typeof id === 'string' ? new ObjectId(id) : id;
        const passwordHash = await hashPassword(newPassword);

        const result = await this.collection.updateOne(
            { _id },
            {
                $set: {
                    passwordHash,
                    updatedAt: new Date(),
                },
            }
        );

        return result.modifiedCount === 1;
    }

    /**
     * Verify user password
     */
    async verifyPassword(user: User, password: string): Promise<boolean> {
        return verifyPassword(password, user.passwordHash);
    }

    /**
     * Record failed login attempt
     */
    async recordFailedLogin(id: string | ObjectId): Promise<void> {
        const _id = typeof id === 'string' ? new ObjectId(id) : id;

        await this.collection.updateOne(
            { _id },
            {
                $inc: { failedLoginAttempts: 1 },
                $set: { updatedAt: new Date() },
            }
        );
    }

    /**
     * Reset failed login attempts and record successful login
     */
    async recordSuccessfulLogin(id: string | ObjectId): Promise<void> {
        const _id = typeof id === 'string' ? new ObjectId(id) : id;

        await this.collection.updateOne(
            { _id },
            {
                $set: {
                    failedLoginAttempts: 0,
                    lastLoginAt: new Date(),
                    updatedAt: new Date(),
                },
                $unset: {
                    lockedUntil: '',
                },
            }
        );
    }

    /**
     * Lock user account
     */
    async lockAccount(id: string | ObjectId, until: Date): Promise<void> {
        const _id = typeof id === 'string' ? new ObjectId(id) : id;

        await this.collection.updateOne(
            { _id },
            {
                $set: {
                    lockedUntil: until,
                    updatedAt: new Date(),
                },
            }
        );
    }

    /**
     * Mark email as verified
     */
    async verifyEmail(id: string | ObjectId): Promise<boolean> {
        const _id = typeof id === 'string' ? new ObjectId(id) : id;

        const result = await this.collection.updateOne(
            { _id },
            {
                $set: {
                    emailVerified: true,
                    updatedAt: new Date(),
                },
            }
        );

        return result.modifiedCount === 1;
    }

    /**
     * Delete user
     */
    async delete(id: string | ObjectId): Promise<boolean> {
        const _id = typeof id === 'string' ? new ObjectId(id) : id;
        const result = await this.collection.deleteOne({ _id });
        return result.deletedCount === 1;
    }

    /**
     * Check if email exists
     */
    async emailExists(email: string): Promise<boolean> {
        const count = await this.collection.countDocuments({ email: email.toLowerCase() });
        return count > 0;
    }

    /**
     * Check if username exists
     */
    async usernameExists(username: string): Promise<boolean> {
        const count = await this.collection.countDocuments({ username });
        return count > 0;
    }
}

export const userRepository = new UserRepository();
