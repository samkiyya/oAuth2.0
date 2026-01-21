import type { User, CreateUserInput } from '@oauth2/shared-types';
import { OAuthErrors, ConflictError, UnauthorizedError, NotFoundError } from '@oauth2/shared-utils';
import { userRepository } from '../repositories/user.repository.js';
import { tokenRepository } from '../repositories/token.repository.js';
import { logger, logSecurityEvent } from '../utils/logger.js';

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

/**
 * User Service - Business logic for user management
 */
export class UserService {
    /**
     * Register a new user
     */
    async register(input: CreateUserInput): Promise<User> {
        // Check if email already exists
        if (await userRepository.emailExists(input.email)) {
            throw new ConflictError('Email already registered');
        }

        // Check if username already exists (if provided)
        if (input.username && (await userRepository.usernameExists(input.username))) {
            throw new ConflictError('Username already taken');
        }

        const user = await userRepository.create(input);

        logSecurityEvent(logger, {
            event: 'user_registered',
            success: true,
            userId: user._id.toString(),
            details: { email: input.email },
        });

        return user;
    }

    /**
     * Authenticate user with email and password
     */
    async authenticate(email: string, password: string, ipAddress?: string): Promise<User> {
        const user = await userRepository.findByEmail(email);

        if (!user) {
            logSecurityEvent(logger, {
                event: 'login_attempt',
                success: false,
                ipAddress,
                details: { email, reason: 'user_not_found' },
            });
            throw new UnauthorizedError('Invalid email or password');
        }

        // Check if account is locked
        if (user.lockedUntil && user.lockedUntil > new Date()) {
            const remainingMinutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
            logSecurityEvent(logger, {
                event: 'login_attempt',
                success: false,
                userId: user._id.toString(),
                ipAddress,
                details: { reason: 'account_locked', remainingMinutes },
            });
            throw new UnauthorizedError(`Account locked. Try again in ${remainingMinutes} minutes.`);
        }

        // Verify password
        const isValid = await userRepository.verifyPassword(user, password);

        if (!isValid) {
            await userRepository.recordFailedLogin(user._id);

            // Check if we should lock the account
            if (user.failedLoginAttempts + 1 >= MAX_FAILED_ATTEMPTS) {
                const lockUntil = new Date(Date.now() + LOCKOUT_DURATION);
                await userRepository.lockAccount(user._id, lockUntil);

                logSecurityEvent(logger, {
                    event: 'account_locked',
                    success: false,
                    userId: user._id.toString(),
                    ipAddress,
                    details: { reason: 'max_failed_attempts' },
                });
            }

            logSecurityEvent(logger, {
                event: 'login_attempt',
                success: false,
                userId: user._id.toString(),
                ipAddress,
                details: { reason: 'invalid_password', attemptCount: user.failedLoginAttempts + 1 },
            });

            throw new UnauthorizedError('Invalid email or password');
        }

        // Reset failed attempts and record successful login
        await userRepository.recordSuccessfulLogin(user._id);

        logSecurityEvent(logger, {
            event: 'login_success',
            success: true,
            userId: user._id.toString(),
            ipAddress,
        });

        return user;
    }

    /**
     * Get user by ID
     */
    async getUserById(id: string): Promise<User> {
        const user = await userRepository.findById(id);
        if (!user) {
            throw new NotFoundError('User', id);
        }
        return user;
    }

    /**
     * Get user by email
     */
    async getUserByEmail(email: string): Promise<User | null> {
        return userRepository.findByEmail(email);
    }

    /**
     * Update user profile
     */
    async updateProfile(
        userId: string,
        updates: { name?: string; givenName?: string; familyName?: string; picture?: string }
    ): Promise<User> {
        const user = await userRepository.update(userId, { profile: updates });
        if (!user) {
            throw new NotFoundError('User', userId);
        }
        return user;
    }

    /**
     * Change user password
     */
    async changePassword(
        userId: string,
        currentPassword: string,
        newPassword: string
    ): Promise<void> {
        const user = await userRepository.findById(userId);
        if (!user) {
            throw new NotFoundError('User', userId);
        }

        const isValid = await userRepository.verifyPassword(user, currentPassword);
        if (!isValid) {
            throw new UnauthorizedError('Current password is incorrect');
        }

        await userRepository.updatePassword(userId, newPassword);

        // Revoke all existing tokens for security
        await tokenRepository.revokeAllUserTokens(user._id);

        logSecurityEvent(logger, {
            event: 'password_changed',
            success: true,
            userId,
        });
    }

    /**
     * Logout user (revoke all tokens)
     */
    async logout(userId: string, clientId?: string): Promise<void> {
        const user = await userRepository.findById(userId);
        if (!user) {
            throw new NotFoundError('User', userId);
        }

        if (clientId) {
            await tokenRepository.revokeUserClientTokens(user._id, clientId);
        } else {
            await tokenRepository.revokeAllUserTokens(user._id);
        }

        logSecurityEvent(logger, {
            event: 'logout',
            success: true,
            userId,
            clientId,
        });
    }
}

export const userService = new UserService();
