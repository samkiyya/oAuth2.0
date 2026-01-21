import { authenticator } from 'otplib';
import * as qrcode from 'qrcode';
import type { User } from '@oauth2/shared-types';
import { userRepository } from '../repositories/user.repository.js';
import { createLogger } from '@oauth2/shared-utils';

const logger = createLogger({ name: 'mfa-service' });

/**
 * MFA Service - TOTP-based Multi-Factor Authentication
 */
export class MFAService {
    private readonly issuer = 'OAuth2 Server';

    /**
     * Generate MFA secret and QR code for user enrollment
     */
    async generateSecret(userId: string, email: string): Promise<{
        secret: string;
        otpAuthUrl: string;
        qrCodeDataUrl: string;
    }> {
        const secret = authenticator.generateSecret();
        const otpAuthUrl = authenticator.keyuri(email, this.issuer, secret);

        const qrCodeDataUrl = await qrcode.toDataURL(otpAuthUrl);

        logger.info({ userId }, 'MFA secret generated');

        return {
            secret,
            otpAuthUrl,
            qrCodeDataUrl,
        };
    }

    /**
     * Verify TOTP code
     */
    verifyToken(secret: string, token: string): boolean {
        try {
            return authenticator.verify({ token, secret });
        } catch {
            return false;
        }
    }

    /**
     * Enable MFA for user
     */
    async enableMFA(userId: string, secret: string, token: string): Promise<boolean> {
        // Verify the token first
        if (!this.verifyToken(secret, token)) {
            logger.warn({ userId }, 'MFA verification failed during enrollment');
            return false;
        }

        // Store the secret
        const user = await userRepository.findById(userId);
        if (!user) {
            return false;
        }

        await userRepository.update(userId, {
            mfaEnabled: true,
            mfaSecret: secret,
        } as any);

        logger.info({ userId }, 'MFA enabled for user');
        return true;
    }

    /**
     * Disable MFA for user
     */
    async disableMFA(userId: string): Promise<boolean> {
        await userRepository.update(userId, {
            mfaEnabled: false,
            mfaSecret: undefined,
        } as any);

        logger.info({ userId }, 'MFA disabled for user');
        return true;
    }

    /**
     * Verify MFA for login
     */
    async verifyMFA(user: User, token: string): Promise<boolean> {
        if (!user.mfaEnabled || !user.mfaSecret) {
            return true; // MFA not enabled, proceed
        }

        const isValid = this.verifyToken(user.mfaSecret, token);

        if (!isValid) {
            logger.warn({ userId: user._id.toString() }, 'MFA verification failed');
        }

        return isValid;
    }

    /**
     * Generate backup codes
     */
    generateBackupCodes(count: number = 10): string[] {
        const codes: string[] = [];
        for (let i = 0; i < count; i++) {
            const code = Math.random().toString(36).substring(2, 10).toUpperCase();
            codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
        }
        return codes;
    }
}

export const mfaService = new MFAService();
