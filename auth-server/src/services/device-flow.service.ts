import { ObjectId } from 'mongodb';
import { generateSecureRandomString, createLogger } from '@oauth2/shared-utils';
import { getCollections } from '../config/database.js';
import config from '../config/index.js';

const logger = createLogger({ name: 'device-flow-service' });

/**
 * Device Authorization entity
 */
export interface DeviceAuthorization {
    _id: ObjectId;
    deviceCode: string;
    userCode: string;
    clientId: string;
    scope: string;
    userId?: ObjectId | undefined;
    status: 'pending' | 'authorized' | 'denied' | 'expired';
    expiresAt: Date;
    interval: number;
    lastPolledAt?: Date | undefined;
    createdAt: Date;
}

/**
 * Device Flow Service - RFC 8628 Device Authorization Grant
 */
export class DeviceFlowService {
    private get collection() {
        return getCollections().deviceAuthorizations;
    }

    /**
     * Initiate device authorization
     */
    async initiateDeviceAuthorization(
        clientId: string,
        scope: string
    ): Promise<{
        device_code: string;
        user_code: string;
        verification_uri: string;
        verification_uri_complete: string;
        expires_in: number;
        interval: number;
    }> {
        const deviceCode = generateSecureRandomString(32);
        const userCode = this.generateUserCode();
        const expiresIn = 600; // 10 minutes
        const interval = 5; // Poll every 5 seconds

        const authorization: Omit<DeviceAuthorization, '_id'> = {
            deviceCode,
            userCode: userCode.toUpperCase(),
            clientId,
            scope,
            status: 'pending',
            expiresAt: new Date(Date.now() + expiresIn * 1000),
            interval,
            createdAt: new Date(),
        };

        await this.collection.insertOne(authorization as DeviceAuthorization);

        const verificationUri = `${config.server.issuer}/device`;
        const verificationUriComplete = `${verificationUri}?user_code=${userCode}`;

        logger.info({ clientId, userCode }, 'Device authorization initiated');

        return {
            device_code: deviceCode,
            user_code: userCode,
            verification_uri: verificationUri,
            verification_uri_complete: verificationUriComplete,
            expires_in: expiresIn,
            interval,
        };
    }

    /**
     * Generate user-friendly code (e.g., ABCD-1234)
     */
    private generateUserCode(): string {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // No I, O to avoid confusion
        const nums = '23456789'; // No 0, 1 to avoid confusion

        let code = '';
        for (let i = 0; i < 4; i++) {
            code += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        code += '-';
        for (let i = 0; i < 4; i++) {
            code += nums.charAt(Math.floor(Math.random() * nums.length));
        }

        return code;
    }

    /**
     * Get device authorization by user code
     */
    async getByUserCode(userCode: string): Promise<DeviceAuthorization | null> {
        return this.collection.findOne({
            userCode: userCode.toUpperCase().replace(/[^A-Z0-9]/g, ''),
            status: 'pending',
            expiresAt: { $gt: new Date() },
        });
    }

    /**
     * Get device authorization by device code
     */
    async getByDeviceCode(deviceCode: string): Promise<DeviceAuthorization | null> {
        return this.collection.findOne({ deviceCode });
    }

    /**
     * Authorize device (user approved)
     */
    async authorizeDevice(userCode: string, userId: ObjectId): Promise<boolean> {
        const result = await this.collection.updateOne(
            {
                userCode: userCode.toUpperCase(),
                status: 'pending',
                expiresAt: { $gt: new Date() },
            },
            {
                $set: {
                    status: 'authorized',
                    userId,
                },
            }
        );

        if (result.modifiedCount === 1) {
            logger.info({ userCode, userId: userId.toString() }, 'Device authorized');
            return true;
        }
        return false;
    }

    /**
     * Deny device authorization
     */
    async denyDevice(userCode: string): Promise<boolean> {
        const result = await this.collection.updateOne(
            {
                userCode: userCode.toUpperCase(),
                status: 'pending',
            },
            {
                $set: { status: 'denied' },
            }
        );

        return result.modifiedCount === 1;
    }

    /**
     * Poll for device authorization status
     */
    async pollDeviceCode(
        deviceCode: string,
        clientId: string
    ): Promise<{
        status: 'pending' | 'authorized' | 'denied' | 'expired' | 'slow_down';
        userId?: ObjectId | undefined;
        scope?: string | undefined;
    }> {
        const auth = await this.getByDeviceCode(deviceCode);

        if (!auth) {
            return { status: 'expired' };
        }

        if (auth.clientId !== clientId) {
            return { status: 'expired' };
        }

        if (auth.expiresAt < new Date()) {
            await this.collection.updateOne(
                { deviceCode },
                { $set: { status: 'expired' } }
            );
            return { status: 'expired' };
        }

        // Check for slow polling
        if (auth.lastPolledAt) {
            const timeSinceLastPoll = Date.now() - auth.lastPolledAt.getTime();
            if (timeSinceLastPoll < auth.interval * 1000) {
                return { status: 'slow_down' };
            }
        }

        // Update last polled time
        await this.collection.updateOne(
            { deviceCode },
            { $set: { lastPolledAt: new Date() } }
        );

        if (auth.status === 'authorized' && auth.userId) {
            return {
                status: 'authorized',
                userId: auth.userId,
                scope: auth.scope,
            };
        }

        if (auth.status === 'denied') {
            return { status: 'denied' };
        }

        return { status: 'pending' };
    }

    /**
     * Cleanup expired authorizations
     */
    async cleanupExpired(): Promise<number> {
        const result = await this.collection.deleteMany({
            expiresAt: { $lt: new Date() },
        });
        return result.deletedCount;
    }
}

export const deviceFlowService = new DeviceFlowService();
