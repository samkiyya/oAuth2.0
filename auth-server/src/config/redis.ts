import { Redis } from 'ioredis';
import { createLogger } from '@oauth2/shared-utils';
import config from './index.js';

const logger = createLogger({ name: 'redis' });

let redis: Redis | null = null;

/**
 * Connect to Redis
 */
export async function connectRedis(): Promise<Redis> {
    if (redis) {
        return redis;
    }

    try {
        logger.info('Connecting to Redis...');

        redis = new Redis(config.redis.url, {
            maxRetriesPerRequest: 3,
            enableReadyCheck: true,
            retryStrategy(times) {
                const delay = Math.min(times * 50, 2000);
                return delay;
            },
        });

        redis.on('connect', () => {
            logger.info('Redis connected');
        });

        redis.on('ready', () => {
            logger.info('Redis ready');
        });

        redis.on('error', (error) => {
            logger.error({ error }, 'Redis error');
        });

        redis.on('close', () => {
            logger.warn('Redis connection closed');
        });

        // Wait for ready
        await new Promise<void>((resolve, reject) => {
            redis!.once('ready', resolve);
            redis!.once('error', reject);
        });

        logger.info('Connected to Redis successfully');
        return redis;
    } catch (error) {
        logger.error({ error }, 'Failed to connect to Redis');
        throw error;
    }
}

/**
 * Get Redis instance
 */
export function getRedis(): Redis {
    if (!redis) {
        throw new Error('Redis not connected. Call connectRedis() first.');
    }
    return redis;
}

/**
 * Disconnect from Redis
 */
export async function disconnectRedis(): Promise<void> {
    if (redis) {
        logger.info('Disconnecting from Redis...');
        await redis.quit();
        redis = null;
        logger.info('Disconnected from Redis');
    }
}

/**
 * Redis key prefixes for different data types
 */
export const RedisKeys = {
    session: (sessionId: string) => `session:${sessionId}`,
    jwksCache: () => 'jwks:cache',
    rateLimit: (key: string) => `ratelimit:${key}`,
    authAttempt: (ip: string) => `auth:attempt:${ip}`,
    tokenBlacklist: (jti: string) => `token:blacklist:${jti}`,
} as const;

/**
 * Cache helpers
 */
export const cache = {
    async get<T>(key: string): Promise<T | null> {
        const redis = getRedis();
        const value = await redis.get(key);
        if (!value) return null;
        try {
            return JSON.parse(value) as T;
        } catch {
            return null;
        }
    },

    async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
        const redis = getRedis();
        const serialized = JSON.stringify(value);
        if (ttlSeconds) {
            await redis.setex(key, ttlSeconds, serialized);
        } else {
            await redis.set(key, serialized);
        }
    },

    async del(key: string): Promise<void> {
        const redis = getRedis();
        await redis.del(key);
    },

    async exists(key: string): Promise<boolean> {
        const redis = getRedis();
        const result = await redis.exists(key);
        return result === 1;
    },
};
