import { MongoClient, Db, Collection } from 'mongodb';
import type {
    User,
    OAuthClient,
    AuthorizationCode,
    RefreshToken,
    AccessTokenRecord,
    UserConsent,
    SigningKey,
} from '@oauth2/shared-types';
import type { DeviceAuthorization } from '../services/device-flow.service.js';
import { createLogger } from '@oauth2/shared-utils';
import config from './index.js';

const logger = createLogger({ name: 'database' });

let client: MongoClient | null = null;
let db: Db | null = null;

/**
 * Database collections
 */
export interface Collections {
    users: Collection<User>;
    clients: Collection<OAuthClient>;
    authorizationCodes: Collection<AuthorizationCode>;
    refreshTokens: Collection<RefreshToken>;
    accessTokens: Collection<AccessTokenRecord>;
    consents: Collection<UserConsent>;
    signingKeys: Collection<SigningKey>;
    deviceAuthorizations: Collection<DeviceAuthorization>;
}

let collections: Collections | null = null;

/**
 * Connect to MongoDB
 */
export async function connectDatabase(): Promise<Db> {
    if (db) {
        return db;
    }

    try {
        logger.info('Connecting to MongoDB...');

        client = new MongoClient(config.database.uri, {
            maxPoolSize: 10,
            minPoolSize: 2,
            maxIdleTimeMS: 30000,
            connectTimeoutMS: 10000,
            serverSelectionTimeoutMS: 10000,
        });

        await client.connect();
        db = client.db();

        // Verify connection
        await db.admin().ping();
        logger.info('Connected to MongoDB successfully');

        return db;
    } catch (error) {
        logger.error({ error }, 'Failed to connect to MongoDB');
        throw error;
    }
}

/**
 * Get database collections
 */
export function getCollections(): Collections {
    if (!db) {
        throw new Error('Database not connected. Call connectDatabase() first.');
    }

    if (!collections) {
        collections = {
            users: db.collection<User>('users'),
            clients: db.collection<OAuthClient>('clients'),
            authorizationCodes: db.collection<AuthorizationCode>('authorization_codes'),
            refreshTokens: db.collection<RefreshToken>('refresh_tokens'),
            accessTokens: db.collection<AccessTokenRecord>('access_tokens'),
            consents: db.collection<UserConsent>('consents'),
            signingKeys: db.collection<SigningKey>('signing_keys'),
            deviceAuthorizations: db.collection<DeviceAuthorization>('device_authorizations'),
        };
    }

    return collections;
}

/**
 * Get database instance
 */
export function getDb(): Db {
    if (!db) {
        throw new Error('Database not connected. Call connectDatabase() first.');
    }
    return db;
}

/**
 * Disconnect from MongoDB
 */
export async function disconnectDatabase(): Promise<void> {
    if (client) {
        logger.info('Disconnecting from MongoDB...');
        await client.close();
        client = null;
        db = null;
        collections = null;
        logger.info('Disconnected from MongoDB');
    }
}

/**
 * Create database indexes
 */
export async function createIndexes(): Promise<void> {
    const cols = getCollections();

    logger.info('Creating database indexes...');

    // Users indexes
    await cols.users.createIndex({ email: 1 }, { unique: true });
    await cols.users.createIndex({ username: 1 }, { unique: true, sparse: true });

    // Clients indexes
    await cols.clients.createIndex({ clientId: 1 }, { unique: true });

    // Authorization codes indexes (with TTL)
    await cols.authorizationCodes.createIndex({ codeHash: 1 }, { unique: true });
    await cols.authorizationCodes.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0 }
    );

    // Refresh tokens indexes (with TTL)
    await cols.refreshTokens.createIndex({ tokenHash: 1 }, { unique: true });
    await cols.refreshTokens.createIndex({ userId: 1 });
    await cols.refreshTokens.createIndex({ family: 1 });
    await cols.refreshTokens.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0 }
    );

    // Access tokens indexes (with TTL)
    await cols.accessTokens.createIndex({ jti: 1 }, { unique: true });
    await cols.accessTokens.createIndex({ userId: 1 });
    await cols.accessTokens.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0 }
    );

    // Consents indexes
    await cols.consents.createIndex({ userId: 1, clientId: 1 }, { unique: true });

    // Signing keys indexes
    await cols.signingKeys.createIndex({ kid: 1 }, { unique: true });
    await cols.signingKeys.createIndex({ status: 1 });

    logger.info('Database indexes created successfully');
}
