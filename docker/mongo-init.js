// MongoDB initialization script
// This runs when MongoDB container is first created

db = db.getSiblingDB('oauth2');

// Create application user
db.createUser({
    user: 'oauth2_app',
    pwd: 'oauth2_app_password',
    roles: [
        {
            role: 'readWrite',
            db: 'oauth2',
        },
    ],
});

// Create collections with validation
db.createCollection('users', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['email', 'passwordHash', 'createdAt'],
            properties: {
                email: {
                    bsonType: 'string',
                    pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
                },
                username: {
                    bsonType: 'string',
                    minLength: 3,
                    maxLength: 50,
                },
                passwordHash: {
                    bsonType: 'string',
                },
                profile: {
                    bsonType: 'object',
                    properties: {
                        name: { bsonType: 'string' },
                        picture: { bsonType: 'string' },
                        givenName: { bsonType: 'string' },
                        familyName: { bsonType: 'string' },
                    },
                },
                emailVerified: {
                    bsonType: 'bool',
                },
                createdAt: {
                    bsonType: 'date',
                },
                updatedAt: {
                    bsonType: 'date',
                },
            },
        },
    },
});

db.createCollection('clients', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['clientId', 'clientName', 'redirectUris', 'createdAt'],
            properties: {
                clientId: {
                    bsonType: 'string',
                },
                clientSecretHash: {
                    bsonType: 'string',
                },
                clientName: {
                    bsonType: 'string',
                },
                clientType: {
                    enum: ['confidential', 'public'],
                },
                redirectUris: {
                    bsonType: 'array',
                    items: { bsonType: 'string' },
                },
                allowedScopes: {
                    bsonType: 'array',
                    items: { bsonType: 'string' },
                },
                allowedGrantTypes: {
                    bsonType: 'array',
                    items: { bsonType: 'string' },
                },
                createdAt: {
                    bsonType: 'date',
                },
            },
        },
    },
});

db.createCollection('authorization_codes');
db.createCollection('refresh_tokens');
db.createCollection('access_tokens');
db.createCollection('consents');
db.createCollection('signing_keys');

// Create indexes
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ username: 1 }, { unique: true, sparse: true });

db.clients.createIndex({ clientId: 1 }, { unique: true });

db.authorization_codes.createIndex({ code: 1 }, { unique: true });
db.authorization_codes.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

db.refresh_tokens.createIndex({ token: 1 }, { unique: true });
db.refresh_tokens.createIndex({ userId: 1 });
db.refresh_tokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

db.access_tokens.createIndex({ jti: 1 }, { unique: true });
db.access_tokens.createIndex({ userId: 1 });
db.access_tokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

db.consents.createIndex({ userId: 1, clientId: 1 }, { unique: true });

db.signing_keys.createIndex({ kid: 1 }, { unique: true });
db.signing_keys.createIndex({ status: 1 });

// Insert demo client
db.clients.insertOne({
    clientId: 'demo-client',
    clientSecretHash: '$2b$12$LQcaON4jV7s1wD3K9m1YOecdWHGC7YF/XVbv1EzFJjP/zy4Qz0UWO', // demosecret123
    clientName: 'Demo Application',
    clientType: 'confidential',
    redirectUris: ['http://localhost:3001/callback', 'http://localhost:3001/silent-refresh'],
    allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
    allowedGrantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    tokenEndpointAuthMethod: 'client_secret_post',
    logoUri: null,
    policyUri: null,
    tosUri: null,
    createdAt: new Date(),
    updatedAt: new Date(),
});

print('OAuth2 database initialized successfully!');
