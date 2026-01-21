import { z } from 'zod';

/**
 * Environment configuration schema with validation
 */
const envSchema = z.object({
    // Server
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),

    // URLs
    ISSUER: z.string().url().default('http://localhost:3000'),
    CORS_ORIGIN: z.string().default('http://localhost:3001'),

    // Database
    MONGODB_URI: z.string().min(1),

    // Redis
    REDIS_URL: z.string().min(1),

    // Sessions
    SESSION_SECRET: z.string().min(32),

    // JWT
    JWT_ACCESS_TOKEN_EXPIRES_IN: z.string().default('15m'),
    JWT_REFRESH_TOKEN_EXPIRES_IN: z.string().default('7d'),
    JWT_ID_TOKEN_EXPIRES_IN: z.string().default('1h'),

    // Security
    BCRYPT_ROUNDS: z.coerce.number().int().min(10).max(15).default(12),
    RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(900000),
    RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(100),
});

type EnvConfig = z.infer<typeof envSchema>;

function loadConfig(): EnvConfig {
    const result = envSchema.safeParse(process.env);

    if (!result.success) {
        console.error('❌ Invalid environment configuration:');
        console.error(result.error.format());
        process.exit(1);
    }

    return result.data;
}

const env = loadConfig();

/**
 * Application configuration
 */
export const config = {
    env: env.NODE_ENV,
    isProduction: env.NODE_ENV === 'production',
    isDevelopment: env.NODE_ENV === 'development',
    isTest: env.NODE_ENV === 'test',

    server: {
        port: env.PORT,
        issuer: env.ISSUER,
        corsOrigin: env.CORS_ORIGIN.split(',').map((o) => o.trim()),
    },

    database: {
        uri: env.MONGODB_URI,
    },

    redis: {
        url: env.REDIS_URL,
    },

    session: {
        secret: env.SESSION_SECRET,
        name: 'oauth2.sid',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },

    jwt: {
        accessTokenExpiresIn: env.JWT_ACCESS_TOKEN_EXPIRES_IN,
        refreshTokenExpiresIn: env.JWT_REFRESH_TOKEN_EXPIRES_IN,
        idTokenExpiresIn: env.JWT_ID_TOKEN_EXPIRES_IN,
        algorithm: 'RS256' as const,
    },

    security: {
        bcryptRounds: env.BCRYPT_ROUNDS,
        rateLimit: {
            windowMs: env.RATE_LIMIT_WINDOW_MS,
            maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
        },
    },

    oauth: {
        authorizationCodeExpiresIn: 5 * 60 * 1000, // 5 minutes
        supportedScopes: ['openid', 'profile', 'email', 'offline_access'],
        supportedGrantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
        supportedResponseTypes: ['code'],
        supportedCodeChallengeMethods: ['S256'],
    },
} as const;

export type Config = typeof config;
export default config;
