import { z } from 'zod';
import { createLogger } from '@oauth2/shared-utils';

const logger = createLogger({ name: 'config' });

const envSchema = z.object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().int().positive().default(3001),

    // OAuth Server URLs
    AUTH_SERVER_URL: z.string().url().default('http://localhost:3000'),
    AUTH_SERVER_PUBLIC_URL: z.string().url().optional(),
    RESOURCE_SERVER_URL: z.string().url().default('http://localhost:3002'),

    // Client Credentials
    CLIENT_ID: z.string().min(1).default('demo-client'),
    CLIENT_SECRET: z.string().min(1).default('demo-secret'),
    REDIRECT_URI: z.string().url().default('http://localhost:3001/callback'),

    // Session
    SESSION_SECRET: z.string().min(32).default('client-session-secret-change-in-production-32'),
    SESSION_MAX_AGE: z.coerce.number().default(24 * 60 * 60 * 1000),

    // Redis (optional for session store)
    REDIS_URL: z.string().optional(),

    // Logging
    LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),
});

type EnvConfig = z.infer<typeof envSchema>;

function loadConfig(): EnvConfig {
    const result = envSchema.safeParse(process.env);

    if (!result.success) {
        logger.error({ errors: result.error.format() }, 'Invalid environment configuration');
        process.exit(1);
    }

    return result.data;
}

const env = loadConfig();

export const config = {
    env: env.NODE_ENV,
    isProduction: env.NODE_ENV === 'production',
    isDevelopment: env.NODE_ENV === 'development',

    server: {
        port: env.PORT,
    },

    oauth: {
        authServerUrl: env.AUTH_SERVER_URL,
        authServerPublicUrl: env.AUTH_SERVER_PUBLIC_URL ?? env.AUTH_SERVER_URL,
        resourceServerUrl: env.RESOURCE_SERVER_URL,
        clientId: env.CLIENT_ID,
        clientSecret: env.CLIENT_SECRET,
        redirectUri: env.REDIRECT_URI,
        scopes: 'openid profile email offline_access',
    },

    session: {
        secret: env.SESSION_SECRET,
        name: 'client.sid',
        maxAge: env.SESSION_MAX_AGE,
    },

    redis: {
        url: env.REDIS_URL,
    },

    logging: {
        level: env.LOG_LEVEL,
    },
} as const;

export type Config = typeof config;
export default config;
