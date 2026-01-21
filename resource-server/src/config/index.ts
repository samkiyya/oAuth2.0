import { z } from 'zod';
import { createLogger } from '@oauth2/shared-utils';

const logger = createLogger({ name: 'config' });

const envSchema = z.object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().int().positive().default(3002),

    // Auth Server
    AUTH_SERVER_URL: z.string().url().default('http://localhost:3000'),
    JWKS_URI: z.string().url().optional(),
    ISSUER: z.string().url().optional(),
    AUDIENCE: z.string().min(1).default('resource-server'),

    // CORS
    CORS_ORIGINS: z.string().default('http://localhost:3001'),

    // Redis for token blacklist
    REDIS_URL: z.string().optional(),

    // Cache
    JWKS_CACHE_TTL: z.coerce.number().default(300000), // 5 minutes

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
        corsOrigins: env.CORS_ORIGINS.split(',').map((o) => o.trim()),
    },

    auth: {
        authServerUrl: env.AUTH_SERVER_URL,
        jwksUri: env.JWKS_URI ?? `${env.AUTH_SERVER_URL}/.well-known/jwks.json`,
        issuer: env.ISSUER ?? env.AUTH_SERVER_URL,
        audience: env.AUDIENCE,
    },

    redis: {
        url: env.REDIS_URL,
    },

    cache: {
        jwksTtl: env.JWKS_CACHE_TTL,
    },

    logging: {
        level: env.LOG_LEVEL,
    },
} as const;

export type Config = typeof config;
export default config;
