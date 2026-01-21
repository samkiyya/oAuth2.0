import { beforeAll, afterAll, vi } from 'vitest';

// Mock environment variables
process.env.NODE_ENV = 'test';
process.env.PORT = '3000';
process.env.ISSUER = 'http://localhost:3000';
process.env.MONGODB_URI = 'mongodb://localhost:27017/oauth2_test';
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.SESSION_SECRET = 'test-session-secret-minimum-32-characters-long';
process.env.JWT_ACCESS_TOKEN_EXPIRES_IN = '15m';
process.env.JWT_REFRESH_TOKEN_EXPIRES_IN = '7d';
process.env.JWT_ID_TOKEN_EXPIRES_IN = '1h';

// Global test hooks
beforeAll(async () => {
    // Setup code before all tests
});

afterAll(async () => {
    // Cleanup code after all tests
});

// Mock external services if needed
vi.mock('ioredis', () => {
    const Redis = vi.fn();
    Redis.prototype.get = vi.fn();
    Redis.prototype.set = vi.fn();
    Redis.prototype.del = vi.fn();
    Redis.prototype.setex = vi.fn();
    Redis.prototype.exists = vi.fn();
    Redis.prototype.ping = vi.fn().mockResolvedValue('PONG');
    Redis.prototype.quit = vi.fn();
    return { default: Redis };
});
