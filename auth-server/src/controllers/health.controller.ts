import type { Request, Response } from 'express';
import { getDb } from '../config/database.js';
import { getRedis } from '../config/redis.js';

/**
 * Health check endpoint
 * GET /health
 */
export async function healthCheck(_req: Request, res: Response): Promise<void> {
    const checks = {
        status: 'healthy' as 'healthy' | 'unhealthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        checks: {} as Record<string, { status: string; latency?: number }>,
    };

    // Check MongoDB
    try {
        const startMongo = Date.now();
        await getDb().admin().ping();
        checks.checks['mongodb'] = {
            status: 'healthy',
            latency: Date.now() - startMongo,
        };
    } catch {
        checks.checks['mongodb'] = { status: 'unhealthy' };
        checks.status = 'unhealthy';
    }

    // Check Redis
    try {
        const startRedis = Date.now();
        await getRedis().ping();
        checks.checks['redis'] = {
            status: 'healthy',
            latency: Date.now() - startRedis,
        };
    } catch {
        checks.checks['redis'] = { status: 'unhealthy' };
        checks.status = 'unhealthy';
    }

    const statusCode = checks.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json(checks);
}

/**
 * Liveness probe
 * GET /health/live
 */
export function livenessProbe(_req: Request, res: Response): void {
    res.status(200).json({ status: 'alive' });
}

/**
 * Readiness probe
 * GET /health/ready
 */
export async function readinessProbe(_req: Request, res: Response): Promise<void> {
    try {
        await getDb().admin().ping();
        await getRedis().ping();
        res.status(200).json({ status: 'ready' });
    } catch {
        res.status(503).json({ status: 'not_ready' });
    }
}
