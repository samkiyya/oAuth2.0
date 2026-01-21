import type { Request, Response } from 'express';
import os from 'os';

const startTime = Date.now();

/**
 * Get user profile (requires 'profile' scope)
 * GET /api/v1/profile
 */
export function getProfile(req: Request, res: Response): void {
    if (!req.user) {
        res.status(401).json({
            error: 'unauthorized',
            message: 'Authentication required',
        });
        return;
    }

    res.json({
        message: 'Protected profile data retrieved successfully',
        data: {
            userId: req.user.sub,
            scope: req.user.scope,
            clientId: req.user.clientId,
            email: req.user.email,
            name: req.user.name,
        },
        metadata: {
            requestId: req.id,
            timestamp: new Date().toISOString(),
        },
    });
}

/**
 * Get user data (requires 'email' scope)
 * GET /api/v1/user
 */
export function getUser(req: Request, res: Response): void {
    if (!req.user) {
        res.status(401).json({
            error: 'unauthorized',
            message: 'Authentication required',
        });
        return;
    }

    res.json({
        sub: req.user.sub,
        email: req.user.email,
        name: req.user.name,
        scope: req.user.scope,
        tokenIssuedAt: req.user.iat ? new Date(req.user.iat * 1000).toISOString() : undefined,
        tokenExpiresAt: req.user.exp ? new Date(req.user.exp * 1000).toISOString() : undefined,
        metadata: {
            timestamp: new Date().toISOString(),
        },
    });
}

/**
 * Get protected resources (requires 'read' scope)
 * GET /api/v1/resources
 */
export function getResources(req: Request, res: Response): void {
    if (!req.user) {
        res.status(401).json({
            error: 'unauthorized',
            message: 'Authentication required',
        });
        return;
    }

    res.json({
        message: 'Protected resources retrieved successfully',
        data: [
            { id: '1', name: 'Resource 1', type: 'document', createdAt: '2024-01-01T00:00:00Z' },
            { id: '2', name: 'Resource 2', type: 'image', createdAt: '2024-01-02T00:00:00Z' },
            { id: '3', name: 'Resource 3', type: 'video', createdAt: '2024-01-03T00:00:00Z' },
        ],
        pagination: {
            total: 3,
            page: 1,
            limit: 10,
        },
        metadata: {
            requestId: req.id,
            timestamp: new Date().toISOString(),
        },
    });
}

/**
 * Health check
 * GET /health
 */
export function healthCheck(_req: Request, res: Response): void {
    const uptime = Date.now() - startTime;

    res.json({
        status: 'healthy',
        service: 'resource-server',
        version: process.env.npm_package_version ?? '1.0.0',
        uptime: Math.floor(uptime / 1000),
        uptimeHuman: formatUptime(uptime),
        timestamp: new Date().toISOString(),
        system: {
            memory: {
                used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                total: Math.round(os.totalmem() / 1024 / 1024),
                unit: 'MB',
            },
            cpu: os.loadavg(),
        },
    });
}

/**
 * Liveness probe for Kubernetes
 * GET /health/live
 */
export function livenessProbe(_req: Request, res: Response): void {
    res.status(200).json({ status: 'alive' });
}

/**
 * Readiness probe for Kubernetes
 * GET /health/ready
 */
export function readinessProbe(_req: Request, res: Response): void {
    // Add more checks here (database, cache, etc.)
    res.status(200).json({ status: 'ready' });
}

function formatUptime(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
}
