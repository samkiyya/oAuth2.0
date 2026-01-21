import type { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import config from '../config/index.js';

/**
 * Helmet security headers middleware
 */
export const helmetMiddleware = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com'],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: config.isProduction ? [] : null,
        },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    hsts: config.isProduction
        ? { maxAge: 31536000, includeSubDomains: true, preload: true }
        : false,
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
});

/**
 * CORS middleware configuration
 */
export const corsMiddleware = cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or Postman)
        if (!origin) {
            callback(null, true);
            return;
        }

        if (config.server.corsOrigin.includes(origin)) {
            callback(null, true);
        } else if (config.isDevelopment) {
            // Be more permissive in development
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Correlation-ID'],
    exposedHeaders: ['X-Correlation-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
    maxAge: 86400, // 24 hours
});

/**
 * Add correlation ID to requests
 */
export function correlationMiddleware(req: Request, res: Response, next: NextFunction): void {
    const correlationId =
        (req.headers['x-correlation-id'] as string) ??
        `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;

    (req as Request & { correlationId: string }).correlationId = correlationId;
    res.setHeader('X-Correlation-ID', correlationId);

    next();
}

/**
 * Prevent caching of sensitive responses
 */
export function noCacheMiddleware(req: Request, res: Response, next: NextFunction): void {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    next();
}

/**
 * Enforce HTTPS in production
 */
export function httpsRedirectMiddleware(req: Request, res: Response, next: NextFunction): void {
    if (config.isProduction && req.headers['x-forwarded-proto'] !== 'https') {
        res.redirect(301, `https://${req.hostname}${req.url}`);
        return;
    }
    next();
}
