import type { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { RateLimitError } from '@oauth2/shared-utils';
import config from '../config/index.js';
import { getRedis } from '../config/redis.js';

/**
 * General rate limiter for all endpoints
 */
export const generalRateLimiter = rateLimit({
    windowMs: config.security.rateLimit.windowMs,
    max: config.security.rateLimit.maxRequests,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'too_many_requests',
        error_description: 'Rate limit exceeded. Please try again later.',
    },
    keyGenerator: (req) => {
        return req.ip ?? req.socket.remoteAddress ?? 'unknown';
    },
});

/**
 * Strict rate limiter for authentication endpoints
 */
export const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 requests per 15 minutes
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: {
        error: 'too_many_requests',
        error_description: 'Too many authentication attempts. Please try again later.',
    },
    keyGenerator: (req) => {
        const email = req.body?.email ?? '';
        const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
        return `auth:${ip}:${email}`;
    },
});

/**
 * Token endpoint rate limiter
 */
export const tokenRateLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // 30 requests per minute
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'too_many_requests',
        error_description: 'Too many token requests. Please try again later.',
    },
    keyGenerator: (req) => {
        const clientId = req.body?.client_id ?? '';
        const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
        return `token:${ip}:${clientId}`;
    },
});

/**
 * Client registration rate limiter
 */
export const registrationRateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 client registrations per hour
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'too_many_requests',
        error_description: 'Too many registration attempts. Please try again later.',
    },
    keyGenerator: (req) => {
        return `register:${req.ip ?? req.socket.remoteAddress ?? 'unknown'}`;
    },
});
