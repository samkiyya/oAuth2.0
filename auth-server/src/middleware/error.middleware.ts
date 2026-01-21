import type { Request, Response, NextFunction } from 'express';
import { AppError, OAuthError, ValidationError, isOperationalError } from '@oauth2/shared-utils';
import { logger } from '../utils/logger.js';
import config from '../config/index.js';

/**
 * Global error handling middleware
 */
export function errorMiddleware(
    err: Error,
    req: Request,
    res: Response,
    _next: NextFunction
): void {
    // Get correlation ID from request
    const correlationId = (req as { correlationId?: string }).correlationId;

    // Log the error
    if (isOperationalError(err)) {
        logger.warn({ err, correlationId, path: req.path }, 'Operational error');
    } else {
        logger.error({ err, correlationId, path: req.path, stack: err.stack }, 'Unexpected error');
    }

    // Handle OAuth errors (RFC-compliant response)
    if (err instanceof OAuthError) {
        res.status(err.statusCode).json(err.toJSON());
        return;
    }

    // Handle validation errors
    if (err instanceof ValidationError) {
        res.status(400).json({
            error: 'validation_error',
            error_description: 'Request validation failed',
            details: err.errors,
        });
        return;
    }

    // Handle other application errors
    if (err instanceof AppError) {
        res.status(err.statusCode).json({
            error: err.name.toLowerCase().replace('error', '_error'),
            error_description: err.message,
            ...(err.details && { details: err.details }),
        });
        return;
    }

    // Handle unexpected errors
    const statusCode = 500;
    const response = {
        error: 'server_error',
        error_description: config.isProduction
            ? 'An unexpected error occurred'
            : err.message,
        ...(correlationId && { correlation_id: correlationId }),
    };

    res.status(statusCode).json(response);
}

/**
 * 404 handler
 */
export function notFoundHandler(req: Request, res: Response): void {
    res.status(404).json({
        error: 'not_found',
        error_description: `Route ${req.method} ${req.path} not found`,
    });
}
