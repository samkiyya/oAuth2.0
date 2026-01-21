import type { OAuthErrorCode } from './oauth.js';

/**
 * Base API Error
 */
export interface APIError {
    statusCode: number;
    error: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    path?: string;
    correlationId?: string;
}

/**
 * OAuth 2.0 Error with RFC-compliant fields
 */
export interface OAuthError extends APIError {
    error: OAuthErrorCode;
    error_description?: string;
    error_uri?: string;
}

/**
 * Validation Error
 */
export interface ValidationError extends APIError {
    error: 'validation_error';
    details: {
        field: string;
        message: string;
        code: string;
    }[];
}

/**
 * Rate Limit Error
 */
export interface RateLimitError extends APIError {
    error: 'rate_limit_exceeded';
    retryAfter: number;
}

/**
 * HTTP Status Codes commonly used
 */
export const HttpStatus = {
    OK: 200,
    CREATED: 201,
    NO_CONTENT: 204,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    UNPROCESSABLE_ENTITY: 422,
    TOO_MANY_REQUESTS: 429,
    INTERNAL_SERVER_ERROR: 500,
    SERVICE_UNAVAILABLE: 503,
} as const;

export type HttpStatusCode = (typeof HttpStatus)[keyof typeof HttpStatus];
