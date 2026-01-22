import type { OAuthErrorCode } from './oauth.js';
/**
 * Base API Error
 */
export interface APIError {
    statusCode: number;
    error: string;
    message: string;
    details?: any;
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
export declare const HttpStatus: {
    readonly OK: 200;
    readonly CREATED: 201;
    readonly NO_CONTENT: 204;
    readonly BAD_REQUEST: 400;
    readonly UNAUTHORIZED: 401;
    readonly FORBIDDEN: 403;
    readonly NOT_FOUND: 404;
    readonly CONFLICT: 409;
    readonly UNPROCESSABLE_ENTITY: 422;
    readonly TOO_MANY_REQUESTS: 429;
    readonly INTERNAL_SERVER_ERROR: 500;
    readonly SERVICE_UNAVAILABLE: 503;
};
export type HttpStatusCode = (typeof HttpStatus)[keyof typeof HttpStatus];
//# sourceMappingURL=errors.d.ts.map