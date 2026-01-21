import type { OAuthErrorCode, HttpStatusCode } from '@oauth2/shared-types';

/**
 * Base application error
 */
export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly details?: Record<string, unknown>;

    constructor(
        message: string,
        statusCode: number = 500,
        isOperational: boolean = true,
        details?: Record<string, unknown>
    ) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperational;
        this.details = details;
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * OAuth 2.0 RFC-compliant error
 */
export class OAuthError extends AppError {
    public readonly error: OAuthErrorCode;
    public readonly errorDescription?: string;
    public readonly errorUri?: string;

    constructor(
        error: OAuthErrorCode,
        errorDescription?: string,
        statusCode: number = 400,
        errorUri?: string
    ) {
        super(errorDescription ?? error, statusCode);
        this.error = error;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;
    }

    toJSON(): Record<string, unknown> {
        return {
            error: this.error,
            ...(this.errorDescription && { error_description: this.errorDescription }),
            ...(this.errorUri && { error_uri: this.errorUri }),
        };
    }
}

/**
 * Validation error
 */
export class ValidationError extends AppError {
    public readonly errors: { field: string; message: string; code: string }[];

    constructor(errors: { field: string; message: string; code: string }[]) {
        super('Validation failed', 400);
        this.errors = errors;
    }
}

/**
 * Not found error
 */
export class NotFoundError extends AppError {
    constructor(resource: string, identifier?: string) {
        super(
            identifier ? `${resource} with identifier '${identifier}' not found` : `${resource} not found`,
            404
        );
    }
}

/**
 * Unauthorized error
 */
export class UnauthorizedError extends AppError {
    constructor(message: string = 'Authentication required') {
        super(message, 401);
    }
}

/**
 * Forbidden error
 */
export class ForbiddenError extends AppError {
    constructor(message: string = 'Access denied') {
        super(message, 403);
    }
}

/**
 * Conflict error (e.g., duplicate resource)
 */
export class ConflictError extends AppError {
    constructor(message: string) {
        super(message, 409);
    }
}

/**
 * Rate limit exceeded error
 */
export class RateLimitError extends AppError {
    public readonly retryAfter: number;

    constructor(retryAfter: number) {
        super('Rate limit exceeded', 429);
        this.retryAfter = retryAfter;
    }
}

/**
 * Common OAuth errors factory
 */
export const OAuthErrors = {
    invalidRequest: (description?: string): OAuthError =>
        new OAuthError('invalid_request', description ?? 'The request is missing a required parameter', 400),

    invalidClient: (description?: string): OAuthError =>
        new OAuthError('invalid_client', description ?? 'Client authentication failed', 401),

    invalidGrant: (description?: string): OAuthError =>
        new OAuthError('invalid_grant', description ?? 'The provided grant is invalid or expired', 400),

    unauthorizedClient: (description?: string): OAuthError =>
        new OAuthError('unauthorized_client', description ?? 'The client is not authorized for this grant type', 401),

    unsupportedGrantType: (grantType?: string): OAuthError =>
        new OAuthError(
            'unsupported_grant_type',
            grantType ? `Grant type '${grantType}' is not supported` : 'The grant type is not supported',
            400
        ),

    invalidScope: (description?: string): OAuthError =>
        new OAuthError('invalid_scope', description ?? 'The requested scope is invalid or unknown', 400),

    accessDenied: (description?: string): OAuthError =>
        new OAuthError('access_denied', description ?? 'The resource owner denied the request', 403),

    serverError: (description?: string): OAuthError =>
        new OAuthError('server_error', description ?? 'An unexpected error occurred', 500),

    invalidToken: (description?: string): OAuthError =>
        new OAuthError('invalid_token', description ?? 'The access token is invalid or expired', 401),

    insufficientScope: (requiredScope?: string): OAuthError =>
        new OAuthError(
            'insufficient_scope',
            requiredScope ? `The request requires scope: ${requiredScope}` : 'Insufficient scope for this resource',
            403
        ),
};

/**
 * Check if error is operational (expected) or programming error
 */
export function isOperationalError(error: Error): boolean {
    if (error instanceof AppError) {
        return error.isOperational;
    }
    return false;
}
