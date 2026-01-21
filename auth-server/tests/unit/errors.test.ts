import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
    AppError,
    OAuthError,
    ValidationError,
    OAuthErrors,
    isOperationalError,
} from '@oauth2/shared-utils';

describe('Error Classes', () => {
    describe('AppError', () => {
        it('should create an operational error', () => {
            const error = new AppError('Test error', 400, true);

            expect(error.message).toBe('Test error');
            expect(error.statusCode).toBe(400);
            expect(error.isOperational).toBe(true);
            expect(error.name).toBe('AppError');
        });

        it('should default to operational = true', () => {
            const error = new AppError('Test error', 500);
            expect(error.isOperational).toBe(true);
        });
    });

    describe('OAuthError', () => {
        it('should create an OAuth error', () => {
            const error = new OAuthError('invalid_request', 'Missing parameter', 400);

            expect(error.error).toBe('invalid_request');
            expect(error.errorDescription).toBe('Missing parameter');
            expect(error.statusCode).toBe(400);
        });

        it('should serialize to JSON correctly', () => {
            const error = new OAuthError('invalid_grant', 'Code expired', 400);
            const json = error.toJSON();

            expect(json).toEqual({
                error: 'invalid_grant',
                error_description: 'Code expired',
            });
        });

        it('should include error_uri if provided', () => {
            const error = new OAuthError('invalid_request', 'Error', 400, 'https://example.com/errors');
            const json = error.toJSON();

            expect(json.error_uri).toBe('https://example.com/errors');
        });
    });

    describe('ValidationError', () => {
        it('should create a validation error', () => {
            const errors = [
                { field: 'email', message: 'Invalid email', code: 'invalid_type' },
                { field: 'password', message: 'Too short', code: 'too_small' },
            ];

            const error = new ValidationError(errors);

            expect(error.errors).toEqual(errors);
            expect(error.statusCode).toBe(400);
        });
    });

    describe('OAuthErrors factory', () => {
        it('should create invalidRequest error', () => {
            const error = OAuthErrors.invalidRequest('Missing client_id');

            expect(error.error).toBe('invalid_request');
            expect(error.statusCode).toBe(400);
        });

        it('should create invalidClient error', () => {
            const error = OAuthErrors.invalidClient('Unknown client');

            expect(error.error).toBe('invalid_client');
            expect(error.statusCode).toBe(401);
        });

        it('should create invalidGrant error', () => {
            const error = OAuthErrors.invalidGrant('Code expired');

            expect(error.error).toBe('invalid_grant');
            expect(error.statusCode).toBe(400);
        });

        it('should create unauthorizedClient error', () => {
            const error = OAuthErrors.unauthorizedClient('Not authorized for grant');

            expect(error.error).toBe('unauthorized_client');
            expect(error.statusCode).toBe(403);
        });

        it('should create unsupportedGrantType error', () => {
            const error = OAuthErrors.unsupportedGrantType('password');

            expect(error.error).toBe('unsupported_grant_type');
            expect(error.statusCode).toBe(400);
        });

        it('should create invalidScope error', () => {
            const error = OAuthErrors.invalidScope('admin');

            expect(error.error).toBe('invalid_scope');
            expect(error.statusCode).toBe(400);
        });

        it('should create invalidToken error', () => {
            const error = OAuthErrors.invalidToken('Token expired');

            expect(error.error).toBe('invalid_token');
            expect(error.statusCode).toBe(401);
        });

        it('should create insufficientScope error', () => {
            const error = OAuthErrors.insufficientScope('admin');

            expect(error.error).toBe('insufficient_scope');
            expect(error.statusCode).toBe(403);
        });

        it('should create accessDenied error', () => {
            const error = OAuthErrors.accessDenied('User denied');

            expect(error.error).toBe('access_denied');
            expect(error.statusCode).toBe(403);
        });

        it('should create serverError', () => {
            const error = OAuthErrors.serverError('Internal error');

            expect(error.error).toBe('server_error');
            expect(error.statusCode).toBe(500);
        });
    });

    describe('isOperationalError', () => {
        it('should return true for AppError', () => {
            const error = new AppError('Test', 400);
            expect(isOperationalError(error)).toBe(true);
        });

        it('should return true for OAuthError', () => {
            const error = new OAuthError('invalid_request', 'Test', 400);
            expect(isOperationalError(error)).toBe(true);
        });

        it('should return false for regular Error', () => {
            const error = new Error('Test');
            expect(isOperationalError(error)).toBe(false);
        });

        it('should return false for non-operational AppError', () => {
            const error = new AppError('Test', 500, false);
            expect(isOperationalError(error)).toBe(false);
        });
    });
});
