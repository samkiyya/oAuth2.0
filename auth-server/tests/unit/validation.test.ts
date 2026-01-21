import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
    tokenRequestSchema,
    clientRegistrationSchema,
    userLoginSchema,
    userRegistrationSchema,
} from '@oauth2/shared-utils';

describe('Token Request Validation', () => {
    describe('authorization_code grant', () => {
        it('should validate a correct authorization_code request', () => {
            const request = {
                grant_type: 'authorization_code',
                code: 'test-code',
                redirect_uri: 'https://example.com/callback',
                client_id: 'test-client',
                code_verifier: 'a'.repeat(43),
            };

            const result = tokenRequestSchema.safeParse(request);
            expect(result.success).toBe(true);
        });

        it('should reject authorization_code without code_verifier', () => {
            const request = {
                grant_type: 'authorization_code',
                code: 'test-code',
                redirect_uri: 'https://example.com/callback',
                client_id: 'test-client',
            };

            const result = tokenRequestSchema.safeParse(request);
            expect(result.success).toBe(false);
        });

        it('should reject short code_verifier', () => {
            const request = {
                grant_type: 'authorization_code',
                code: 'test-code',
                redirect_uri: 'https://example.com/callback',
                client_id: 'test-client',
                code_verifier: 'short',
            };

            const result = tokenRequestSchema.safeParse(request);
            expect(result.success).toBe(false);
        });
    });

    describe('refresh_token grant', () => {
        it('should validate a correct refresh_token request', () => {
            const request = {
                grant_type: 'refresh_token',
                refresh_token: 'test-refresh-token',
                client_id: 'test-client',
            };

            const result = tokenRequestSchema.safeParse(request);
            expect(result.success).toBe(true);
        });

        it('should reject refresh_token without token', () => {
            const request = {
                grant_type: 'refresh_token',
                client_id: 'test-client',
            };

            const result = tokenRequestSchema.safeParse(request);
            expect(result.success).toBe(false);
        });
    });

    describe('client_credentials grant', () => {
        it('should validate a correct client_credentials request', () => {
            const request = {
                grant_type: 'client_credentials',
                client_id: 'test-client',
                client_secret: 'test-secret',
            };

            const result = tokenRequestSchema.safeParse(request);
            expect(result.success).toBe(true);
        });
    });
});

describe('Client Registration Validation', () => {
    it('should validate a correct registration request', () => {
        const request = {
            redirect_uris: ['https://example.com/callback'],
            client_name: 'Test App',
            grant_types: ['authorization_code', 'refresh_token'],
        };

        const result = clientRegistrationSchema.safeParse(request);
        expect(result.success).toBe(true);
    });

    it('should reject request without redirect_uris', () => {
        const request = {
            client_name: 'Test App',
        };

        const result = clientRegistrationSchema.safeParse(request);
        expect(result.success).toBe(false);
    });

    it('should reject invalid redirect URI', () => {
        const request = {
            redirect_uris: ['not-a-url'],
            client_name: 'Test App',
        };

        const result = clientRegistrationSchema.safeParse(request);
        expect(result.success).toBe(false);
    });
});

describe('User Validation', () => {
    describe('Login', () => {
        it('should validate correct login', () => {
            const request = {
                email: 'test@example.com',
                password: 'Password123!',
            };

            const result = userLoginSchema.safeParse(request);
            expect(result.success).toBe(true);
        });

        it('should reject invalid email', () => {
            const request = {
                email: 'not-an-email',
                password: 'Password123!',
            };

            const result = userLoginSchema.safeParse(request);
            expect(result.success).toBe(false);
        });
    });

    describe('Registration', () => {
        it('should validate correct registration', () => {
            const request = {
                email: 'new@example.com',
                password: 'Password123!',
                confirmPassword: 'Password123!',
            };

            const result = userRegistrationSchema.safeParse(request);
            expect(result.success).toBe(true);
        });

        it('should reject weak password', () => {
            const request = {
                email: 'new@example.com',
                password: 'weak',
                confirmPassword: 'weak',
            };

            const result = userRegistrationSchema.safeParse(request);
            expect(result.success).toBe(false);
        });

        it('should reject mismatched passwords', () => {
            const request = {
                email: 'new@example.com',
                password: 'Password123!',
                confirmPassword: 'DifferentPassword123!',
            };

            const result = userRegistrationSchema.safeParse(request);
            expect(result.success).toBe(false);
        });
    });
});
