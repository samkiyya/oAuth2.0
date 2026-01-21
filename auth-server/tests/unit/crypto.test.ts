import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
    generateCodeVerifier,
    generateCodeChallenge,
    verifyCodeChallenge,
    generateState,
    generateNonce,
    hashToken,
} from '@oauth2/shared-utils';

describe('PKCE Utilities', () => {
    describe('generateCodeVerifier', () => {
        it('should generate a code verifier of correct length', () => {
            const verifier = generateCodeVerifier();
            expect(verifier.length).toBeGreaterThanOrEqual(43);
            expect(verifier.length).toBeLessThanOrEqual(128);
        });

        it('should generate different verifiers each time', () => {
            const verifier1 = generateCodeVerifier();
            const verifier2 = generateCodeVerifier();
            expect(verifier1).not.toBe(verifier2);
        });

        it('should only contain valid characters', () => {
            const verifier = generateCodeVerifier();
            expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
        });
    });

    describe('generateCodeChallenge', () => {
        it('should generate a valid S256 challenge', () => {
            const verifier = generateCodeVerifier();
            const challenge = generateCodeChallenge(verifier);

            // Base64URL encoded SHA-256 is always 43 characters
            expect(challenge.length).toBe(43);
            // Should not contain + or / (base64url encoding)
            expect(challenge).not.toMatch(/[+/=]/);
        });

        it('should generate same challenge for same verifier', () => {
            const verifier = generateCodeVerifier();
            const challenge1 = generateCodeChallenge(verifier);
            const challenge2 = generateCodeChallenge(verifier);
            expect(challenge1).toBe(challenge2);
        });
    });

    describe('verifyCodeChallenge', () => {
        it('should verify valid verifier and challenge', () => {
            const verifier = generateCodeVerifier();
            const challenge = generateCodeChallenge(verifier);

            const isValid = verifyCodeChallenge(verifier, challenge, 'S256');
            expect(isValid).toBe(true);
        });

        it('should reject invalid verifier', () => {
            const verifier = generateCodeVerifier();
            const challenge = generateCodeChallenge(verifier);
            const wrongVerifier = generateCodeVerifier();

            const isValid = verifyCodeChallenge(wrongVerifier, challenge, 'S256');
            expect(isValid).toBe(false);
        });

        it('should reject unsupported method', () => {
            const verifier = generateCodeVerifier();
            const challenge = generateCodeChallenge(verifier);

            expect(() => {
                verifyCodeChallenge(verifier, challenge, 'plain' as any);
            }).toThrow();
        });
    });
});

describe('Security Utilities', () => {
    describe('generateState', () => {
        it('should generate a state value', () => {
            const state = generateState();
            expect(state).toBeDefined();
            expect(typeof state).toBe('string');
            expect(state.length).toBeGreaterThan(0);
        });

        it('should generate unique values', () => {
            const state1 = generateState();
            const state2 = generateState();
            expect(state1).not.toBe(state2);
        });
    });

    describe('generateNonce', () => {
        it('should generate a nonce value', () => {
            const nonce = generateNonce();
            expect(nonce).toBeDefined();
            expect(typeof nonce).toBe('string');
            expect(nonce.length).toBeGreaterThan(0);
        });
    });

    describe('hashToken', () => {
        it('should hash a token consistently', () => {
            const token = 'test-token-123';
            const hash1 = hashToken(token);
            const hash2 = hashToken(token);
            expect(hash1).toBe(hash2);
        });

        it('should produce different hashes for different tokens', () => {
            const hash1 = hashToken('token-1');
            const hash2 = hashToken('token-2');
            expect(hash1).not.toBe(hash2);
        });

        it('should produce a hex string', () => {
            const hash = hashToken('test');
            expect(hash).toMatch(/^[a-f0-9]+$/);
        });
    });
});
