import { randomBytes, createHash, timingSafeEqual } from 'crypto';

/**
 * Base64URL encode a buffer
 */
export function base64url(input: Buffer): string {
    return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * Base64URL decode a string
 */
export function base64urlDecode(input: string): Buffer {
    const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(base64, 'base64');
}

/**
 * Generate a cryptographically secure random string
 */
export function generateSecureRandomString(length: number = 32): string {
    return base64url(randomBytes(length));
}

/**
 * Generate a PKCE code verifier
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
 */
export function generateCodeVerifier(): string {
    return base64url(randomBytes(32));
}

/**
 * Generate a PKCE code challenge from a code verifier
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
 */
export function generateCodeChallenge(codeVerifier: string): string {
    const hash = createHash('sha256').update(codeVerifier).digest();
    return base64url(hash);
}

/**
 * Verify a PKCE code challenge
 */
export function verifyCodeChallenge(
    codeVerifier: string,
    codeChallenge: string,
    method: 'S256' | 'plain' = 'S256'
): boolean {
    if (method === 'plain') {
        return codeVerifier === codeChallenge;
    }

    const computedChallenge = generateCodeChallenge(codeVerifier);
    return computedChallenge === codeChallenge;
}

/**
 * Generate a cryptographically secure state parameter
 */
export function generateState(): string {
    return base64url(randomBytes(16));
}

/**
 * Generate a nonce for OpenID Connect
 */
export function generateNonce(): string {
    return base64url(randomBytes(16));
}

/**
 * Hash a token for storage (using SHA-256)
 */
export function hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
}

/**
 * Verify a token against its hash (timing-safe)
 */
export function verifyTokenHash(token: string, hash: string): boolean {
    const computedHash = hashToken(token);
    try {
        return timingSafeEqual(Buffer.from(computedHash, 'hex'), Buffer.from(hash, 'hex'));
    } catch {
        return false;
    }
}

/**
 * Generate at_hash or c_hash for ID tokens
 * @see https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
 */
export function generateTokenHash(token: string, algorithm: 'RS256' | 'ES256' = 'RS256'): string {
    const hashAlg = algorithm === 'RS256' || algorithm === 'ES256' ? 'sha256' : 'sha256';
    const hash = createHash(hashAlg).update(token).digest();
    const halfLength = hash.length / 2;
    return base64url(hash.subarray(0, halfLength));
}

/**
 * Generate a unique identifier for tokens (jti)
 */
export function generateTokenId(): string {
    return base64url(randomBytes(16));
}

/**
 * Generate a family ID for refresh token rotation
 */
export function generateTokenFamily(): string {
    return base64url(randomBytes(8));
}
