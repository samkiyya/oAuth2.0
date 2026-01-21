import { z } from 'zod';

/**
 * Validation schema for OAuth 2.0 Authorization Request
 */
export const authorizationRequestSchema = z.object({
    response_type: z.enum(['code', 'token', 'id_token']).default('code'),
    client_id: z.string().min(1, 'client_id is required'),
    redirect_uri: z.string().url('redirect_uri must be a valid URL'),
    scope: z.string().optional(),
    state: z.string().optional(),
    code_challenge: z.string().min(43).max(128).optional(),
    code_challenge_method: z.enum(['S256', 'plain']).optional(),
    nonce: z.string().optional(),
    prompt: z.enum(['none', 'login', 'consent', 'select_account']).optional(),
    max_age: z.coerce.number().int().positive().optional(),
    ui_locales: z.string().optional(),
    login_hint: z.string().email().optional(),
});

export type AuthorizationRequestInput = z.infer<typeof authorizationRequestSchema>;

/**
 * Validation schema for Token Request - Authorization Code
 */
export const tokenRequestAuthCodeSchema = z.object({
    grant_type: z.literal('authorization_code'),
    code: z.string().min(1, 'code is required'),
    redirect_uri: z.string().url('redirect_uri must be a valid URL'),
    client_id: z.string().min(1, 'client_id is required'),
    client_secret: z.string().optional(),
    code_verifier: z.string().min(43).max(128).optional(),
});

/**
 * Validation schema for Token Request - Refresh Token
 */
export const tokenRequestRefreshSchema = z.object({
    grant_type: z.literal('refresh_token'),
    refresh_token: z.string().min(1, 'refresh_token is required'),
    client_id: z.string().min(1, 'client_id is required'),
    client_secret: z.string().optional(),
    scope: z.string().optional(),
});

/**
 * Validation schema for Token Request - Client Credentials
 */
export const tokenRequestClientCredentialsSchema = z.object({
    grant_type: z.literal('client_credentials'),
    client_id: z.string().min(1, 'client_id is required'),
    client_secret: z.string().min(1, 'client_secret is required'),
    scope: z.string().optional(),
});

/**
 * Combined token request schema
 */
export const tokenRequestSchema = z.discriminatedUnion('grant_type', [
    tokenRequestAuthCodeSchema,
    tokenRequestRefreshSchema,
    tokenRequestClientCredentialsSchema,
]);

export type TokenRequestInput = z.infer<typeof tokenRequestSchema>;

/**
 * Validation schema for Token Revocation
 */
export const revocationRequestSchema = z.object({
    token: z.string().min(1, 'token is required'),
    token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
});

export type RevocationRequestInput = z.infer<typeof revocationRequestSchema>;

/**
 * Validation schema for Token Introspection
 */
export const introspectionRequestSchema = z.object({
    token: z.string().min(1, 'token is required'),
    token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
});

export type IntrospectionRequestInput = z.infer<typeof introspectionRequestSchema>;

/**
 * Validation schema for User Registration
 */
export const userRegistrationSchema = z.object({
    email: z.string().email('Invalid email format'),
    username: z
        .string()
        .min(3, 'Username must be at least 3 characters')
        .max(50, 'Username must be at most 50 characters')
        .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens')
        .optional(),
    password: z
        .string()
        .min(8, 'Password must be at least 8 characters')
        .max(128, 'Password must be at most 128 characters')
        .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
        .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
        .regex(/[0-9]/, 'Password must contain at least one number')
        .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
    confirmPassword: z.string(),
    profile: z
        .object({
            name: z.string().max(100).optional(),
            givenName: z.string().max(50).optional(),
            familyName: z.string().max(50).optional(),
        })
        .optional(),
}).refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
});

export type UserRegistrationInput = z.infer<typeof userRegistrationSchema>;

/**
 * Validation schema for User Login
 */
export const userLoginSchema = z.object({
    email: z.string().email('Invalid email format'),
    password: z.string().min(1, 'Password is required'),
    remember: z.boolean().optional(),
});

export type UserLoginInput = z.infer<typeof userLoginSchema>;

/**
 * Validation schema for Client Registration
 */
export const clientRegistrationSchema = z.object({
    client_name: z.string().min(1).max(100),
    redirect_uris: z.array(z.string().url()).min(1, 'At least one redirect_uri is required'),
    grant_types: z
        .array(z.enum(['authorization_code', 'refresh_token', 'client_credentials']))
        .optional(),
    response_types: z.array(z.enum(['code', 'token', 'id_token'])).optional(),
    scope: z.string().optional(),
    token_endpoint_auth_method: z
        .enum(['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'])
        .optional(),
    logo_uri: z.string().url().optional(),
    policy_uri: z.string().url().optional(),
    tos_uri: z.string().url().optional(),
    contacts: z.array(z.string().email()).optional(),
});

export type ClientRegistrationInput = z.infer<typeof clientRegistrationSchema>;

/**
 * Parse and validate input with detailed error formatting
 */
export function validateInput<T>(
    schema: z.ZodSchema<T>,
    data: unknown
): { success: true; data: T } | { success: false; errors: ValidationErrorDetail[] } {
    const result = schema.safeParse(data);

    if (result.success) {
        return { success: true, data: result.data };
    }

    const errors: ValidationErrorDetail[] = result.error.errors.map((err) => ({
        field: err.path.join('.'),
        message: err.message,
        code: err.code,
    }));

    return { success: false, errors };
}

export interface ValidationErrorDetail {
    field: string;
    message: string;
    code: string;
}

export { z };
