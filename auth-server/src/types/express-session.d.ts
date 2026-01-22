import 'express-session';
import type { ObjectId } from 'mongodb';
import type { AuthorizationRequest } from '@oauth2/shared-types';

declare module 'express-session' {
    interface SessionData {
        // User identification
        userId?: string | undefined;
        authTime?: number | undefined;

        // MFA state
        pendingMFAUserId?: string | undefined;
        pendingMFASecret?: string | undefined;

        // Device flow
        pendingDeviceCode?: string | undefined;

        // Authorization flow
        pendingAuth?: {
            clientId: string;
            redirectUri: string;
            scope: string;
            state?: string | undefined;
            codeChallenge?: string | undefined;
            codeChallengeMethod?: string | undefined;
            nonce?: string | undefined;
            responseType?: string | undefined;
            prompt?: string | undefined;
        } | undefined;

        // CSRF state
        csrfSecret?: string | undefined;
    }
}
