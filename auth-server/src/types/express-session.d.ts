import 'express-session';
import type { ObjectId } from 'mongodb';
import type { AuthorizationRequest } from '@oauth2/shared-types';

declare module 'express-session' {
    interface SessionData {
        // User identification
        userId?: string;
        authTime?: number;

        // MFA state
        pendingMFAUserId?: string;
        pendingMFASecret?: string;

        // Device flow
        pendingDeviceCode?: string;

        // Authorization flow
        pendingAuth?: {
            clientId: string;
            redirectUri: string;
            scope: string;
            state?: string;
            codeChallenge?: string;
            codeChallengeMethod?: string;
            nonce?: string;
            responseType: string;
            prompt?: string;
        };

        // CSRF state
        csrfSecret?: string;
    }
}
