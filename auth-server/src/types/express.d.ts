import { User } from '@oauth2/shared-types';

declare global {
    namespace Express {
        interface Request {
            user?: User;
            correlationId?: string;
        }
    }
}
