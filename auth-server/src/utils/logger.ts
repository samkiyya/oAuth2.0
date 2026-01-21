import { createLogger as createSharedLogger } from '@oauth2/shared-utils';

export const logger = createSharedLogger({
    name: 'auth-server',
    level: process.env['LOG_LEVEL'] ?? 'info',
    prettyPrint: process.env['NODE_ENV'] !== 'production',
});

export { withCorrelation, logSecurityEvent } from '@oauth2/shared-utils';
