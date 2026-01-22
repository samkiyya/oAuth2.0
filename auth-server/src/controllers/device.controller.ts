import type { Request, Response, NextFunction } from 'express';
import { deviceFlowService } from '../services/device-flow.service.js';
import { clientService } from '../services/client.service.js';
import { tokenService } from '../services/token.service.js';
import { userRepository } from '../repositories/user.repository.js';
import { OAuthErrors } from '@oauth2/shared-utils';

/**
 * Device Authorization endpoint
 * POST /device/code
 */
export async function deviceAuthorization(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const { client_id, scope } = req.body;

        if (!client_id) {
            throw OAuthErrors.invalidRequest('client_id is required');
        }

        // Validate client
        const client = await clientService.validateClientForAuthorization(client_id);

        // Check if client supports device flow
        if (!client.allowedGrantTypes.includes('urn:ietf:params:oauth:grant-type:device_code' as any)) {
            throw OAuthErrors.unauthorizedClient('Client is not authorized for device flow');
        }

        const result = await deviceFlowService.initiateDeviceAuthorization(
            client_id,
            scope ?? 'openid profile'
        );

        res.json(result);
    } catch (error) {
        next(error);
    }
}

/**
 * Device verification page
 * GET /device
 */
export function deviceVerificationPage(req: Request, res: Response): void {
    const userCode = req.query.user_code as string | undefined;

    res.render('device', {
        userCode: userCode ?? '',
        error: req.query.error as string | undefined,
    });
}

/**
 * Verify device code (user submits code)
 * POST /device/verify
 */
export async function verifyDeviceCode(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const { user_code } = req.body;

        if (!req.session.userId) {
            req.session.pendingDeviceCode = user_code;
            res.redirect('/login');
            return;
        }

        const auth = await deviceFlowService.getByUserCode(user_code);

        if (!auth) {
            res.render('device', {
                userCode: user_code,
                error: 'Invalid or expired user code',
            });
            return;
        }

        // Get client info
        const client = await clientService.getClient(auth.clientId);

        // Show confirmation page
        res.render('device-confirm', {
            client: {
                name: client.clientName,
                logoUri: client.logoUri,
            },
            userCode: user_code,
            scope: auth.scope.split(' '),
        });
    } catch (error) {
        next(error);
    }
}

/**
 * Authorize device (user confirmed)
 * POST /device/authorize
 */
export async function authorizeDevice(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const { user_code, action } = req.body;

        if (!req.session.userId) {
            res.redirect('/login');
            return;
        }

        const user = await userRepository.findById(req.session.userId);
        if (!user) {
            res.redirect('/login');
            return;
        }

        if (action === 'deny') {
            await deviceFlowService.denyDevice(user_code);
            res.render('device-complete', { denied: true });
            return;
        }

        const success = await deviceFlowService.authorizeDevice(user_code, user._id);

        if (!success) {
            res.render('device', {
                userCode: user_code,
                error: 'Authorization failed or code expired',
            });
            return;
        }

        res.render('device-complete', { denied: false });
    } catch (error) {
        next(error);
    }
}

/**
 * Device token endpoint
 * POST /token (grant_type=urn:ietf:params:oauth:grant-type:device_code)
 */
import type { TokenResponse } from '@oauth2/shared-types';

export async function deviceTokenExchange(
    deviceCode: string,
    clientId: string
): Promise<{
    status: 'success' | 'authorization_pending' | 'slow_down' | 'access_denied' | 'expired_token';
    tokens?: TokenResponse;
}> {
    const pollResult = await deviceFlowService.pollDeviceCode(deviceCode, clientId);

    switch (pollResult.status) {
        case 'authorized':
            if (!pollResult.userId) {
                return { status: 'expired_token' };
            }

            const tokens = await tokenService.issueTokensForAuthCode({
                userId: pollResult.userId,
                clientId,
                scope: pollResult.scope ?? 'openid profile',
            });

            return {
                status: 'success',
                tokens,
            };

        case 'pending':
            return { status: 'authorization_pending' };

        case 'slow_down':
            return { status: 'slow_down' };

        case 'denied':
            return { status: 'access_denied' };

        case 'expired':
        default:
            return { status: 'expired_token' };
    }
}
