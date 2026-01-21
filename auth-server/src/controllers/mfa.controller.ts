import type { Request, Response, NextFunction } from 'express';
import { mfaService } from '../services/mfa.service.js';
import { userRepository } from '../repositories/user.repository.js';
import { logger } from '../utils/logger.js';

/**
 * Get MFA setup page
 * GET /mfa/setup
 */
export async function getMFASetup(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        if (!req.session.userId) {
            res.redirect('/login');
            return;
        }

        const user = await userRepository.findById(req.session.userId);
        if (!user) {
            res.redirect('/login');
            return;
        }

        if (user.mfaEnabled) {
            res.redirect('/mfa/manage');
            return;
        }

        const { secret, qrCodeDataUrl } = await mfaService.generateSecret(
            req.session.userId,
            user.email
        );

        // Store secret temporarily in session
        req.session.pendingMFASecret = secret;

        res.render('mfa-setup', {
            qrCodeDataUrl,
            secret,
            error: req.query.error as string | undefined,
        });
    } catch (error) {
        next(error);
    }
}

/**
 * Enable MFA
 * POST /mfa/setup
 */
export async function enableMFA(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        if (!req.session.userId || !req.session.pendingMFASecret) {
            res.redirect('/mfa/setup');
            return;
        }

        const { token } = req.body;

        const success = await mfaService.enableMFA(
            req.session.userId,
            req.session.pendingMFASecret,
            token
        );

        if (!success) {
            res.redirect('/mfa/setup?error=Invalid verification code');
            return;
        }

        delete req.session.pendingMFASecret;

        // Generate backup codes
        const backupCodes = mfaService.generateBackupCodes();

        res.render('mfa-complete', {
            backupCodes,
        });
    } catch (error) {
        next(error);
    }
}

/**
 * MFA verification page (during login)
 * GET /mfa/verify
 */
export function getMFAVerify(req: Request, res: Response): void {
    if (!req.session.pendingMFAUserId) {
        res.redirect('/login');
        return;
    }

    res.render('mfa-verify', {
        error: req.query.error as string | undefined,
    });
}

/**
 * Verify MFA code
 * POST /mfa/verify
 */
export async function verifyMFA(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        if (!req.session.pendingMFAUserId) {
            res.redirect('/login');
            return;
        }

        const { token } = req.body;

        const user = await userRepository.findById(req.session.pendingMFAUserId);
        if (!user) {
            res.redirect('/login');
            return;
        }

        const isValid = await mfaService.verifyMFA(user, token);

        if (!isValid) {
            res.redirect('/mfa/verify?error=Invalid verification code');
            return;
        }

        // MFA verified - complete login
        const pendingAuth = req.session.pendingAuth;
        delete req.session.pendingMFAUserId;

        req.session.userId = user._id.toString();
        req.session.authTime = Math.floor(Date.now() / 1000);

        if (pendingAuth) {
            req.session.pendingAuth = pendingAuth;
            res.redirect('/authorize');
        } else {
            res.redirect('/');
        }
    } catch (error) {
        next(error);
    }
}

/**
 * Manage MFA settings
 * GET /mfa/manage
 */
export async function getMFAManage(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        if (!req.session.userId) {
            res.redirect('/login');
            return;
        }

        const user = await userRepository.findById(req.session.userId);
        if (!user) {
            res.redirect('/login');
            return;
        }

        res.render('mfa-manage', {
            mfaEnabled: user.mfaEnabled,
        });
    } catch (error) {
        next(error);
    }
}

/**
 * Disable MFA
 * POST /mfa/disable
 */
export async function disableMFA(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        if (!req.session.userId) {
            res.redirect('/login');
            return;
        }

        const { token, password } = req.body;

        const user = await userRepository.findById(req.session.userId);
        if (!user) {
            res.redirect('/login');
            return;
        }

        // Verify password
        const isPasswordValid = await userRepository.verifyPassword(user, password);
        if (!isPasswordValid) {
            res.redirect('/mfa/manage?error=Invalid password');
            return;
        }

        // Verify MFA token
        const isMFAValid = await mfaService.verifyMFA(user, token);
        if (!isMFAValid) {
            res.redirect('/mfa/manage?error=Invalid verification code');
            return;
        }

        await mfaService.disableMFA(req.session.userId);

        res.redirect('/mfa/manage?success=MFA disabled');
    } catch (error) {
        next(error);
    }
}
