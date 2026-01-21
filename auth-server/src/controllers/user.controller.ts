import type { Request, Response, NextFunction } from 'express';
import { userService } from '../services/user.service.js';
import { userLoginSchema, userRegistrationSchema } from '@oauth2/shared-utils';
import { logger } from '../utils/logger.js';

/**
 * Render login page
 * GET /login
 */
export function getLogin(req: Request, res: Response): void {
    const error = req.query.error as string | undefined;
    res.render('login', {
        error,
        csrfToken: req.session.id, // Simple CSRF using session ID
    });
}

/**
 * Handle login form submission
 * POST /login
 */
export async function postLogin(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const validation = userLoginSchema.safeParse(req.body);
        if (!validation.success) {
            res.redirect('/login?error=' + encodeURIComponent('Invalid input'));
            return;
        }

        const { email, password } = validation.data;
        const ipAddress = req.ip ?? req.socket.remoteAddress;

        const user = await userService.authenticate(email, password, ipAddress);

        // Regenerate session to prevent session fixation
        const pendingAuth = req.session.pendingAuth;
        req.session.regenerate((err) => {
            if (err) {
                next(err);
                return;
            }

            req.session.userId = user._id.toString();
            req.session.authTime = Math.floor(Date.now() / 1000);

            // Restore pending auth if exists
            if (pendingAuth) {
                req.session.pendingAuth = pendingAuth;
                res.redirect('/authorize');
            } else {
                res.redirect('/');
            }
        });
    } catch (error) {
        logger.warn({ error }, 'Login failed');
        res.redirect('/login?error=' + encodeURIComponent('Invalid email or password'));
    }
}

/**
 * Render registration page
 * GET /register
 */
export function getRegister(req: Request, res: Response): void {
    const error = req.query.error as string | undefined;
    res.render('register', {
        error,
        csrfToken: req.session.id,
    });
}

/**
 * Handle registration form submission
 * POST /register
 */
export async function postRegister(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const validation = userRegistrationSchema.safeParse(req.body);
        if (!validation.success) {
            const errorMsg = validation.error.errors[0]?.message ?? 'Invalid input';
            res.redirect('/register?error=' + encodeURIComponent(errorMsg));
            return;
        }

        const { email, password, username, profile } = validation.data;

        await userService.register({
            email,
            password,
            username,
            profile,
        });

        // Redirect to login with success message
        res.redirect('/login?registered=true');
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Registration failed';
        logger.warn({ error }, 'Registration failed');
        res.redirect('/register?error=' + encodeURIComponent(message));
    }
}

/**
 * Handle logout
 * GET/POST /logout
 */
export async function logout(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const userId = req.session.userId;
        const postLogoutRedirectUri = req.query.post_logout_redirect_uri as string | undefined;

        if (userId) {
            await userService.logout(userId);
        }

        req.session.destroy((err) => {
            if (err) {
                logger.error({ error: err }, 'Session destruction failed');
            }

            res.clearCookie('oauth2.sid');

            if (postLogoutRedirectUri) {
                res.redirect(postLogoutRedirectUri);
            } else {
                res.redirect('/login');
            }
        });
    } catch (error) {
        next(error);
    }
}

/**
 * Get current user profile
 * GET /userinfo
 */
export async function getUserInfo(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        if (!req.user) {
            res.status(401).json({
                error: 'invalid_token',
                error_description: 'Access token is required',
            });
            return;
        }

        const user = req.user;

        // Return claims based on scope (simplified - in production, check token scope)
        res.json({
            sub: user._id.toString(),
            email: user.email,
            email_verified: user.emailVerified,
            name: user.profile.name,
            given_name: user.profile.givenName,
            family_name: user.profile.familyName,
            picture: user.profile.picture,
            locale: user.profile.locale,
            updated_at: Math.floor(user.updatedAt.getTime() / 1000),
        });
    } catch (error) {
        next(error);
    }
}
