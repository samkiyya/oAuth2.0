import type { Request, Response, NextFunction } from 'express';

/**
 * Load user from session if present
 */
export function loadUser(_req: Request, _res: Response, next: NextFunction): void {
    // User is loaded from session automatically by express-session
    // This middleware just continues
    next();
}

/**
 * Require authenticated session
 */
export function requireSession(req: Request, res: Response, next: NextFunction): void {
    if (!req.session.userId) {
        const returnUrl = req.originalUrl;
        res.redirect(`/login?returnUrl=${encodeURIComponent(returnUrl)}`);
        return;
    }
    next();
}

/**
 * Require NO session (for login/register pages)
 */
export function requireNoSession(req: Request, res: Response, next: NextFunction): void {
    if (req.session.userId) {
        res.redirect('/');
        return;
    }
    next();
}

/**
 * Set auth time in session
 */
export function setAuthTime(req: Request): void {
    req.session.authTime = Math.floor(Date.now() / 1000);
}

/**
 * Clear session data (for logout)
 */
export function clearSession(req: Request): Promise<void> {
    return new Promise((resolve, reject) => {
        req.session.destroy((err) => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });
    });
}
