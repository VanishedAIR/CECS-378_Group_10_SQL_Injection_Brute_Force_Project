import { SESSION_COOKIE_NAME, SESSION_DURATION_MS, } from "./sessions.js";
import express, { type Router } from "express";
import type { AppDependencies } from "./app.js";
import { requireSession } from "./authMiddleware.js";
import { createLoginPolicy } from "./loginPolicy.js";
import { requireUsernameKey, validatePasswordLength } from "./normalize.js";
import { hashPassword, verifyPassword } from "./passwords.js";
import type { AuthUser, PublicUser } from "./sessions.js";
import { sendJsonError, sourceIpFromRequest } from "./http.js";
/** Reject cross-origin browser login/logout submissions before changing session state. */
function requireSameOrigin(req: express.Request, res: express.Response, next: express.NextFunction): void {
    const origin = req.headers.origin;
    if (origin !== undefined) {
        const expectedOrigin = `${req.protocol}://${req.get("host")}`;
        if (origin !== expectedOrigin) {
            sendJsonError(res, 403, "FORBIDDEN", "Cross-origin requests are not allowed.");
            return;
        }
    }
    // Browsers may identify a cross-site request even when Origin is absent.
    const fetchSite = req.get("sec-fetch-site");
    if (fetchSite === "cross-site" || fetchSite === "same-site") {
        sendJsonError(res, 403, "FORBIDDEN", "Cross-origin requests are not allowed.");
        return;
    }
    next();
}
type UserRow = {
    id: number;
    username_key: string;
    display_username: string;
    password_hash: string;
    role: "user" | "admin";
};
/**
 * Create the dummy hash once, not once per failed login.
 * Unknown usernames still require an expensive scrypt verification.
 */
let dummyHash: string | null = null;
/** Cache a fictional scrypt hash so unknown usernames still take the password-verification path. */
function getDummyHash(): string {
    if (dummyHash === null) {
        dummyHash = hashPassword("dummy-password-not-used-for-login");
    }
    return dummyHash;
}
/** Assemble login, logout, and current-user routes using one shared policy and database. Successful login regenerates and saves a session. */
export function createAuthRouter(deps: AppDependencies): Router {
    const router = express.Router();
    const policy = createLoginPolicy(deps.db, deps.config, deps.clock);
    router.post("/api/login", requireSameOrigin, async (req, res, next) => {
        try {
            const username = req.body?.username;
            const password = req.body?.password;
            if (typeof username !== "string" || typeof password !== "string") {
                sendJsonError(res, 400, "INVALID_REQUEST", "Invalid login request.");
                return;
            }
            let usernameKey: string;
            try {
                usernameKey = requireUsernameKey(username);
                validatePasswordLength(password);
            }
            catch {
                sendJsonError(res, 400, "INVALID_REQUEST", "Invalid login request.");
                return;
            }
            let authenticatedUser: AuthUser | null = null;
            let publicUser: PublicUser | null = null;
            const decision = await policy.evaluate({
                requestId: req.requestId,
                username: usernameKey,
                sourceIp: sourceIpFromRequest(req),
            }, async (normalizedUsername) => {
                const row = deps.db
                    .prepare(`SELECT id, username_key, display_username, password_hash, role
              FROM users
              WHERE username_key = ?`)
                    .get(normalizedUsername) as UserRow | undefined;
                const valid = verifyPassword(password, row?.password_hash ?? getDummyHash());
                if (row && valid) {
                    authenticatedUser = {
                        userId: row.id,
                        usernameKey: row.username_key,
                        role: row.role,
                    };
                    publicUser = {
                        id: row.id,
                        usernameKey: row.username_key,
                        displayUsername: row.display_username,
                        role: row.role,
                    };
                }
                return {
                    valid: Boolean(row && valid),
                    userId: row?.id ?? null,
                };
            });
            if (decision.status === 429) {
                const retryAfterSeconds = decision.retryAfterSeconds ?? 0;
                res.setHeader("Retry-After", String(retryAfterSeconds));
                res.status(429).json({
                    error: {
                        code: "LOGIN_COOLDOWN",
                        message: "Login temporarily restricted.",
                    },
                    retryAfterSeconds,
                });
                return;
            }
            if (decision.status !== 200 || !authenticatedUser) {
                sendJsonError(res, 401, "INVALID_CREDENTIALS", "Invalid credentials.");
                return;
            }
            if (!publicUser) {
                sendJsonError(res, 401, "INVALID_CREDENTIALS", "Invalid credentials.");
                return;
            }
            const loginUser: PublicUser = publicUser;
            // Regenerate the session to prevent session fixation.
            req.session.regenerate((error) => {
                if (error) {
                    next(error);
                    return;
                }
                req.session.userId = loginUser.id;
                // Set this once after regeneration. Ordinary requests never extend the deadline.
                req.session.expiresAt = Date.now() + SESSION_DURATION_MS;
                req.session.save((saveError) => {
                    if (saveError) {
                        next(saveError);
                        return;
                    }
                    res.status(200).json({
                        user: loginUser,
                        redirectTo: "/search",
                    });
                });
            });
        }
        catch (error) {
            next(error);
        }
    });
    router.post("/api/logout", requireSameOrigin, (req, res, next) => {
        req.session.destroy((error) => {
            if (error) {
                next(error);
                return;
            }
            res.clearCookie(SESSION_COOKIE_NAME, {
                httpOnly: true,
                sameSite: "lax",
                secure: false,
                path: "/",
            });
            res.status(204).end();
        });
    });
    router.get("/api/me", requireSession(deps.db), (req, res, next) => {
        try {
            const row = deps.db
                .prepare(`SELECT id, username_key, display_username, role
         FROM users
         WHERE id = ?`)
                .get(req.auth!.userId) as {
                id: number;
                username_key: string;
                display_username: string;
                role: "user" | "admin";
            } | undefined;
            if (!row) {
                res.status(401).json({
                    error: "AUTH_REQUIRED",
                    message: "Authentication is required.",
                });
                return;
            }
            res.status(200).json({
                user: {
                    id: row.id,
                    usernameKey: row.username_key,
                    displayUsername: row.display_username,
                    role: row.role,
                },
            });
        }
        catch (error) {
            next(error);
        }
    });
    return router;
}
