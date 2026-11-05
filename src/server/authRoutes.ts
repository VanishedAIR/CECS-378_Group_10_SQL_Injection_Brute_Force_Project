
import express, { type Router } from "express";
import { requireSessionStore, type AppDependencies } from "./app.js";
import { requireSession, readSessionToken } from "./authMiddleware.js";
import { createLoginPolicy } from "./loginPolicy.js";
import { requireUsernameKey, validatePasswordLength } from "./normalize.js";
import { hashPassword, verifyPassword } from "./passwords.js";
import {
  createSessionStore,
  SESSION_COOKIE_NAME,
  SESSION_DURATION_MS,
  type AuthUser,
  type SessionStore,
} from "./sessions.js";
import { sendJsonError, sourceIpFromRequest } from "./http.js";


/**
 * Reject browser requests that originate from another website.
 * The application runs on a loopback host with trust proxy disabled.
 */
function requireSameOrigin(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  const origin = req.headers.origin;

  if (origin !== undefined) {
    const expectedOrigin = `${req.protocol}://${req.get("host")}`;

    if (origin !== expectedOrigin) {
      sendJsonError(
        res,
        403,
        "FORBIDDEN",
        "Cross-origin requests are not allowed."
      );
      return;
    }
  }


  // Browsers may identify a cross-site request even when Origin is absent.
  const fetchSite = req.get("sec-fetch-site");

  if (fetchSite === "cross-site" || fetchSite === "same-site") {
    sendJsonError(
      res,
      403,
      "FORBIDDEN",
      "Cross-origin requests are not allowed."
    );
    return;
  }

  next();
}

type UserRow = {
  id: number;
  username_key: string;
  password_hash: string;
  role: "user" | "admin";
};

/**
 * Create the dummy hash once, not once per failed login.
 * Unknown usernames still require an expensive scrypt verification.
 */
let dummyHash: string | null = null;

function getDummyHash(): string {
  if (dummyHash === null) {
    dummyHash = hashPassword("dummy-password-not-used-for-login");
  }
  return dummyHash;
}

function cookieOptions(req: express.Request) {
  return {
    httpOnly: true,
    sameSite: "strict" as const,
    secure: req.secure,
    path: "/",
    maxAge: SESSION_DURATION_MS,
  };
}

/**
 * Supply the same SessionStore to authentication and protected routers.
 * Tests may inject a fake-clock store.
 */


export function createAuthRouter(
  deps: AppDependencies,
  sessions: SessionStore = requireSessionStore(deps)
): Router {
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
      } catch {
        sendJsonError(res, 400, "INVALID_REQUEST", "Invalid login request.");
        return;
      }

      let authenticatedUser: AuthUser | null = null;

      const decision = await policy.evaluate(
        {
          requestId: req.requestId,
          username: usernameKey,
          sourceIp: sourceIpFromRequest(req),
        },
        async (normalizedUsername) => {
          const row = deps.db
            .prepare(
              `SELECT id, username_key, password_hash, role
               FROM users
               WHERE username_key = ?`
            )
            .get(normalizedUsername) as UserRow | undefined;

          const valid = verifyPassword(
            password,
            row?.password_hash ?? getDummyHash()
          );

          if (row && valid) {
            authenticatedUser = {
              userId: row.id,
              usernameKey: row.username_key,
              role: row.role,
            };
          }

          return {
            valid: Boolean(row && valid),
            userId: row?.id ?? null,
          };
        }
      );

      if (decision.status === 429) {
        if (decision.retryAfterSeconds !== null) {
          res.setHeader("Retry-After", String(decision.retryAfterSeconds));
        }
        sendJsonError(
          res,
          429,
          "LOGIN_COOLDOWN",
          "Login temporarily restricted."
        );
        return;
      }

      if (decision.status !== 200 || !authenticatedUser) {
        sendJsonError(
          res,
          401,
          "INVALID_CREDENTIALS",
          "Invalid credentials."
        );
        return;
      }

      // Replace an existing session when the user logs in again.
      const previousToken = readSessionToken(req);

      if (previousToken !== null) {
        sessions.destroy(previousToken);
      }

      const token = sessions.create(authenticatedUser);
      res.cookie(SESSION_COOKIE_NAME, token, cookieOptions(req));

      res.status(200).json({
        user: authenticatedUser,
      });
    } catch (error) {
      next(error);
    }
  });

  router.post("/api/logout", requireSameOrigin, (req, res) => {
    const token = readSessionToken(req);

    if (token !== null) {
      sessions.destroy(token);
    }

    res.clearCookie(SESSION_COOKIE_NAME, {
      httpOnly: true,
      sameSite: "strict",
      secure: req.secure,
      path: "/",
    });

    res.status(200).json({ ok: true });
  });

  router.get("/api/me", requireSession(sessions), (req, res) => {
    res.status(200).json({ user: req.auth });
  });

  return router;
}
