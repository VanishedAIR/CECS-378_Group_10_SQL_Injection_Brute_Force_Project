
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { sendJsonError } from "./http.js";
import {
  SESSION_COOKIE_NAME,
  type AuthUser,
  type SessionStore,
} from "./sessions.js";

declare module "express-serve-static-core" {
  interface Request {
    auth?: AuthUser;
  }
}

/**
 * Read a session cookie without requiring an additional dependency.
 * Reject duplicate session cookies rather than choosing one arbitrarily.
 */
export function readSessionToken(req: Request): string | null {
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) {
    return null;
  }

  let token: string | null = null;

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");

    if (separator < 0) {
      continue;
    }

    const name = part.slice(0, separator).trim();

    if (name !== SESSION_COOKIE_NAME) {
      continue;
    }

    if (token !== null) {
      return null;
    }

    token = part.slice(separator + 1).trim();
  }

  return token;
}

/**
 * Require a valid session and attach the authenticated user to req.auth.
 */
export function requireSession(sessions: SessionStore): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const token = readSessionToken(req);
    const user = token === null ? null : sessions.get(token);

    if (!user) {
      sendJsonError(
        res,
        401,
        "AUTH_REQUIRED",
        "Authentication is required."
      );
      return;
    }

    req.auth = user;
    next();
  };
}

/**
 * Require an authenticated administrator.
 * Mount requireSession before this middleware.
 */
export const requireAdmin: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (!req.auth) {
    sendJsonError(
      res,
      401,
      "AUTH_REQUIRED",
      "Authentication is required."
    );
    return;
  }

  if (req.auth.role !== "admin") {
    sendJsonError(
      res,
      403,
      "FORBIDDEN",
      "Administrator access is required."
    );
    return;
  }

  next();
};
