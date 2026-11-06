
import type {
  NextFunction,
  Request,
  RequestHandler,
  Response,
} from "express";
import type { DatabaseSync } from "node:sqlite";
import { sendJsonError } from "./http.js";
import type { AuthUser } from "./sessions.js";

declare module "express-serve-static-core" {
  interface Request {
    auth?: AuthUser;
  }
}

type CurrentUserRow = {
  id: number;
  username_key: string;
  role: "user" | "admin";
};

/**
 * Require a valid session and load the user's CURRENT
 * identity and role from the shared database.
 *
 * This ensures deleted users lose access and demoted
 * administrators immediately lose admin privileges.
 */
export function requireSession(db: DatabaseSync): RequestHandler {
  const findUser = db.prepare(
    `SELECT id, username_key, role
     FROM users
     WHERE id = ?`
  );

  return (req: Request, res: Response, next: NextFunction): void => {
    const userId = req.session?.userId;

    if (typeof userId !== "number" || !Number.isSafeInteger(userId)) {
      sendJsonError(
        res,
        401,
        "AUTH_REQUIRED",
        "Authentication is required."
      );
      return;
    }

    try {
      const row = findUser.get(userId) as CurrentUserRow | undefined;

      if (!row) {
        sendJsonError(
          res,
          401,
          "AUTH_REQUIRED",
          "Authentication is required."
        );
        return;
      }

      req.auth = {
        userId: row.id,
        usernameKey: row.username_key,
        role: row.role,
      };

      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Require an authenticated administrator.
 * Mount requireSession(db) before this middleware.
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
