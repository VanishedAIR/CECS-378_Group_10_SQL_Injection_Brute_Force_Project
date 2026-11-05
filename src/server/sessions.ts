
import { createHash, randomBytes } from "node:crypto";
import type { Clock } from "./clock.js";
import { systemClock } from "./clock.js";

export type AuthUser = {
  userId: number;
  usernameKey: string;
  role: "user" | "admin";
};

type SessionRecord = {
  user: AuthUser;
  expiresAt: number;
};

export const SESSION_COOKIE_NAME = "lab_session";
export const SESSION_DURATION_MS = 60 * 60 * 1000;

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * Creates an in-memory session store.
 * Sessions are lost when the server restarts.
 */
export function createSessionStore(
  clock: Clock = systemClock(),
  durationMs = SESSION_DURATION_MS
) {
  if (!Number.isSafeInteger(durationMs) || durationMs <= 0) {
    throw new Error("Session duration must be a positive integer.");
  }

  const sessions = new Map<string, SessionRecord>();

  return {
    create(user: AuthUser): string {
      const token = randomBytes(32).toString("hex");

      sessions.set(hashToken(token), {
        user: { ...user },
        expiresAt: clock.now() + durationMs,
      });

      return token;
    },

    get(token: string): AuthUser | null {
      if (!/^[0-9a-f]{64}$/.test(token)) {
        return null;
      }

      const key = hashToken(token);
      const session = sessions.get(key);

      if (!session) {
        return null;
      }

      if (clock.now() >= session.expiresAt) {
        sessions.delete(key);
        return null;
      }

      return { ...session.user };
    },

    destroy(token: string): void {
      if (/^[0-9a-f]{64}$/.test(token)) {
        sessions.delete(hashToken(token));
      }
    },
  };
}

export type SessionStore = ReturnType<typeof createSessionStore>;
