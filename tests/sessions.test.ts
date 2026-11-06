
import { describe, expect, it, vi } from "vitest";
import session from "express-session";
import { SESSION_DURATION_MS } from "../src/server/sessions.js";

describe("Express session expiration", () => {
  it("uses a 30-minute session duration", () => {
    expect(SESSION_DURATION_MS).toBe(30 * 60 * 1000);
  });

  it("keeps a session valid just before expiration and expires it exactly at the boundary", async () => {
    const startTime = new Date("2026-01-01T12:00:00.000Z");

    vi.useFakeTimers();
    vi.setSystemTime(startTime);

    const store = new session.MemoryStore();

    try {
      const sessionId = "test-session-id";

      const testSession = {
        cookie: Object.assign(new session.Cookie(), {
  originalMaxAge: SESSION_DURATION_MS,
  expires: new Date(startTime.getTime() + SESSION_DURATION_MS),
  httpOnly: true,
  sameSite: "lax" as const,
  secure: false,
}),
        userId: 1,
      } as session.SessionData;

      await new Promise<void>((resolve, reject) => {
        store.set(sessionId, testSession as session.Session & Partial<session.SessionData>, (error) => {
          if (error) reject(error);
          else resolve();
        });
      });

      vi.setSystemTime(
        new Date(startTime.getTime() + SESSION_DURATION_MS - 1)
      );

      const justBefore = await new Promise<session.SessionData | undefined>(
        (resolve, reject) => {
          store.get(sessionId, (error, value) => {
            if (error) reject(error);
            else resolve(value ?? undefined);
          });
        }
      );

      expect(justBefore?.userId).toBe(1);

      vi.setSystemTime(
        new Date(startTime.getTime() + SESSION_DURATION_MS)
      );

      const atExpiry = await new Promise<session.SessionData | undefined>(
        (resolve, reject) => {
          store.get(sessionId, (error, value) => {
            if (error) reject(error);
            else resolve(value ?? undefined);
          });
        }
      );

      expect(atExpiry).toBeUndefined();
    } finally {
      store.clear();
      vi.useRealTimers();
    }
  });
});
