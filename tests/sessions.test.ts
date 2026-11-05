
import { describe, expect, it } from "vitest";
import { createFakeClock } from "../src/server/clock.js";
import {
  createSessionStore,
  SESSION_DURATION_MS,
  type AuthUser,
} from "../src/server/sessions.js";

const regularUser: AuthUser = {
  userId: 1,
  usernameKey: "alice",
  role: "user",
};

const adminUser: AuthUser = {
  userId: 2,
  usernameKey: "admin",
  role: "admin",
};

describe("In-memory session store", () => {
  it("creates a session and retrieves the authenticated user", () => {
    const clock = createFakeClock(1_000_000);
    const sessions = createSessionStore(clock);

    const token = sessions.create(regularUser);

    expect(token).toMatch(/^[0-9a-f]{64}$/);
    expect(sessions.get(token)).toEqual(regularUser);
  });

  it("generates unique tokens for separate sessions", () => {
    const sessions = createSessionStore(createFakeClock(1_000_000));

    const first = sessions.create(regularUser);
    const second = sessions.create(regularUser);

    expect(first).not.toBe(second);
    expect(sessions.get(first)).toEqual(regularUser);
    expect(sessions.get(second)).toEqual(regularUser);
  });

  it("rejects missing, invalid, and unknown tokens", () => {
    const sessions = createSessionStore(createFakeClock(1_000_000));

    expect(sessions.get("")).toBeNull();
    expect(sessions.get("invalid-token")).toBeNull();
    expect(sessions.get("a".repeat(64))).toBeNull();
  });

  it("expires sessions after the configured duration", () => {
    const clock = createFakeClock(1_000_000);
    const sessions = createSessionStore(clock);

    const token = sessions.create(regularUser);

    clock.advance(SESSION_DURATION_MS - 1);
    expect(sessions.get(token)).toEqual(regularUser);

    clock.advance(1);
    expect(sessions.get(token)).toBeNull();
  });

  it("invalidates a session after logout", () => {
    const sessions = createSessionStore(createFakeClock(1_000_000));

    const token = sessions.create(regularUser);

    sessions.destroy(token);

    expect(sessions.get(token)).toBeNull();
  });

  it("keeps ordinary-user and admin roles separate", () => {
    const sessions = createSessionStore(createFakeClock(1_000_000));

    const userToken = sessions.create(regularUser);
    const adminToken = sessions.create(adminUser);

    expect(sessions.get(userToken)?.role).toBe("user");
    expect(sessions.get(adminToken)?.role).toBe("admin");
  });

  it("rejects invalid session durations", () => {
    const clock = createFakeClock(1_000_000);

    expect(() => createSessionStore(clock, 0)).toThrow();
    expect(() => createSessionStore(clock, -1000)).toThrow();
  });
});
