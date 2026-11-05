
import { afterEach, describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import type { Server } from "node:http";
import { createApp } from "../src/server/app.js";
import { createFakeClock } from "../src/server/clock.js";
import type { ServerConfig } from "../src/server/config.js";
import { applySchema } from "../src/server/db.js";
import { hashPassword } from "../src/server/passwords.js";
import { createSessionStore } from "../src/server/sessions.js";

const servers: Server[] = [];
const databases: DatabaseSync[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => {
            if (error) reject(error);
            else resolve();
          });
        })
    )
  );

  for (const db of databases.splice(0)) {
    db.close();
  }
});

async function startTestApp() {
  const db = new DatabaseSync(":memory:");
  databases.push(db);
  applySchema(db);

  db.prepare(
    `INSERT INTO users
     (username_key, display_username, password_hash, role)
     VALUES (?, ?, ?, ?)`
  ).run("alice", "Alice", hashPassword("correct-password"), "user");

  const clock = createFakeClock(1_000_000);
  const config: ServerConfig = {
    host: "127.0.0.1",
    port: 3000,
    databasePath: ":memory:",
    loginMode: "protect",
    labMode: true,
    accountFailureLimit: 5,
    ipFailureLimit: 15,
    windowSeconds: 60,
    accountCooldownSeconds: 60,
    ipCooldownSeconds: 60,
  };

  const sessions = createSessionStore(clock);

  const app = createApp({
    db,
    config,
    clock,
    sessions,
});


  const server = app.listen(0, "127.0.0.1");
  servers.push(server);

  await new Promise<void>((resolve) => {
    server.once("listening", resolve);
  });

  const address = server.address();

  if (!address || typeof address === "string") {
    throw new Error("Missing test server address.");
  }

  return {
    db,
    clock,
    sessions,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

describe("Authentication API", () => {
  it("logs in successfully and allows /api/me with the session cookie", async () => {
    const { baseUrl } = await startTestApp();

    const loginResponse = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "Alice",
        password: "correct-password",
      }),
    });

    expect(loginResponse.status).toBe(200);

    const loginBody = await loginResponse.json();

    expect(loginBody.user).toEqual({
      userId: 1,
      usernameKey: "alice",
      role: "user",
    });

    const setCookie = loginResponse.headers.get("set-cookie");

    expect(setCookie).toBeTruthy();
    expect(setCookie).toContain("lab_session=");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Strict");

    const sessionCookie = setCookie!.split(";")[0];

    const meResponse = await fetch(`${baseUrl}/api/me`, {
      headers: {
        Cookie: sessionCookie,
      },
    });

    expect(meResponse.status).toBe(200);

    expect(await meResponse.json()).toEqual({
      user: {
        userId: 1,
        usernameKey: "alice",
        role: "user",
      },
    });
  });

  it("rejects an incorrect password without creating a session", async () => {
    const { baseUrl, db } = await startTestApp();

    const response = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "alice",
        password: "wrong-password",
      }),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      error: {
        code: "INVALID_CREDENTIALS",
        message: "Invalid credentials.",
      },
    });

    expect(response.headers.get("set-cookie")).toBeNull();

    const attempt = db.prepare(
      "SELECT outcome FROM login_attempts ORDER BY id DESC LIMIT 1"
    ).get() as { outcome: string };

    expect(attempt.outcome).toBe("failure");
  });

  it("rejects an unknown username with the same generic error", async () => {
    const { baseUrl, db } = await startTestApp();

    const response = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "unknown_user",
        password: "wrong-password",
      }),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      error: {
        code: "INVALID_CREDENTIALS",
        message: "Invalid credentials.",
      },
    });

    expect(response.headers.get("set-cookie")).toBeNull();

    const attempt = db.prepare(
      "SELECT outcome, user_id FROM login_attempts ORDER BY id DESC LIMIT 1"
    ).get() as { outcome: string; user_id: number | null };

    expect(attempt.outcome).toBe("failure");
    expect(attempt.user_id).toBeNull();
  });


  it("logs out and invalidates the existing session", async () => {
    const { baseUrl } = await startTestApp();

    // Log in with valid credentials.
    const loginResponse = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "alice",
        password: "correct-password",
      }),
    });

    expect(loginResponse.status).toBe(200);

    const setCookie = loginResponse.headers.get("set-cookie");
    expect(setCookie).toBeTruthy();

    const sessionCookie = setCookie!.split(";")[0];

    // Confirm the session works before logout.
    const beforeLogout = await fetch(`${baseUrl}/api/me`, {
      headers: {
        Cookie: sessionCookie,
      },
    });

    expect(beforeLogout.status).toBe(200);

    // Log out using the session cookie.
    const logoutResponse = await fetch(`${baseUrl}/api/logout`, {
      method: "POST",
      headers: {
        Cookie: sessionCookie,
      },
    });

    expect(logoutResponse.status).toBe(200);
    expect(await logoutResponse.json()).toEqual({ ok: true });

    const clearedCookie = logoutResponse.headers.get("set-cookie");
    expect(clearedCookie).toContain("lab_session=");
    expect(clearedCookie).toContain("Expires=");

    // Even the old cookie must no longer work.
    const afterLogout = await fetch(`${baseUrl}/api/me`, {
      headers: {
        Cookie: sessionCookie,
      },
    });

    expect(afterLogout.status).toBe(401);
    expect(await afterLogout.json()).toEqual({
      error: {
        code: "AUTH_REQUIRED",
        message: "Authentication is required.",
      },
    });
  });

  it("rejects an expired session through /api/me", async () => {
    const { baseUrl, clock } = await startTestApp();

    // Log in successfully.
    const loginResponse = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "alice",
        password: "correct-password",
      }),
    });

    expect(loginResponse.status).toBe(200);

    const setCookie = loginResponse.headers.get("set-cookie");
    expect(setCookie).toBeTruthy();

    const sessionCookie = setCookie!.split(";")[0];

    // Verify the session works before expiration.
    const beforeExpiry = await fetch(`${baseUrl}/api/me`, {
      headers: {
        Cookie: sessionCookie,
      },
    });

    expect(beforeExpiry.status).toBe(200);

    // Advance the fake clock by one hour.
    clock.advance(60 * 60 * 1000);

    // The same session cookie must now be rejected.
    const afterExpiry = await fetch(`${baseUrl}/api/me`, {
      headers: {
        Cookie: sessionCookie,
      },
    });

    expect(afterExpiry.status).toBe(401);
    expect(await afterExpiry.json()).toEqual({
      error: {
        code: "AUTH_REQUIRED",
        message: "Authentication is required.",
      },
    });
  });

  it("blocks login after repeated failures and allows recovery after cooldown", async () => {
    const { baseUrl, clock, db } = await startTestApp();

    const login = async (password: string) => {
      return fetch(`${baseUrl}/api/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: "alice",
          password,
        }),
      });
    };

    // Five failed attempts reach the configured account threshold.
    for (let i = 0; i < 5; i++) {
      const response = await login("wrong-password");
      expect(response.status).toBe(401);
    }

    // Even the correct password is blocked during the cooldown.
    const blocked = await login("correct-password");

    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("Retry-After")).toBe("60");
    expect(await blocked.json()).toEqual({
      error: {
        code: "LOGIN_COOLDOWN",
        message: "Login temporarily restricted.",
      },
    });

    // Move past the cooldown without waiting in real time.
    clock.advance(60_000);

    const recovered = await login("correct-password");

    expect(recovered.status).toBe(200);
    expect(recovered.headers.get("set-cookie")).toContain("lab_session=");

    // Confirm all seven attempts were recorded.
    const attempts = db.prepare(
      "SELECT COUNT(*) AS count FROM login_attempts"
    ).get() as { count: number };

    expect(attempts.count).toBe(7);

    // Confirm the threshold generated a brute-force security event.
    const events = db.prepare(
      `SELECT COUNT(*) AS count
       FROM security_events
       WHERE event_type = 'BRUTE_FORCE_DETECTED'`
    ).get() as { count: number };

    expect(events.count).toBeGreaterThanOrEqual(1);
  });

  it("replaces the previous session when logging in again", async () => {
    const { baseUrl } = await startTestApp();

    const login = async (cookie?: string) => {
      return fetch(`${baseUrl}/api/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(cookie ? { Cookie: cookie } : {}),
        },
        body: JSON.stringify({
          username: "alice",
          password: "correct-password",
        }),
      });
    };

    // First login creates the original session.
    const firstLogin = await login();
    expect(firstLogin.status).toBe(200);

    const firstCookie = firstLogin.headers.get("set-cookie")!.split(";")[0];

    // Second login presents the original session cookie.
    const secondLogin = await login(firstCookie);
    expect(secondLogin.status).toBe(200);

    const secondCookie = secondLogin.headers.get("set-cookie")!.split(";")[0];

    // A new token must be issued.
    expect(secondCookie).not.toBe(firstCookie);

    // The previous session must no longer work.
    const oldSession = await fetch(`${baseUrl}/api/me`, {
      headers: {
        Cookie: firstCookie,
      },
    });

    expect(oldSession.status).toBe(401);

    // The replacement session must work.
    const newSession = await fetch(`${baseUrl}/api/me`, {
      headers: {
        Cookie: secondCookie,
      },
    });

    expect(newSession.status).toBe(200);
    expect(await newSession.json()).toEqual({
      user: {
        userId: 1,
        usernameKey: "alice",
        role: "user",
      },
    });
  });

  it("rejects cross-origin login and logout requests", async () => {
    const { baseUrl } = await startTestApp();

    // A request from a different website must not log in.
    const crossOriginLogin = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://attacker.example",
      },
      body: JSON.stringify({
        username: "alice",
        password: "correct-password",
      }),
    });

    expect(crossOriginLogin.status).toBe(403);
    expect(crossOriginLogin.headers.get("set-cookie")).toBeNull();

    expect(await crossOriginLogin.json()).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Cross-origin requests are not allowed.",
      },
    });

    // First create a legitimate session.
    const loginResponse = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "alice",
        password: "correct-password",
      }),
    });

    expect(loginResponse.status).toBe(200);

    const sessionCookie =
      loginResponse.headers.get("set-cookie")!.split(";")[0];

    // A different website must not be able to log out this session.
    const crossOriginLogout = await fetch(`${baseUrl}/api/logout`, {
      method: "POST",
      headers: {
        Origin: "https://attacker.example",
        Cookie: sessionCookie,
      },
    });

    expect(crossOriginLogout.status).toBe(403);

    // The blocked logout must not destroy the legitimate session.
    const meResponse = await fetch(`${baseUrl}/api/me`, {
      headers: {
        Cookie: sessionCookie,
      },
    });

    expect(meResponse.status).toBe(200);
  });

  it("rejects cross-site browser requests without an Origin header", async () => {
    const { baseUrl } = await startTestApp();

    // A cross-site browser request must be blocked even without Origin.
    const crossSiteLogin = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "cross-site",
      },
      body: JSON.stringify({
        username: "alice",
        password: "correct-password",
      }),
    });

    expect(crossSiteLogin.status).toBe(403);
    expect(crossSiteLogin.headers.get("set-cookie")).toBeNull();

    expect(await crossSiteLogin.json()).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Cross-origin requests are not allowed.",
      },
    });

    // A same-site request from a different origin is also rejected.
    const sameSiteLogin = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "same-site",
      },
      body: JSON.stringify({
        username: "alice",
        password: "correct-password",
      }),
    });

    expect(sameSiteLogin.status).toBe(403);

    // A same-origin browser request should still work.
    const sameOriginLogin = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "same-origin",
        Origin: baseUrl,
      },
      body: JSON.stringify({
        username: "alice",
        password: "correct-password",
      }),
    });

    expect(sameOriginLogin.status).toBe(200);
    expect(sameOriginLogin.headers.get("set-cookie")).toContain(
      "lab_session="
    );
  });
});
