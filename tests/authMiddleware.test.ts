
import { afterEach, describe, expect, it } from "vitest";
import express from "express";
import type { Server } from "node:http";
import { createFakeClock } from "../src/server/clock.js";
import {
  requireAdmin,
  requireSession,
} from "../src/server/authMiddleware.js";
import {
  createSessionStore,
  SESSION_COOKIE_NAME,
} from "../src/server/sessions.js";

const activeServers: Server[] = [];

async function startTestServer() {
  const clock = createFakeClock(1_000_000);
  const sessions = createSessionStore(clock);
  const app = express();

  app.get("/protected", requireSession(sessions), (req, res) => {
    res.json({ auth: req.auth });
  });

  app.get(
    "/admin",
    requireSession(sessions),
    requireAdmin,
    (req, res) => {
      res.json({ auth: req.auth });
    }
  );

  const server = await new Promise<Server>((resolve) => {
    const listeningServer = app.listen(0, "127.0.0.1", () => {
      resolve(listeningServer);
    });
  });

  activeServers.push(server);

  const address = server.address();

  if (!address || typeof address === "string") {
    throw new Error("Test server did not provide a port.");
  }

  return {
    clock,
    sessions,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

afterEach(async () => {
  await Promise.all(
    activeServers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => {
            if (error) reject(error);
            else resolve();
          });
        })
    )
  );
});

describe("Authentication middleware", () => {
  it("returns 401 when a session cookie is missing", async () => {
    const { baseUrl } = await startTestServer();

    const response = await fetch(`${baseUrl}/protected`);

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      error: {
        code: "AUTH_REQUIRED",
        message: "Authentication is required.",
      },
    });
  });

  it("returns 401 for an invalid session token", async () => {
    const { baseUrl } = await startTestServer();

    const response = await fetch(`${baseUrl}/protected`, {
      headers: {
        Cookie: `${SESSION_COOKIE_NAME}=invalid-token`,
      },
    });

    expect(response.status).toBe(401);
  });

  it("allows a valid session and attaches req.auth", async () => {
    const { baseUrl, sessions } = await startTestServer();

    const token = sessions.create({
      userId: 10,
      usernameKey: "alice",
      role: "user",
    });

    const response = await fetch(`${baseUrl}/protected`, {
      headers: {
        Cookie: `${SESSION_COOKIE_NAME}=${token}`,
      },
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      auth: {
        userId: 10,
        usernameKey: "alice",
        role: "user",
      },
    });
  });

  it("returns 403 when an ordinary user accesses an admin route", async () => {
    const { baseUrl, sessions } = await startTestServer();

    const token = sessions.create({
      userId: 10,
      usernameKey: "alice",
      role: "user",
    });

    const response = await fetch(`${baseUrl}/admin`, {
      headers: {
        Cookie: `${SESSION_COOKIE_NAME}=${token}`,
      },
    });

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Administrator access is required.",
      },
    });
  });

  it("allows administrators to access admin routes", async () => {
    const { baseUrl, sessions } = await startTestServer();

    const token = sessions.create({
      userId: 20,
      usernameKey: "admin",
      role: "admin",
    });

    const response = await fetch(`${baseUrl}/admin`, {
      headers: {
        Cookie: `${SESSION_COOKIE_NAME}=${token}`,
      },
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      auth: {
        userId: 20,
        usernameKey: "admin",
        role: "admin",
      },
    });
  });

  it("returns 401 when a session has expired", async () => {
    const { baseUrl, sessions, clock } = await startTestServer();

    const token = sessions.create({
      userId: 10,
      usernameKey: "alice",
      role: "user",
    });

    clock.advance(60 * 60 * 1000);

    const response = await fetch(`${baseUrl}/protected`, {
      headers: {
        Cookie: `${SESSION_COOKIE_NAME}=${token}`,
      },
    });

    expect(response.status).toBe(401);
  });

  it("rejects duplicate session cookies", async () => {
    const { baseUrl, sessions } = await startTestServer();

    const token = sessions.create({
      userId: 10,
      usernameKey: "alice",
      role: "user",
    });

    const response = await fetch(`${baseUrl}/protected`, {
      headers: {
        Cookie: `${SESSION_COOKIE_NAME}=${token}; ${SESSION_COOKIE_NAME}=${token}`,
      },
    });

    expect(response.status).toBe(401);
  });

  it("returns 401 for an admin route without authentication", async () => {
    const { baseUrl } = await startTestServer();

    const response = await fetch(`${baseUrl}/admin`);

    expect(response.status).toBe(401);
  });
});
