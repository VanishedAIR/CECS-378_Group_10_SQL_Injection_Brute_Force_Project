
import { afterEach, describe, expect, it } from "vitest";
import express from "express";
import session from "express-session";
import { DatabaseSync } from "node:sqlite";
import type { Server } from "node:http";
import {
  requireAdmin,
  requireSession,
} from "../src/server/authMiddleware.js";
import { applySchema } from "../src/server/db.js";
import { hashPassword } from "../src/server/passwords.js";
import {
  SESSION_COOKIE_NAME,
  SESSION_DURATION_MS,
} from "../src/server/sessions.js";

const activeServers: Server[] = [];
const databases: DatabaseSync[] = [];

async function startTestServer() {
  const db = new DatabaseSync(":memory:");
  databases.push(db);
  applySchema(db);

  const insertUser = db.prepare(
    `INSERT INTO users
     (username_key, display_username, password_hash, role)
     VALUES (?, ?, ?, ?)`
  );

  const alice = insertUser.run(
    "alice",
    "Alice",
    hashPassword("test-password"),
    "user"
  );

  const admin = insertUser.run(
    "admin",
    "Admin",
    hashPassword("test-password"),
    "admin"
  );

  const aliceId = Number(alice.lastInsertRowid);
  const adminId = Number(admin.lastInsertRowid);

  const app = express();

  app.use(
    session({
      name: SESSION_COOKIE_NAME,
      secret: "test-only-session-secret-at-least-32-characters",
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: SESSION_DURATION_MS,
      },
    })
  );

  // Test-only endpoint for creating a session.
  // This route exists only in this isolated test server.
  app.post("/test-login/:userId", (req, res, next) => {
    const userId = Number(req.params.userId);

    req.session.regenerate((error) => {
      if (error) {
        next(error);
        return;
      }

      req.session.userId = userId;

      req.session.save((saveError) => {
        if (saveError) {
          next(saveError);
          return;
        }

        res.status(204).end();
      });
    });
  });

  app.get("/protected", requireSession(db), (req, res) => {
    res.json({ auth: req.auth });
  });

  app.get(
    "/admin",
    requireSession(db),
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
    db,
    aliceId,
    adminId,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

async function login(baseUrl: string, userId: number): Promise<string> {
  const response = await fetch(`${baseUrl}/test-login/${userId}`, {
    method: "POST",
  });

  expect(response.status).toBe(204);

  const cookie = response.headers.get("set-cookie");
  expect(cookie).not.toBeNull();

  return cookie!.split(";")[0];
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

  for (const db of databases.splice(0)) {
    db.close();
  }
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

  it("returns 401 for an invalid session cookie", async () => {
    const { baseUrl } = await startTestServer();

    const response = await fetch(`${baseUrl}/protected`, {
      headers: {
        Cookie: `${SESSION_COOKIE_NAME}=invalid-token`,
      },
    });

    expect(response.status).toBe(401);
  });

  it("allows a valid session and attaches req.auth", async () => {
    const { baseUrl, aliceId } = await startTestServer();
    const cookie = await login(baseUrl, aliceId);

    const response = await fetch(`${baseUrl}/protected`, {
      headers: { Cookie: cookie },
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      auth: {
        userId: aliceId,
        usernameKey: "alice",
        role: "user",
      },
    });
  });

  it("returns 403 when a user accesses an admin route", async () => {
    const { baseUrl, aliceId } = await startTestServer();
    const cookie = await login(baseUrl, aliceId);

    const response = await fetch(`${baseUrl}/admin`, {
      headers: { Cookie: cookie },
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
    const { baseUrl, adminId } = await startTestServer();
    const cookie = await login(baseUrl, adminId);

    const response = await fetch(`${baseUrl}/admin`, {
      headers: { Cookie: cookie },
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      auth: {
        userId: adminId,
        usernameKey: "admin",
        role: "admin",
      },
    });
  });

  it("rejects an administrator after demotion", async () => {
    const { baseUrl, db, adminId } = await startTestServer();
    const cookie = await login(baseUrl, adminId);

    const before = await fetch(`${baseUrl}/admin`, {
      headers: { Cookie: cookie },
    });
    expect(before.status).toBe(200);

    db.prepare("UPDATE users SET role = 'user' WHERE id = ?")
      .run(adminId);

    const after = await fetch(`${baseUrl}/admin`, {
      headers: { Cookie: cookie },
    });

    expect(after.status).toBe(403);
  });

  it("rejects a deleted user with an existing session", async () => {
    const { baseUrl, db, aliceId } = await startTestServer();
    const cookie = await login(baseUrl, aliceId);

    db.prepare("DELETE FROM users WHERE id = ?").run(aliceId);

    const response = await fetch(`${baseUrl}/protected`, {
      headers: { Cookie: cookie },
    });

    expect(response.status).toBe(401);
  });

  it("returns 401 for an admin route without authentication", async () => {
    const { baseUrl } = await startTestServer();

    const response = await fetch(`${baseUrl}/admin`);

    expect(response.status).toBe(401);
  });
});
