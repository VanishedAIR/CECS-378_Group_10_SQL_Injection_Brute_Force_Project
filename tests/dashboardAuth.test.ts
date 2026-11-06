
import { afterEach, describe, expect, it } from "vitest";
import express from "express";
import session from "express-session";
import { DatabaseSync } from "node:sqlite";
import type { Server } from "node:http";

import { applySchema } from "../src/server/db.js";
import { requireSession, requireAdmin } from "../src/server/authMiddleware.js";
import { createDashboardRouter } from "../src/server/dashboard.js";
import type { AppDependencies } from "../src/server/app.js";

const servers: Server[] = [];
const databases: DatabaseSync[] = [];

// Create a temporary server for testing the dashboard
async function startTestServer() {
  const db = new DatabaseSync(":memory:");
  databases.push(db);
  applySchema(db);

  // Add a regular user and an administrator
  const insertUser = db.prepare(
    `INSERT INTO users
     (username_key, display_username, password_hash, role)
     VALUES (?, ?, ?, ?)`
  );

  const user = insertUser.run(
    "student", "Student", "test-hash", "user"
  );

  const admin = insertUser.run(
    "admin", "Admin", "test-hash", "admin"
  );

  const deps = {
    db,
    clock: { now: () => 100000 },
    config: { loginMode: "observe" },
  } as AppDependencies;

  const app = express();

  app.use(
    session({
      secret: "test-only-session-secret-at-least-32-characters",
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: true },
    })
  );

  // This login route is only for the tests
  app.post("/test-login/:id", (req, res, next) => {
    req.session.regenerate((error) => {
      if (error) {
        next(error);
        return;
      }

      req.session.userId = Number(req.params.id);

      req.session.save((saveError) => {
        if (saveError) {
          next(saveError);
          return;
        }

        res.status(204).end();
      });
    });
  });

  // Protect only the dashboard API routes
  app.use(
    ["/api/dashboard", "/api/cooldowns", "/api/alerts"],
    requireSession(db),
    requireAdmin
  );

  app.use(createDashboardRouter(deps, requireAdmin));

  const server = await new Promise<Server>((resolve) => {
    const running = app.listen(0, "127.0.0.1", () => {
      resolve(running);
    });
  });

  servers.push(server);

  const address = server.address();

  if (!address || typeof address === "string") {
    throw new Error("Could not start test server");
  }

  return {
    db,
    userId: Number(user.lastInsertRowid),
    adminId: Number(admin.lastInsertRowid),
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

// Create a login cookie for one test user
async function login(baseUrl: string, userId: number) {
  const response = await fetch(
    `${baseUrl}/test-login/${userId}`,
    { method: "POST" }
  );

  expect(response.status).toBe(204);

  const cookie = response.headers.get("set-cookie");
  expect(cookie).not.toBeNull();

  return cookie!.split(";")[0];
}

// Close everything after each test
afterEach(async () => {
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  for (const db of databases.splice(0)) {
    db.close();
  }
});

describe("Dashboard Security Tests", () => {

  it("returns 401 when not logged in", async () => {
    const { baseUrl } = await startTestServer();

    const response = await fetch(`${baseUrl}/api/dashboard`);

    expect(response.status).toBe(401);
  });

  it("returns 403 for a regular user", async () => {
    const { baseUrl, userId } = await startTestServer();
    const cookie = await login(baseUrl, userId);

    const response = await fetch(`${baseUrl}/api/dashboard`, {
      headers: { Cookie: cookie },
    });

    expect(response.status).toBe(403);
  });

  it("allows an administrator to view the dashboard", async () => {
    const { baseUrl, adminId } = await startTestServer();
    const cookie = await login(baseUrl, adminId);

    const response = await fetch(`${baseUrl}/api/dashboard`, {
      headers: { Cookie: cookie },
    });

    expect(response.status).toBe(200);

    const data = await response.json();
    expect(data.totals.failedLogins).toBe(0);
    expect(data.recentAlerts).toEqual([]);
  });

  it("protects the cooldown information", async () => {
    const { baseUrl, userId, adminId } = await startTestServer();

    const userCookie = await login(baseUrl, userId);
    const denied = await fetch(`${baseUrl}/api/cooldowns`, {
      headers: { Cookie: userCookie },
    });

    expect(denied.status).toBe(403);

    const adminCookie = await login(baseUrl, adminId);
    const allowed = await fetch(`${baseUrl}/api/cooldowns`, {
      headers: { Cookie: adminCookie },
    });

    expect(allowed.status).toBe(200);
  });

  it("protects alert evidence", async () => {
    // Use the SAME database as the server
    const { baseUrl, userId, adminId, db } = await startTestServer();

    // Create a failed login for the security alert
    const loginResult = db.prepare(
      `INSERT INTO login_attempts
       (request_id, timestamp_utc, username_key, source_ip, outcome)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      "test-alert",
      100000,
      "student",
      "127.0.0.1",
      "failure"
    );

    // Create a security alert linked to the failed login
    const event = db.prepare(
      `INSERT INTO security_events
       (timestamp_utc, event_type, rule_id, severity,
        scope_type, scope_key, trigger_login_attempt_id, details_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      100000,
      "BRUTE_FORCE_DETECTED",
      "LOGIN_ACCOUNT_FAILURE_LIMIT_V1",
      "medium",
      "account",
      "student",
      Number(loginResult.lastInsertRowid),
      "{}"
    );

    const alertId = Number(event.lastInsertRowid);

    // A regular user should not see alert evidence
    const userCookie = await login(baseUrl, userId);

    const denied = await fetch(
      `${baseUrl}/api/alerts/${alertId}`,
      { headers: { Cookie: userCookie } }
    );

    expect(denied.status).toBe(403);

    // An administrator should be able to see alert evidence
    const adminCookie = await login(baseUrl, adminId);

    const allowed = await fetch(
      `${baseUrl}/api/alerts/${alertId}`,
      { headers: { Cookie: adminCookie } }
    );

    expect(allowed.status).toBe(200);

    const evidence = await allowed.json();
    expect(evidence).toBeDefined();
  });

});
