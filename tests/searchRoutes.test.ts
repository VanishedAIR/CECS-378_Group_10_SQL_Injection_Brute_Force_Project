import { afterEach, describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import type { Server } from "node:http";
import { createApp } from "../src/server/app.js";
import { createFakeClock } from "../src/server/clock.js";
import { loadConfig } from "../src/server/config.js";
import { applySchema } from "../src/server/db.js";
import { seedProducts } from "../src/server/seedProducts.js";
import { hashPassword } from "../src/server/passwords.js";

describe("Search HTTP routes", () => {
  const servers: Server[] = [];
  const databases: DatabaseSync[] = [];

  afterEach(async () => {
    for (const server of servers.splice(0)) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }

    for (const db of databases.splice(0)) {
      db.close();
    }
  });

  async function startApp(labMode: boolean) {
    const db = new DatabaseSync(":memory:");
    databases.push(db);
    applySchema(db);
    seedProducts(db);

    // Create a test account for authenticated search requests.
    db.prepare(`
      INSERT INTO users
      (id, username_key, display_username, password_hash, role)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      1,
      "alice",
      "Alice",
      hashPassword("correct-password"),
      "user"
    );

    const config = {
      ...loadConfig(),
      labMode,
      sessionSecret: "test-only-session-secret-at-least-32-characters-long",
    };

    const app = createApp({
      db,
      config,
      clock: createFakeClock(1000),
    });

    const server: Server = await new Promise((resolve) => {
      const listening = app.listen(0, "127.0.0.1", () => {
        resolve(listening);
      });
    });

    servers.push(server);

    const address = server.address();

    if (!address || typeof address === "string") {
      throw new Error("Could not start test server");
    }

    return `http://127.0.0.1:${address.port}`;
  }

  // Log in and return the session cookie for authenticated tests.
  async function login(baseUrl: string): Promise<string> {
    const response = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "Alice",
        password: "correct-password",
      }),
    });

    expect(response.status).toBe(200);

    const cookie = response.headers.get("set-cookie");
    expect(cookie).not.toBeNull();

    return cookie!.split(";")[0];
  }

  it("rejects unauthenticated protected searches", async () => {
    const baseUrl = await startApp(false);

    const response = await fetch(
      `${baseUrl}/api/search/protected?q=Mouse`
    );

    expect(response.status).toBe(401);

    const body = await response.json();
    expect(body).toEqual({
      error: {
        code: "AUTH_REQUIRED",
        message: "Authentication is required.",
      },
    });
  });

  it("rejects unauthenticated vulnerable searches", async () => {
    const baseUrl = await startApp(true);

    const response = await fetch(
      `${baseUrl}/api/search/vulnerable?q=Mouse`
    );

    expect(response.status).toBe(401);
  });

  it("does not expose SQL details in unauthorized responses", async () => {
    const baseUrl = await startApp(true);

    const response = await fetch(
      `${baseUrl}/api/search/vulnerable?q=${encodeURIComponent("' OR 1=1 --")}`
    );

    expect(response.status).toBe(401);

    const body = JSON.stringify(await response.json());

    expect(body).not.toContain("SELECT");
    expect(body).not.toContain("FROM products");
    expect(body).not.toContain("stack");
  });

  it("does not audit unauthenticated search requests", async () => {
    const baseUrl = await startApp(true);

    await fetch(`${baseUrl}/api/search/protected?q=Mouse`);

    const db = databases[0];

    const row = db.prepare(
      "SELECT COUNT(*) AS count FROM query_audit"
    ).get() as { count: number };

        expect(row.count).toBe(0);
  });

  it("allows authenticated protected searches", async () => {
    const baseUrl = await startApp(false);
    const cookie = await login(baseUrl);

    const response = await fetch(
      `${baseUrl}/api/search/protected?q=Mouse`,
      {
        headers: { Cookie: cookie },
      }
    );

    expect(response.status).toBe(200);

    const body = await response.json();

    expect(body.mode).toBe("protected");
    expect(body.resultCount).toBe(1);
    expect(body.rows[0].name).toBe("Mouse");
  });

  it("allows authenticated vulnerable searches in lab mode", async () => {
  const baseUrl = await startApp(true);
  const cookie = await login(baseUrl);

  const payload = "' OR 1=1 --";

  const response = await fetch(
    `${baseUrl}/api/search/vulnerable?q=${encodeURIComponent(payload)}`,
    {
      headers: { Cookie: cookie },
    }
  );

  expect(response.status).toBe(200);

  const body = await response.json();

  expect(body.mode).toBe("vulnerable");
  expect(body.resultCount).toBe(3);
  expect(body.rows.map((row: { name: string }) => row.name))
    .toEqual(["Mouse", "Keyboard", "Monitor"]);
  });

  it("blocks vulnerable searches when lab mode is disabled", async () => {
  const baseUrl = await startApp(false);
  const cookie = await login(baseUrl);

  const response = await fetch(
    `${baseUrl}/api/search/vulnerable?q=Mouse`,
    {
      headers: { Cookie: cookie },
    }
  );

  expect(response.status).toBe(404);

  const body = await response.json();

  expect(body.error.code).toBe("NOT_FOUND");

  // Blocked searches should not create audit records.
  const db = databases[0];

  const audit = db.prepare(
    "SELECT COUNT(*) AS count FROM query_audit"
  ).get() as { count: number };

  expect(audit.count).toBe(0);
  });

  it("rejects empty and oversized search inputs", async () => {
  const baseUrl = await startApp(true);
  const cookie = await login(baseUrl);

  const invalidInputs = ["", "a".repeat(101)];

  for (const input of invalidInputs) {
    const response = await fetch(
      `${baseUrl}/api/search/protected?q=${encodeURIComponent(input)}`,
      {
        headers: { Cookie: cookie },
      }
    );

    expect(response.status).toBe(400);

    const body = await response.json();
    expect(body.error.code).toBe("INVALID_REQUEST");
  }

  // Invalid requests should not be recorded as executed searches.
  const db = databases[0];

  const row = db.prepare(
    "SELECT COUNT(*) AS count FROM query_audit"
  ).get() as { count: number };

  expect(row.count).toBe(0);
  });

  it("returns a safe error when the database query fails", async () => {
  const baseUrl = await startApp(true);
  const cookie = await login(baseUrl);

  const db = databases[0];

  // Simulate a database failure after the user logs in.
  db.exec("DROP TABLE products");

  const response = await fetch(
    `${baseUrl}/api/search/protected?q=Mouse`,
    {
      headers: { Cookie: cookie },
    }
  );

  expect(response.status).toBe(500);

  const body = await response.json();

  expect(body.error.code).toBe("INTERNAL_ERROR");
  expect(body.error.message).toBe("Search failed.");

  // Internal database information should not reach the browser.
  const responseText = JSON.stringify(body);

  expect(responseText).not.toContain("SELECT");
  expect(responseText).not.toContain("products");
  expect(responseText).not.toContain("SQLITE_ERROR");

  // The failed query should still be recorded.
  const audit = db.prepare(`
    SELECT result_count, error_code
    FROM query_audit
  `).get() as {
    result_count: number | null;
    error_code: string | null;
  };

  expect(audit.result_count).toBeNull();
  expect(audit.error_code).toBe("SQL_EXECUTION_ERROR");
  });

  it("records the authenticated user and SQL injection alert", async () => {
  const baseUrl = await startApp(true);
  const cookie = await login(baseUrl);

  const payload = "' OR 1=1 --";

  const response = await fetch(
    `${baseUrl}/api/search/vulnerable?q=${encodeURIComponent(payload)}`,
    {
      headers: { Cookie: cookie },
    }
  );

  expect(response.status).toBe(200);

  const db = databases[0];

  // Check that the search was recorded under the logged-in user.
  const audit = db.prepare(`
    SELECT id, user_id, route_mode, result_count,
           query_template, lab_sql
    FROM query_audit
  `).get() as {
    id: number;
    user_id: number;
    route_mode: string;
    result_count: number;
    query_template: string;
    lab_sql: string;
  };

  expect(audit.user_id).toBe(1);
  expect(audit.route_mode).toBe("vulnerable");
  expect(audit.result_count).toBe(3);

  // The template should not contain the actual injection input.
  expect(audit.query_template).toContain("{q}");
  expect(audit.query_template).not.toContain(payload);
  expect(audit.lab_sql).toContain(payload);

  // The security alert must reference the same audit record.
  const alert = db.prepare(`
    SELECT event_type, query_audit_id
    FROM security_events
    WHERE event_type = 'SQLI_ATTEMPT'
  `).get() as {
    event_type: string;
    query_audit_id: number;
  };

  expect(alert.event_type).toBe("SQLI_ATTEMPT");
  expect(alert.query_audit_id).toBe(audit.id);
  });
});