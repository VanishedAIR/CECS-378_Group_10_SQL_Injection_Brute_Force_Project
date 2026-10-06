import express from "express";
import fs from "node:fs";
import type { Server } from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  insertLoginAttempt,
  insertQueryAudit,
  insertSecurityEvent,
  readAlertEvidence,
} from "../src/server/audit.js";
import {
  createApp,
  openLabDatabase,
  shutdownServer,
  type AppDependencies,
} from "../src/server/app.js";
import { createFakeClock } from "../src/server/clock.js";
import { loadConfig, type ServerConfig } from "../src/server/config.js";
import { applySchema, openDatabase, withTransaction } from "../src/server/db.js";
import {
  attachRequestContext,
  errorEnvelope,
  sourceIpFromRequest,
} from "../src/server/http.js";
import {
  normalizeSourceIp,
  requireUsernameKey,
  validatePasswordLength,
} from "../src/server/normalize.js";
import { resetLabEvidence } from "../src/server/resetLab.js";
import { seedProducts } from "../src/server/seedProducts.js";

function tempDb(): string {
  return path.join(os.tmpdir(), `lab-foundation-${Date.now()}-${Math.random()}.db`);
}

function testConfig(databasePath: string): ServerConfig {
  return {
    ...loadConfig(),
    databasePath,
    host: "127.0.0.1",
    port: 0,
  };
}

describe("withTransaction", () => {
  const paths: string[] = [];

  afterEach(() => {
    for (const file of paths.splice(0)) {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    }
  });

  it("commits successful work and rolls back failed work", () => {
    const file = tempDb();
    paths.push(file);
    const db = openDatabase(file);
    applySchema(db);

    withTransaction(db, (tx) => {
      seedProducts(tx);
    });
    const committed = db.prepare("SELECT COUNT(*) AS n FROM products").get() as {
      n: number;
    };
    expect(committed.n).toBe(3);

    expect(() =>
      withTransaction(db, (tx) => {
        tx.prepare("DELETE FROM products").run();
        throw new Error("stop");
      })
    ).toThrow("stop");

    const kept = db.prepare("SELECT COUNT(*) AS n FROM products").get() as {
      n: number;
    };
    expect(kept.n).toBe(3);
    db.close();
  });

  it("rejects a nested transaction and a Promise callback", () => {
    const file = tempDb();
    paths.push(file);
    const db = openDatabase(file);
    applySchema(db);

    expect(() =>
      withTransaction(db, (tx) => {
        withTransaction(tx, () => undefined);
      })
    ).toThrow(/Nested withTransaction/);

    expect(() =>
      withTransaction(db, () => Promise.resolve(1) as unknown as undefined)
    ).toThrow(/synchronous/);
    db.close();
  });

  it("recovers when BEGIN fails and leaves an existing caller transaction intact", () => {
    const file = tempDb();
    paths.push(file);
    const db = openDatabase(file);
    applySchema(db);
    db.exec("BEGIN");
    seedProducts(db);

    expect(() => withTransaction(db, () => undefined)).toThrow();

    const during = db.prepare("SELECT COUNT(*) AS n FROM products").get() as {
      n: number;
    };
    expect(during.n).toBe(3);
    db.exec("COMMIT");

    withTransaction(db, (tx) => {
      tx.prepare("DELETE FROM products WHERE id = 3").run();
    });
    const after = db.prepare("SELECT COUNT(*) AS n FROM products").get() as {
      n: number;
    };
    expect(after.n).toBe(2);
    db.close();
  });
});

describe("audit writes", () => {
  const paths: string[] = [];

  afterEach(() => {
    for (const file of paths.splice(0)) {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    }
  });

  function readyDb(): ReturnType<typeof openDatabase> {
    const file = tempDb();
    paths.push(file);
    const db = openDatabase(file);
    applySchema(db);
    db.prepare(
      `INSERT INTO users (username_key, display_username, password_hash, role)
       VALUES ('demo_user', 'demo_user', 'fixture-not-a-hash', 'user')`
    ).run();
    return db;
  }

  it("links a failed login to a brute-force alert", () => {
    const db = readyDb();
    const attemptId = insertLoginAttempt(db, {
      requestId: "req-login-1",
      timestampUtc: 1_000,
      usernameKey: "demo_user",
      sourceIp: "127.0.0.1",
      userId: 1,
      outcome: "failure",
      blockedScopes: [],
    });

    const eventId = insertSecurityEvent(db, {
      timestampUtc: 1_000,
      eventType: "BRUTE_FORCE_DETECTED",
      ruleId: "LOGIN_ACCOUNT_FAILURE_LIMIT_V1",
      severity: "medium",
      scopeType: "account",
      scopeKey: "demo_user",
      triggerLoginAttemptId: attemptId,
      queryAuditId: null,
      details: {
        count: 1,
        limit: 5,
        windowStart: 0,
        windowEnd: 1_000,
        loginMode: "observe",
        attemptIds: [attemptId],
        cooldownStart: null,
        cooldownUntil: null,
      },
    });

    const evidence = readAlertEvidence(db, eventId);
    expect(evidence?.evidence.loginAttempts[0]?.id).toBe(attemptId);
    expect(evidence?.evidence.query).toBeNull();
    expect(evidence?.alert.summary).toBe("Account failure threshold reached.");
    db.close();
  });

  it("links a query row to an SQL alert and rejects a missing parent id", () => {
    const db = readyDb();
    const queryId = insertQueryAudit(db, {
      requestId: "req-search-1",
      timestampUtc: 2_000,
      userId: 1,
      sourceIp: "127.0.0.1",
      routeMode: "protected",
      inputExcerpt: "' OR 1=1 --",
      queryTemplate:
        "SELECT id, name, description FROM products WHERE name LIKE ?",
      parameters: ["%' OR 1=1 --%"],
      labSql: null,
      resultCount: 0,
      durationMs: 3,
      errorCode: null,
    });

    const eventId = insertSecurityEvent(db, {
      timestampUtc: 2_000,
      eventType: "SQLI_ATTEMPT",
      ruleId: "SQLI_SIGNATURE_V1",
      severity: "medium",
      scopeType: "request",
      scopeKey: "req-search-1",
      triggerLoginAttemptId: null,
      queryAuditId: queryId,
      details: {
        matchedIndicators: ["boolean_tautology"],
        routeMode: "protected",
      },
    });

    const evidence = readAlertEvidence(db, eventId);
    expect(evidence?.evidence.query?.id).toBe(queryId);
    expect(evidence?.evidence.loginAttempts).toEqual([]);

    const realAttempt = insertLoginAttempt(db, {
      requestId: "req-login-2",
      timestampUtc: 3_000,
      usernameKey: "demo_user",
      sourceIp: "127.0.0.1",
      userId: 1,
      outcome: "blocked",
      blockedScopes: ["ip", "account"],
    });

    expect(() =>
      insertSecurityEvent(db, {
        timestampUtc: 3_000,
        eventType: "BRUTE_FORCE_DETECTED",
        ruleId: "LOGIN_ACCOUNT_FAILURE_LIMIT_V1",
        severity: "medium",
        scopeType: "account",
        scopeKey: "demo_user",
        triggerLoginAttemptId: realAttempt,
        queryAuditId: null,
        details: {
          count: 2,
          limit: 5,
          windowStart: 0,
          windowEnd: 3_000,
          loginMode: "protect",
          attemptIds: [realAttempt, 999],
          cooldownStart: 3_000,
          cooldownUntil: 63_000,
        },
      })
    ).toThrow(/999 does not exist/);

    const stored = db
      .prepare("SELECT blocked_scopes_json FROM login_attempts WHERE id = ?")
      .get(realAttempt) as { blocked_scopes_json: string };
    expect(stored.blocked_scopes_json).toBe('["account","ip"]');
    db.close();
  });

  it("refuses secret fields inside details JSON", () => {
    const db = readyDb();
    const attemptId = insertLoginAttempt(db, {
      requestId: "req-login-3",
      timestampUtc: 4_000,
      usernameKey: "demo_user",
      sourceIp: "127.0.0.1",
      userId: null,
      outcome: "failure",
      blockedScopes: [],
    });

    expect(() =>
      insertSecurityEvent(db, {
        timestampUtc: 4_000,
        eventType: "BRUTE_FORCE_DETECTED",
        ruleId: "LOGIN_ACCOUNT_FAILURE_LIMIT_V1",
        severity: "medium",
        scopeType: "account",
        scopeKey: "demo_user",
        triggerLoginAttemptId: attemptId,
        queryAuditId: null,
        details: {
          count: 1,
          limit: 5,
          windowStart: 0,
          windowEnd: 4_000,
          loginMode: "observe",
          attemptIds: [attemptId],
          cooldownStart: null,
          cooldownUntil: null,
          password: "secret",
        } as never,
      })
    ).toThrow(/must not include password/);
    db.close();
  });

  it("rejects blocked scopes on failure and duplicate evidence ids", () => {
    const db = readyDb();
    expect(() =>
      insertLoginAttempt(db, {
        requestId: "bad-scopes",
        timestampUtc: 6_000,
        usernameKey: "demo_user",
        sourceIp: "127.0.0.1",
        userId: 1,
        outcome: "failure",
        blockedScopes: ["account"],
      })
    ).toThrow(/empty blockedScopes/);

    const attemptId = insertLoginAttempt(db, {
      requestId: "one-failure",
      timestampUtc: 6_001,
      usernameKey: "demo_user",
      sourceIp: "127.0.0.1",
      userId: 1,
      outcome: "failure",
      blockedScopes: [],
    });

    expect(() =>
      insertSecurityEvent(db, {
        timestampUtc: 6_001,
        eventType: "BRUTE_FORCE_DETECTED",
        ruleId: "LOGIN_ACCOUNT_FAILURE_LIMIT_V1",
        severity: "medium",
        scopeType: "account",
        scopeKey: "demo_user",
        triggerLoginAttemptId: attemptId,
        queryAuditId: null,
        details: {
          count: 5,
          limit: 5,
          windowStart: 0,
          windowEnd: 6_001,
          loginMode: "observe",
          attemptIds: [attemptId, attemptId, attemptId, attemptId, attemptId],
          cooldownStart: null,
          cooldownUntil: null,
        },
      })
    ).toThrow(/duplicates/);
    db.close();
  });
});

describe("normalize and clock", () => {
  it("normalizes usernames before validating and does not trim passwords", () => {
    expect(requireUsernameKey("  Demo_User ")).toBe("demo_user");
    expect(() => requireUsernameKey("ab")).toThrow(/3 to 32/);
    expect(validatePasswordLength("  AbC ")).toBe("  AbC ");
  });

  it("normalizes connection IP addresses", () => {
    expect(normalizeSourceIp("::ffff:127.0.0.1")).toBe("127.0.0.1");
    expect(normalizeSourceIp("::1")).toBe("127.0.0.1");
    expect(normalizeSourceIp("::ffff:10.1.2.3")).toBe("10.1.2.3");
    expect(normalizeSourceIp("10.0.0.8")).toBe("10.0.0.8");
  });

  it("advances a fake clock without waiting", () => {
    const clock = createFakeClock(1_000);
    expect(clock.now()).toBe(1_000);
    clock.advance(60_000);
    expect(clock.now()).toBe(61_000);
  });
});

describe("http utilities and server lifecycle", () => {
  const paths: string[] = [];

  afterEach(() => {
    for (const file of paths.splice(0)) {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    }
  });

  it("serves health, hides internal errors, and shares one database handle", async () => {
    const file = tempDb();
    paths.push(file);
    const config = testConfig(file);
    const db = openLabDatabase(config);
    seedProducts(db);
    const deps: AppDependencies = {
      db,
      config,
      clock: createFakeClock(10),
    };

    const app = createApp(deps, [
      () => {
        const router = express.Router();
        router.get("/boom", (_req, _res, next) => {
          next(new Error("internal detail should-not-leak"));
        });
        router.get("/product-count", (_req, res) => {
          const row = deps.db
            .prepare("SELECT COUNT(*) AS n FROM products")
            .get() as { n: number };
          res.json({ count: row.n, now: deps.clock.now() });
        });
        return router;
      },
    ]);

    const server: Server = await new Promise((resolve) => {
      const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("expected a TCP port");
    }

    const health = await fetch(`http://127.0.0.1:${address.port}/health`);
    expect(health.status).toBe(200);
    expect(health.headers.get("x-request-id")).toMatch(
      /^[0-9a-f-]{36}$/i
    );

    const boom = await fetch(`http://127.0.0.1:${address.port}/boom`);
    const boomBody = (await boom.json()) as { error: { message: string } };
    expect(boom.status).toBe(500);
    expect(boomBody).toEqual(
      errorEnvelope("INTERNAL_ERROR", "An unexpected error occurred.")
    );
    expect(JSON.stringify(boomBody)).not.toContain("should-not-leak");

    const products = await fetch(
      `http://127.0.0.1:${address.port}/product-count`
    );
    expect(await products.json()).toEqual({ count: 3, now: 10 });

    await shutdownServer(server, db);
    expect(() => db.prepare("SELECT 1").get()).toThrow();
  });

  it("returns a request id for malformed JSON and 413 for an oversized body", async () => {
    const file = tempDb();
    paths.push(file);
    const config = testConfig(file);
    const db = openLabDatabase(config);
    const app = createApp({ db, config, clock: createFakeClock(1) });
    const server: Server = await new Promise((resolve) => {
      const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("expected a TCP port");
    }
    const url = `http://127.0.0.1:${address.port}/health`;

    const malformed = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{",
    });
    expect(malformed.status).toBe(400);
    expect(malformed.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/i);
    expect(await malformed.json()).toEqual(
      errorEnvelope("INVALID_REQUEST", "The request could not be read.")
    );

    const oversized = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"pad":"${"x".repeat(40_000)}"}`,
    });
    expect(oversized.status).toBe(413);
    expect(oversized.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/i);
    const oversizedBody = (await oversized.json()) as {
      error: { code: string };
    };
    expect(oversizedBody.error.code).toBe("INVALID_REQUEST");

    await shutdownServer(server, db);
  });

  it("reads the socket address and ignores a spoofed forwarding header", () => {
    const req = {
      socket: { remoteAddress: "::ffff:127.0.0.1" },
      headers: { "x-forwarded-for": "1.2.3.4" },
    } as unknown as express.Request;
    expect(sourceIpFromRequest(req)).toBe("127.0.0.1");
    expect(attachRequestContext).toBeTypeOf("function");
  });
});

describe("resetLabEvidence", () => {
  it("clears attempts and restores products on a temporary database", () => {
    const file = tempDb();
    const db = openDatabase(file);
    try {
      applySchema(db);
      seedProducts(db);
      insertLoginAttempt(db, {
        requestId: "reset-me",
        timestampUtc: 5,
        usernameKey: "demo_user",
        sourceIp: "127.0.0.1",
        userId: null,
        outcome: "failure",
        blockedScopes: [],
      });

      resetLabEvidence(db);

      const attempts = db
        .prepare("SELECT COUNT(*) AS n FROM login_attempts")
        .get() as { n: number };
      const products = db
        .prepare("SELECT name FROM products ORDER BY id")
        .all() as { name: string }[];
      expect(attempts.n).toBe(0);
      expect(products.map((row) => row.name)).toEqual([
        "Mouse",
        "Keyboard",
        "Monitor",
      ]);
    } finally {
      db.close();
      fs.unlinkSync(file);
    }
  });
});
