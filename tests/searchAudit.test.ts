import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { executeAuditedSearch } from "../src/server/search.js";
import { createFakeClock } from "../src/server/clock.js";
import { getQueryAuditById, readAlertEvidence } from "../src/server/audit.js";
import { applySchema } from "../src/server/db.js";
import { seedProducts } from "../src/server/seedProducts.js";

function setupDatabase() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  applySchema(db);
  seedProducts(db);

  // Fictional user required by the audit foreign key
  db.prepare(`
    INSERT INTO users
    (id, username_key, display_username, password_hash, role)
    VALUES (?, ?, ?, ?, ?)
  `).run(1, "demo_user", "Demo User", "test-hash", "user");

  return db;
}

describe("Search auditing and SQL injection alerts", () => {
  it("records a normal protected search without an alert", () => {
    const db = setupDatabase();

    try {
      const requestId = randomUUID();

      const results = executeAuditedSearch(db, "protected", "Mouse", {
        userId: 1,
        sourceIp: "127.0.0.1",
        requestId,
        clock: createFakeClock(1000),
      });

      expect(results).toHaveLength(1);

      const audit = db.prepare(
        "SELECT id FROM query_audit WHERE request_id = ?"
      ).get(requestId) as { id: number };

      const record = getQueryAuditById(db, audit.id);

      expect(record?.routeMode).toBe("protected");
      expect(record?.resultCount).toBe(1);

      const events = db.prepare(
        "SELECT COUNT(*) AS count FROM security_events"
      ).get() as { count: number };

      expect(events.count).toBe(0);
    } finally {
      db.close();
    }
  });

  it("records an SQL injection alert linked to its query", () => {
    const db = setupDatabase();

    try {
      const requestId = randomUUID();

      const results = executeAuditedSearch(
        db,
        "vulnerable",
        "' OR 1=1 --",
        {
          userId: 1,
          sourceIp: "127.0.0.1",
          requestId,
          clock: createFakeClock(2000),
        }
      );

      expect(results).toHaveLength(3);

      const event = db.prepare(`
        SELECT id FROM security_events
        WHERE event_type = 'SQLI_ATTEMPT'
      `).get() as { id: number };

      const evidence = readAlertEvidence(db, event.id);

      expect(evidence?.alert.eventType).toBe("SQLI_ATTEMPT");
      expect(evidence?.evidence.query?.resultCount).toBe(3);
      expect(evidence?.evidence.query?.routeMode).toBe("vulnerable");
    } finally {
      db.close();
    }
  });

  it("detects suspicious input on the protected route", () => {
    const db = setupDatabase();

    try {
      const results = executeAuditedSearch(
        db,
        "protected",
        "' OR 1=1 --",
        {
          userId: 1,
          sourceIp: "127.0.0.1",
          requestId: randomUUID(),
          clock: createFakeClock(3000),
        }
      );

      expect(results).toHaveLength(0);

      const event = db.prepare(`
        SELECT COUNT(*) AS count FROM security_events
        WHERE event_type = 'SQLI_ATTEMPT'
      `).get() as { count: number };

      expect(event.count).toBe(1);
    } finally {
      db.close();
    }
  });

  it("records a database error without exposing SQL details", () => {
    const db = setupDatabase();

    try {
      db.exec("DROP TABLE products");

      const requestId = randomUUID();

      expect(() =>
        executeAuditedSearch(db, "protected", "Mouse", {
          userId: 1,
          sourceIp: "127.0.0.1",
          requestId,
          clock: createFakeClock(4000),
        })
      ).toThrow("Search failed.");

      const audit = db.prepare(`
        SELECT result_count, error_code
        FROM query_audit WHERE request_id = ?
      `).get(requestId) as {
        result_count: number | null;
        error_code: string | null;
      };

      expect(audit.result_count).toBeNull();
      expect(audit.error_code).toBe("SQL_EXECUTION_ERROR");
    } finally {
      db.close();
    }
  });
});
