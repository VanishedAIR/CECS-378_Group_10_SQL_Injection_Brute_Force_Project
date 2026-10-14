import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  loadConfig,
  resetDotEnvForTests,
} from "../src/server/config.js";
import {
  applySchema,
  closeDatabase,
  listUserTables,
  openDatabase,
  withDatabase,
} from "../src/server/db.js";
import { getSchemaVersion, SCHEMA_VERSION } from "../src/server/schemaMigrate.js";
import { validateSecurityEventEvidence } from "../src/server/securityEventRules.js";
import { SEED_PRODUCTS, seedProducts } from "../src/server/seedProducts.js";

describe("database foundation", () => {
  let dbPath: string;

  afterEach(() => {
    if (dbPath && fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }
  });

  it("creates all six agreed tables with foreign keys enabled", () => {
    dbPath = path.join(os.tmpdir(), `lab-test-${Date.now()}.db`);
    const db = openDatabase(dbPath);
    try {
      applySchema(db);

      const fk = db.prepare("PRAGMA foreign_keys").get() as {
        foreign_keys: number;
      };
      expect(fk.foreign_keys).toBe(1);

      expect(listUserTables(db)).toEqual([
        "cooldowns",
        "lab_schema_meta",
        "login_attempts",
        "products",
        "query_audit",
        "security_events",
        "users",
      ]);
      expect(getSchemaVersion(db)).toBe(SCHEMA_VERSION);
    } finally {
      closeDatabase(db);
    }
  });

  it("seeds Mouse, Keyboard, and Monitor with stable IDs", () => {
    dbPath = path.join(os.tmpdir(), `lab-seed-${Date.now()}.db`);
    withDatabase(dbPath, (db) => {
      applySchema(db);
      seedProducts(db);

      const rows = db
        .prepare("SELECT id, name, description FROM products ORDER BY id")
        .all() as { id: number; name: string; description: string }[];

      expect(rows).toEqual([...SEED_PRODUCTS]);
    });
  });

  it("allows running seed twice without duplicate errors", () => {
    dbPath = path.join(os.tmpdir(), `lab-seed-twice-${Date.now()}.db`);
    withDatabase(dbPath, (db) => {
      applySchema(db);
      seedProducts(db);
      seedProducts(db);

      const count = db
        .prepare("SELECT COUNT(*) AS n FROM products")
        .get() as { n: number };
      expect(count.n).toBe(3);
    });
  });

  it("closes the database when seed work throws", () => {
    dbPath = path.join(os.tmpdir(), `lab-close-${Date.now()}.db`);
    expect(() =>
      withDatabase(dbPath, (db) => {
        applySchema(db);
        throw new Error("simulated seed failure");
      })
    ).toThrow("simulated seed failure");

    expect(() => {
      const db = openDatabase(dbPath);
      db.prepare("SELECT 1").get();
      closeDatabase(db);
    }).not.toThrow();
  });

  it("rejects foreign-key violations", () => {
    dbPath = path.join(os.tmpdir(), `lab-fk-${Date.now()}.db`);
    const db = openDatabase(dbPath);
    try {
      applySchema(db);
      expect(() =>
        db
          .prepare(
            `INSERT INTO query_audit (
              request_id, timestamp_utc, user_id, source_ip, route_mode,
              input_excerpt, query_template, duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run("req-1", Date.now(), 999, "127.0.0.1", "protected", "x", "tpl", 1)
      ).toThrow();
    } finally {
      closeDatabase(db);
    }
  });

  it("migrates an existing database without deleting product rows", () => {
    dbPath = path.join(os.tmpdir(), `lab-migrate-${Date.now()}.db`);
    const db = openDatabase(dbPath);
    try {
      db.exec(`
        CREATE TABLE products (
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          description TEXT NOT NULL
        );
        INSERT INTO products (id, name, description) VALUES (1, 'Mouse', 'keep me');
      `);

      applySchema(db);

      const row = db
        .prepare("SELECT description FROM products WHERE id = 1")
        .get() as { description: string };
      expect(row.description).toBe("keep me");
      expect(getSchemaVersion(db)).toBe(SCHEMA_VERSION);
    } finally {
      closeDatabase(db);
    }
  });

  it("rejects invalid security_events at the database layer", () => {
    dbPath = path.join(os.tmpdir(), `lab-events-${Date.now()}.db`);
    const db = openDatabase(dbPath);
    try {
      applySchema(db);

      const insert = db.prepare(`
        INSERT INTO security_events (
          timestamp_utc, event_type, rule_id, severity, scope_type, scope_key,
          trigger_login_attempt_id, query_audit_id, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}')
      `);

      expect(() =>
        insert.run(
          Date.now(),
          "SQLI_ATTEMPT",
          "SQLI_SIGNATURE_V1",
          "medium",
          "request",
          "req-1",
          1,
          null
        )
      ).toThrow();

      expect(() =>
        insert.run(
          Date.now(),
          "SQLI_ATTEMPT",
          "SQLI_SIGNATURE_V1",
          "medium",
          "account",
          "req-1",
          null,
          1
        )
      ).toThrow();
    } finally {
      closeDatabase(db);
    }
  });
});

describe("securityEventRules", () => {
  it("accepts valid brute-force and SQL shapes", () => {
    expect(() =>
      validateSecurityEventEvidence({
        eventType: "BRUTE_FORCE_DETECTED",
        scopeType: "account",
        triggerLoginAttemptId: 1,
        queryAuditId: null,
      })
    ).not.toThrow();

    expect(() =>
      validateSecurityEventEvidence({
        eventType: "SQLI_ATTEMPT",
        scopeType: "request",
        triggerLoginAttemptId: null,
        queryAuditId: 2,
      })
    ).not.toThrow();
  });

  it("rejects neither or both evidence references", () => {
    expect(() =>
      validateSecurityEventEvidence({
        eventType: "BRUTE_FORCE_DETECTED",
        scopeType: "account",
        triggerLoginAttemptId: null,
        queryAuditId: null,
      })
    ).toThrow(/exactly one evidence/);

    expect(() =>
      validateSecurityEventEvidence({
        eventType: "BRUTE_FORCE_DETECTED",
        scopeType: "account",
        triggerLoginAttemptId: 1,
        queryAuditId: 2,
      })
    ).toThrow(/exactly one evidence/);
  });
});

describe("loadConfig", () => {
  const envKeys = ["HOST", "PORT", "DATABASE_PATH"] as const;
  const saved: Record<string, string | undefined> = {};

  afterEach(() => {
    for (const key of envKeys) {
      if (saved[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = saved[key];
      }
    }
    resetDotEnvForTests();
  });

  it("loads .env without overriding existing environment variables", () => {
    for (const key of envKeys) {
      saved[key] = process.env[key];
    }

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lab-env-"));
    fs.writeFileSync(
      path.join(dir, ".env"),
      "PORT=4001\nDATABASE_PATH=./from-dotenv.db\n"
    );

    const previousCwd = process.cwd();
    process.env.PORT = "5000";
    delete process.env.DATABASE_PATH;
    delete process.env.HOST;
    resetDotEnvForTests();

    try {
      process.chdir(dir);
      const config = loadConfig();
      expect(config.port).toBe(5000);
      expect(config.databasePath).toBe("./from-dotenv.db");
      expect(config.host).toBe("127.0.0.1");
    } finally {
      process.chdir(previousCwd);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects non-loopback HOST values", () => {
    for (const key of envKeys) {
      saved[key] = process.env[key];
    }

    process.env.HOST = "0.0.0.0";
    resetDotEnvForTests();
    expect(() => loadConfig()).toThrow(/loopback/);
  });
});
