import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { applySchema, withDatabase } from "../src/server/db.js";
import { hashPassword, verifyPassword } from "../src/server/passwords.js";
import { DEMO_ACCOUNTS } from "../src/server/seedAccounts.js";
import { SEED_PRODUCTS } from "../src/server/seedProducts.js";

describe("demo account seed command (temporary SQLite only)", () => {
  let directory: string;
  let databasePath: string;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "lab-account-seed-"));
    databasePath = path.join(directory, "seed.db");
  });

  afterEach(() => {
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function runSeed(): string {
    const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/seed-products.ts"], {
      env: { ...process.env, DATABASE_PATH: databasePath },
      encoding: "utf8",
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    return result.stdout;
  }

  it("seeds products and verifiable accounts; reruns preserve accounts and all audit data", () => {
    const output = runSeed();
    withDatabase(databasePath, (db) => {
      expect(db.prepare("SELECT * FROM products ORDER BY id").all()).toEqual([...SEED_PRODUCTS]);
      const accounts = db.prepare("SELECT * FROM users ORDER BY id").all();
      expect(accounts).toHaveLength(2);
      for (const demo of DEMO_ACCOUNTS) {
        const row = accounts.find((account) => account.username_key === demo.username)!;
        expect(row.display_username).toBe(demo.username);
        expect(row.role).toBe(demo.role);
        expect(row.password_hash).not.toBe(demo.password);
        expect(verifyPassword(demo.password, String(row.password_hash))).toBe(true);
        expect(verifyPassword("wrong-password", String(row.password_hash))).toBe(false);
        expect(output).toContain(`Created ${demo.username} (${demo.role})`);
        expect(output).not.toContain(demo.password);
        expect(output).not.toContain(String(row.password_hash));
      }

      // Representative linked evidence in every audit/cooldown table.
      db.exec(`
        INSERT INTO login_attempts VALUES (1, 'seed-test-login', 1000, 'demo_user', '127.0.0.1', 1, 'failure', '[]');
        INSERT INTO query_audit VALUES (1, 'seed-test-query', 1000, 1, '127.0.0.1', 'protected', 'Mouse', 'SELECT fixture', '[]', NULL, 1, 0, NULL);
        INSERT INTO security_events VALUES (1, 1000, 'BRUTE_FORCE_DETECTED', 'LOGIN_ACCOUNT_FAILURE_LIMIT_V1', 'medium', 'account', 'demo_user', 1, NULL, '{}');
        INSERT INTO cooldowns VALUES ('account', 'demo_user', 2000, 1000, 1);
      `);
      const tables = ["users", "products", "login_attempts", "query_audit", "security_events", "cooldowns"];
      const before = tables.map((table) => db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all());
      const secondOutput = runSeed();
      expect(secondOutput).not.toContain("Created demo_");
      expect(secondOutput).toContain("Skipped demo_user: username already exists");
      expect(secondOutput).toContain("Skipped demo_admin: username already exists");
      expect(tables.map((table) => db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all())).toEqual(before);
    });
  });

  it.each(DEMO_ACCOUNTS)("preserves an existing conflicting $username and reports it", (demo) => {
    const originalHash = hashPassword("ExistingFictionalPassword!");
    withDatabase(databasePath, (db) => {
      applySchema(db);
      db.prepare(`INSERT INTO users (username_key, display_username, password_hash, role)
        VALUES (?, ?, ?, ?)`).run(demo.username, "Existing fictional account", originalHash,
          demo.role === "user" ? "admin" : "user");
    });
    const output = runSeed();
    expect(output).toContain(`Skipped ${demo.username}: username already exists`);
    expect(output).toContain("Demo credentials and expected role");
    expect(output).not.toContain(`Created ${demo.username}`);
    withDatabase(databasePath, (db) => {
      const rows = db.prepare("SELECT * FROM users").all();
      expect(rows).toHaveLength(2);
      const existing = rows.find((row) => row.username_key === demo.username)!;
      expect(existing.display_username).toBe("Existing fictional account");
      expect(existing.password_hash).toBe(originalHash);
      expect(existing.role).toBe(demo.role === "user" ? "admin" : "user");
      expect(verifyPassword(demo.password, String(existing.password_hash))).toBe(false);
    });
  });
});
