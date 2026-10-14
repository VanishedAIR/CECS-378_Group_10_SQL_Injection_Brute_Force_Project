import { executeAuditedSearch } from "../src/server/search.js";
import { createFakeClock } from "../src/server/clock.js";
import { applySchema } from "../src/server/db.js";
import { getQueryAuditById, readAlertEvidence } from "../src/server/audit.js";
import { afterEach, describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { protectedSearch, vulnerableSearch } from "../src/server/search.js";

let db: DatabaseSync;

function setupDatabase() {
  db = new DatabaseSync(":memory:");

  db.exec(`
    CREATE TABLE products (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL
    );

    INSERT INTO products (name, description) VALUES
      ('Mouse', 'Wireless mouse'),
      ('Keyboard', 'Mechanical keyboard'),
      ('Monitor', 'Computer monitor');
  `);
}

afterEach(() => {
  db?.close();
});

describe("Protected product search", () => {
  it("returns matching products", () => {
    setupDatabase();

    const results = protectedSearch(db, "Mouse");

    expect(results).toHaveLength(1);
    expect(results[0]?.name).toBe("Mouse");
  });

  it("returns no matches for SQL injection input", () => {
    setupDatabase();

    const results = protectedSearch(db, "' OR 1=1 --");

    expect(results).toHaveLength(0);
  });

  it("returns an empty array when nothing matches", () => {
    setupDatabase();

    expect(protectedSearch(db, "Laptop")).toEqual([]);
  });
  
it("vulnerable search returns a normal product", () => {
  setupDatabase();

  const results = vulnerableSearch(db, "Mouse");

  expect(results).toHaveLength(1);
  expect(results[0]?.name).toBe("Mouse");
});

it("vulnerable search allows the lab SQL injection", () => {
  setupDatabase();

  const results = vulnerableSearch(db, "' OR 1=1 --");

  expect(results).toHaveLength(3);
});

});
