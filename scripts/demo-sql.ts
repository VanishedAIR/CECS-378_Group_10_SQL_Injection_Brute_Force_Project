import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { applySchema } from "../src/server/db.js";
import { seedProducts } from "../src/server/seedProducts.js";
import { executeAuditedSearch } from "../src/server/search.js";
import { systemClock } from "../src/server/clock.js";

const db = new DatabaseSync(":memory:");

try {
  db.exec("PRAGMA foreign_keys = ON");
  applySchema(db);
  seedProducts(db);

  // Add a fictional user for the audit records
  db.prepare(`
    INSERT INTO users
    (id, username_key, display_username, password_hash, role)
    VALUES (?, ?, ?, ?, ?)
  `).run(1, "demo_user", "Demo User", "demo-only", "user");

  const searches = ["Mouse", "' OR 1=1 --"];

  for (const q of searches) {
    console.log(`\nSearch input: ${q}`);

    for (const mode of ["vulnerable", "protected"] as const) {
      const results = executeAuditedSearch(db, mode, q, {
        userId: 1,
        sourceIp: "127.0.0.1",
        requestId: randomUUID(),
        clock: systemClock(),
      });

      console.log(`${mode}: ${results.length} products`);
      console.log(results.map((product) => product.name));
    }
  }

  const auditCount = db.prepare(
    "SELECT COUNT(*) AS count FROM query_audit"
  ).get() as { count: number };

  const alertCount = db.prepare(
    "SELECT COUNT(*) AS count FROM security_events WHERE event_type = 'SQLI_ATTEMPT'"
  ).get() as { count: number };

  console.log("\nAudit records:", auditCount.count);
  console.log("SQL injection alerts:", alertCount.count);
} finally {
  db.close();
}
