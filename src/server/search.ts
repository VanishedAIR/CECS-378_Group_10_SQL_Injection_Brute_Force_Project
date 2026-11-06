import { randomUUID } from "node:crypto";
import type { Clock } from "./clock.js";
import type { RouteMode } from "./audit.js";
import { insertQueryAudit, insertSecurityEvent } from "./audit.js";
import { detectSqlInjection } from "./sqlDetector.js";
import type { DatabaseSync } from "node:sqlite";
import { withTransaction } from "./db.js";

export type Product = {
  id: number;
  name: string;
  description: string;
};

export function protectedSearch(
  db: DatabaseSync,
  q: string
): Product[] {
  const sql =
    "SELECT id, name, description FROM products WHERE name LIKE ?";

  // The user input is passed separately from the SQL statement.
  const statement = db.prepare(sql);

  return statement.all(`%${q}%`) as Product[];
}

export function vulnerableSearch(
  db: DatabaseSync,
  q: string
): Product[] {
  // Intentionally unsafe SQL for the local demonstration
  const sql =
    "SELECT id, name, description FROM products " +
    "WHERE name LIKE '%" + q + "%'";

  return db.prepare(sql).all() as Product[];
}

export type SearchContext = {
  userId: number;
  sourceIp: string;
  requestId: string;
  clock: Clock;
};

export function executeAuditedSearch(
  db: DatabaseSync,
  mode: RouteMode,
  q: string,
  context: SearchContext
): Product[] {
  const start = performance.now();

  const protectedSql =
    "SELECT id, name, description FROM products WHERE name LIKE ?";

  const unsafeSql =
    "SELECT id, name, description FROM products " +
    "WHERE name LIKE '%" + q + "%'";

  let results: Product[] = [];
  let errorCode: string | null = null;

  try {
    results =
      mode === "protected"
        ? protectedSearch(db, q)
        : vulnerableSearch(db, q);
  } catch {
    errorCode = "SQL_EXECUTION_ERROR";
  }

  
withTransaction(db, () => {
  const auditId = insertQueryAudit(db, {
    requestId: context.requestId || randomUUID(),
    timestampUtc: context.clock.now(),
    userId: context.userId,
    sourceIp: context.sourceIp,
    routeMode: mode,
    inputExcerpt: q.slice(0, 200),
    queryTemplate: mode === "protected" ? protectedSql : unsafeSql,
    parameters: mode === "protected" ? [`%${q}%`] : [],
    labSql: mode === "vulnerable" ? unsafeSql : null,
    resultCount: errorCode ? null : results.length,
    durationMs: performance.now() - start,
    errorCode,
  });

  const indicators = detectSqlInjection(q);

  if (indicators.length > 0) {
    insertSecurityEvent(db, {
      timestampUtc: context.clock.now(),
      eventType: "SQLI_ATTEMPT",
      ruleId: "SQLI_SIGNATURE_V1",
      severity: "medium",
      scopeType: "request",
      scopeKey: context.requestId,
      triggerLoginAttemptId: null,
      queryAuditId: auditId,
      details: {
        matchedIndicators: indicators,
        routeMode: mode,
      },
    });
  }
});

  if (errorCode) {
    throw new Error("Search failed.");
  }

  return results;
}
