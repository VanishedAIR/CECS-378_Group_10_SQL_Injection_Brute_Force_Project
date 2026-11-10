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
/** Return matching products using a fixed statement and a bound LIKE value. SQLite errors propagate. */
export function protectedSearch(db: DatabaseSync, q: string): Product[] {
    const sql = "SELECT id, name, description FROM products WHERE name LIKE ?";
    // The user input is passed separately from the SQL statement.
    const statement = db.prepare(sql);
    return statement.all(`%${q}%`) as Product[];
}
/** Run deliberately concatenated SQL for the local demonstration. The HTTP caller must enforce authentication and LAB_MODE. */
export function vulnerableSearch(db: DatabaseSync, q: string): Product[] {
    // Intentionally unsafe SQL for the local demonstration
    const sql = "SELECT id, name, description FROM products " +
        "WHERE name LIKE '%" + q + "%'";
    return db.prepare(sql).all() as Product[];
}
export type SearchContext = {
    userId: number;
    sourceIp: string;
    requestId: string;
    clock: Clock;
};
/** Execute one search, then atomically write its audit and optional linked alert. Handled SQL failures are recorded before a generic error is thrown. */
export function executeAuditedSearch(db: DatabaseSync, mode: RouteMode, q: string, context: SearchContext): Product[] {
    const start = performance.now();
    const protectedSql = "SELECT id, name, description FROM products WHERE name LIKE ?";
    const vulnerableTemplate = "SELECT id, name, description FROM products WHERE name LIKE '%{q}%'";
    const unsafeSql = "SELECT id, name, description FROM products " +
        "WHERE name LIKE '%" + q + "%'";
    let results: Product[] = [];
    let errorCode: string | null = null;
    try {
        results =
            mode === "protected"
                ? protectedSearch(db, q)
                : vulnerableSearch(db, q);
    }
    catch {
        errorCode = "SQL_EXECUTION_ERROR";
    }
    // Keep the query audit and its optional alert together; an alert must link to this exact query.
    withTransaction(db, () => {
        const auditId = insertQueryAudit(db, {
            requestId: context.requestId || randomUUID(),
            timestampUtc: context.clock.now(),
            userId: context.userId,
            sourceIp: context.sourceIp,
            routeMode: mode,
            inputExcerpt: q.slice(0, 200),
            queryTemplate: mode === "protected" ? protectedSql : vulnerableTemplate,
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
