import type { DatabaseSync } from "node:sqlite";
import { validateSecurityEventEvidence } from "./securityEventRules.js";

export type LoginOutcome = "success" | "failure" | "blocked";
export type BlockedScope = "account" | "ip";
export type RouteMode = "vulnerable" | "protected";
export type LoginMode = "observe" | "protect";
export type SqlIndicator =
  | "sql_comment"
  | "union_select"
  | "boolean_tautology";

const FORBIDDEN_JSON_KEYS = new Set([
  "password",
  "passwordhash",
  "cookie",
  "sessionid",
  "authorization",
  "databaseurl",
  "connectionstring",
]);

export type LoginAttemptInput = {
  requestId: string;
  timestampUtc: number;
  usernameKey: string;
  sourceIp: string;
  userId: number | null;
  outcome: LoginOutcome;
  blockedScopes: BlockedScope[];
};

export type LoginAttemptRecord = {
  id: number;
  requestId: string;
  timestampUtc: number;
  usernameKey: string;
  sourceIp: string;
  userId: number | null;
  outcome: LoginOutcome;
  blockedScopes: BlockedScope[];
};

export type QueryAuditInput = {
  requestId: string;
  timestampUtc: number;
  userId: number;
  sourceIp: string;
  routeMode: RouteMode;
  inputExcerpt: string;
  queryTemplate: string;
  parameters: string[];
  labSql: string | null;
  resultCount: number | null;
  durationMs: number;
  errorCode: string | null;
};

export type QueryAuditRecord = {
  id: number;
  requestId: string;
  timestampUtc: number;
  userId: number;
  sourceIp: string;
  routeMode: RouteMode;
  inputExcerpt: string;
  queryTemplate: string;
  parameters: string[];
  labSql: string | null;
  resultCount: number | null;
  durationMs: number;
  errorCode: string | null;
};

export type BruteForceDetails = {
  count: number;
  limit: number;
  windowStart: number;
  windowEnd: number;
  loginMode: LoginMode;
  attemptIds: number[];
  cooldownStart: number | null;
  cooldownUntil: number | null;
};

export type SqlAlertDetails = {
  matchedIndicators: SqlIndicator[];
  routeMode: RouteMode;
};

export type SecurityEventInput = {
  timestampUtc: number;
  eventType: "BRUTE_FORCE_DETECTED" | "SQLI_ATTEMPT";
  ruleId: string;
  severity: "low" | "medium" | "high";
  scopeType: "account" | "ip" | "request";
  scopeKey: string;
  triggerLoginAttemptId: number | null;
  queryAuditId: number | null;
  details: BruteForceDetails | SqlAlertDetails;
};

export type AlertSummary = {
  id: number;
  timestampUtc: number;
  eventType: string;
  ruleId: string;
  severity: string;
  scope: { type: string; key: string };
  summary: string;
};

const SCOPE_ORDER: BlockedScope[] = ["account", "ip"];

function insertedId(result: { lastInsertRowid: number | bigint }): number {
  return Number(result.lastInsertRowid);
}

function assertNoSecrets(value: unknown, path = "details"): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoSecrets(item, `${path}[${index}]`));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      if (FORBIDDEN_JSON_KEYS.has(key.toLowerCase())) {
        throw new Error(`Audit JSON must not include ${key}.`);
      }
      assertNoSecrets(nested, `${path}.${key}`);
    }
  }
}

function orderBlockedScopes(scopes: BlockedScope[]): BlockedScope[] {
  const unique = new Set(scopes);
  return SCOPE_ORDER.filter((scope) => unique.has(scope));
}

function assertOutcomeScopes(
  outcome: LoginOutcome,
  scopes: BlockedScope[]
): void {
  if ((outcome === "success" || outcome === "failure") && scopes.length > 0) {
    throw new Error(
      "success and failure login attempts must use an empty blockedScopes list."
    );
  }
}

function rowExists(db: DatabaseSync, sql: string, id: number): boolean {
  const row = db.prepare(sql).get(id) as { id: number } | undefined;
  return row !== undefined;
}

export function summaryForRule(ruleId: string): string {
  switch (ruleId) {
    case "LOGIN_ACCOUNT_FAILURE_LIMIT_V1":
      return "Account failure threshold reached.";
    case "LOGIN_IP_FAILURE_LIMIT_V1":
      return "IP failure threshold reached.";
    case "SQLI_SIGNATURE_V1":
      return "Suspicious SQL input pattern detected.";
    default:
      return "Security event recorded.";
  }
}

/**
 * Inserts one login_attempts row. Does not begin or commit a transaction.
 * Bin decides the outcome before calling this.
 */
export function insertLoginAttempt(
  db: DatabaseSync,
  input: LoginAttemptInput
): number {
  assertOutcomeScopes(input.outcome, input.blockedScopes);
  const blockedScopes = orderBlockedScopes(input.blockedScopes);
  const result = db
    .prepare(
      `INSERT INTO login_attempts (
         request_id, timestamp_utc, username_key, source_ip, user_id,
         outcome, blocked_scopes_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      input.requestId,
      input.timestampUtc,
      input.usernameKey,
      input.sourceIp,
      input.userId,
      input.outcome,
      JSON.stringify(blockedScopes)
    );
  return insertedId(result);
}

/**
 * Inserts one query_audit row. real thd decides route mode and SQL text.
 */
export function insertQueryAudit(
  db: DatabaseSync,
  input: QueryAuditInput
): number {
  const result = db
    .prepare(
      `INSERT INTO query_audit (
         request_id, timestamp_utc, user_id, source_ip, route_mode,
         input_excerpt, query_template, parameters_json, lab_sql,
         result_count, duration_ms, error_code
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      input.requestId,
      input.timestampUtc,
      input.userId,
      input.sourceIp,
      input.routeMode,
      input.inputExcerpt,
      input.queryTemplate,
      JSON.stringify(input.parameters),
      input.labSql,
      input.resultCount,
      input.durationMs,
      input.errorCode
    );
  return insertedId(result);
}

function assertAttemptIdsExist(db: DatabaseSync, ids: number[]): void {
  for (const id of ids) {
    if (!rowExists(db, "SELECT id FROM login_attempts WHERE id = ?", id)) {
      throw new Error(`Contributing login attempt ${id} does not exist.`);
    }
  }
}

/**
 * Inserts one security_events row after checking evidence shape and that
 * referenced parent rows exist. Does not decide thresholds or SQL signatures.
 */
export function insertSecurityEvent(
  db: DatabaseSync,
  input: SecurityEventInput
): number {
  validateSecurityEventEvidence({
    eventType: input.eventType,
    scopeType: input.scopeType,
    triggerLoginAttemptId: input.triggerLoginAttemptId,
    queryAuditId: input.queryAuditId,
  });
  assertNoSecrets(input.details);

  if (input.triggerLoginAttemptId != null) {
    if (
      !rowExists(
        db,
        "SELECT id FROM login_attempts WHERE id = ?",
        input.triggerLoginAttemptId
      )
    ) {
      throw new Error("trigger_login_attempt_id does not exist.");
    }
  }

  if (input.queryAuditId != null) {
    if (
      !rowExists(db, "SELECT id FROM query_audit WHERE id = ?", input.queryAuditId)
    ) {
      throw new Error("query_audit_id does not exist.");
    }
  }

  if (input.eventType === "BRUTE_FORCE_DETECTED") {
    const details = input.details as BruteForceDetails;
    if (new Set(details.attemptIds).size !== details.attemptIds.length) {
      throw new Error("attemptIds must not contain duplicates.");
    }
    if (details.attemptIds.length !== details.count) {
      throw new Error("attemptIds length must equal count.");
    }
    assertAttemptIdsExist(db, details.attemptIds);
    if (
      input.triggerLoginAttemptId != null &&
      !details.attemptIds.includes(input.triggerLoginAttemptId)
    ) {
      throw new Error("attemptIds must include the triggering login attempt.");
    }
  }

  const result = db
    .prepare(
      `INSERT INTO security_events (
         timestamp_utc, event_type, rule_id, severity, scope_type, scope_key,
         trigger_login_attempt_id, query_audit_id, details_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      input.timestampUtc,
      input.eventType,
      input.ruleId,
      input.severity,
      input.scopeType,
      input.scopeKey,
      input.triggerLoginAttemptId,
      input.queryAuditId,
      JSON.stringify(input.details)
    );
  return insertedId(result);
}

type LoginRow = {
  id: number;
  request_id: string;
  timestamp_utc: number;
  username_key: string;
  source_ip: string;
  user_id: number | null;
  outcome: LoginOutcome;
  blocked_scopes_json: string;
};

function mapLogin(row: LoginRow): LoginAttemptRecord {
  return {
    id: row.id,
    requestId: row.request_id,
    timestampUtc: row.timestamp_utc,
    usernameKey: row.username_key,
    sourceIp: row.source_ip,
    userId: row.user_id,
    outcome: row.outcome,
    blockedScopes: JSON.parse(row.blocked_scopes_json) as BlockedScope[],
  };
}

export function getLoginAttemptsByIds(
  db: DatabaseSync,
  ids: number[]
): LoginAttemptRecord[] {
  if (ids.length === 0) {
    return [];
  }
  const placeholders = ids.map(() => "?").join(", ");
  const rows = db
    .prepare(
      `SELECT id, request_id, timestamp_utc, username_key, source_ip, user_id,
              outcome, blocked_scopes_json
       FROM login_attempts
       WHERE id IN (${placeholders})
       ORDER BY timestamp_utc ASC, id ASC`
    )
    .all(...ids) as LoginRow[];
  return rows.map(mapLogin);
}

type QueryRow = {
  id: number;
  request_id: string;
  timestamp_utc: number;
  user_id: number;
  source_ip: string;
  route_mode: RouteMode;
  input_excerpt: string;
  query_template: string;
  parameters_json: string;
  lab_sql: string | null;
  result_count: number | null;
  duration_ms: number;
  error_code: string | null;
};

function mapQuery(row: QueryRow): QueryAuditRecord {
  return {
    id: row.id,
    requestId: row.request_id,
    timestampUtc: row.timestamp_utc,
    userId: row.user_id,
    sourceIp: row.source_ip,
    routeMode: row.route_mode,
    inputExcerpt: row.input_excerpt,
    queryTemplate: row.query_template,
    parameters: JSON.parse(row.parameters_json) as string[],
    labSql: row.lab_sql,
    resultCount: row.result_count,
    durationMs: row.duration_ms,
    errorCode: row.error_code,
  };
}

export function getQueryAuditById(
  db: DatabaseSync,
  id: number
): QueryAuditRecord | null {
  const row = db
    .prepare(
      `SELECT id, request_id, timestamp_utc, user_id, source_ip, route_mode,
              input_excerpt, query_template, parameters_json, lab_sql,
              result_count, duration_ms, error_code
       FROM query_audit WHERE id = ?`
    )
    .get(id) as QueryRow | undefined;
  return row ? mapQuery(row) : null;
}

type EventRow = {
  id: number;
  timestamp_utc: number;
  event_type: string;
  rule_id: string;
  severity: string;
  scope_type: string;
  scope_key: string;
  trigger_login_attempt_id: number | null;
  query_audit_id: number | null;
  details_json: string;
};

export function getSecurityEventById(
  db: DatabaseSync,
  id: number
): (AlertSummary & { details: unknown }) | null {
  const row = db
    .prepare(
      `SELECT id, timestamp_utc, event_type, rule_id, severity, scope_type,
              scope_key, trigger_login_attempt_id, query_audit_id, details_json
       FROM security_events WHERE id = ?`
    )
    .get(id) as EventRow | undefined;
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    timestampUtc: row.timestamp_utc,
    eventType: row.event_type,
    ruleId: row.rule_id,
    severity: row.severity,
    scope: { type: row.scope_type, key: row.scope_key },
    summary: summaryForRule(row.rule_id),
    details: JSON.parse(row.details_json) as unknown,
  };
}

/**
 * Admin evidence bundle for one alert. Ediz's future route can return this JSON.
 * Returns null when the alert id does not exist.
 */
export function readAlertEvidence(
  db: DatabaseSync,
  eventId: number
): {
  alert: AlertSummary;
  details: unknown;
  evidence: {
    loginAttempts: LoginAttemptRecord[];
    query: QueryAuditRecord | null;
  };
} | null {
  const event = getSecurityEventById(db, eventId);
  if (!event) {
    return null;
  }

  const { details, ...alert } = event;
  if (alert.eventType === "BRUTE_FORCE_DETECTED") {
    const brute = details as BruteForceDetails;
    return {
      alert,
      details,
      evidence: {
        loginAttempts: getLoginAttemptsByIds(db, brute.attemptIds ?? []),
        query: null,
      },
    };
  }

  const raw = db
    .prepare("SELECT query_audit_id FROM security_events WHERE id = ?")
    .get(eventId) as { query_audit_id: number | null };
  const query =
    raw.query_audit_id == null
      ? null
      : getQueryAuditById(db, raw.query_audit_id);

  return {
    alert,
    details,
    evidence: { loginAttempts: [], query },
  };
}
