/**
 * Validates security_events rows before insert/update.
 * Matches SQLite triggers installed by schema migrations (see schemaMigrate.ts).
 */

export const SECURITY_EVENT_TYPES = [
  "BRUTE_FORCE_DETECTED",
  "SQLI_ATTEMPT",
] as const;

export type SecurityEventType = (typeof SECURITY_EVENT_TYPES)[number];

export type SecurityEventEvidenceInput = {
  eventType: string;
  scopeType: string;
  triggerLoginAttemptId: number | null;
  queryAuditId: number | null;
};

export function validateSecurityEventEvidence(
  input: SecurityEventEvidenceInput
): void {
  if (!SECURITY_EVENT_TYPES.includes(input.eventType as SecurityEventType)) {
    throw new Error(`Unsupported event_type: ${input.eventType}`);
  }

  const hasLogin = input.triggerLoginAttemptId != null;
  const hasQuery = input.queryAuditId != null;

  if (hasLogin === hasQuery) {
    throw new Error(
      "security_events must reference exactly one evidence source: login attempt or query audit"
    );
  }

  if (input.eventType === "BRUTE_FORCE_DETECTED") {
    if (!hasLogin) {
      throw new Error("BRUTE_FORCE_DETECTED requires trigger_login_attempt_id");
    }
    if (input.scopeType !== "account" && input.scopeType !== "ip") {
      throw new Error(
        "BRUTE_FORCE_DETECTED requires scope_type account or ip"
      );
    }
    return;
  }

  if (input.eventType === "SQLI_ATTEMPT") {
    if (!hasQuery) {
      throw new Error("SQLI_ATTEMPT requires query_audit_id");
    }
    if (input.scopeType !== "request") {
      throw new Error("SQLI_ATTEMPT requires scope_type request");
    }
  }
}
