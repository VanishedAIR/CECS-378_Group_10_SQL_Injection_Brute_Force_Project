import type { DatabaseSync } from "node:sqlite";
import type { ServerConfig } from "./config.js";
import type { Clock } from "./clock.js";
import { systemClock } from "./clock.js";
import { withTransaction } from "./db.js";
import { insertLoginAttempt, insertSecurityEvent, type BlockedScope } from "./audit.js";
import { requireUsernameKey, normalizeSourceIp } from "./normalize.js";
export type LoginDecision = {
    outcome: "success" | "failure" | "blocked";
    status: 200 | 401 | 429;
    attemptId: number;
    blockedScopes: BlockedScope[];
    retryAfterSeconds: number | null;
    eventIds: number[];
};
export type LoginRequest = {
    requestId: string;
    username: string;
    /** Server-observed socket IP, never a user-provided header. */
    sourceIp: string;
};
export type VerifyResult = {
    valid: boolean;
    userId: number | null;
};
export type VerifyCredentials = (usernameKey: string) => Promise<VerifyResult>;
type Scope = {
    type: BlockedScope;
    key: string;
    limit: number;
    cooldownMs: number;
};
type CooldownRow = {
    blocked_until: number;
};
type AttemptRow = {
    id: number;
};
/** Create a serialized login evaluator using shared settings and a millisecond clock. Each decision records its outcome and any threshold evidence atomically. */
export function createLoginPolicy(db: DatabaseSync, config: ServerConfig, clock: Clock = systemClock()) {
    let tail: Promise<void> = Promise.resolve();
    /** Queue the entire async verification/decision so concurrent attempts cannot race a threshold. */
    function serialize<T>(operation: () => Promise<T>): Promise<T> {
        const result = tail.then(operation);
        tail = result.then(() => undefined, () => undefined);
        return result;
    }
    return {
        /** Validate username/password before calling this; password is never passed to audit. */
        evaluate(request: LoginRequest, verify: VerifyCredentials): Promise<LoginDecision> {
            const usernameKey = requireUsernameKey(request.username);
            const sourceIp = normalizeSourceIp(request.sourceIp);
            if (!sourceIp)
                throw new Error("Missing connection-derived source IP");
            if (!request.requestId)
                throw new Error("Missing request ID");
            return serialize(async () => {
                const now = clock.now();
                const scopes: Scope[] = [
                    { type: "account", key: usernameKey, limit: config.accountFailureLimit, cooldownMs: config.accountCooldownSeconds * 1000 },
                    { type: "ip", key: sourceIp, limit: config.ipFailureLimit, cooldownMs: config.ipCooldownSeconds * 1000 },
                ];
                const active = scopes.map((scope) => ({
                    ...scope,
                    until: (db.prepare("SELECT blocked_until FROM cooldowns WHERE scope_type = ? AND scope_key = ?")
                        .get(scope.type, scope.key) as CooldownRow | undefined)?.blocked_until ?? 0,
                })).filter((scope) => scope.until > now);
                if (config.loginMode === "protect" && active.length) {
                    return withTransaction(db, () => {
                        const blockedScopes = active.map((scope) => scope.type);
                        const attemptId = insertLoginAttempt(db, { requestId: request.requestId, timestampUtc: now,
                            usernameKey, sourceIp, userId: null, outcome: "blocked", blockedScopes });
                        return { outcome: "blocked" as const, status: 429 as const, attemptId, blockedScopes,
                            retryAfterSeconds: Math.ceil(Math.max(...active.map((scope) => scope.until - now)) / 1000), eventIds: [] };
                    });
                }
                // The verifier is owned by authentication. It must use bound SQL and check the password.
                const verification = await verify(usernameKey);
                // Refresh the timestamp after asynchronous password verification.
                // Failure windows, audit records, and new cooldowns must use completion time.
                const verifiedAt = clock.now();
                return withTransaction(db, () => {
                    const outcome = verification.valid ? "success" as const : "failure" as const;
                    const attemptId = insertLoginAttempt(db, { requestId: request.requestId, timestampUtc: verifiedAt,
                        usernameKey, sourceIp, userId: verification.userId, outcome, blockedScopes: [] });
                    const eventIds: number[] = [];
                    if (outcome === "failure") {
                        for (const scope of scopes) {
                            const column = scope.type === "account" ? "username_key" : "source_ip";
                            // Only a server-selected column is interpolated. Values stay bound.
                            // The rolling window is (start, end], in UTC milliseconds.
                            const rows = db.prepare(`SELECT id FROM login_attempts WHERE ${column} = ? AND outcome = 'failure' AND timestamp_utc > ? AND timestamp_utc <= ? ORDER BY id`)
                                .all(scope.key, verifiedAt - config.windowSeconds * 1000, verifiedAt) as AttemptRow[];
                            const count = rows.length;
                            if (count !== scope.limit)
                                continue; // Exactly one alert at threshold crossing.
                            const until = config.loginMode === "protect" ? verifiedAt + scope.cooldownMs : null;
                            const eventId = insertSecurityEvent(db, {
                                timestampUtc: verifiedAt, eventType: "BRUTE_FORCE_DETECTED",
                                ruleId: scope.type === "account" ? "LOGIN_ACCOUNT_FAILURE_LIMIT_V1" : "LOGIN_IP_FAILURE_LIMIT_V1",
                                severity: "medium", scopeType: scope.type, scopeKey: scope.key,
                                triggerLoginAttemptId: attemptId, queryAuditId: null,
                                details: { count, limit: scope.limit, windowStart: verifiedAt - config.windowSeconds * 1000,
                                    windowEnd: verifiedAt, loginMode: config.loginMode, attemptIds: rows.map((row) => row.id),
                                    cooldownStart: until === null ? null : verifiedAt, cooldownUntil: until },
                            });
                            eventIds.push(eventId);
                            if (until !== null) {
                                db.prepare(`INSERT INTO cooldowns (scope_type, scope_key, blocked_until, created_at, trigger_event_id)
                  VALUES (?, ?, ?, ?, ?) ON CONFLICT(scope_type, scope_key) DO UPDATE SET
                  blocked_until = excluded.blocked_until, created_at = excluded.created_at,
                  trigger_event_id = excluded.trigger_event_id`)
                                    .run(scope.type, scope.key, until, verifiedAt, eventId);
                            }
                        }
                    }
                    return { outcome, status: verification.valid ? 200 as const : 401 as const,
                        attemptId, blockedScopes: [], retryAfterSeconds: null, eventIds };
                });
            });
        },
    };
}
