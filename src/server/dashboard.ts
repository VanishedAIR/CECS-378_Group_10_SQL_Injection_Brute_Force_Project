import { Router, type RequestHandler } from "express";
import type { DatabaseSync } from "node:sqlite";
import type { AppDependencies } from "./app.js";
import { readAlertEvidence, summaryForRule } from "./audit.js";

// Run a query that returns one total
function count(db: DatabaseSync, sql: string): number {
    const row = db.prepare(sql).get() as { total: number };
    return row.total;
}

// Get all the information needed for the dashboard
export function getDashboardData(
    db: DatabaseSync,
    now: number,
    loginMode: string
) {
    // Count the different login results
    const successfulLogins = count(db,
        "SELECT COUNT(*) AS total FROM login_attempts WHERE outcome = 'success'"
    );

    const failedLogins = count(db,
        "SELECT COUNT(*) AS total FROM login_attempts WHERE outcome = 'failure'"
    );

    const blockedLogins = count(db,
        "SELECT COUNT(*) AS total FROM login_attempts WHERE outcome = 'blocked'"
    );

    // Count the searches
    const searchQueries = count(db,
        "SELECT COUNT(*) AS total FROM query_audit"
    );

    // Count detected attacks
    const sqlInjectionAlerts = count(db,
        "SELECT COUNT(*) AS total FROM security_events WHERE event_type = 'SQLI_ATTEMPT'"
    );

    const bruteForceAlerts = count(db,
        "SELECT COUNT(*) AS total FROM security_events WHERE event_type = 'BRUTE_FORCE_DETECTED'"
    );

    // Count account and IP alerts separately
    const accountBruteForceAlerts = count(db,
        "SELECT COUNT(*) AS total FROM security_events WHERE event_type = 'BRUTE_FORCE_DETECTED' AND scope_type = 'account'"
    );

    const ipBruteForceAlerts = count(db,
        "SELECT COUNT(*) AS total FROM security_events WHERE event_type = 'BRUTE_FORCE_DETECTED' AND scope_type = 'ip'"
    );

    // Get cooldowns that have not expired
    const cooldownRows = db.prepare(
        `SELECT scope_type, scope_key, created_at,
                blocked_until, trigger_event_id
         FROM cooldowns
         WHERE blocked_until > ?
         ORDER BY blocked_until ASC`
    ).all(now) as any[];

    const activeCooldowns = cooldownRows.map(row => ({
        scope: {
            type: row.scope_type,
            key: row.scope_key
        },
        createdAt: row.created_at,
        blockedUntil: row.blocked_until,
        remainingSeconds: Math.ceil(
            (row.blocked_until - now) / 1000
        ),
        triggerEventId: row.trigger_event_id
    }));

    // Get the newest 20 security alerts
    const alertRows = db.prepare(
        `SELECT id, timestamp_utc, event_type, rule_id,
                severity, scope_type, scope_key
         FROM security_events
         ORDER BY timestamp_utc DESC, id DESC
         LIMIT 20`
    ).all() as any[];

    const recentAlerts = alertRows.map(row => ({
        id: row.id,
        timestampUtc: row.timestamp_utc,
        eventType: row.event_type,
        ruleId: row.rule_id,
        severity: row.severity,
        scope: {
            type: row.scope_type,
            key: row.scope_key
        },
        summary: summaryForRule(row.rule_id)
    }));

    // Get the newest 20 login attempts
    const loginRows = db.prepare(
        `SELECT id, request_id, timestamp_utc,
                username_key, source_ip, user_id,
                outcome, blocked_scopes_json
         FROM login_attempts
         ORDER BY timestamp_utc DESC, id DESC
         LIMIT 20`
    ).all() as any[];

    const recentLoginAttempts = loginRows.map(row => ({
        id: row.id,
        requestId: row.request_id,
        timestampUtc: row.timestamp_utc,
        usernameKey: row.username_key,
        sourceIp: row.source_ip,
        userId: row.user_id,
        outcome: row.outcome,
        blockedScopes: JSON.parse(row.blocked_scopes_json)
    }));

    // Send the dashboard information back
    return {
        generatedAt: now,
        loginMode,
        totals: {
            successfulLogins,
            failedLogins,
            blockedLogins,
            searchQueries,
            sqlInjectionAlerts,
            bruteForceAlerts,
            accountBruteForceAlerts,
            ipBruteForceAlerts
        },
        activeCooldowns,
        recentAlerts,
        recentLoginAttempts
    };
}

// Get just the active cooldown information
export function getCooldownData(db: DatabaseSync, now: number) {
    const data = getDashboardData(db, now, "observe");

    return {
        generatedAt: now,
        activeCooldowns: data.activeCooldowns
    };
}

// Create the three administrator routes
// requireAdmin must come from Bin's login/session module
export function createDashboardRouter(
    deps: AppDependencies,
    requireAdmin: RequestHandler
): Router {
    const router = Router();

    // Return dashboard totals and recent activity
    router.get("/api/dashboard", requireAdmin, (_req, res) => {
        const data = getDashboardData(
            deps.db,
            deps.clock.now(),
            deps.config.loginMode
        );

        res.json(data);
    });

    // Return active cooldowns
    router.get("/api/cooldowns", requireAdmin, (_req, res) => {
        res.json(getCooldownData(deps.db, deps.clock.now()));
    });

    // Return the evidence for one alert
    router.get("/api/alerts/:id", requireAdmin, (req, res) => {
        const idText = req.params.id;

        // Only accept positive whole-number IDs
        if (!/^[1-9][0-9]*$/.test(idText)) {
            res.status(400).json({
                error: {
                    code: "INVALID_REQUEST",
                    message: "Invalid alert ID."
                }
            });
            return;
        }

        const id = Number(idText);

        if (!Number.isSafeInteger(id)) {
            res.status(400).json({
                error: {
                    code: "INVALID_REQUEST",
                    message: "Invalid alert ID."
                }
            });
            return;
        }

        // Use the team's existing evidence reader
        const alert = readAlertEvidence(deps.db, id);

        if (!alert) {
            res.status(404).json({
                error: {
                    code: "NOT_FOUND",
                    message: "Alert not found."
                }
            });
            return;
        }

        res.json(alert);
    });

    return router;
}

