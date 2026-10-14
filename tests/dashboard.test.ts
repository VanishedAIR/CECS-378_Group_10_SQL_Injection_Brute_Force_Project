
import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { applySchema } from "../src/server/db.js";
import {
    getDashboardData,
    getCooldownData
} from "../src/server/dashboard.js";

describe("Dashboard Tests", () => {

    // Create a new temporary database for each test
    function makeDatabase() {
        const db = new DatabaseSync(":memory:");
        applySchema(db);
        return db;
    }

    it("starts with zero security events", () => {
        const db = makeDatabase();

        // Get dashboard data from the empty database
        const data = getDashboardData(db, 100000, "observe");

        expect(data.totals.failedLogins).toBe(0);
        expect(data.totals.sqlInjectionAlerts).toBe(0);
        expect(data.totals.bruteForceAlerts).toBe(0);

        db.close();
    });

    it("counts failed logins", () => {
        const db = makeDatabase();

        // Add a fake failed login
        db.prepare(
            `INSERT INTO login_attempts
             (request_id, timestamp_utc, username_key,
              source_ip, outcome)
             VALUES (?, ?, ?, ?, ?)`
        ).run(
            "test-1",
            100000,
            "demo_user",
            "127.0.0.1",
            "failure"
        );

        const data = getDashboardData(db, 100000, "observe");

        // We should now have one failed login
        expect(data.totals.failedLogins).toBe(1);
        expect(data.recentLoginAttempts.length).toBe(1);

        db.close();
    });

    it("shows active cooldowns", () => {
        const db = makeDatabase();

        // Add one failed login for the alert evidence
        const result = db.prepare(
            `INSERT INTO login_attempts
             (request_id, timestamp_utc, username_key,
              source_ip, outcome)
             VALUES (?, ?, ?, ?, ?)`
        ).run(
            "test-cooldown",
            100000,
            "demo_user",
            "127.0.0.1",
            "failure"
        );

        // Add a test security alert
        const event = db.prepare(
            `INSERT INTO security_events
             (timestamp_utc, event_type, rule_id, severity,
              scope_type, scope_key, trigger_login_attempt_id,
              details_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
            100000,
            "BRUTE_FORCE_DETECTED",
            "LOGIN_ACCOUNT_FAILURE_LIMIT_V1",
            "medium",
            "account",
            "demo_user",
            Number(result.lastInsertRowid),
            "{}"
        );

        // This cooldown expires at 160000
        db.prepare(
            `INSERT INTO cooldowns
             (scope_type, scope_key, blocked_until,
              created_at, trigger_event_id)
             VALUES (?, ?, ?, ?, ?)`
        ).run(
            "account",
            "demo_user",
            160000,
            100000,
            Number(event.lastInsertRowid)
        );

        const data = getCooldownData(db, 100000);

        // The cooldown should have 60 seconds left
        expect(data.activeCooldowns.length).toBe(1);
        expect(data.activeCooldowns[0].remainingSeconds).toBe(60);

        // It should disappear after expiring
        const expired = getCooldownData(db, 160000);
        expect(expired.activeCooldowns.length).toBe(0);

        db.close();
    });

});

