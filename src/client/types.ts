import type { AlertSummary, LoginAttemptRecord, QueryAuditRecord } from "../server/audit.js";
export type User = {
    id: number;
    usernameKey: string;
    displayUsername: string;
    role: "user" | "admin";
};
export type Cooldown = {
    scope: {
        type: string;
        key: string;
    };
    createdAt: number;
    blockedUntil: number;
    remainingSeconds: number;
    triggerEventId: number;
};
export type Totals = Record<"successfulLogins" | "failedLogins" | "blockedLogins" | "searchQueries" | "sqlInjectionAlerts" | "bruteForceAlerts" | "accountBruteForceAlerts" | "ipBruteForceAlerts", number>;
export type DashboardData = {
    generatedAt: number;
    loginMode: string;
    totals: Totals;
    activeCooldowns: Cooldown[];
    recentAlerts: AlertSummary[];
    recentLoginAttempts: LoginAttemptRecord[];
};
export type AlertBundle = {
    alert: AlertSummary;
    details: Record<string, unknown>;
    evidence: {
        loginAttempts: LoginAttemptRecord[];
        query: QueryAuditRecord | null;
    };
};
export type { AlertSummary, LoginAttemptRecord };
