import type { AlertSummary, LoginAttemptRecord } from "./types.js";
export type Filters = {
    kind: string;
    scope: string;
    outcome: string;
    term: string;
    metric: string;
};
/** Start with all loaded records visible. Filters never fetch older history. */
export function emptyFilters(): Filters { return { kind: "all", scope: "all", outcome: "all", term: "", metric: "" }; }
/** Translate an applicable overview card into explicit recent-list filters. */
export function metricFilters(metric: string): Filters {
    const state = emptyFilters();
    state.metric = metric;
    if (["success", "failure", "blocked"].includes(metric))
        state.outcome = metric;
    else if (metric === "sql")
        state.kind = "SQLI_ATTEMPT";
    else if (["brute", "account", "ip"].includes(metric)) {
        state.kind = "BRUTE_FORCE_DETECTED";
        if (metric !== "brute")
            state.scope = metric;
    }
    return state;
}
/** Filter supplied alert summaries by kind, scope and visible text only. */
export function filterAlerts(rows: AlertSummary[], state: Filters): AlertSummary[] {
    const term = state.term.trim().toLowerCase();
    return rows.filter(row => (state.kind === "all" || row.eventType === state.kind) && (state.scope === "all" || row.scope.type === state.scope) && `${row.id} ${row.summary} ${row.ruleId} ${row.scope.type} ${row.scope.key}`.toLowerCase().includes(term));
}
/** Filter loaded attempts by outcome and visible username/IP/scope text. */
export function filterLogins(rows: LoginAttemptRecord[], state: Filters): LoginAttemptRecord[] {
    const term = state.term.trim().toLowerCase();
    return rows.filter(row => (state.outcome === "all" || row.outcome === state.outcome) && `${row.id} ${row.usernameKey} ${row.sourceIp} ${row.outcome} ${row.blockedScopes.join(" ")}`.toLowerCase().includes(term));
}
