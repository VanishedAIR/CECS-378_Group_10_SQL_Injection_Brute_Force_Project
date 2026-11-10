import { api, ApiError, element, initShell, showTime, textNode } from "./common.js";
import { emptyFilters, metricFilters, filterAlerts, filterLogins } from "./dashboardModel.js";
import type { AlertBundle, DashboardData, LoginAttemptRecord } from "./types.js";
let data: DashboardData | undefined;
let filters = emptyFilters();
let loadVersion = 0, detailVersion = 0;
let authorized = false;
const cards = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-metric]"));
/** Add one safely rendered value to a table row. */
function cell(row: HTMLTableRowElement, value: string): HTMLTableCellElement {
    const node = textNode("td", value);
    row.appendChild(node);
    return node;
}
/** Replace a table body with a readable empty or unavailable state. */
function emptyTable(id: string, columns: number, message: string): void {
    const row = document.createElement("tr");
    const td = cell(row, message);
    td.colSpan = columns;
    element(id).replaceChildren(row);
}
/** Build an outcome badge with a text label as well as a color. */
function outcomeLabel(attempt: LoginAttemptRecord): HTMLElement {
    const labels = { success: "Success", failure: "Failed credentials", blocked: "Blocked by cooldown" };
    return textNode("span", labels[attempt.outcome], `badge ${attempt.outcome}`);
}
/** Clear loaded counts, evidence and pending responses after access is lost or logout starts. */
function clearDashboard(): void {
    authorized = false;
    data = undefined;
    loadVersion++;
    closeDetail();
    for (const node of document.querySelectorAll<HTMLElement>("[data-total]"))
        node.textContent = "Not loaded";
    for (const [id, columns] of [["alerts", 5], ["logins", 5], ["cooldowns", 4]] as const)
        emptyTable(id, columns, "No authorized snapshot loaded.");
    element("alert-count").textContent = "No records loaded";
    element("login-count").textContent = "No records loaded";
    element("message").textContent = "Snapshot cleared. Sign in again to load security data.";
    element("snapshot-time").textContent = "No snapshot";
    element<HTMLButtonElement>("refresh").disabled = true;
    element("report").setAttribute("aria-busy", "false");
}
/** Synchronize the visible controls and selected cards with the active recent-record filters. */
function syncFilters(): void {
    element<HTMLSelectElement>("alert-kind").value = filters.kind;
    element<HTMLSelectElement>("alert-scope").value = filters.scope;
    element<HTMLSelectElement>("login-outcome").value = filters.outcome;
    element<HTMLInputElement>("record-search").value = filters.term;
    for (const card of cards)
        card.setAttribute("aria-pressed", String(card.dataset.metric === filters.metric));
}
/** Render only the loaded recent records; history totals are deliberately left unchanged. */
function renderRecent(): void {
    if (!data)
        return;
    const alerts = filterAlerts(data.recentAlerts, filters), logins = filterLogins(data.recentLoginAttempts, filters);
    element("alert-count").textContent = `Showing ${alerts.length} of ${data.recentAlerts.length} loaded alerts`;
    element("login-count").textContent = `Showing ${logins.length} of ${data.recentLoginAttempts.length} loaded login attempts`;
    const labels = [filters.kind === "all" ? "all alert types" : filters.kind === "SQLI_ATTEMPT" ? "SQL alerts" : "brute-force alerts", filters.scope === "all" ? "all scopes" : `${filters.scope} scope`, filters.outcome === "all" ? "all login outcomes" : `${filters.outcome} logins`, filters.term ? `text: ${filters.term}` : "no text filter"];
    element("filter-label").textContent = `Recent-record filters: ${labels.join("; ")}.`;
    element("alerts").replaceChildren();
    for (const alert of alerts) {
        const row = document.createElement("tr");
        cell(row, showTime(alert.timestampUtc));
        const summary = cell(row, "");
        summary.append(textNode("span", alert.eventType === "SQLI_ATTEMPT" ? "SQL pattern" : "Brute force", "badge " + (alert.eventType === "SQLI_ATTEMPT" ? "info" : "warning")), textNode("div", alert.summary, "row-summary"));
        cell(row, `${alert.scope.type}: ${alert.scope.key}`);
        cell(row, alert.severity);
        const button = textNode("button", `Inspect #${alert.id}`, "button small secondary");
        button.type = "button";
        button.addEventListener("click", () => { void loadAlert(alert.id); });
        cell(row, "").appendChild(button);
        element("alerts").appendChild(row);
    }
    if (!alerts.length)
        emptyTable("alerts", 5, data.recentAlerts.length ? "No loaded alerts match these filters. Clear filters to see the other recent records." : "No security alerts have been recorded yet.");
    element("logins").replaceChildren();
    for (const attempt of logins) {
        const row = document.createElement("tr");
        row.className = `outcome-${attempt.outcome}`;
        cell(row, showTime(attempt.timestampUtc));
        cell(row, attempt.usernameKey);
        cell(row, attempt.sourceIp);
        cell(row, "").appendChild(outcomeLabel(attempt));
        cell(row, attempt.blockedScopes.length ? attempt.blockedScopes.join(" + ") : "None");
        element("logins").appendChild(row);
    }
    if (!logins.length)
        emptyTable("logins", 5, data.recentLoginAttempts.length ? "No loaded login attempts match these filters." : "No login attempts recorded yet.");
}
/** Fetch a new authorized snapshot. Discard old evidence and fail closed if the refresh fails. */
async function refresh(): Promise<void> {
    if (!authorized)
        return;
    const current = ++loadVersion;
    closeDetail();
    data = undefined;
    element<HTMLButtonElement>("refresh").disabled = true;
    element("report").setAttribute("aria-busy", "true");
    element("message").textContent = "Loading a new snapshot...";
    try {
        const next = await api<DashboardData>("/api/dashboard");
        if (current !== loadVersion)
            return;
        data = next;
        for (const node of document.querySelectorAll<HTMLElement>("[data-total]"))
            node.textContent = String(next.totals[node.dataset.total as keyof typeof next.totals]);
        element("mode").textContent = `${next.loginMode === "protect" ? "Protect" : "Observe"} mode`;
        element("snapshot-time").textContent = `Snapshot: ${showTime(next.generatedAt)}`;
        element("cooldowns").replaceChildren();
        for (const cooldown of next.activeCooldowns) {
            const row = document.createElement("tr");
            cell(row, `${cooldown.scope.type}: ${cooldown.scope.key}`);
            cell(row, showTime(cooldown.blockedUntil));
            cell(row, `${cooldown.remainingSeconds} seconds at capture`);
            const button = textNode("button", `Inspect #${cooldown.triggerEventId}`, "button small secondary");
            button.type = "button";
            button.addEventListener("click", () => { void loadAlert(cooldown.triggerEventId); });
            cell(row, "").appendChild(button);
            element("cooldowns").appendChild(row);
        }
        if (!next.activeCooldowns.length)
            emptyTable("cooldowns", 4, "No active cooldowns at capture.");
        syncFilters();
        renderRecent();
        element("message").className = "notice";
        element("message").textContent = "Snapshot loaded. Refresh to check for new records or expired cooldowns.";
    }
    catch (error) {
        if (current !== loadVersion)
            return;
        // A failed refresh must not leave old figures looking current.
        clearDashboard();
        authorized = !(error instanceof ApiError && [401, 403].includes(error.status));
        element("message").className = "notice error";
        element("message").textContent = error instanceof Error ? error.message : "Could not load security data. Retry refresh.";
    }
    finally {
        if (current === loadVersion || !data) {
            element<HTMLButtonElement>("refresh").disabled = !authorized;
            element("report").setAttribute("aria-busy", "false");
        }
    }
}
/** Add a label/value pair to the structured evidence summary. Values remain text. */
function fact(list: HTMLElement, label: string, value: unknown): void {
    list.append(textNode("dt", label), textNode("dd", value === null || value === undefined ? "Not applicable" : String(value)));
}
/** Add readable SQL or JSON data without interpreting any part as HTML. */
function codeBlock(parent: HTMLElement, label: string, value: string): void {
    parent.append(textNode("h3", label), textNode("pre", value, "code-block"));
}
/** Display the linked query or exact contributing login attempts, rather than a raw JSON dump. */
function renderEvidence(bundle: AlertBundle): void {
    const target = element("alert-details");
    target.replaceChildren();
    const facts = textNode("dl", "", "facts");
    fact(facts, "Rule", bundle.alert.ruleId);
    fact(facts, "Recorded", showTime(bundle.alert.timestampUtc));
    fact(facts, "Scope", `${bundle.alert.scope.type}: ${bundle.alert.scope.key}`);
    fact(facts, "Severity", bundle.alert.severity);
    target.appendChild(facts);
    const query = bundle.evidence.query;
    if (query) {
        const summary = textNode("dl", "", "facts");
        fact(summary, "Query evidence", `#${query.id} (${query.routeMode})`);
        fact(summary, "Request ID", query.requestId);
        fact(summary, "Account / source", `User #${query.userId}, source ${query.sourceIp}`);
        fact(summary, "Outcome", query.errorCode ?? `${query.resultCount} results`);
        fact(summary, "Duration", `${query.durationMs.toFixed(2)} ms`);
        fact(summary, "Indicators", Array.isArray(bundle.details.matchedIndicators) ? bundle.details.matchedIndicators.join(", ") : "None");
        target.appendChild(summary);
        codeBlock(target, "Submitted input", query.inputExcerpt);
        codeBlock(target, "SQL template", query.queryTemplate);
        codeBlock(target, "Bound parameters", JSON.stringify(query.parameters, null, 2));
        codeBlock(target, "Executed lab SQL", query.labSql ?? "Not used. The protected query binds values separately.");
    }
    else {
        const policy = textNode("dl", "", "facts");
        fact(policy, "Failure count / threshold", `${bundle.details.count} / ${bundle.details.limit}`);
        fact(policy, "Window start (exclusive)", showTime(Number(bundle.details.windowStart)));
        fact(policy, "Window end (inclusive)", showTime(Number(bundle.details.windowEnd)));
        fact(policy, "Policy mode", bundle.details.loginMode);
        fact(policy, "Cooldown until", bundle.details.cooldownUntil === null ? "None (Observe mode)" : showTime(Number(bundle.details.cooldownUntil)));
        target.append(policy, textNode("h3", "Linked login evidence (oldest first)"));
        for (const attempt of bundle.evidence.loginAttempts) {
            const entry = textNode("article", "", "evidence-entry");
            entry.append(textNode("h4", `Attempt #${attempt.id}: ${attempt.usernameKey}`), outcomeLabel(attempt), textNode("p", `${showTime(attempt.timestampUtc)}. Source: ${attempt.sourceIp}`), textNode("p", `Request: ${attempt.requestId}`, "mono"));
            target.appendChild(entry);
        }
        if (!bundle.evidence.loginAttempts.length)
            target.appendChild(textNode("p", "No linked login records are available."));
    }
}
/** Load one alert; an older response cannot reopen a dismissed or cleared detail panel. */
async function loadAlert(id: number): Promise<void> {
    if (!authorized)
        return;
    const current = ++detailVersion;
    element("detail-panel").hidden = false;
    element("alert-details").replaceChildren();
    element("detail-title").textContent = `Alert #${id}`;
    element("alert-message").textContent = "Loading linked evidence...";
    element("detail-title").focus();
    try {
        const bundle = await api<AlertBundle>(`/api/alerts/${id}`);
        if (current !== detailVersion)
            return;
        element("alert-message").textContent = bundle.alert.summary;
        renderEvidence(bundle);
    }
    catch (error) {
        if (current === detailVersion)
            element("alert-message").textContent = error instanceof Error ? error.message : "Evidence could not be loaded. Retry the Inspect button.";
    }
}
/** Dismiss and erase evidence, including an unfinished detail request. */
function closeDetail(): void { detailVersion++; element("detail-panel").hidden = true; element("alert-details").replaceChildren(); element("alert-message").textContent = ""; }
for (const card of cards)
    card.addEventListener("click", () => {
        filters = metricFilters(card.dataset.metric ?? "");
        syncFilters();
        renderRecent();
        element(filters.outcome !== "all" ? "login-heading" : "alert-heading").focus();
    });
for (const id of ["alert-kind", "alert-scope", "login-outcome", "record-search"])
    element(id).addEventListener(id === "record-search" ? "input" : "change", () => {
        filters = { kind: element<HTMLSelectElement>("alert-kind").value, scope: element<HTMLSelectElement>("alert-scope").value, outcome: element<HTMLSelectElement>("login-outcome").value, term: element<HTMLInputElement>("record-search").value, metric: "" };
        syncFilters();
        renderRecent();
    });
element("clear-filters").addEventListener("click", () => { filters = emptyFilters(); syncFilters(); renderRecent(); });
element("close-detail").addEventListener("click", () => { closeDetail(); element("alert-heading").focus(); });
element("refresh").addEventListener("click", () => { void refresh(); });
void initShell(clearDashboard).then(() => { authorized = true; void refresh(); }).catch(() => { clearDashboard(); });
