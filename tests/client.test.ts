import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import { emptyFilters, filterAlerts, filterLogins, metricFilters } from "../src/client/dashboardModel.js";
import type { AlertBundle, DashboardData } from "../src/client/types.js";

/** Minimal event/text DOM for controller tests. It does not prove browser layout, focus order or accessibility. */
class Node {
  children: Node[] = []; listeners: Record<string, ((event: Event) => void)[]> = {};
  dataset: Record<string, string> = {}; attrs: Record<string, string> = {};
  value = ""; className = ""; hidden = false; disabled = false; type = ""; colSpan = 1;
  private text = "";
  constructor(public tag: string) {}
  set textContent(value: string) { this.text = String(value); this.children = []; }
  get textContent(): string { return this.text + this.children.map(child => child.textContent).join(""); }
  set innerHTML(_value: string) { throw Error("Unsafe HTML sink"); }
  appendChild(child: Node): Node { this.children.push(child); return child; }
  append(...nodes: Node[]): void { this.children.push(...nodes); }
  replaceChildren(...nodes: Node[]): void { this.text = ""; this.children = nodes; }
  setAttribute(name: string, value: string): void { this.attrs[name] = value; }
  addEventListener(name: string, fn: (event: Event) => void): void { (this.listeners[name] ??= []).push(fn); }
  focus(): void {}
  emit(name: string): void { for (const fn of this.listeners[name] ?? []) fn({ preventDefault() {} } as Event); }
}

/** Load actual template IDs and data attributes so renamed controls break these tests. */
function dom(page: string) {
  const nodes: Node[] = [], ids: Record<string, Node> = {};
  for (const match of fs.readFileSync(`public/${page}.html`, "utf8").matchAll(/<([a-z][\w-]*)\b([^>]+)>/g)) {
    const node = new Node(match[1]);
    for (const attr of match[2].matchAll(/([\w-]+)="([^"]*)"/g)) {
      if (attr[1] === "id") ids[attr[2]] = node;
      else if (attr[1].startsWith("data-")) node.dataset[attr[1].slice(5)] = attr[2];
    }
    node.hidden = /\bhidden\b/.test(match[2]); nodes.push(node);
  }
  vi.stubGlobal("document", { body: { dataset: { page } }, getElementById: (id: string) => ids[id] ?? null,
    createElement: (tag: string) => new Node(tag), querySelectorAll: (selector: string) => nodes.filter(n => selector === "[data-metric]" ? n.dataset.metric : n.dataset.total) });
  const assign = vi.fn();
  vi.stubGlobal("window", { location: { assign }, setInterval, clearInterval, addEventListener: vi.fn() });
  return { ids, nodes, assign };
}

/** Flush controller promises without waiting for wall-clock intervals. */
async function settle(): Promise<void> { for (let i = 0; i < 40; i++) await Promise.resolve(); }
/** Construct a JSON response and allow tests to detect accidental JSON parsing of a 204. */
function response(status: number, body?: unknown) { return { ok: status >= 200 && status < 300, status, json: vi.fn(async () => body) }; }
/** Supply a realistic dashboard payload with history totals larger than the loaded lists. */
function snapshot(): DashboardData {
  return { generatedAt: 1000, loginMode: "protect", totals: { successfulLogins: 80, failedLogins: 25, blockedLogins: 9, searchQueries: 40, sqlInjectionAlerts: 12, bruteForceAlerts: 7, accountBruteForceAlerts: 4, ipBruteForceAlerts: 3 }, activeCooldowns: [],
    recentAlerts: [
      { id: 3, timestampUtc: 1000, eventType: "SQLI_ATTEMPT", ruleId: "SQLI_SIGNATURE_V1", severity: "medium", scope: { type: "request", key: "request-3" }, summary: "SQL pattern" },
      { id: 2, timestampUtc: 900, eventType: "BRUTE_FORCE_DETECTED", ruleId: "LOGIN_ACCOUNT_FAILURE_LIMIT_V1", severity: "medium", scope: { type: "account", key: "demo_user" }, summary: "Account failure threshold" },
      { id: 1, timestampUtc: 800, eventType: "BRUTE_FORCE_DETECTED", ruleId: "LOGIN_IP_FAILURE_LIMIT_V1", severity: "medium", scope: { type: "ip", key: "127.0.0.1" }, summary: "IP failure threshold" }],
    recentLoginAttempts: ["success", "failure", "blocked"].map((outcome, i) => ({ id: i + 1, requestId: `r${i}`, timestampUtc: 1000, usernameKey: "demo_user", sourceIp: "127.0.0.1", userId: 1, outcome: outcome as "success" | "failure" | "blocked", blockedScopes: outcome === "blocked" ? ["account"] : [] })) };
}
const user = { user: { id: 2, usernameKey: "demo_admin", displayUsername: "Demo Admin", role: "admin" } };
const detail: AlertBundle = { alert: snapshot().recentAlerts[0], details: { matchedIndicators: ["sql_comment"] }, evidence: { loginAttempts: [], query: { id: 1, requestId: "q1", timestampUtc: 1000, userId: 1, sourceIp: "127.0.0.1", routeMode: "protected", inputExcerpt: "<img src=x onerror=alert(1)>", queryTemplate: "SELECT name FROM products WHERE name LIKE ?", parameters: ["%<img>%"], labSql: null, resultCount: 0, durationMs: 1, errorCode: null } } };

beforeEach(() => { vi.resetModules(); vi.useFakeTimers(); });
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("Recent-record filters", () => {
  it("translates cards into scoped filters without changing retained totals", () => {
    const data = snapshot(); expect(filterAlerts(data.recentAlerts, metricFilters("account")).map(x => x.id)).toEqual([2]);
    expect(filterAlerts(data.recentAlerts, metricFilters("ip")).map(x => x.id)).toEqual([1]);
    expect(filterAlerts(data.recentAlerts, metricFilters("sql")).map(x => x.id)).toEqual([3]);
    expect(filterLogins(data.recentLoginAttempts, metricFilters("blocked"))).toHaveLength(1);
    expect(data.totals.sqlInjectionAlerts).toBe(12);
  });
  it("combines visible-text filters and restores all loaded rows on clear", () => {
    expect(filterAlerts(snapshot().recentAlerts, { ...metricFilters("brute"), term: "DEMO_USER" })).toHaveLength(1);
    expect(filterLogins(snapshot().recentLoginAttempts, { ...emptyFilters(), term: "absent" })).toEqual([]);
    expect(filterAlerts(snapshot().recentAlerts, emptyFilters())).toHaveLength(3);
  });
});

describe("Login and shared session controls", () => {
  it("keeps password spaces, suppresses duplicate submits, and respects the actual retry delay", async () => {
    const { ids } = dom("login"); ids.username.value = " Demo_User "; ids.password.value = " password with spaces ";
    let finish!: (value: unknown) => void;
    const fetch = vi.fn((_url: string, _options?: RequestInit) => new Promise(resolve => { finish = resolve; })); vi.stubGlobal("fetch", fetch);
    await import("../src/client/login.js"); ids["login-form"].emit("submit"); ids["login-form"].emit("submit");
    expect(fetch).toHaveBeenCalledTimes(1); expect(JSON.parse(fetch.mock.calls[0][1]!.body as string)).toEqual({ username: " Demo_User ", password: " password with spaces " });
    finish(response(429, { error: { code: "LOGIN_COOLDOWN", message: "Login temporarily restricted." }, retryAfterSeconds: 60 })); await settle();
    expect(ids.message.textContent).toContain("60 seconds"); expect(ids.submit.disabled).toBe(true);
    vi.advanceTimersByTime(60_000); expect(ids.submit.disabled).toBe(false); expect(ids.password.value).toBe(" password with spaces ");
  });
  it("reenables the form after a network failure", async () => {
    const { ids } = dom("login"); vi.stubGlobal("fetch", vi.fn().mockRejectedValue(Error("offline")));
    await import("../src/client/login.js"); ids["login-form"].emit("submit"); await settle();
    expect(ids.message.textContent).toContain("local server"); expect(ids.submit.disabled).toBe(false);
  });
  it("clears data before logout and does not parse an empty 204", async () => {
    const { assign } = dom("search"); const empty = response(204); const clear = vi.fn();
    vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(url === "/api/me" ? response(200, user) : empty)));
    const common = await import("../src/client/common.js"); await common.initShell(clear); await common.logout();
    expect(clear).toHaveBeenCalledOnce(); expect(empty.json).not.toHaveBeenCalled(); expect(assign).toHaveBeenCalledWith("/login");
  });
  it("rejects a late JSON response after authentication has been lost", async () => {
    const { ids } = dom("dashboard"); let finish!: (data: unknown) => void; const clear = vi.fn();
    vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(url === "/api/me" ? response(200, user) : url === "/slow" ? { ok: true, status: 200, json: () => new Promise(resolve => { finish = resolve; }) } : response(401, { error: { message: "Expired" } }))));
    const common = await import("../src/client/common.js"); await common.initShell(clear);
    const slow = common.api("/slow"); await settle(); await expect(common.api("/denied")).rejects.toThrow("Expired");
    finish({ sensitive: true }); await expect(slow).rejects.toThrow("Session changed"); expect(clear).toHaveBeenCalled(); expect(ids["sign-in-again"].hidden).toBe(false);
  });
});

describe("Catalog controller", () => {
  it("preserves q and renders hostile-looking product text without HTML", async () => {
    const { ids } = dom("search");
    const fetch = vi.fn((url: string) => Promise.resolve(response(200, url === "/api/me" ? user : { mode: "protected", resultCount: 1, rows: [{ id: 1, name: "<img src=x onerror=alert(1)>", description: "<script>text</script>" }] }))); vi.stubGlobal("fetch", fetch);
    await import("../src/client/search.js"); await settle(); ids["search-input"].value = " Mouse ' "; ids["search-form"].emit("submit"); await settle();
    expect(fetch.mock.calls[1][0]).toBe("/api/search/protected?q=" + encodeURIComponent(" Mouse ' "));
    expect(ids.results.textContent).toContain("<img"); expect(ids.results.children[0].tag).toBe("article"); expect(ids["result-count"].textContent).toContain("1 product");
  });
  it("explains LAB_MODE rejection without discarding the input", async () => {
    const { ids } = dom("search"); vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(url === "/api/me" ? response(200, user) : response(404, { error: { message: "Not found." } }))));
    await import("../src/client/search.js"); await settle(); ids["search-input"].value = "Mouse"; ids.vulnerable.emit("click"); await settle();
    expect(ids.message.textContent).toContain("LAB_MODE=true"); expect(ids["search-input"].value).toBe("Mouse");
  });
});

describe("Dashboard controller", () => {
  it("clicks cards, combines controls, clears filters, and shows loaded counts separately", async () => {
    const { ids, nodes } = dom("dashboard"); vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(response(200, url === "/api/me" ? user : snapshot()))));
    await import("../src/client/dashboard.js"); await settle();
    const account = nodes.find(n => n.dataset.metric === "account")!; account.emit("click");
    expect(account.attrs["aria-pressed"]).toBe("true"); expect(ids["alert-count"].textContent).toBe("Showing 1 of 3 loaded alerts");
    expect(nodes.find(n => n.dataset.total === "accountBruteForceAlerts")!.textContent).toBe("4");
    ids["record-search"].value = "absent"; ids["record-search"].emit("input"); expect(ids.alerts.textContent).toContain("No loaded alerts match");
    ids["clear-filters"].emit("click"); expect(ids["alert-count"].textContent).toContain("3 of 3"); expect(account.attrs["aria-pressed"]).toBe("false");
    const blocked = nodes.find(n => n.dataset.metric === "blocked")!; blocked.emit("click"); expect(ids["login-count"].textContent).toBe("Showing 1 of 3 loaded login attempts");
  });
  it("opens structured evidence as text and closes it on refresh", async () => {
    const { ids } = dom("dashboard"); vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(response(200, url === "/api/me" ? user : url.startsWith("/api/alerts/") ? detail : snapshot()))));
    await import("../src/client/dashboard.js"); await settle(); ids.alerts.children[0].children[4].children[0].emit("click"); await settle();
    expect(ids["detail-panel"].hidden).toBe(false); expect(ids["alert-details"].textContent).toContain("Bound parameters"); expect(ids["alert-details"].textContent).toContain("<img");
    ids.refresh.emit("click"); await settle(); expect(ids["detail-panel"].hidden).toBe(true); expect(ids["alert-details"].textContent).toBe("");
  });
  it("erases old totals and evidence on a failed refresh, then permits retry", async () => {
    const { ids, nodes } = dom("dashboard"); let fail = false;
    vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(url === "/api/me" ? response(200, user) : fail ? response(500, { error: { message: "Unavailable" } }) : response(200, snapshot()))));
    await import("../src/client/dashboard.js"); await settle(); fail = true; ids.refresh.emit("click"); await settle();
    expect(nodes.find(n => n.dataset.total)!.textContent).toBe("Not loaded"); expect(ids.alerts.textContent).toContain("No authorized snapshot"); expect(ids.refresh.disabled).toBe(false);
    fail = false; ids.refresh.emit("click"); await settle(); expect(ids["alert-count"].textContent).toContain("3 of 3");
  });
  it("clears loaded security data on a session denial", async () => {
    const { ids, nodes } = dom("dashboard"); let denied = false;
    vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(url === "/api/me" ? response(200, user) : denied ? response(401, { error: { message: "Authentication is required." } }) : response(200, snapshot()))));
    await import("../src/client/dashboard.js"); await settle(); denied = true; ids.refresh.emit("click"); await settle();
    expect(nodes.find(n => n.dataset.total)!.textContent).toBe("Not loaded"); expect(ids.refresh.disabled).toBe(true); expect(ids["sign-in-again"].hidden).toBe(false);
  });
  it("does not reopen dismissed evidence when a slow detail response arrives", async () => {
    const { ids } = dom("dashboard"); let finish!: (value: unknown) => void;
    vi.stubGlobal("fetch", vi.fn((url: string) => url.startsWith("/api/alerts/") ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(response(200, url === "/api/me" ? user : snapshot()))));
    await import("../src/client/dashboard.js"); await settle(); ids.alerts.children[0].children[4].children[0].emit("click"); await settle();
    ids["close-detail"].emit("click"); finish(response(200, detail)); await settle();
    expect(ids["detail-panel"].hidden).toBe(true); expect(ids["alert-details"].textContent).toBe("");
  });
  it("renders genuine empty lists and revoked administrator access", async () => {
    const { ids } = dom("dashboard"); const empty = snapshot(); empty.recentAlerts = []; empty.recentLoginAttempts = [];
    let demoted = false;
    vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(response(200, url === "/api/me" ? (demoted ? { user: { ...user.user, role: "user" } } : user) : empty))));
    await import("../src/client/dashboard.js"); await settle(); expect(ids.alerts.textContent).toContain("No security alerts"); expect(ids.logins.textContent).toContain("No login attempts");
    demoted = true; vi.advanceTimersByTime(30_000); await settle();
    expect(ids.alerts.textContent).toContain("No authorized snapshot"); expect(ids["admin-link"].hidden).toBe(true);
  });
});
