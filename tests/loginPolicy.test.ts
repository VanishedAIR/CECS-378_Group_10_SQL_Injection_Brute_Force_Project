import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { applySchema } from "../src/server/db.js";
import { createFakeClock } from "../src/server/clock.js";
import { createLoginPolicy } from "../src/server/loginPolicy.js";
import type { ServerConfig } from "../src/server/config.js";

const base: ServerConfig = { host: "127.0.0.1", port: 3000, databasePath: ":memory:", labMode: true,
  loginMode: "protect", accountFailureLimit: 5, ipFailureLimit: 15, windowSeconds: 60,
  accountCooldownSeconds: 60, ipCooldownSeconds: 60 };
let db: DatabaseSync;
let clock: ReturnType<typeof createFakeClock>;
let sequence: number;
const failure = async () => ({ valid: false, userId: null });
const success = async () => ({ valid: true, userId: null });
function request(username = "demo_user", sourceIp = "127.0.0.1") {
  return { requestId: `request-${++sequence}`, username, sourceIp };
}
function count(table: string) { return (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n; }

beforeEach(() => { db = new DatabaseSync(":memory:"); applySchema(db); clock = createFakeClock(1000000); sequence = 0; });
afterEach(() => db.close());

describe("Huy login policy", () => {
  it("triggers account on fifth failure, then blocks sixth without verifying", async () => {
    const policy = createLoginPolicy(db, base, clock);
    for (let i = 0; i < 4; i++) expect((await policy.evaluate(request(), failure)).eventIds).toEqual([]);
    const fifth = await policy.evaluate(request(), failure);
    expect(fifth.status).toBe(401);
    expect(fifth.eventIds).toHaveLength(1);
    const blocked = await policy.evaluate(request(), async () => { throw new Error("verifier must not run"); });
    expect(blocked.status).toBe(429);
    expect(blocked.retryAfterSeconds).toBe(60);
    expect(count("security_events")).toBe(1);
    expect(count("login_attempts")).toBe(6);
  });
  it("observe mode alerts without blocking", async () => {
    const policy = createLoginPolicy(db, { ...base, loginMode: "observe" }, clock);
    for (let i = 0; i < 6; i++) expect((await policy.evaluate(request(), failure)).status).toBe(401);
    expect(count("security_events")).toBe(1);
    expect(count("cooldowns")).toBe(0);
  });
  it("normalizes username and aggregates across IP changes", async () => {
    const policy = createLoginPolicy(db, base, clock);
    for (let i = 0; i < 5; i++) await policy.evaluate(request(i % 2 ? " Demo_User " : "demo_user", `192.0.2.${i+1}`), failure);
    expect(count("security_events")).toBe(1);
    expect((await policy.evaluate(request("DEMO_USER", "198.51.100.1"), success)).status).toBe(429);
  });
  it("triggers IP threshold across different accounts", async () => {
    const policy = createLoginPolicy(db, base, clock);
    for (let i = 0; i < 15; i++) await policy.evaluate(request(`user_${Math.floor(i/3)}`, "198.51.100.1"), failure);
    const row = db.prepare("SELECT scope_type FROM security_events").get() as { scope_type: string };
    expect(row.scope_type).toBe("ip");
    expect((await policy.evaluate(request("another_user", "198.51.100.1"), success)).status).toBe(429);
  });
  it("recovers at exact expiry; blocked requests do not extend expiry", async () => {
    const policy = createLoginPolicy(db, base, clock);
    for (let i = 0; i < 5; i++) await policy.evaluate(request(), failure);
    clock.advance(30000);
    expect((await policy.evaluate(request(), success)).status).toBe(429);
    clock.advance(30000);
    expect((await policy.evaluate(request(), success)).status).toBe(200);
  });
  it("excludes failures exactly at the rolling window boundary", async () => {
    const policy = createLoginPolicy(db, { ...base, loginMode: "observe" }, clock);
    await policy.evaluate(request(), failure);
    clock.advance(60000);
    for (let i = 0; i < 4; i++) await policy.evaluate(request(), failure);
    expect(count("security_events")).toBe(0);
  });
  it("serializes concurrent requests", async () => {
    const policy = createLoginPolicy(db, base, clock);
    const results = await Promise.all(Array.from({ length: 6 }, () => policy.evaluate(request(), failure)));
    expect(results.map((result) => result.status)).toEqual([401, 401, 401, 401, 401, 429]);
  });
});
