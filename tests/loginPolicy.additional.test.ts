import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { applySchema } from "../src/server/db.js";
import { createFakeClock } from "../src/server/clock.js";
import { createLoginPolicy } from "../src/server/loginPolicy.js";
import type { ServerConfig } from "../src/server/config.js";

const config: ServerConfig = {
  host: "127.0.0.1", port: 3000, databasePath: ":memory:", labMode: true,
  loginMode: "protect", accountFailureLimit: 5, ipFailureLimit: 15,
  windowSeconds: 60, accountCooldownSeconds: 60, ipCooldownSeconds: 60,
};
const fail = async () => ({ valid: false, userId: null });
const success = async () => ({ valid: true, userId: null });

describe("Bin additional login-policy checks", () => {
  it("blocked attempts do not count as failures or extend cooldown", async () => {
    const db = new DatabaseSync(":memory:");
    try {
      applySchema(db);
      const clock = createFakeClock(1_000_000);
      const policy = createLoginPolicy(db, config, clock);
      let n = 0;
      const req = () => ({ requestId: `extra-${++n}`, username: "Demo", sourceIp: "192.0.2.1" });
      for (let i = 0; i < 5; i++) await policy.evaluate(req(), fail);
      const before = db.prepare("SELECT blocked_until FROM cooldowns WHERE scope_type = 'account'").get() as { blocked_until: number };
      clock.advance(30_000);
      const blocked = await policy.evaluate(req(), success);
      expect(blocked.status).toBe(429);
      expect(blocked.retryAfterSeconds).toBe(30);
      const after = db.prepare("SELECT blocked_until FROM cooldowns WHERE scope_type = 'account'").get() as { blocked_until: number };
      expect(after.blocked_until).toBe(before.blocked_until);
      const failures = db.prepare("SELECT COUNT(*) AS count FROM login_attempts WHERE outcome = 'failure'").get() as { count: number };
      expect(failures.count).toBe(5);
    } finally { db.close(); }
  });
  it("successful login does not increment failure count", async () => {
    const db = new DatabaseSync(":memory:");
    try {
      applySchema(db);
      const policy = createLoginPolicy(db, config, createFakeClock(1_000_000));
      const result = await policy.evaluate({ requestId: "successful", username: "demo", sourceIp: "192.0.2.1" }, success);
      expect(result.status).toBe(200);
      expect(result.eventIds).toEqual([]);
      const row = db.prepare("SELECT COUNT(*) AS count FROM login_attempts WHERE outcome = 'failure'").get() as { count: number };
      expect(row.count).toBe(0);
    } finally { db.close(); }
  });
});
