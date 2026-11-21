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

describe("Huy additional login-policy checks", () => {
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
  it("starts cooldown after delayed password verification", async () => {
    const db = new DatabaseSync(":memory:");
    try {
      applySchema(db);
      const clock = createFakeClock(1_000_000);
      const policy = createLoginPolicy(db, config, clock);

      let n = 0;
      const req = () => ({
        requestId: `delayed-${++n}`,
        username: "Demo",
        sourceIp: "192.0.2.10",
      });

      // Four failures occur at the initial time.
      for (let i = 0; i < 4; i++) {
        await policy.evaluate(req(), fail);
      }

      // The fifth verification takes 10 seconds.
      const result = await policy.evaluate(req(), async () => {
        clock.advance(10_000);
        return { valid: false, userId: null };
      });

      expect(result.status).toBe(401);
      expect(result.eventIds).toHaveLength(1);

      // The cooldown must begin when verification finishes.
      const cooldown = db.prepare(
        "SELECT blocked_until, created_at FROM cooldowns WHERE scope_type = 'account'"
      ).get() as {
        blocked_until: number;
        created_at: number;
      };

      expect(cooldown.created_at).toBe(1_010_000);
      expect(cooldown.blocked_until).toBe(1_070_000);

      // The fifth attempt must also use the refreshed timestamp.
      const attempt = db.prepare(
        "SELECT timestamp_utc FROM login_attempts WHERE request_id = ?"
      ).get("delayed-5") as { timestamp_utc: number };

      expect(attempt.timestamp_utc).toBe(1_010_000);
    } finally {
      db.close();
    }
  });

  it("excludes expired failures after delayed verification", async () => {
    const db = new DatabaseSync(":memory:");
    try {
      applySchema(db);
      const clock = createFakeClock(1_000_000);
      const policy = createLoginPolicy(db, config, clock);

      let n = 0;
      const req = () => ({
        requestId: `window-${++n}`,
        username: "Demo",
        sourceIp: "192.0.2.11",
      });

      // Four failures occur at the initial time.
      for (let i = 0; i < 4; i++) {
        await policy.evaluate(req(), fail);
      }

      // This verification completes after the 60-second window.
      const result = await policy.evaluate(req(), async () => {
        clock.advance(61_000);
        return { valid: false, userId: null };
      });

      expect(result.status).toBe(401);

      // The four earlier failures have expired, so no alert.
      expect(result.eventIds).toEqual([]);

      const cooldowns = db.prepare(
        "SELECT COUNT(*) AS count FROM cooldowns"
      ).get() as { count: number };

      expect(cooldowns.count).toBe(0);

      const attempt = db.prepare(
        "SELECT timestamp_utc FROM login_attempts WHERE request_id = ?"
      ).get("window-5") as { timestamp_utc: number };

      expect(attempt.timestamp_utc).toBe(1_061_000);
    } finally {
      db.close();
    }
  });
});
