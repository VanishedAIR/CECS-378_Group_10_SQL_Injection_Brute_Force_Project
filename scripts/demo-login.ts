/** Local, simulated authentication demonstration. No real credentials or network requests. */
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
const db = new DatabaseSync(":memory:");
applySchema(db);
const clock = createFakeClock(1_000_000);
const policy = createLoginPolicy(db, config, clock);
const fail = async () => ({ valid: false, userId: null });
const succeed = async () => ({ valid: true, userId: null });
let id = 0;
const request = () => ({ requestId: `demo-${++id}`, username: " Demo_User ", sourceIp: "192.0.2.10" });
try {
  console.log("Local login-protection demo (simulated credential results)");
  for (let n = 1; n <= 5; n++) {
    const result = await policy.evaluate(request(), fail);
    console.log(`Failure ${n}: HTTP ${result.status}, new alerts: ${result.eventIds.length}`);
  }
  const blocked = await policy.evaluate(request(), async () => { throw new Error("Verifier should not run during cooldown"); });
  console.log(`Attempt 6: HTTP ${blocked.status}, retry after ${blocked.retryAfterSeconds}s`);
  clock.advance(60_000);
  const recovered = await policy.evaluate(request(), succeed);
  console.log(`After 60 seconds: HTTP ${recovered.status}`);
  if (blocked.status !== 429 || recovered.status !== 200) process.exitCode = 1;
} finally {
  db.close();
}
