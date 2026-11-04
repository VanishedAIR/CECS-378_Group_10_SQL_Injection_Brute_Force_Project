
import { afterEach, describe, expect, it } from "vitest";
import express, { type Router } from "express";
import { DatabaseSync } from "node:sqlite";
import { createApp, type AppDependencies } from "../src/server/app.js";
import { applySchema } from "../src/server/db.js";
import { createFakeClock } from "../src/server/clock.js";
import { createLoginPolicy } from "../src/server/loginPolicy.js";
import { sourceIpFromRequest, sendJsonError } from "../src/server/http.js";
import type { ServerConfig } from "../src/server/config.js";
import type { Server } from "node:http";

describe("login protection HTTP integration", () => {
  const servers: Server[] = [];
  const databases: DatabaseSync[] = [];

  afterEach(async () => {
    await Promise.all(
      servers.splice(0).map(
        (server) =>
          new Promise<void>((resolve, reject) => {
            server.close((error) =>
              error ? reject(error) : resolve()
            );
          })
      )
    );
    for (const db of databases.splice(0)) db.close();
  });

  it("blocks after five failures and allows login after cooldown", async () => {
    const db = new DatabaseSync(":memory:");
    databases.push(db);
    applySchema(db);

    const clock = createFakeClock(1_000_000);

    const config: ServerConfig = {
      host: "127.0.0.1",
      port: 3000,
      databasePath: ":memory:",
      labMode: true,
      loginMode: "protect",
      accountFailureLimit: 5,
      ipFailureLimit: 15,
      windowSeconds: 60,
      accountCooldownSeconds: 60,
      ipCooldownSeconds: 60,
    };

    const testRouter = (deps: AppDependencies): Router => {
      const router = express.Router();
      const policy = createLoginPolicy(
        deps.db,
        deps.config,
        deps.clock
      );

      router.post("/test-login", async (req, res, next) => {
        try {
          const username = req.body?.username;
          if (typeof username !== "string" || !username.trim()) {
            sendJsonError(res, 400, "INVALID_REQUEST", "Invalid username");
            return;
          }

          const result = await policy.evaluate(
            {
              requestId: req.requestId,
              username,
              sourceIp: sourceIpFromRequest(req),
            },
            async () => ({
              valid: req.body?.success === true,
              userId: null,
            })
          );

          if (result.status === 429) {
            res.setHeader(
              "Retry-After",
              String(result.retryAfterSeconds)
            );
            sendJsonError(
              res,
              429,
              "LOGIN_COOLDOWN",
              "Login temporarily restricted."
            );
            return;
          }

          if (result.status === 401) {
            sendJsonError(
              res,
              401,
              "INVALID_CREDENTIALS",
              "Invalid credentials."
            );
            return;
          }

          res.status(200).json({ ok: true });
        } catch (error) {
          next(error);
        }
      });

      return router;
    };

    const app = createApp(
      { db, config, clock },
      [testRouter]
    );

    const server = app.listen(0, "127.0.0.1");
    servers.push(server);

    await new Promise<void>((resolve) =>
      server.once("listening", resolve)
    );

    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Missing server address");
    }

    const url = `http://127.0.0.1:${address.port}/test-login`;

    const login = async (success: boolean) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: "Demo_User",
          success,
        }),
      });
      return response;
    };

    for (let i = 0; i < 5; i++) {
      const response = await login(false);
      expect(response.status).toBe(401);
      expect(response.headers.get("X-Request-Id")).toBeTruthy();
    }

    const blocked = await login(true);
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("Retry-After")).toBe("60");
    expect((await blocked.json()).error.code).toBe("LOGIN_COOLDOWN");

    clock.advance(60_000);

    const recovered = await login(true);
    expect(recovered.status).toBe(200);

    const attempts = db.prepare(
      "SELECT COUNT(*) AS count FROM login_attempts"
    ).get() as { count: number };

    expect(attempts.count).toBe(7);

    const events = db.prepare(
      "SELECT COUNT(*) AS count FROM security_events WHERE event_type = 'BRUTE_FORCE_DETECTED'"
    ).get() as { count: number };

    expect(events.count).toBe(1);
  });
});
