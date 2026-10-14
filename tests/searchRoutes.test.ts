import { afterEach, describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import type { Server } from "node:http";
import { createApp } from "../src/server/app.js";
import { createFakeClock } from "../src/server/clock.js";
import { loadConfig } from "../src/server/config.js";
import { applySchema } from "../src/server/db.js";
import { seedProducts } from "../src/server/seedProducts.js";

describe("Search HTTP routes", () => {
  const servers: Server[] = [];
  const databases: DatabaseSync[] = [];

  afterEach(async () => {
    for (const server of servers.splice(0)) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }

    for (const db of databases.splice(0)) {
      db.close();
    }
  });

  async function startApp(labMode: boolean) {
    const db = new DatabaseSync(":memory:");
    databases.push(db);
    applySchema(db);
    seedProducts(db);

    const config = {
      ...loadConfig(),
      labMode,
    };

    const app = createApp({
      db,
      config,
      clock: createFakeClock(1000),
    });

    const server: Server = await new Promise((resolve) => {
      const listening = app.listen(0, "127.0.0.1", () => {
        resolve(listening);
      });
    });

    servers.push(server);

    const address = server.address();

    if (!address || typeof address === "string") {
      throw new Error("Could not start test server");
    }

    return `http://127.0.0.1:${address.port}`;
  }

  it("rejects unauthenticated protected searches", async () => {
    const baseUrl = await startApp(false);

    const response = await fetch(
      `${baseUrl}/api/search/protected?q=Mouse`
    );

    expect(response.status).toBe(401);

    const body = await response.json();
    expect(body).toEqual({
      error: {
        code: "AUTH_REQUIRED",
        message: "Login required.",
      },
    });
  });

  it("rejects unauthenticated vulnerable searches", async () => {
    const baseUrl = await startApp(true);

    const response = await fetch(
      `${baseUrl}/api/search/vulnerable?q=Mouse`
    );

    expect(response.status).toBe(401);
  });

  it("does not expose SQL details in unauthorized responses", async () => {
    const baseUrl = await startApp(true);

    const response = await fetch(
      `${baseUrl}/api/search/vulnerable?q=${encodeURIComponent("' OR 1=1 --")}`
    );

    expect(response.status).toBe(401);

    const body = JSON.stringify(await response.json());

    expect(body).not.toContain("SELECT");
    expect(body).not.toContain("FROM products");
    expect(body).not.toContain("stack");
  });

  it("does not audit unauthenticated search requests", async () => {
    const baseUrl = await startApp(true);

    await fetch(`${baseUrl}/api/search/protected?q=Mouse`);

    const db = databases[0];

    const row = db.prepare(
      "SELECT COUNT(*) AS count FROM query_audit"
    ).get() as { count: number };

    expect(row.count).toBe(0);
  });
});
