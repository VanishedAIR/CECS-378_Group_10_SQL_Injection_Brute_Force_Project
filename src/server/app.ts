import express, { type Router } from "express";
import type { Server } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { DatabaseSync } from "node:sqlite";
import { systemClock, type Clock } from "./clock.js";
import { loadConfig, resolveProjectPath, type ServerConfig } from "./config.js";
import { applySchema, closeDatabase, openDatabase } from "./db.js";
import { attachRequestContext, handleUnexpectedError } from "./http.js";

/** Shared objects future route modules receive. They must not open their own database. */
export type AppDependencies = {
  db: DatabaseSync;
  config: ServerConfig;
  clock: Clock;
};

/**
 * Bin, real thd, and Ediz each export a function with this shape and add one
 * line to `moduleRouters` in this file when their module exists.
 * Example (do not import until the file exists):
 *   moduleRouters.push((deps) => createAuthRouter(deps));
 */
export type ModuleRouterFactory = (deps: AppDependencies) => Router;

export const moduleRouters: ModuleRouterFactory[] = [];

export function openLabDatabase(config: ServerConfig): DatabaseSync {
  const db = openDatabase(config.databasePath);
  applySchema(db);
  return db;
}

export function createApp(
  deps: AppDependencies,
  extraRouters: ModuleRouterFactory[] = []
): express.Express {
  const app = express();
  app.set("trust proxy", false);
  app.disable("x-powered-by");
  app.locals.lab = deps;

  app.use(attachRequestContext);
  app.use(express.json({ limit: "32kb" }));
  app.use(express.static(resolveProjectPath("public")));

    // Serve the public folder
  app.use(express.static(resolveProjectPath("public")));
  
  // Serve our CSS file
  app.get("/style.css", (_req, res) => {
      res.sendFile(resolveProjectPath("static/style.css"));
  });
  
  // Serve our browser JavaScript files
  app.use(
      "/client",
      express.static(resolveProjectPath("dist/src/client"))
  );
  
  // Open the login page
  app.get("/login", (_req, res) => {
      res.sendFile(resolveProjectPath("public/login.html"));
  });
  
  // Open the search page
  app.get("/search", (_req, res) => {
      res.sendFile(resolveProjectPath("public/search.html"));
  });
  
  // Open the dashboard page
  app.get("/dashboard", (_req, res) => {
      res.sendFile(resolveProjectPath("public/dashboard.html"));
  });

  // Serve the dashboard CSS file
  app.get("/style.css", (_req, res) => {
      res.sendFile(resolveProjectPath("static/style.css"));
  });

  // Serve the compiled browser TypeScript
  app.use(
      "/client",
      express.static(resolveProjectPath("dist/src/client"))
  );

  
  app.get("/health", (_req, res) => {
    res.json({ ok: true });
  });

  for (const factory of [...moduleRouters, ...extraRouters]) {
    app.use(factory(deps));
  }

  app.use(handleUnexpectedError);
  return app;
}

export function shutdownServer(server: Server, db: DatabaseSync): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      closeDatabase(db);
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

export function startServer(): void {
  const config = loadConfig();
  const db = openLabDatabase(config);
  const app = createApp({ db, config, clock: systemClock() });

  const server = app.listen(config.port, config.host, () => {
    console.log(
      `Security lab listening at http://${config.host}:${config.port}/`
    );
  });

  const stop = (): void => {
    void shutdownServer(server, db).then(() => {
      process.exit(0);
    });
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

const isMain =
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isMain) {
  startServer();
}
