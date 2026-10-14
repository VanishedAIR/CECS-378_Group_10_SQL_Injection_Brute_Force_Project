
import express, { type Router } from "express";
import type { Server } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { DatabaseSync } from "node:sqlite";
import { systemClock, type Clock } from "./clock.js";
import { loadConfig, resolveProjectPath, type ServerConfig } from "./config.js";
import { applySchema, closeDatabase, openDatabase } from "./db.js";
import { attachRequestContext, handleUnexpectedError } from "./http.js";

/** Shared objects that other modules use. */
export type AppDependencies = {
  db: DatabaseSync;
  config: ServerConfig;
  clock: Clock;
};

/**
 * Each teammate can add their own routes here.
 * The main app shares the same database and settings.
 */
export type ModuleRouterFactory = (deps: AppDependencies) => Router;

export const moduleRouters: ModuleRouterFactory[] = [];

// Open the database and set up the tables
export function openLabDatabase(config: ServerConfig): DatabaseSync {
  const db = openDatabase(config.databasePath);
  applySchema(db);
  return db;
}

// Create our Express application
export function createApp(
  deps: AppDependencies,
  extraRouters: ModuleRouterFactory[] = []
): express.Express {
  const app = express();

  app.set("trust proxy", false);
  app.disable("x-powered-by");
  app.locals.lab = deps;

  // Set up requests
  app.use(attachRequestContext);
  app.use(express.json({ limit: "32kb" }));

  // Serve files from the public folder
  app.use(express.static(resolveProjectPath("public")));

  // Serve our CSS file
  app.get("/style.css", (_req, res) => {
    res.sendFile(resolveProjectPath("static/style.css"));
  });

  // Serve the compiled JavaScript files
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

  // Check if the server is running
  app.get("/health", (_req, res) => {
    res.json({ ok: true });
  });

  // Add routes from the other team members
  for (const factory of [...moduleRouters, ...extraRouters]) {
    app.use(factory(deps));
  }

  // Handle unexpected errors
  app.use(handleUnexpectedError);

  return app;
}

// Close the server and database
export function shutdownServer(
  server: Server,
  db: DatabaseSync
): Promise<void> {
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

// Start the server
export function startServer(): void {
  const config = loadConfig();
  const db = openLabDatabase(config);
  const app = createApp({ db, config, clock: systemClock() });

  const server = app.listen(config.port, config.host, () => {
    console.log(
      `Security lab listening at http://${config.host}:${config.port}/`
    );
  });

  // Stop the server safely
  const stop = (): void => {
    void shutdownServer(server, db).then(() => {
      process.exit(0);
    });
  };

  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

// Start only when this file is run directly
const isMain =
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isMain) {
  startServer();
}
