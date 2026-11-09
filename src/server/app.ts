
import "dotenv/config";
import express, { type Router } from "express";
import session from "express-session";
import type { Server } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { DatabaseSync } from "node:sqlite";

import { systemClock, type Clock } from "./clock.js";
import { loadConfig, resolveProjectPath, type ServerConfig } from "./config.js";
import { applySchema, closeDatabase, openDatabase } from "./db.js";
import { attachRequestContext, handleUnexpectedError } from "./http.js";
import { createSearchRouter } from "./searchRoutes.js";
import { createAuthRouter } from "./authRoutes.js";
import { requireSession, requireAdmin } from "./authMiddleware.js";
import { createDashboardRouter } from "./dashboard.js";
import {
  SESSION_COOKIE_NAME,
  SESSION_DURATION_MS,
} from "./sessions.js";

// Shared objects that all modules use
export type AppDependencies = {
  db: DatabaseSync;
  config: ServerConfig;
  clock: Clock;
};

// Each teammate can add their own routes here
export type ModuleRouterFactory = (deps: AppDependencies) => Router;



// Include the team's authentication, search, and dashboard routes
export const moduleRouters: ModuleRouterFactory[] = [
  // Bin's authentication routes
  (deps) => createAuthRouter(deps),

  // SQL injection search routes
  createSearchRouter,

  // Dashboard routes for administrators
  (deps) => {
    const router = express.Router();

    router.use(
      ["/api/dashboard", "/api/cooldowns", "/api/alerts"],
      requireSession(deps.db),
      requireAdmin
    );

    router.use(createDashboardRouter(deps, requireAdmin));

    return router;
  },
];

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

  // Set up the session secret
  const secret = deps.config.sessionSecret;

  if (!secret || secret.length < 32) {
    throw new Error(
      "SESSION_SECRET must be configured and contain at least 32 characters."
    );
  }

  app.locals.lab = deps;

  // Set up requests
  app.use(attachRequestContext);

  // Set up Bin's login sessions
  app.use(
    session({
      name: SESSION_COOKIE_NAME,
      secret,
      resave: false,
      saveUninitialized: false,
      rolling: false,
      cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        path: "/",
        maxAge: SESSION_DURATION_MS,
      },
    })
  );

  app.use(express.json({ limit: "32kb" }));

  // Protect the dashboard HTML file from direct access
  app.get(
    "/dashboard.html",
    requireSession(deps.db),
    requireAdmin,
    (_req, res) => {
      res.sendFile(resolveProjectPath("public/dashboard.html"));
    }
  );

  // Serve the other public files
  app.use(express.static(resolveProjectPath("public")));

  // Serve our CSS file
  app.get("/style.css", (_req, res) => {
    res.sendFile(resolveProjectPath("static/style.css"));
  });

  // Serve compiled JavaScript files
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

  // Only administrators can open the dashboard page
  app.get(
    "/dashboard",
    requireSession(deps.db),
    requireAdmin,
    (_req, res) => {
      res.sendFile(resolveProjectPath("public/dashboard.html"));
    }
  );

  // Check if the server is running
  app.get("/health", (_req, res) => {
    res.json({ ok: true });
  });

  // Add routes from the team members
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
