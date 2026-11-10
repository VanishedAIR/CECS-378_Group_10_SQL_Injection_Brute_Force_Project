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
import { SESSION_COOKIE_NAME, SESSION_DURATION_MS, } from "./sessions.js";
export type AppDependencies = {
    db: DatabaseSync;
    config: ServerConfig;
    clock: Clock;
};
export type ModuleRouterFactory = (deps: AppDependencies) => Router;
// Mount each feature once. The dashboard wrapper applies session and role checks before reporting.
export const moduleRouters: ModuleRouterFactory[] = [
    (deps) => createAuthRouter(deps),
    createSearchRouter,
    (deps) => {
        const router = express.Router();
        router.use(["/api/dashboard", "/api/cooldowns", "/api/alerts"], requireSession(deps.db), requireAdmin);
        router.use(createDashboardRouter(deps, requireAdmin));
        return router;
    },
];
/** Open the configured SQLite file and apply its schema and migrations. */
export function openLabDatabase(config: ServerConfig): DatabaseSync {
    const db = openDatabase(config.databasePath);
    applySchema(db);
    return db;
}
/** Assemble the shared session, page, API, and error middleware without starting a listener. */
export function createApp(deps: AppDependencies, extraRouters: ModuleRouterFactory[] = []): express.Express {
    const app = express();
    app.set("trust proxy", false);
    app.disable("x-powered-by");
    const secret = deps.config.sessionSecret;
    if (!secret || secret.length < 32) {
        throw new Error("SESSION_SECRET must be configured and contain at least 32 characters.");
    }
    app.locals.lab = deps;
    app.use(attachRequestContext);
    // Sessions must be available before any protected page or feature router runs.
    app.use(session({
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
    }));
    app.use(express.json({ limit: "32kb" }));
    // Protect the dashboard HTML file from direct access
    app.get("/dashboard.html", requireSession(deps.db), requireAdmin, (_req, res) => {
        res.sendFile(resolveProjectPath("public/dashboard.html"));
    });
    app.use(express.static(resolveProjectPath("public")));
    app.get("/style.css", (_req, res) => {
        res.sendFile(resolveProjectPath("static/style.css"));
    });
    app.use("/client", express.static(resolveProjectPath("dist/src/client")));
    app.get("/login", (_req, res) => {
        res.sendFile(resolveProjectPath("public/login.html"));
    });
    app.get("/search", (_req, res) => {
        res.sendFile(resolveProjectPath("public/search.html"));
    });
    // Only administrators can open the dashboard page
    app.get("/dashboard", requireSession(deps.db), requireAdmin, (_req, res) => {
        res.sendFile(resolveProjectPath("public/dashboard.html"));
    });
    app.get("/health", (_req, res) => {
        res.json({ ok: true });
    });
    for (const factory of [...moduleRouters, ...extraRouters]) {
        app.use(factory(deps));
    }
    app.use(handleUnexpectedError);
    return app;
}
/** Stop accepting connections, close SQLite, and reject if the HTTP server cannot close. */
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
/** Load local settings, open SQLite, listen on loopback, and register shutdown handlers. */
export function startServer(): void {
    const config = loadConfig();
    const db = openLabDatabase(config);
    const app = createApp({ db, config, clock: systemClock() });
    const server = app.listen(config.port, config.host, () => {
        console.log(`Security lab listening at http://${config.host}:${config.port}/`);
    });
    const stop = (): void => {
        void shutdownServer(server, db).then(() => {
            process.exit(0);
        });
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
}
// Start only when this file is run directly
const isMain = process.argv[1] &&
    fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
    startServer();
}
