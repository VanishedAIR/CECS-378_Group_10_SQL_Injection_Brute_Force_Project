import dotenv from "dotenv";
import fs from "node:fs";
import path from "node:path";
export type LoginMode = "observe" | "protect";
export type ServerConfig = {
    host: string;
    port: number;
    databasePath: string;
    sessionSecret?: string;
    loginMode: LoginMode;
    labMode: boolean;
    accountFailureLimit: number;
    ipFailureLimit: number;
    windowSeconds: number;
    accountCooldownSeconds: number;
    ipCooldownSeconds: number;
};
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);
let dotenvLoaded = false;
/** Load the local .env once without replacing shell values. No file is required. */
export function loadDotEnv(): void {
    if (dotenvLoaded) {
        return;
    }
    const envPath = resolveProjectPath(".env");
    if (fs.existsSync(envPath)) {
        dotenv.config({ path: envPath, override: false });
    }
    dotenvLoaded = true;
}
/** Allow tests to load a different temporary environment file. */
export function resetDotEnvForTests(): void {
    dotenvLoaded = false;
}
/** Resolve a project-relative path from the CLI working directory. */
export function resolveProjectPath(relativePath: string): string {
    return path.resolve(process.cwd(), relativePath);
}
/** Read the base schema; filesystem errors propagate to the caller. */
export function readSchemaSql(): string {
    const schemaPath = resolveProjectPath("schema.sql");
    return fs.readFileSync(schemaPath, "utf8");
}
/** Normalize a loopback host or throw before a server can bind publicly. */
function normalizeHost(rawHost: string): string {
    const trimmed = rawHost.trim().toLowerCase();
    if (trimmed === "::ffff:127.0.0.1") {
        return "127.0.0.1";
    }
    if (!LOOPBACK_HOSTS.has(trimmed)) {
        throw new Error(`HOST must be a loopback address (127.0.0.1, localhost, or ::1). Received: ${rawHost}`);
    }
    return trimmed === "localhost" ? "127.0.0.1" : trimmed;
}
/** Read a positive integer setting, using the fallback only for a missing or blank value. */
function readPositiveInt(name: string, fallback: number): number {
    const raw = process.env[name];
    if (raw === undefined || raw.trim() === "") {
        return fallback;
    }
    const value = Number(raw);
    if (!Number.isInteger(value) || value < 1) {
        throw new Error(`${name} must be a positive integer.`);
    }
    return value;
}
/** Read observe/protect mode and reject any other spelling. */
function readLoginMode(): LoginMode {
    const raw = (process.env.LOGIN_MODE ?? "observe").trim().toLowerCase();
    if (raw !== "observe" && raw !== "protect") {
        throw new Error("LOGIN_MODE must be observe or protect.");
    }
    return raw;
}
/** Read the explicit true/false lab switch; default to disabled. */
function readLabMode(): boolean {
    const raw = (process.env.LAB_MODE ?? "false").trim().toLowerCase();
    if (raw !== "true" && raw !== "false") {
        throw new Error("LAB_MODE must be true or false.");
    }
    return raw === "true";
}
/** Load validated local settings. Shell values win over .env; invalid settings throw. */
export function loadConfig(): ServerConfig {
    loadDotEnv();
    const host = normalizeHost(process.env.HOST ?? "127.0.0.1");
    const port = Number(process.env.PORT ?? "3000");
    const databasePath = process.env.DATABASE_PATH ?? "./data/lab.db";
    const sessionSecret = process.env.SESSION_SECRET?.trim();
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`Invalid PORT: ${process.env.PORT}`);
    }
    return {
        host,
        port,
        databasePath,
        sessionSecret,
        loginMode: readLoginMode(),
        labMode: readLabMode(),
        accountFailureLimit: readPositiveInt("ACCOUNT_FAILURE_LIMIT", 5),
        ipFailureLimit: readPositiveInt("IP_FAILURE_LIMIT", 15),
        windowSeconds: readPositiveInt("WINDOW_SECONDS", 60),
        accountCooldownSeconds: readPositiveInt("ACCOUNT_COOLDOWN_SECONDS", 60),
        ipCooldownSeconds: readPositiveInt("IP_COOLDOWN_SECONDS", 60),
    };
}
