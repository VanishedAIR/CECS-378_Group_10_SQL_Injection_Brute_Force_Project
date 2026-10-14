import dotenv from "dotenv";
import fs from "node:fs";
import path from "node:path";

export type LoginMode = "observe" | "protect";

export type ServerConfig = {
  host: string;
  port: number;
  databasePath: string;
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

/**
 * Loads variables from `.env` in the project root when the file exists.
 *
 * Precedence (highest wins): existing `process.env` values are kept; `.env` only
 * fills variables that are not already set. Shell exports and inline env vars
 * therefore override `.env`. Call this before reading config in every entry
 * point (`dev`, compiled `start`, and seed scripts) via `loadConfig()`.
 */
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

/** @internal Resets dotenv load state for tests only. */
export function resetDotEnvForTests(): void {
  dotenvLoaded = false;
}

export function resolveProjectPath(relativePath: string): string {
  return path.resolve(process.cwd(), relativePath);
}

export function readSchemaSql(): string {
  const schemaPath = resolveProjectPath("schema.sql");
  return fs.readFileSync(schemaPath, "utf8");
}

function normalizeHost(rawHost: string): string {
  const trimmed = rawHost.trim().toLowerCase();
  if (trimmed === "::ffff:127.0.0.1") {
    return "127.0.0.1";
  }
  if (!LOOPBACK_HOSTS.has(trimmed)) {
    throw new Error(
      `HOST must be a loopback address (127.0.0.1, localhost, or ::1). Received: ${rawHost}`
    );
  }
  return trimmed === "localhost" ? "127.0.0.1" : trimmed;
}

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

function readLoginMode(): LoginMode {
  const raw = (process.env.LOGIN_MODE ?? "observe").trim().toLowerCase();
  if (raw !== "observe" && raw !== "protect") {
    throw new Error("LOGIN_MODE must be observe or protect.");
  }
  return raw;
}

function readLabMode(): boolean {
  const raw = (process.env.LAB_MODE ?? "false").trim().toLowerCase();
  if (raw !== "true" && raw !== "false") {
    throw new Error("LAB_MODE must be true or false.");
  }
  return raw === "true";
}

/**
 * Reads server settings after `loadDotEnv()`.
 * Defaults match `.env.example`. There is no HTTP endpoint that changes them.
 */
export function loadConfig(): ServerConfig {
  loadDotEnv();

  const host = normalizeHost(process.env.HOST ?? "127.0.0.1");
  const port = Number(process.env.PORT ?? "3000");
  const databasePath = process.env.DATABASE_PATH ?? "./data/lab.db";

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid PORT: ${process.env.PORT}`);
  }

  return {
    host,
    port,
    databasePath,
    loginMode: readLoginMode(),
    labMode: readLabMode(),
    accountFailureLimit: readPositiveInt("ACCOUNT_FAILURE_LIMIT", 5),
    ipFailureLimit: readPositiveInt("IP_FAILURE_LIMIT", 15),
    windowSeconds: readPositiveInt("WINDOW_SECONDS", 60),
    accountCooldownSeconds: readPositiveInt("ACCOUNT_COOLDOWN_SECONDS", 60),
    ipCooldownSeconds: readPositiveInt("IP_COOLDOWN_SECONDS", 60),
  };
}
