# CECS-378 Group 10 — SQL Injection and Login Protection Lab

Local TypeScript/Express + SQLite security lab. Ediz's Flask/Jinja files (`templates/`, `app.py`, `static/style.css`) stay in the repo as the UI reference. The running app is the TypeScript server.

## Requirements

- **Node.js 24.x** (`.nvmrc` and `package.json` `volta` pin **24.21.0**). `.npmrc` sets `engine-strict=true`.
- Copy `.env.example` to `.env`. Do not commit `.env`.

## Fresh clone

```powershell
cd CECS-378_Group_10_SQL_Injection_Brute_Force_Project
nvm use 24.21.0
node --version # must print v24.21.0
copy .env.example .env # fresh checkout only; preserve an existing .env
npm ci
npm run db:seed
npm run dev
```

If PowerShell blocks `npm.ps1`, use `npm.cmd` instead.

### Environment variables

`loadConfig()` calls `loadDotEnv()` first:

1. Values already in the process environment win.
2. Missing values are filled from `.env`.
3. Anything still missing uses the defaults in `.env.example`.

`HOST` must be loopback (`127.0.0.1`, `localhost`, or `::1`). `LOGIN_MODE` is `observe` or `protect`. `LAB_MODE` is `true` or `false`. There is no HTTP endpoint that changes these.

`db:seed` creates `./data/lab.db`, applies `schema.sql`, and inserts **Mouse**, **Keyboard**, and **Monitor**. It also creates the two fictional demo accounts below using Bin's `hashPassword`. Existing usernames are reported as **Skipped**: their passwords, display names and roles are preserved, so the documented credentials and expected roles are not guaranteed for those rows. Repeated seeds preserve audit records and cooldowns. `db:reset` clears login, query, alert, and cooldown rows in a transaction and restores those three products. It is a CLI only. Startup does not reset the database.

`db:check:neon` is an optional PostgreSQL connectivity check. The application database remains SQLite.

## Commands

| Script | What it does |
| --- | --- |
| `npm run dev` | Start the TypeScript server with tsx |
| `npm run build` / `npm start` | Compile, then run `dist/` |
| `npm run typecheck` | Typecheck without emitting |
| `npm test` | Vitest |
| `npm run db:seed` | Apply schema and seed products plus missing demo accounts |
| `npm run db:reset` | Clear evidence and restore products |
| `npm run db:check:neon` | Optional Neon check (needs `DATABASE_URL` in `.env`) |

Open **http://127.0.0.1:3000/** and **http://127.0.0.1:3000/health**.

## Fictional localhost demo accounts

These public passwords are for this local lab only. Do not reuse real credentials.

| Username | Demo-only password | Role |
| --- | --- | --- |
| `demo_user` | `DemoUser123!` | `user` |
| `demo_admin` | `DemoAdmin123!` | `admin` |

Run `npm run db:seed` before starting the server. It uses `DATABASE_PATH` from the shell, then `.env`, then `./data/lab.db`. It never connects to Neon. Only encoded password hashes enter SQLite; credentials are not printed by the command. If a username is skipped, inspect it and use its existing credentials; seeding never resets it. The broader five-account IP demonstration remains outside this two-account contribution.

Flow to present: **seed command -> password hashing -> SQLite insert -> login lookup**. `db:seed` loads the shared config, opens SQLite and applies the schema. Products and missing accounts seed in one transaction. `requireUsernameKey` normalizes each username; Bin's `hashPassword` generates a salted scrypt hash. A parameterized insert stores the username, display name, hash and role. Bin's login code will look up `users` by normalized `username_key` using a bound parameter, pass the submitted password and `password_hash` to `verifyPassword`, then use the row's ID and role for the session. Login/session routes are still pending on this branch; this seed does not implement them.

### Verify without touching an existing database

Use Node **24.21.0**. The focused tests run the actual seed CLI against temporary SQLite files, check products, both roles and passwords with Bin's verifier, rerun and compare every account and audit row, and check conflicting usernames with different passwords and roles.

```powershell
nvm use 24.21.0
node --version
npm ci
npm test -- tests/seedAccounts.test.ts
npm run typecheck
npm test
npm run build
```

For a manual temporary seed and an inspection that never displays hashes:

```powershell
$savedSeedDatabasePath = $env:DATABASE_PATH
$demoSeedPath = Join-Path ([System.IO.Path]::GetTempPath()) ("cecs378-demo-" + [guid]::NewGuid() + ".db")
try {
  $env:DATABASE_PATH = $demoSeedPath
  npm run db:seed
  npm run db:seed # accounts are reported as skipped, never recreated
  @'
import { DatabaseSync } from "node:sqlite";
const db = new DatabaseSync(process.env.DATABASE_PATH, { readOnly: true });
console.table(db.prepare("SELECT username_key, display_username, role FROM users ORDER BY username_key").all());
db.close();
'@ | node --input-type=module
} finally {
  $env:DATABASE_PATH = $savedSeedDatabasePath
  Remove-Item -LiteralPath $demoSeedPath -ErrorAction SilentlyContinue
}
```

To inspect the normal local lab database, use the same read-only query with `DATABASE_PATH` set to its SQLite file. It selects only usernames and roles. Keep `.env` and generated database files out of Git.

## Shared modules for teammates

Every route module receives the same `AppDependencies` object (`db`, `config`, `clock`). Do not open a second database. Register a router by appending a factory to `moduleRouters` in `src/server/app.ts` when your file exists:

```typescript
moduleRouters.push((deps) => createAuthRouter(deps));
```

| Module | Use it for |
| --- | --- |
| `db.ts` | `openDatabase`, `applySchema`, `withTransaction`, `withDatabase` |
| `audit.ts` | Insert and read login attempts, query rows, and security events. Writers do not start transactions. |
| `normalize.ts` | Username key and source IP. Never pass a password to the username helper. |
| `clock.ts` | `systemClock()` or `createFakeClock(start)` in tests |
| `http.ts` | Request id, socket IP, JSON error envelope |
| `config.ts` | `loadConfig()` |
| `resetLab.ts` | CLI reset only |

Audit writes belong inside the caller's `withTransaction`. Bin decides login outcomes and threshold crossings. real thd decides SQL indicators. Ediz reads evidence; he does not invent a second insert path.

Agent notes stay on the `context-docs` branch. Do not commit `.context/` from a feature branch.
