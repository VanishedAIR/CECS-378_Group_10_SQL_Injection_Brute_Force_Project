# CECS-378 Group 10 — SQL Injection and Login Protection Lab

Local TypeScript/Express + SQLite security lab. Ediz's Flask/Jinja files (`templates/`, `app.py`, `static/style.css`) stay in the repo as the UI reference. The running app is the TypeScript server.

## Requirements

- **Node.js 24.x** (`.nvmrc` and `package.json` `volta` pin **24.21.0**). `.npmrc` sets `engine-strict=true`.
- Copy `.env.example` to `.env`. Do not commit `.env`.

## Fresh clone

```powershell
cd CECS-378_Group_10_SQL_Injection_Brute_Force_Project
copy .env.example .env
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

`db:seed` creates `./data/lab.db`, applies `schema.sql`, and inserts **Mouse**, **Keyboard**, and **Monitor**. User accounts are **not** seeded. Bin's `hashPassword` must exist before any account seed. `db:reset` clears login, query, alert, and cooldown rows in a transaction and restores those three products. It is a CLI only. Startup does not reset the database.

`db:check:neon` is an optional PostgreSQL connectivity check. The application database remains SQLite.

## Commands

| Script | What it does |
| --- | --- |
| `npm run dev` | Start the TypeScript server with tsx |
| `npm run build` / `npm start` | Compile, then run `dist/` |
| `npm run typecheck` | Typecheck without emitting |
| `npm test` | Vitest |
| `npm run db:seed` | Apply schema and seed products |
| `npm run db:reset` | Clear evidence and restore products |
| `npm run db:check:neon` | Optional Neon check (needs `DATABASE_URL` in `.env`) |

Open **http://127.0.0.1:3000/** and **http://127.0.0.1:3000/health**.

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
