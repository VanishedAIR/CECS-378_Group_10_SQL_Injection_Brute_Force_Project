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
| `npm run demo:sql` | Demonstrate vulnerable/protected searches, auditing, and SQL injection alerts |

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


## SQL Injection Module

The SQL injection module demonstrates the difference between unsafe SQL string concatenation and parameterized queries.

### Search endpoints

- `GET /api/search/protected?q=Mouse`
- `GET /api/search/vulnerable?q=Mouse`

Both endpoints require an authenticated user.

The vulnerable endpoint is intended only for local demonstrations and is available when `LAB_MODE=true`. The protected endpoint is always available to authenticated users.

**Current integration status:** The routes are registered, but authentication is not connected yet. Both endpoints currently return HTTP 401.

### Search behavior

The vulnerable search directly inserts user input into its SQL statement. This allows a specially crafted input to change the query's meaning.

The protected search uses a parameterized SQLite query, so user input is handled as data rather than executable SQL.

| Search input | Vulnerable results | Protected results |
| --- | --- | --- |
| `Mouse` | 1 | 1 |
| `' OR 1=1 --` | 3 | 0 |

### SQL injection detection

The detector checks search inputs for three indicators:

- `sql_comment`: SQL comment syntax
- `union_select`: UNION SELECT statements
- `boolean_tautology`: OR 1=1 patterns

Detection runs on both search modes. A suspicious input can generate an alert even when the protected query prevents exploitation.

### Query auditing and alerts

Each executed search creates a `query_audit` record containing the request ID, user ID, source IP, search mode, input excerpt, result count, duration, and error information.

Detected SQL injection patterns generate a `SQLI_ATTEMPT` security event linked to the corresponding query audit record.

Database execution errors are recorded without exposing SQL statements or stack traces through the API.

### SQL demonstration

Run:

```powershell
npm run demo:sql
```

The script creates an in-memory SQLite database, seeds three fictional products, and demonstrates normal searches and SQL injection attempts against both search modes.

Expected totals:

- 4 query audit records
- 2 SQL injection alerts

The demonstration does not modify the application's persistent database.

### Testing

Run:

```powershell
npm run typecheck
npm test
```

The SQL injection module includes tests for search results, SQL injection detection, audit records, security alerts, database errors, and unauthenticated HTTP requests.

At the time of initial implementation, the project passes 43 automated tests across 6 test files.

### Remaining integration

- Connect the search routes to the shared authentication/session middleware.
- Add authenticated HTTP tests for successful searches, LAB_MODE restrictions, input validation, and database failures.
- Verify integration with the team's dashboard and login protection features.
```
