# Northstar Supply - CECS 378 Group 10

Northstar Supply is a fictional office-supply catalog built to demonstrate two common web attacks and how to defend against them:

- **SQL injection**: the same product search runs as a parameterized (protected) query and as a deliberately unsafe (vulnerable) query, so the results can be compared side by side.
- **Brute-force login**: failed logins are tracked per account and per IP address, with an Observe mode that only raises alerts and a Protect mode that also applies a temporary cooldown.

An administrator dashboard shows the resulting alerts and links each one back to the stored login attempts or query record that caused it.

The app runs entirely on localhost: an Express server written in TypeScript, plain HTML/CSS pages, and a local SQLite database. No cloud services or external accounts are required.

## Requirements

- Node.js 24 (the project pins 24.21.0 in `.nvmrc`)
- npm

## Getting started

```powershell
npm ci
Copy-Item .env.example .env        # macOS/Linux: cp .env.example .env
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Paste the generated value into `.env` as `SESSION_SECRET`, then seed the database and start the server:

```powershell
npm run db:seed
npm run dev
```

Open http://127.0.0.1:3000/. On Windows, use `npm.cmd` if PowerShell blocks `npm`.

## Demo accounts

These fictional accounts are created by `npm run db:seed`. Running the seed again leaves existing accounts and history unchanged.

| Username | Password | Role |
| --- | --- | --- |
| `demo_user` | `DemoUser123!` | user |
| `demo_admin` | `DemoAdmin123!` | admin |

## Features

- **Catalog search.** Signed-in users can search the products. The protected query binds the input as a parameter. The vulnerable query concatenates it into the SQL string and only works when `LAB_MODE=true`; otherwise it returns 404.
- **SQL injection detection.** Every search is recorded with its input, SQL template, bound parameters, and row count. Inputs that match known patterns (comments, `UNION SELECT`, `OR 1=1`) also create an alert linked to that record. An alert means the pattern was seen, not that the attack succeeded.
- **Login protection.** Five failures for one account, or fifteen from one IP, within 60 seconds raises an alert. In Protect mode that account or IP is then blocked for 60 seconds and further attempts receive `429 Too Many Requests`.
- **Investigation dashboard.** Administrators see overall totals, the 20 most recent alerts and login attempts, active cooldowns, and the evidence behind each alert. Regular users receive 403 from every admin route.
- **Sessions.** Passwords are stored as salted scrypt hashes. Sessions expire 30 minutes after login, and signing out invalidates the session on the server.

## Configuration

Settings are read from `.env` (see `.env.example`). Restart the server after changing them.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SESSION_SECRET` | (required) | Random string of at least 32 characters |
| `HOST` / `PORT` | `127.0.0.1` / `3000` | Listen address; only loopback addresses are accepted |
| `DATABASE_PATH` | `./data/lab.db` | SQLite file location |
| `LOGIN_MODE` | `observe` | `observe` (alerts only) or `protect` (alerts and cooldowns) |
| `LAB_MODE` | `false` | Set to `true` to enable the vulnerable search |
| `ACCOUNT_FAILURE_LIMIT` / `IP_FAILURE_LIMIT` | `5` / `15` | Failures that trigger an alert |
| `WINDOW_SECONDS` | `60` | Rolling window for counting failures |
| `ACCOUNT_COOLDOWN_SECONDS` / `IP_COOLDOWN_SECONDS` | `60` / `60` | Cooldown length in Protect mode |
| `DATABASE_URL` | (empty) | Optional; only used by `npm run db:check:neon` |

## Scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Build, then start the development server |
| `npm run build` / `npm start` | Compile TypeScript / run the compiled server |
| `npm run watch` | Recompile on file changes |
| `npm run typecheck` | Type-check without emitting files |
| `npm test` | Run the Vitest test suite |
| `npm run db:seed` | Create the schema, products, and demo accounts |
| `npm run db:reset` | Clear login attempts, search records, alerts, and cooldowns (keeps users) |
| `npm run demo:sql` | In-memory comparison of protected and vulnerable queries |
| `npm run demo:login` | In-memory demonstration of the login policy |
| `npm run db:check:neon` | Optional PostgreSQL connection check |

Tests use temporary or in-memory databases and never touch `data/lab.db`.

## Project structure

```text
public/          HTML pages (home, login, search, dashboard)
static/          Stylesheet
src/client/      Browser TypeScript for each page
src/server/      Express server, authentication, search, auditing, dashboard
scripts/         Seed, reset, and demo command-line scripts
tests/           Vitest tests
schema.sql       SQLite schema
```

## API

| Method and path | Access | Description |
| --- | --- | --- |
| `POST /api/login` | public | Sign in; returns the user and a redirect path |
| `POST /api/logout` | signed in | End the session (204) |
| `GET /api/me` | signed in | Current user |
| `GET /api/search/protected?q=` | signed in | Parameterized product search |
| `GET /api/search/vulnerable?q=` | signed in, `LAB_MODE=true` | Unsafe product search |
| `GET /api/dashboard` | admin | Totals and recent activity |
| `GET /api/cooldowns` | admin | Active cooldowns |
| `GET /api/alerts/:id` | admin | One alert with its linked evidence |

Errors use the shape `{ "error": { "code", "message" } }`.

## Team

| Member | Area | Main files |
| --- | --- | --- |
| Vansh | Database and integration | `db.ts`, `audit.ts`, `app.ts`, `schema.sql` |
| Huy | Authentication and login protection | `passwords.ts`, `authRoutes.ts`, `authMiddleware.ts`, `sessions.ts`, `loginPolicy.ts` |
| Dean | SQL injection search | `search.ts`, `searchRoutes.ts`, `sqlDetector.ts` |
| Ediz | Investigation dashboard | `dashboard.ts`, `src/client/dashboard*.ts` |

Server files are in `src/server/`.

## Disclaimer

This project was built for a university security course. The vulnerable query is intentional and is disabled by default. Run the app only on your own machine, and do not reuse the demo credentials anywhere else.
