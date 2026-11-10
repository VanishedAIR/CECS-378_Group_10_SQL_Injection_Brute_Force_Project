# Northstar Supply ? CECS 378 Group 10

A fictional workplace catalog and security investigation app. HTML/CSS and browser TypeScript talk to Express on localhost; SQLite stores accounts, products, login attempts, query evidence, alerts, and cooldowns. No CDN, public signup, or cloud database is needed.

## Start locally

Use **Node 24.21.0** (pinned in `.nvmrc` and `package.json`; `.npmrc` enforces Node 24). Run commands from the project root. If PowerShell blocks `npm.ps1`, use `npm.cmd`.

```powershell
nvm use 24.21.0
node --version # v24.21.0
npm ci
if (!(Test-Path -LiteralPath .env)) { Copy-Item -LiteralPath .env.example -Destination .env }
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Before starting, copy that freshly generated value into **your local** `.env` as `SESSION_SECRET`. It must be at least 32 characters. Keep the existing file and its other settings; do not overwrite it, commit it, reuse a published secret, or share the generated value. The example contains only a blank placeholder. For an isolated run, a process environment variable can supply the secret without creating `.env`.

Choose `LOGIN_MODE=observe` or `protect`, and set `LAB_MODE=true` only for the intentionally vulnerable localhost demonstration. With the default `LAB_MODE=false`, authenticated vulnerable searches return 404. There is no HTTP mode-switch endpoint. Restart after changing server settings.

```powershell
npm run db:seed
npm run dev
```

Open **http://127.0.0.1:3000/**. `predev` builds server and browser TypeScript before the server starts, including on a fresh checkout with no `dist`. `/health` is the health endpoint. Shell settings take precedence over `.env`; code defaults apply after those. `HOST` accepts only loopback addresses. The default SQLite file is `./data/lab.db`.

### Editing and compiled startup

While `npm run dev` is running, open a second terminal in the same root:

```powershell
npm run watch
```

The compiler re-emits browser modules into `dist/src/client` after edits. Reload the browser to see them; there is no hot reload. The watcher also compiles server code, but the running tsx server must be restarted for server changes. Without the watcher, run `npm run build` and reload after browser edits. To run compiled output, use `npm run build` followed by `npm start`. Stop both terminal commands with Ctrl+C.

## Fictional accounts and data

These public credentials are for the localhost demonstration only. Never reuse real credentials.

| Username | Demo-only password | Role |
| --- | --- | --- |
| `demo_user` | `DemoUser123!` | user |
| `demo_admin` | `DemoAdmin123!` | admin |

Seeding applies the schema, restores Mouse/Keyboard/Monitor, and inserts missing accounts in one transaction. It uses Bin's shared `hashPassword` (salted scrypt); only hashes enter SQLite. Existing usernames are **Skipped**, with passwords, display names, roles, and audit history unchanged. For skipped rows the public credentials and expected role are not guaranteed. The two seeded accounts do not provide the five distinct identities used in the optional IP-wide presentation scenario.

`npm run db:reset` deliberately clears evidence/cooldowns and restores products in one transaction, preserving users. It is a CLI only and never runs on server startup. Do not run reset against a database whose evidence you need to keep.

Inspect usernames and roles without printing hashes (this reads the default file; change the path explicitly for a different database):

```powershell
node --input-type=module -e "import {DatabaseSync} from 'node:sqlite'; const db=new DatabaseSync('./data/lab.db',{readOnly:true}); console.table(db.prepare('SELECT username_key, display_username, role FROM users ORDER BY username_key').all()); db.close();"
```

## Presentation flow

1. Sign in as `demo_user`. Login returns the agreed `/search` redirect for both roles.
2. Search `Mouse`: each query mode returns one product. Search `' OR 1=1 --`: vulnerable returns three products; protected returns zero. Input stays unchanged, 1?100 characters. The protected query binds it as data; this does not claim every possible part of the app is secure.
3. Sign out, sign in as `demo_admin`, and use **Investigation** in the navigation. Regular users receive 403 from admin APIs, regardless of visible navigation.
4. Overview totals cover all retained history. Click a login/alert card to filter only the newest **up to 20** records loaded for each list. Text, type, scope, and outcome controls combine over those loaded records. Visible counts say how many loaded rows match. **Clear filters** resets them; it does not erase database rows.
5. **Inspect** opens linked evidence: SQL input/template/parameters/executed lab SQL or the exact contributing login attempts and threshold window. Detection is evidence of a supported suspicious pattern, not proof that an attack succeeded.
6. **Refresh snapshot** gets current data, preserves filters, and closes old details. Cooldown seconds are explicitly labeled at capture; refresh to check expiry. Counts can exceed the number of loaded rows. There is no fake analytics or full-history browser search.
7. In Protect mode, five failed logins for one username trigger its cooldown. A subsequent login returns 429 with a numeric delay and matching `Retry-After`; the login form shows the delay and avoids automatic retries. The IP threshold remains 15 failures. Observe mode records threshold alerts without blocking.

The dashboard validates access on loading and every 30 seconds. Any detected 401/403, failed validation, or logout clears loaded data; in-flight old responses cannot restore it. Sessions expire **server-side** exactly 30 minutes after login even after active requests. The UI shows a timestamped snapshot, not a live feed; local display cleanup is not the enforcement boundary. Sign-out waits for empty 204 and reports failures instead of claiming success.

## APIs and shared code

| Area | Main files | Behavior |
| --- | --- | --- |
| Startup/storage | `app.ts`, `config.ts`, `db.ts`, `schemaMigrate.ts`, `schema.sql` | One shared database/config/clock; loopback only; non-destructive migrations |
| Authentication | `passwords.ts`, `authRoutes.ts`, `authMiddleware.ts`, `sessions.ts`, `loginPolicy.ts` | Bin's password/session helpers; current database roles; absolute expiry; account/IP policy |
| Search/evidence | `searchRoutes.ts`, `search.ts`, `sqlDetector.ts`, `audit.ts` | Dean's two query modes, signatures, parameterized audit writers and linked evidence |
| Investigation | `dashboard.ts`, `src/client/dashboard*.ts` | Admin-only totals, recent records, scope filters and structured detail |
| Browser | `public/`, `src/client/`, `static/style.css` | Northstar Supply pages; shared access/logout and plain-text rendering |

Server filenames in the table are under `src/server`. Audit writers do not own transactions; callers group related writes in `withTransaction`. Passwords are not trimmed. Client-supplied roles/IDs never authorize requests. Existing API shapes are preserved:

- `POST /api/login` ? `{ user, redirectTo }`; `GET /api/me` ? `{ user }`; `POST /api/logout` ? empty 204.
- `GET /api/search/protected?q=...` and `/api/search/vulnerable?q=...` ? `{ mode, rows, resultCount }`.
- `GET /api/dashboard`, `/api/cooldowns`, `/api/alerts/:id` require current administrator access. Alert detail joins its stored login/query evidence.
- Errors use `{ error: { code, message } }`; 429 additionally returns `retryAfterSeconds`. SQL failures return a generic 500 while recording one failed query audit.

The deliberately unsafe query exists only for the lab. Protected evidence contains fixed SQL and parameters with `labSql=null`. Vulnerable evidence separates the never-executed `%{q}%` descriptive template from the actual executed lab SQL. SQL text is exposed only through authorized evidence routes.

## Commands and checks

| Command | Purpose |
| --- | --- |
| `npm run dev` | Initial build, then local tsx server |
| `npm run watch` | Recompile after edits; reload browser/restart server as described above |
| `npm run build` / `npm start` | Compile / run compiled server |
| `npm run typecheck` | Check TypeScript without emitting |
| `npm test` | All Vitest tests, including browser-controller regressions |
| `npm run db:seed` / `npm run db:reset` | Seed / explicitly reset local evidence |
| `npm run demo:sql` | In-memory SQL comparison: four audits, two SQL alerts |
| `npm run demo:login` | In-memory policy demo with simulated verification and a fake clock |
| `npm run db:check:neon` | Optional standalone PostgreSQL probe; requires DATABASE_URL; never used by app startup |

```powershell
npm run typecheck
npm test -- tests/client.test.ts
npm test
npm run build
npm run demo:sql
```

Tests create temporary/in-memory databases. Controller tests use a minimal event/text DOM and do **not** prove browser rendering, accessibility, console cleanliness, or the full cookie flow. A final browser check should sign in with both roles, compare searches, inspect real evidence, exercise filters, test logout/cooldown, and check a narrow viewport and keyboard focus.

For an isolated manual setup, set `$env:DATABASE_PATH` to a new path in your temporary directory and `$env:SESSION_SECRET` to a newly generated test-only value **before** seeding/starting. Do not use a personal `.env` or existing database for verification. Neon is not needed. Keep `.env`, runtime databases, `dist`, dependencies, logs, and private context out of Git.
