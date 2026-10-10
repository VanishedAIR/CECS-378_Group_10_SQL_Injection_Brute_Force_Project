# Bin — Login protection contribution (draft for team review)

## Added
- `src/server/loginPolicy.ts`: account and IP rolling counters, Observe/Protect mode, cooldown checks, serialized decisions, SQLite transaction and audit evidence.
- `tests/loginPolicy.test.ts`: seven focused tests using an in-memory database and fake clock.

## Interface
Create one policy instance per server/database instance:

```ts
const policy = createLoginPolicy(db, config);
const decision = await policy.evaluate(
  { requestId: crypto.randomUUID(), username: submittedUsername, sourceIp: req.socket.remoteAddress ?? "" },
  async (usernameKey) => {
    // Van_ish: parameterized user lookup and salted password verification.
    // Never log passwords or return them in the result.
    return { valid: passwordMatches, userId: foundUserIdOrNull };
  }
);
```

**IMPORTANT**: Validate the raw password's type and length BEFORE calling `evaluate`; the verification callback should use the original password, unchanged. Never accept IP overrides from headers or JSON. The `verify` callback is called only when the login gate permits it. On `decision.status === 429`, send a generic response with `Retry-After: String(decision.retryAfterSeconds)`. On 401, send a generic credentials error. On 200, regenerate the server-side session; this module does not create sessions. Catch and handle database errors without leaking SQL.

The policy deliberately does not modify `app.ts`, implement password hashing, or create an HTTP login endpoint: those depend on Van_ish's unfinished auth work. The demo script and remaining acceptance tests (both scopes simultaneously, unknown accounts, restart, forwarded-header route test) are still outstanding.

## How to validate on the team's Node 24 runtime

```bash
npm ci
npm run typecheck
npm test
```

The assistant environment currently has Node 22.16.0, whereas the repository requires Node 24, so these commands have **not** been verified successfully here. Please run them locally before creating a pull request.

## Security and design notes
- SQLite transactions cover inserts, counts, event evidence and cooldown upserts.
- One queue per policy instance serializes concurrent login checks. Use one shared instance for the single-process app.
- An account key tracks one username across IP changes; an IP key tracks many usernames from one address.
- Blocked requests are audited but do not increment counters or extend expiry.
- A successful login does not erase prior failures.
- An expiry at or before the current fake-clock time is inactive.
