# Bin — Login Protection and Authentication Integration Notes

## Current implementation

The following work is implemented on `feature/login-protection`:

- `src/server/loginPolicy.ts` — Account-based and IP-based brute-force detection, rolling failure windows, Observe/Protect modes, cooldown enforcement, serialized login decisions, and SQLite audit evidence.
- `tests/loginPolicy.test.ts` — Seven focused login-protection tests.
- `tests/loginPolicy.additional.test.ts` — Four additional tests, including delayed-verification timing and failure-window expiration.
- `tests/loginPolicy.http.test.ts` — Express HTTP integration test using simulated credential verification.
- `scripts/demo-login.ts` — Local demonstration of failed logins, HTTP-style protection decisions, and cooldown recovery.

## Timing correction

The login policy checks existing cooldowns using the time when a request is evaluated.

After asynchronous password verification finishes, it captures a fresh timestamp. This refreshed time is used for the recorded login result, failure-window calculations, new security events, and cooldown creation.

Fake-clock tests cover delayed verification and failures expiring during verification.

## Authentication responsibilities

Under the updated team plan, Bin is responsible for:

- Password hashing and secure password verification.
- Session creation, validation, and invalidation.
- Login, logout, and authenticated-user (`/me`) routes.
- `requireSession` middleware for authenticated routes.
- `requireAdmin` middleware for administrator-only routes.
- Connecting the authentication flow to the existing login-protection policy.

These authentication features are assigned but are not yet implemented in this contribution.

Dean (real thd) needs session authentication for his search routes. The middleware interface should be coordinated with Dean and Ediz before their route integration.

## Login policy interface

Create one shared policy instance per server/database instance:

```ts
const policy = createLoginPolicy(db, config, clock);

const decision = await policy.evaluate(
  {
    requestId: req.requestId,
    username: submittedUsername,
    sourceIp: sourceIpFromRequest(req),
  },
  async (usernameKey) => {
    // Authentication implementation owned by Bin.
    // Look up the account using bound SQL parameters.
    // Verify the original submitted password against its stored hash.
    // Never log or audit plaintext passwords.
    return {
      valid: passwordMatches,
      userId: foundUserIdOrNull,
    };
  }
);
```

Validate the username and password types and lengths before calling `evaluate`. The verification callback must use the original submitted password for password verification.

Use the connection-derived IP address, not a client-supplied IP header or JSON field.

When the decision is:

- HTTP 429: Return a generic cooldown error and the `Retry-After` header.
- HTTP 401: Return a generic invalid-credentials error.
- HTTP 200: Establish an authenticated session after successful verification.

The policy controller does not itself create sessions.

## Session middleware interface — pending implementation

The planned Express middleware exports are:

```ts
requireSession
requireAdmin
```

`requireSession` will reject requests without a valid authenticated session.

`requireAdmin` will reject requests without a valid authenticated session or without administrator privileges.

The exact module path, authenticated-request type, session storage, and route contracts must be confirmed against the updated project plan and shared with Dean and Ediz.

## Validation results

Verified locally using Node.js 24 and the project scripts:

```bash
npm run typecheck
npm test
npm run build
```

Results after the timing correction:

- TypeScript typecheck: passed.
- Automated tests: 37 passed, 0 failed.
- Build: passed.

These results apply to the current login-protection contribution, before the new authentication features are implemented.

## Security and design notes

- SQLite transactions cover login-attempt inserts, failure counts, event evidence, and cooldown updates.
- One queue per policy instance serializes asynchronous login decisions in the single-process application.
- Account tracking detects repeated failures against one username across different IP addresses.
- IP tracking detects failures against multiple usernames from one source address.
- Blocked attempts are audited but do not increment failure counts or extend cooldowns.
- Successful logins do not automatically erase previous failed attempts.
- Expired cooldowns are inactive.
- Passwords must not appear in audit records or security-event details.
- The HTTP integration test uses simulated credential verification and is not a production login endpoint.

## Remaining work

1. Implement password hashing and secure credential verification.
2. Implement session management and login/logout/me routes.
3. Implement and test `requireSession` and `requireAdmin`.
4. Share the finalized middleware interface with Dean and Ediz.
5. Add remaining security acceptance tests and verify integrated routes.
6. Coordinate team review and merge through the existing pull request.