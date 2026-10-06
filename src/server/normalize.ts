const USERNAME_KEY = /^[a-z0-9_]{3,32}$/;

/**
 * Trim and lowercase first. Callers validate the result with
 * requireUsernameKey. Passwords must never be passed here.
 */
export function normalizeUsername(raw: string): string {
  return raw.trim().toLowerCase();
}

/** Normalize, then require the agreed 3–32 character username key. */
export function requireUsernameKey(raw: string): string {
  const key = normalizeUsername(raw);
  if (!USERNAME_KEY.test(key)) {
    throw new Error(
      "Username must be 3 to 32 letters, digits, or underscores after trim and lowercase."
    );
  }
  return key;
}

/**
 * Checks length only. The string is returned unchanged so spaces and case
 * in a password are preserved.
 */
export function validatePasswordLength(password: string): string {
  if (password.length < 1 || password.length > 128) {
    throw new Error("Password must be between 1 and 128 characters.");
  }
  return password;
}

/**
 * Connection-derived address normalization from section 9.4.
 * ::1 and IPv4-mapped loopback become 127.0.0.1. Other ::ffff: addresses
 * drop the prefix. Remaining addresses are lowercased.
 */
export function normalizeSourceIp(raw: string): string {
  const trimmed = raw.trim();
  const lower = trimmed.toLowerCase();

  if (lower === "::1" || lower === "::ffff:127.0.0.1") {
    return "127.0.0.1";
  }

  if (lower.startsWith("::ffff:")) {
    return lower.slice("::ffff:".length);
  }

  return lower;
}
