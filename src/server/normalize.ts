const USERNAME_KEY = /^[a-z0-9_]{3,32}$/;
/** Trim and lowercase a username only; never pass a password here. */
export function normalizeUsername(raw: string): string {
    return raw.trim().toLowerCase();
}
/** Return a normalized 3–32 character username key or throw on invalid characters. */
export function requireUsernameKey(raw: string): string {
    const key = normalizeUsername(raw);
    if (!USERNAME_KEY.test(key)) {
        throw new Error("Username must be 3 to 32 letters, digits, or underscores after trim and lowercase.");
    }
    return key;
}
/** Validate 1–128 characters and return the original password. Spaces can be part of it. */
export function validatePasswordLength(password: string): string {
    if (password.length < 1 || password.length > 128) {
        throw new Error("Password must be between 1 and 128 characters.");
    }
    return password;
}
/** Normalize connection addresses so IPv4-mapped and native loopback share one scope. */
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
