import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { validatePasswordLength } from "./normalize.js";
const SALT_BYTES = 16;
const KEY_BYTES = 64;
const HASH_PREFIX = "scrypt";
const SCRYPT_OPTIONS = {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 32 * 1024 * 1024,
} as const;
/** Derive an encoded scrypt hash with a fresh random salt. Invalid password length throws; plaintext is never stored. */
export function hashPassword(password: string): string {
    validatePasswordLength(password);
    const salt = randomBytes(SALT_BYTES);
    const derivedKey = scryptSync(password, salt, KEY_BYTES, SCRYPT_OPTIONS);
    return [
        HASH_PREFIX,
        SCRYPT_OPTIONS.N,
        SCRYPT_OPTIONS.r,
        SCRYPT_OPTIONS.p,
        salt.toString("hex"),
        derivedKey.toString("hex"),
    ].join("$");
}
/** Compare the original password with a supported encoded hash using timing-safe comparison. Malformed inputs return false. */
export function verifyPassword(password: string, storedHash: string): boolean {
    if (typeof password !== "string" || typeof storedHash !== "string") {
        return false;
    }
    if (password.length < 1 || password.length > 128) {
        return false;
    }
    const parts = storedHash.split("$");
    if (parts.length !== 6 || parts[0] !== HASH_PREFIX) {
        return false;
    }
    const [_, nText, rText, pText, saltHex, hashHex] = parts;
    if (nText !== String(SCRYPT_OPTIONS.N) ||
        rText !== String(SCRYPT_OPTIONS.r) ||
        pText !== String(SCRYPT_OPTIONS.p) ||
        !/^[0-9a-f]{32}$/.test(saltHex) ||
        !/^[0-9a-f]{128}$/.test(hashHex)) {
        return false;
    }
    try {
        const salt = Buffer.from(saltHex, "hex");
        const expected = Buffer.from(hashHex, "hex");
        const actual = scryptSync(password, salt, expected.length, SCRYPT_OPTIONS);
        return timingSafeEqual(actual, expected);
    }
    catch {
        return false;
    }
}
