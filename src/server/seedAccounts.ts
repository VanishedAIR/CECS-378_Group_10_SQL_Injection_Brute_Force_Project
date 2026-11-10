import type { DatabaseSync } from "node:sqlite";
import { requireUsernameKey } from "./normalize.js";
import { hashPassword } from "./passwords.js";
/** Public, fictional credentials for the localhost lab only. */
export const DEMO_ACCOUNTS = [
    { username: "demo_user", password: "DemoUser123!", role: "user" },
    { username: "demo_admin", password: "DemoAdmin123!", role: "admin" },
] as const;
/** Create missing fictional accounts using the shared password helper. Return created/skipped results; never reset existing credentials or roles. */
export function seedAccounts(db: DatabaseSync) {
    const find = db.prepare("SELECT id FROM users WHERE username_key = ?");
    const insert = db.prepare(`INSERT INTO users (username_key, display_username, password_hash, role)
     VALUES (?, ?, ?, ?) ON CONFLICT(username_key) DO NOTHING`);
    return DEMO_ACCOUNTS.map(({ username, password, role }) => {
        const usernameKey = requireUsernameKey(username);
        const created = !find.get(usernameKey) && insert.run(usernameKey, username, hashPassword(password), role).changes === 1;
        return { username: usernameKey, role, created };
    });
}
