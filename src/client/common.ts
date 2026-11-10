import type { User } from "./types.js";
let revision = 0;
let accessLost: (() => void) | undefined;
/** Keep the HTTP status with a readable error so pages can distinguish denied access. */
export class ApiError extends Error {
    constructor(public status: number, message: string) { super(message); }
}
/** Return a required page element; a missing ID is a template error. */
export function element<T extends HTMLElement = HTMLElement>(id: string): T {
    const node = document.getElementById(id);
    if (!node)
        throw new Error(`Missing page element: ${id}`);
    return node as T;
}
/** Create plain text nodes. Product names, SQL and usernames must never become HTML. */
export function textNode<K extends keyof HTMLElementTagNameMap>(tag: K, text: string, className = ""): HTMLElementTagNameMap[K] {
    const node = document.createElement(tag);
    node.textContent = text;
    node.className = className;
    return node;
}
/** Format a UTC millisecond timestamp for the viewer's local timezone. */
export function showTime(value: number): string { return new Date(value).toLocaleString(); }
/** Invalidate pending responses and clear sensitive data before showing an access warning. */
function loseAccess(status: number): void {
    revision++;
    accessLost?.();
    element("identity").textContent = "Session unavailable";
    element("admin-link").hidden = true;
    element("session-message").hidden = false;
    element("session-message").textContent = status === 403 ? "Administrator access is required. Return to the catalog or sign in with an administrator account." : "Your session is no longer available. Sign in again to continue.";
    element("sign-in-again").hidden = false;
}
/** Read same-origin JSON; a logout/denial stops an older response repopulating sensitive data. */
export async function api<T>(url: string, options?: RequestInit): Promise<T> {
    const started = revision;
    const response = await fetch(url, { ...options, credentials: "same-origin", cache: "no-store" });
    if (started !== revision)
        throw new ApiError(401, "Session changed. Sign in again.");
    if (response.status === 401 || response.status === 403)
        loseAccess(response.status);
    if (!response.ok) {
        const data = await response.json().catch(() => null);
        throw new ApiError(response.status, data?.error?.message || "The request could not be completed. Please try again.");
    }
    const data = response.status === 204 ? undefined as T : await response.json() as T;
    if (started !== revision)
        throw new ApiError(401, "Session changed. Sign in again.");
    return data;
}
/** Clear data immediately, then destroy the server session. A 204 response has no JSON body. */
export async function logout(): Promise<void> {
    revision++;
    accessLost?.();
    const button = element<HTMLButtonElement>("logout");
    button.disabled = true;
    try {
        const response = await fetch("/api/logout", { method: "POST", credentials: "same-origin", cache: "no-store" });
        if (response.status !== 204)
            throw new Error("Sign-out failed.");
        window.location.assign("/login");
    }
    catch {
        element("session-message").hidden = false;
        element("session-message").textContent = "Sign-out could not be confirmed. Retry signing out before leaving this shared computer.";
        button.disabled = false;
    }
}
/** Load the public user and wire navigation/logout. Revalidate periodically to clear revoked sessions. */
export async function initShell(onLost: () => void): Promise<User> {
    accessLost = onLost;
    element("logout").addEventListener("click", () => { void logout(); });
    /** Refresh identity from the server so role changes never rely on a cached browser role. */
    const readUser = async (): Promise<User> => {
        const { user } = await api<{
            user: User;
        }>("/api/me");
        element("identity").textContent = `${user.displayUsername} (${user.role === "admin" ? "Administrator" : "Catalog user"})`;
        element("admin-link").hidden = user.role !== "admin";
        if (document.body.dataset.page === "dashboard" && user.role !== "admin") {
            loseAccess(403);
            throw new ApiError(403, "Administrator access is required.");
        }
        return user;
    };
    const user = await readUser();
    const timer = window.setInterval(() => {
        void readUser().catch(() => {
            revision++;
            onLost();
            element("session-message").hidden = false;
            element("session-message").textContent = "Session validation failed. Sign in again or reload this page.";
            element("sign-in-again").hidden = false;
        });
    }, 30000);
    window.addEventListener("pagehide", () => window.clearInterval(timer), { once: true });
    return user;
}
