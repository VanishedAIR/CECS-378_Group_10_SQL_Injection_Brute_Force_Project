import { element } from "./common.js";
const form = element<HTMLFormElement>("login-form");
const submit = element<HTMLButtonElement>("submit");
const message = element("message");
let submitting = false;
let retryUntil = 0;
let retryTimer: number | undefined;
/** Display the server retry delay without automatically resubmitting credentials. */
function updateRetry(): void {
    const seconds = Math.max(0, Math.ceil((retryUntil - Date.now()) / 1000));
    submit.disabled = submitting || seconds > 0;
    if (seconds > 0) {
        message.textContent = `Too many login attempts. Try again in ${seconds} seconds.`;
        message.className = "notice warning";
    }
    else {
        window.clearInterval(retryTimer);
        message.textContent = "You can try signing in again.";
    }
}
/** Send one login at a time. Keep the original password; spaces can be part of it. */
async function signIn(event: Event): Promise<void> {
    event.preventDefault();
    if (submitting || Date.now() < retryUntil)
        return;
    submitting = true;
    submit.disabled = true;
    submit.textContent = "Signing in...";
    form.setAttribute("aria-busy", "true");
    message.className = "notice";
    message.textContent = "Checking your account...";
    try {
        const response = await fetch("/api/login", {
            method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: element<HTMLInputElement>("username").value, password: element<HTMLInputElement>("password").value }),
        });
        const data = await response.json();
        if (response.ok) {
            window.location.assign(data.redirectTo === "/search" ? data.redirectTo : "/search");
            return;
        }
        if (response.status === 429 && Number.isFinite(data.retryAfterSeconds) && data.retryAfterSeconds > 0) {
            retryUntil = Date.now() + data.retryAfterSeconds * 1000;
            updateRetry();
            retryTimer = window.setInterval(updateRetry, 1000);
        }
        else {
            message.className = response.status === 429 ? "notice warning" : "notice error";
            message.textContent = response.status === 429 ? "Too many login attempts. Please try again later." : data.error?.message || "Sign-in failed. Please try again.";
        }
    }
    catch {
        message.className = "notice error";
        message.textContent = "We could not reach the local server. Check that it is running and try again.";
    }
    finally {
        submitting = false;
        submit.disabled = Date.now() < retryUntil;
        submit.textContent = "Sign in";
        form.setAttribute("aria-busy", "false");
    }
}
form.addEventListener("submit", event => { void signIn(event); });
window.addEventListener("pagehide", () => window.clearInterval(retryTimer), { once: true });
