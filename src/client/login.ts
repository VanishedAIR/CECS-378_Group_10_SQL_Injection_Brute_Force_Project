
const form = document.getElementById("login-form") as HTMLFormElement;
const message = document.getElementById("message")!;

// Send the login information to the server
form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = (
        document.getElementById("username") as HTMLInputElement
    ).value;

    const password = (
        document.getElementById("password") as HTMLInputElement
    ).value;

    message.textContent = "Logging in...";

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            // Go to the search page after logging in
            window.location.href = data.redirectTo || "/search";
            return;
        }

        // Show how long the user has to wait after a cooldown
        if (response.status === 429) {
            const seconds = Number(data.retryAfterSeconds);

            if (Number.isFinite(seconds) && seconds > 0) {
                message.textContent =
                    `Too many login attempts. Try again in ${Math.ceil(seconds)} seconds.`;
            } else {
                message.textContent =
                    "Too many login attempts. Please try again later.";
            }
            return;
        }

        // Show other login errors
        message.textContent =
            (typeof data.error === "object"
                ? data.error?.message
                : data.message) || "Login failed.";

    } catch {
        message.textContent = "Could not connect to the server.";
    }
});
