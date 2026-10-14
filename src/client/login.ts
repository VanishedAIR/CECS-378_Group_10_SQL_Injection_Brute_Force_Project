
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
            window.location.href = data.redirectTo;
        } else {
            // Show a general error message
            message.textContent =
                data.error?.message || "Login failed.";
        }

    } catch {
        message.textContent = "Could not connect to the server.";
    }
});

