
// Get an element from the dashboard
function getElement(id: string): HTMLElement {
    const element = document.getElementById(id);

    if (!element) {
        throw new Error("Missing element: " + id);
    }

    return element;
}

// Make database timestamps easier to read
function showTime(value: number): string {
    return new Date(value).toLocaleString();
}

// Create a table cell with plain text
function addCell(row: HTMLTableRowElement, value: string): void {
    const cell = row.insertCell();
    cell.textContent = value;
}

// Show a message when a table has no data
function showEmpty(id: string, columns: number): void {
    const table = getElement(id);
    table.replaceChildren();

    const row = document.createElement("tr");
    const cell = document.createElement("td");

    cell.colSpan = columns;
    cell.textContent = "Nothing to show yet.";

    row.appendChild(cell);
    table.appendChild(row);
}

// Ask the server for the dashboard information
async function loadDashboard(): Promise<void> {
    const message = getElement("message");

    message.textContent = "Loading dashboard...";

    try {
        const response = await fetch("/api/dashboard");

        if (!response.ok) {
            throw new Error(
                "Unable to load dashboard. Status: " + response.status
            );
        }

        const data = await response.json();

        // Update the security counters
        getElement("success").textContent =
            String(data.totals.successfulLogins);

        getElement("failed").textContent =
            String(data.totals.failedLogins);

        getElement("blocked").textContent =
            String(data.totals.blockedLogins);

        getElement("sql").textContent =
            String(data.totals.sqlInjectionAlerts);

        getElement("brute").textContent =
            String(data.totals.bruteForceAlerts);

        // Show the active cooldowns
        const cooldownTable = getElement("cooldowns");
        cooldownTable.replaceChildren();

        for (const cooldown of data.activeCooldowns) {
            const row = document.createElement("tr");

            addCell(row, cooldown.scope.type);
            addCell(row, cooldown.scope.key);
            addCell(row, showTime(cooldown.blockedUntil));
            addCell(row, String(cooldown.remainingSeconds));

            cooldownTable.appendChild(row);
        }

        if (data.activeCooldowns.length === 0) {
            showEmpty("cooldowns", 4);
        }

        // Show recent security alerts
        const alertTable = getElement("alerts");
        alertTable.replaceChildren();

        for (const alert of data.recentAlerts) {
            const row = document.createElement("tr");

            addCell(row, showTime(alert.timestampUtc));
            addCell(row, alert.eventType);
            addCell(row, alert.scope.type + ": " + alert.scope.key);
            addCell(row, alert.severity);

            // Add a button to open alert details
            const cell = row.insertCell();
            const button = document.createElement("button");

            button.textContent = "View";
            button.addEventListener("click", () => {
                void loadAlert(alert.id);
            });

            cell.appendChild(button);
            alertTable.appendChild(row);
        }

        if (data.recentAlerts.length === 0) {
            showEmpty("alerts", 5);
        }

        // Show recent login attempts
        const loginTable = getElement("logins");
        loginTable.replaceChildren();

        for (const attempt of data.recentLoginAttempts) {
            const row = document.createElement("tr");

            addCell(row, showTime(attempt.timestampUtc));
            addCell(row, attempt.usernameKey);
            addCell(row, attempt.sourceIp);
            addCell(row, attempt.outcome.toUpperCase());

            loginTable.appendChild(row);
        }

        if (data.recentLoginAttempts.length === 0) {
            showEmpty("logins", 4);
        }

        message.textContent =
            "Last updated: " + showTime(data.generatedAt);

    } catch (error) {
        message.textContent =
            error instanceof Error ? error.message : "Something went wrong.";
    }
}

// Get the evidence for one security alert
async function loadAlert(id: number): Promise<void> {
    const message = getElement("alert-message");
    const details = getElement("alert-details");

    message.textContent = "Loading alert...";
    details.textContent = "";

    try {
        const response = await fetch("/api/alerts/" + id);

        if (!response.ok) {
            throw new Error("Could not load alert.");
        }

        const data = await response.json();

        message.textContent = data.alert.summary;

        // Show the alert and its evidence as plain text
        details.textContent = JSON.stringify({
            alert: data.alert,
            details: data.details,
            evidence: data.evidence
        }, null, 2);

    } catch {
        message.textContent = "Could not load alert details.";
    }
}

// Load the dashboard when the page opens
void loadDashboard();

// Refresh when the user clicks the button
getElement("refresh").addEventListener("click", () => {
    void loadDashboard();
});

