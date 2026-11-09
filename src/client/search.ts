
const searchInput = document.getElementById(
    "search-input"
) as HTMLInputElement;

const searchMessage = document.getElementById("message")!;
const searchResults = document.getElementById("results")!;

// Run a search using the selected mode
async function runSearch(mode: string): Promise<void> {
    const q = searchInput.value;

    if (!q) {
        searchMessage.textContent = "Enter a product name.";
        return;
    }

    searchMessage.textContent = "Searching...";
    searchResults.replaceChildren();

    try {
        const response = await fetch(
            "/api/search/" + mode + "?q=" + encodeURIComponent(q)
        );

        const data = await response.json();

        if (!response.ok) {
            searchMessage.textContent =
                data.error?.message || "Search failed.";
            return;
        }

        searchMessage.textContent =
            "Found " + data.resultCount + " products.";

        // Display each product safely as text
        for (const product of data.rows) {
            const item = document.createElement("p");

            item.textContent =
                product.name + " - " + product.description;

            searchResults.appendChild(item);
        }

    } catch {
        searchMessage.textContent = "Could not load results.";
    }
}

// Vulnerable search button
document.getElementById("vulnerable")!
    .addEventListener("click", () => {
        void runSearch("vulnerable");
    });

// Protected search button
document.getElementById("protected")!
    .addEventListener("click", () => {
        void runSearch("protected");
    });

