import { api, ApiError, element, initShell, textNode } from "./common.js";
type SearchResponse = {
    mode: "protected" | "vulnerable";
    rows: {
        id: number;
        name: string;
        description: string;
    }[];
    resultCount: number;
};
let request = 0, busy = false, authorized = false;
/** Clear catalog data and invalidate requests that were started before access was lost. */
function clearSearch(): void {
    request++;
    authorized = false;
    busy = false;
    element("results").replaceChildren();
    element("results").setAttribute("aria-busy", "false");
    element("result-count").textContent = "No results loaded";
    element("message").textContent = "Sign in to load catalog data.";
    for (const id of ["protected", "vulnerable"])
        element<HTMLButtonElement>(id).disabled = true;
}
/** Search without trimming q, then render each returned product as plain text. */
async function search(mode: "protected" | "vulnerable"): Promise<void> {
    if (busy || !authorized)
        return;
    const q = element<HTMLInputElement>("search-input").value;
    if (q.length < 1 || q.length > 100) {
        element("message").textContent = "Enter between 1 and 100 characters. Spaces are kept as entered.";
        element("message").className = "notice warning";
        return;
    }
    const current = ++request;
    busy = true;
    element("results").replaceChildren();
    element("result-count").textContent = "Loading results...";
    element("message").className = "notice";
    element("message").textContent = `Running ${mode} search...`;
    element("results").setAttribute("aria-busy", "true");
    for (const id of ["protected", "vulnerable"])
        element<HTMLButtonElement>(id).disabled = true;
    try {
        const data = await api<SearchResponse>(`/api/search/${mode}?q=${encodeURIComponent(q)}`);
        if (current !== request)
            return;
        element("result-count").textContent = `${data.resultCount} ${data.resultCount === 1 ? "product" : "products"}. ${data.mode} query.`;
        element("message").textContent = data.resultCount ? "Search complete. Product data below comes from SQLite." : "No products match this query. Try Mouse, Keyboard, or Monitor.";
        for (const product of data.rows) {
            const card = textNode("article", "", "product-card");
            card.append(textNode("span", `NS / ${String(product.id).padStart(2, "0")}`, "eyebrow"), textNode("h3", product.name), textNode("p", product.description), textNode("span", "Workplace essentials", "tag"));
            element("results").appendChild(card);
        }
    }
    catch (error) {
        if (current !== request)
            return;
        element("result-count").textContent = "Search unavailable";
        element("message").className = "notice error";
        element("message").textContent = error instanceof ApiError && error.status === 404 && mode === "vulnerable" ? "The vulnerable demo is disabled. It requires LAB_MODE=true when the local server starts. Protected search remains available." : error instanceof Error ? error.message : "Search failed. Try again.";
    }
    finally {
        if (current === request) {
            busy = false;
            element("results").setAttribute("aria-busy", "false");
            for (const id of ["protected", "vulnerable"])
                element<HTMLButtonElement>(id).disabled = !authorized;
        }
    }
}
element("vulnerable").addEventListener("click", () => { void search("vulnerable"); });
element("search-form").addEventListener("submit", event => { event.preventDefault(); void search("protected"); });
void initShell(clearSearch).then(() => {
    authorized = true;
    for (const id of ["protected", "vulnerable"])
        element<HTMLButtonElement>(id).disabled = false;
    element("message").textContent = "Ready. Enter a product name and choose a query mode.";
}).catch(() => { clearSearch(); });
