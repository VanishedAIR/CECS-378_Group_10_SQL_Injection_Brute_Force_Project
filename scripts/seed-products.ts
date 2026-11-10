import { loadConfig } from "../src/server/config.js";
import { applySchema, withDatabase, withTransaction } from "../src/server/db.js";
import { seedAccounts } from "../src/server/seedAccounts.js";
import { seedProducts } from "../src/server/seedProducts.js";
/** Apply schema, then seed products and missing accounts together; report conflicts without resetting them. */
function main(): void {
    const { databasePath } = loadConfig();
    withDatabase(databasePath, (db) => {
        applySchema(db);
        const accounts = withTransaction(db, () => {
            seedProducts(db);
            return seedAccounts(db);
        });
        console.log(`Seeded products into ${databasePath}`);
        for (const account of accounts) {
            console.log(account.created
                ? `Created ${account.username} (${account.role})`
                : `Skipped ${account.username}: username already exists; password and role unchanged. Demo credentials and expected role (${account.role}) are not guaranteed.`);
        }
    });
}
main();
