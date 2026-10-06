import { loadConfig } from "../src/server/config.js";
import { applySchema, withDatabase } from "../src/server/db.js";
import { seedProducts } from "../src/server/seedProducts.js";

function main(): void {
  const { databasePath } = loadConfig();

  withDatabase(databasePath, (db) => {
    applySchema(db);
    seedProducts(db);
    console.log(`Seeded products into ${databasePath}`);
  });
}

main();
