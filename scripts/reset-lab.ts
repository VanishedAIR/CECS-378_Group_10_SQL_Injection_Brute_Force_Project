import { loadConfig } from "../src/server/config.js";
import { applySchema, withDatabase } from "../src/server/db.js";
import { resetLabEvidence } from "../src/server/resetLab.js";

function main(): void {
  const { databasePath } = loadConfig();
  withDatabase(databasePath, (db) => {
    applySchema(db);
    resetLabEvidence(db);
    console.log(`Reset lab evidence and restored products in ${databasePath}`);
  });
}

main();
