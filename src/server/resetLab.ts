import type { DatabaseSync } from "node:sqlite";
import { withTransaction } from "./db.js";
import { seedProducts } from "./seedProducts.js";

/**
 * Clears demo evidence and cooldowns, then restores the three products.
 * Does not delete users. Must be called from the local CLI, never from HTTP
 * or server startup. The deletes and product upsert share one transaction.
 */
export function resetLabEvidence(db: DatabaseSync): void {
  withTransaction(db, (tx) => {
    tx.exec("DELETE FROM cooldowns");
    tx.exec("DELETE FROM security_events");
    tx.exec("DELETE FROM query_audit");
    tx.exec("DELETE FROM login_attempts");
    seedProducts(tx);
  });
}
