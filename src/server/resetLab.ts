import type { DatabaseSync } from "node:sqlite";
import { withTransaction } from "./db.js";
import { seedProducts } from "./seedProducts.js";
/** Clear evidence and cooldowns and restore products in one CLI-owned transaction. Users and their credentials are preserved. */
export function resetLabEvidence(db: DatabaseSync): void {
    withTransaction(db, (tx) => {
        tx.exec("DELETE FROM cooldowns");
        tx.exec("DELETE FROM security_events");
        tx.exec("DELETE FROM query_audit");
        tx.exec("DELETE FROM login_attempts");
        seedProducts(tx);
    });
}
