import type { DatabaseSync } from "node:sqlite";

/** Deterministic fictional products for SQL search demos. */
export const SEED_PRODUCTS = [
  {
    id: 1,
    name: "Mouse",
    description: "Fictional wireless mouse for lab demos.",
  },
  {
    id: 2,
    name: "Keyboard",
    description: "Fictional mechanical keyboard for lab demos.",
  },
  {
    id: 3,
    name: "Monitor",
    description: "Fictional display for lab demos.",
  },
] as const;

/**
 * Inserts the three agreed products with fixed IDs.
 * Account seeding waits for Bin's password helper (see context.md section 9.7).
 */
export function seedProducts(db: DatabaseSync): void {
  const insert = db.prepare(
    `INSERT INTO products (id, name, description) VALUES (?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET name = excluded.name, description = excluded.description`
  );

  for (const product of SEED_PRODUCTS) {
    insert.run(product.id, product.name, product.description);
  }
}
