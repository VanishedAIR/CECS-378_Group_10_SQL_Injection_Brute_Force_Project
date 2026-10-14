import { Client } from "pg";
import { loadDotEnv } from "../src/server/config.js";

/**
 * Standalone Neon/PostgreSQL connectivity check. Does not touch SQLite or
 * application tables. Requires DATABASE_URL in the environment (via .env).
 */
async function main(): Promise<void> {
  loadDotEnv();

  const databaseUrl = process.env.DATABASE_URL?.trim();
  if (!databaseUrl) {
    throw new Error(
      "DATABASE_URL is not set. Add it to .env for Neon evaluation only."
    );
  }

  const client = new Client({ connectionString: databaseUrl });

  try {
    await client.connect();

    const result = await client.query(
      "SELECT current_database() AS database_name, version() AS version"
    );

    const row = result.rows[0] as {
      database_name: string;
      version: string;
    };

    console.log(`Database: ${row.database_name}`);
    console.log(`PostgreSQL: ${row.version}`);
  } finally {
    await client.end().catch(() => {
      /* ignore close errors after a failed connect */
    });
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
