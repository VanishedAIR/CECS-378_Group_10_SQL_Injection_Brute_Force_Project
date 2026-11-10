import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { readSchemaSql, resolveProjectPath } from "./config.js";
import { runSchemaMigrations } from "./schemaMigrate.js";
/** Open or create SQLite, create its parent folder, and enable foreign keys. */
export function openDatabase(databasePath: string): DatabaseSync {
    const absolutePath = resolveProjectPath(databasePath);
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
    const db = new DatabaseSync(absolutePath);
    db.exec("PRAGMA foreign_keys = ON;");
    return db;
}
/** Close a supplied database handle; an absent handle needs no cleanup. */
export function closeDatabase(db: DatabaseSync | undefined): void {
    if (db) {
        db.close();
    }
}
/** Create missing base tables and apply migrations without clearing existing rows. */
export function applySchema(db: DatabaseSync): void {
    db.exec(readSchemaSql());
    runSchemaMigrations(db);
}
/** Return application table names, excluding SQLite internal tables. */
export function listUserTables(db: DatabaseSync): string[] {
    const rows = db
        .prepare(`SELECT name FROM sqlite_master
       WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
       ORDER BY name`)
        .all() as {
        name: string;
    }[];
    return rows.map((row) => row.name);
}
export type DatabaseWork<T> = (db: DatabaseSync) => T;
const openTransactions = new WeakSet<DatabaseSync>();
/** Recognize a promise-like callback result so transactions cannot outlive synchronous work. */
function isPromise(value: unknown): value is Promise<unknown> {
    return (typeof value === "object" &&
        value !== null &&
        "then" in value &&
        typeof (value as {
            then: unknown;
        }).then === "function");
}
/** Run synchronous work atomically and return its result. Roll back on error; reject nested calls and promises. Only this caller owns the transaction. */
export function withTransaction<T>(db: DatabaseSync, work: DatabaseWork<T>): T {
    if (openTransactions.has(db)) {
        throw new Error("Nested withTransaction is not allowed. Keep using the same database handle inside the caller's transaction.");
    }
    let started = false;
    try {
        db.exec("BEGIN IMMEDIATE");
        started = true;
    }
    catch (error) {
        // BEGIN never started, so do not roll back a transaction the caller already owns.
        throw error;
    }
    openTransactions.add(db);
    let committed = false;
    try {
        const result = work(db);
        if (isPromise(result)) {
            throw new Error("withTransaction callbacks must be synchronous. Do not return a Promise.");
        }
        db.exec("COMMIT");
        committed = true;
        return result;
    }
    catch (error) {
        if (started && !committed) {
            try {
                db.exec("ROLLBACK");
            }
            catch {
                // The transaction may already be closed after a SQLite abort.
            }
        }
        throw error;
    }
    finally {
        openTransactions.delete(db);
    }
}
/** Open SQLite, return the callback result, and close the handle even if work throws. */
export function withDatabase<T>(databasePath: string, work: DatabaseWork<T>): T {
    const db = openDatabase(databasePath);
    try {
        return work(db);
    }
    finally {
        closeDatabase(db);
    }
}
