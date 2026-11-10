import type { DatabaseSync } from "node:sqlite";
export const SCHEMA_VERSION = 2;
const META_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS lab_schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;
const SECURITY_EVENT_INSERT_TRIGGER = `
CREATE TRIGGER IF NOT EXISTS security_events_validate_insert
BEFORE INSERT ON security_events
BEGIN
  SELECT RAISE(ABORT, 'unsupported event_type')
  WHERE NEW.event_type NOT IN ('BRUTE_FORCE_DETECTED', 'SQLI_ATTEMPT');

  SELECT RAISE(ABORT, 'security_events require exactly one evidence reference')
  WHERE NOT (
    (NEW.trigger_login_attempt_id IS NOT NULL AND NEW.query_audit_id IS NULL)
    OR (NEW.trigger_login_attempt_id IS NULL AND NEW.query_audit_id IS NOT NULL)
  );

  SELECT RAISE(ABORT, 'BRUTE_FORCE_DETECTED evidence mismatch')
  WHERE NEW.event_type = 'BRUTE_FORCE_DETECTED'
    AND (
      NEW.trigger_login_attempt_id IS NULL
      OR NEW.query_audit_id IS NOT NULL
      OR NEW.scope_type NOT IN ('account', 'ip')
    );

  SELECT RAISE(ABORT, 'SQLI_ATTEMPT evidence mismatch')
  WHERE NEW.event_type = 'SQLI_ATTEMPT'
    AND (
      NEW.query_audit_id IS NULL
      OR NEW.trigger_login_attempt_id IS NOT NULL
      OR NEW.scope_type != 'request'
    );
END;
`;
const SECURITY_EVENT_UPDATE_TRIGGER = `
CREATE TRIGGER IF NOT EXISTS security_events_validate_update
BEFORE UPDATE ON security_events
BEGIN
  SELECT RAISE(ABORT, 'unsupported event_type')
  WHERE NEW.event_type NOT IN ('BRUTE_FORCE_DETECTED', 'SQLI_ATTEMPT');

  SELECT RAISE(ABORT, 'security_events require exactly one evidence reference')
  WHERE NOT (
    (NEW.trigger_login_attempt_id IS NOT NULL AND NEW.query_audit_id IS NULL)
    OR (NEW.trigger_login_attempt_id IS NULL AND NEW.query_audit_id IS NOT NULL)
  );

  SELECT RAISE(ABORT, 'BRUTE_FORCE_DETECTED evidence mismatch')
  WHERE NEW.event_type = 'BRUTE_FORCE_DETECTED'
    AND (
      NEW.trigger_login_attempt_id IS NULL
      OR NEW.query_audit_id IS NOT NULL
      OR NEW.scope_type NOT IN ('account', 'ip')
    );

  SELECT RAISE(ABORT, 'SQLI_ATTEMPT evidence mismatch')
  WHERE NEW.event_type = 'SQLI_ATTEMPT'
    AND (
      NEW.query_audit_id IS NULL
      OR NEW.trigger_login_attempt_id IS NOT NULL
      OR NEW.scope_type != 'request'
    );
END;
`;
/** Read the recorded migration version; treat missing or malformed metadata as version zero. */
function readSchemaVersion(db: DatabaseSync): number {
    const row = db
        .prepare("SELECT value FROM lab_schema_meta WHERE key = 'schema_version'")
        .get() as {
        value: string;
    } | undefined;
    if (!row) {
        return 0;
    }
    const parsed = Number(row.value);
    return Number.isInteger(parsed) ? parsed : 0;
}
/** Record a completed version using a bound upsert. */
function writeSchemaVersion(db: DatabaseSync, version: number): void {
    db.prepare(`INSERT INTO lab_schema_meta (key, value) VALUES ('schema_version', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(String(version));
}
/** Install insert/update evidence checks on older databases without rebuilding their tables. */
function migrateToVersion2(db: DatabaseSync): void {
    db.exec(SECURITY_EVENT_INSERT_TRIGGER);
    db.exec(SECURITY_EVENT_UPDATE_TRIGGER);
}
/** Create migration metadata and install missing validation triggers. Base tables must already exist. */
export function runSchemaMigrations(db: DatabaseSync): void {
    db.exec(META_TABLE_SQL);
    const current = readSchemaVersion(db);
    if (current < 2) {
        migrateToVersion2(db);
        writeSchemaVersion(db, 2);
    }
}
/** Ensure the metadata table exists and return its recorded version. */
export function getSchemaVersion(db: DatabaseSync): number {
    db.exec(META_TABLE_SQL);
    return readSchemaVersion(db);
}
