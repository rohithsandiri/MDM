#include "registry.h"

#include <stdio.h>

/* cert_fingerprint is NULL until Phase 3 enrollment promotes a row to an
 * authoritative, cert-bound identity. claimed_device_id is always the
 * untrusted, self-reported value and is never treated as a unique key. */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS devices ("
    "  id                INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  claimed_device_id TEXT NOT NULL,"
    "  cert_fingerprint  TEXT UNIQUE,"
    "  first_seen        INTEGER NOT NULL,"
    "  last_seen         INTEGER NOT NULL,"
    "  status            TEXT NOT NULL DEFAULT 'unenrolled'"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_devices_claimed_device_id "
    "  ON devices(claimed_device_id);";

int mdm_registry_open(mdm_registry_t *reg, const char *db_path) {
    if (sqlite3_open(db_path, &reg->db) != SQLITE_OK) {
        fprintf(stderr, "registry: failed to open %s: %s\n", db_path, sqlite3_errmsg(reg->db));
        return -1;
    }

    char *errmsg = NULL;
    if (sqlite3_exec(reg->db, SCHEMA_SQL, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "registry: schema init failed: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(reg->db);
        return -1;
    }

    return 0;
}

int mdm_registry_record_checkin(mdm_registry_t *reg, const char *claimed_device_id, int64_t now) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    static const char *FIND_SQL =
        "SELECT id FROM devices "
        "WHERE claimed_device_id = ? AND cert_fingerprint IS NULL "
        "ORDER BY last_seen DESC LIMIT 1;";

    if (sqlite3_prepare_v2(reg->db, FIND_SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(find) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, claimed_device_id, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_int64 existing_id = -1;
    if (rc == SQLITE_ROW) {
        existing_id = sqlite3_column_int64(stmt, 0);
    } else if (rc != SQLITE_DONE) {
        fprintf(stderr, "registry: step(find) failed: %s\n", sqlite3_errmsg(reg->db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);

    if (existing_id >= 0) {
        static const char *UPDATE_SQL = "UPDATE devices SET last_seen = ? WHERE id = ?;";
        if (sqlite3_prepare_v2(reg->db, UPDATE_SQL, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "registry: prepare(update) failed: %s\n", sqlite3_errmsg(reg->db));
            return -1;
        }
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
        sqlite3_bind_int64(stmt, 2, existing_id);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "registry: step(update) failed: %s\n", sqlite3_errmsg(reg->db));
            return -1;
        }
        return 0;
    }

    static const char *INSERT_SQL =
        "INSERT INTO devices (claimed_device_id, cert_fingerprint, first_seen, last_seen, status) "
        "VALUES (?, NULL, ?, ?, 'unenrolled');";
    if (sqlite3_prepare_v2(reg->db, INSERT_SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(insert) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, claimed_device_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "registry: step(insert) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }

    return 0;
}

void mdm_registry_close(mdm_registry_t *reg) {
    if (reg->db != NULL) {
        sqlite3_close(reg->db);
        reg->db = NULL;
    }
}
