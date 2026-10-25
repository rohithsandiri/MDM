#include "registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* cert_fingerprint is NULL until Phase 3 enrollment promotes a row to an
 * authoritative, cert-bound identity. claimed_device_id is always the
 * untrusted, self-reported value and is never treated as a unique key.
 * inventory_json holds only the latest snapshot (not history) per row. */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS devices ("
    "  id                   INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  claimed_device_id    TEXT NOT NULL,"
    "  cert_fingerprint     TEXT UNIQUE,"
    "  first_seen           INTEGER NOT NULL,"
    "  last_seen            INTEGER NOT NULL,"
    "  status               TEXT NOT NULL DEFAULT 'unenrolled',"
    "  inventory_json       TEXT,"
    "  inventory_updated_at INTEGER"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_devices_claimed_device_id "
    "  ON devices(claimed_device_id);";

/* Shared by record_checkin/store_inventory/get_latest_inventory: resolves
 * the untrusted claimed_device_id to the same not-yet-enrolled row they
 * all operate on. Returns the row id, or -1 if none exists / on error. */
static sqlite3_int64 find_row_id(mdm_registry_t *reg, const char *claimed_device_id) {
    static const char *FIND_SQL =
        "SELECT id FROM devices "
        "WHERE claimed_device_id = ? AND cert_fingerprint IS NULL "
        "ORDER BY last_seen DESC LIMIT 1;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, FIND_SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(find) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, claimed_device_id, -1, SQLITE_STATIC);

    sqlite3_int64 id = -1;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        id = sqlite3_column_int64(stmt, 0);
    } else if (rc != SQLITE_DONE) {
        fprintf(stderr, "registry: step(find) failed: %s\n", sqlite3_errmsg(reg->db));
    }
    sqlite3_finalize(stmt);
    return id;
}

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
    sqlite3_int64 existing_id = find_row_id(reg, claimed_device_id);
    sqlite3_stmt *stmt = NULL;
    int rc;

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

int mdm_registry_store_inventory(mdm_registry_t *reg, const char *claimed_device_id,
                                  const char *inventory_json, int64_t now) {
    sqlite3_int64 id = find_row_id(reg, claimed_device_id);
    if (id < 0) {
        fprintf(stderr, "registry: store_inventory: no row for '%s' (check-in first)\n",
                claimed_device_id);
        return -1;
    }

    static const char *UPDATE_SQL =
        "UPDATE devices SET inventory_json = ?, inventory_updated_at = ? WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, UPDATE_SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(store_inventory) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, inventory_json, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 3, id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "registry: step(store_inventory) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    return 0;
}

int mdm_registry_get_latest_inventory(mdm_registry_t *reg, const char *claimed_device_id,
                                       char **out_json) {
    *out_json = NULL;

    static const char *SELECT_SQL =
        "SELECT inventory_json FROM devices "
        "WHERE claimed_device_id = ? "
        "ORDER BY last_seen DESC LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, SELECT_SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(get_inventory) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, claimed_device_id, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 1; /* no such device */
    }
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "registry: step(get_inventory) failed: %s\n", sqlite3_errmsg(reg->db));
        sqlite3_finalize(stmt);
        return -1;
    }

    const unsigned char *text = sqlite3_column_text(stmt, 0);
    if (text == NULL) {
        sqlite3_finalize(stmt);
        return 1; /* row exists but no inventory snapshot yet */
    }
    *out_json = strdup((const char *)text);
    sqlite3_finalize(stmt);
    return (*out_json != NULL) ? 0 : -1;
}

void mdm_registry_close(mdm_registry_t *reg) {
    if (reg->db != NULL) {
        sqlite3_close(reg->db);
        reg->db = NULL;
    }
}
