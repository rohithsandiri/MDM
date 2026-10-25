#include "registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* cert_fingerprint is nullable only to allow promoting a pre-Phase-3
 * leftover unenrolled row (see mdm_registry_upsert_enrolled); every row
 * created from here on gets one immediately, since mTLS now gates the
 * whole channel. claimed_device_id is kept purely as an informational,
 * untrusted label. last_command_seq is the per-device replay-protection
 * counter hand-ed to the agent inside each signed command's payload. */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS devices ("
    "  id                   INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  cert_fingerprint     TEXT UNIQUE,"
    "  claimed_device_id    TEXT,"
    "  first_seen           INTEGER NOT NULL,"
    "  last_seen            INTEGER NOT NULL,"
    "  status               TEXT NOT NULL DEFAULT 'enrolled',"
    "  inventory_json       TEXT,"
    "  inventory_updated_at INTEGER,"
    "  last_command_seq     INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS pending_commands ("
    "  id                   INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  device_id            INTEGER NOT NULL REFERENCES devices(id),"
    "  signed_envelope_json TEXT NOT NULL,"
    "  created_at           INTEGER NOT NULL,"
    "  delivered            INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_pending_commands_device "
    "  ON pending_commands(device_id, delivered);";

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

void mdm_registry_close(mdm_registry_t *reg) {
    if (reg->db != NULL) {
        sqlite3_close(reg->db);
        reg->db = NULL;
    }
}

int mdm_registry_find_by_fingerprint(mdm_registry_t *reg, const char *cert_fingerprint,
                                      int64_t *out_device_id) {
    static const char *SQL = "SELECT id FROM devices WHERE cert_fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(find_by_fingerprint) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, cert_fingerprint, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_device_id = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE) return 1;
    fprintf(stderr, "registry: step(find_by_fingerprint) failed: %s\n", sqlite3_errmsg(reg->db));
    return -1;
}

static int64_t find_promotable_legacy_row(mdm_registry_t *reg, const char *claimed_device_id) {
    static const char *SQL =
        "SELECT id FROM devices "
        "WHERE claimed_device_id = ? AND cert_fingerprint IS NULL "
        "ORDER BY last_seen DESC LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, claimed_device_id, -1, SQLITE_STATIC);

    int64_t id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return id;
}

int64_t mdm_registry_upsert_enrolled(mdm_registry_t *reg, const char *cert_fingerprint,
                                      const char *claimed_device_id, int64_t now) {
    int64_t existing_id = -1;
    int rc = mdm_registry_find_by_fingerprint(reg, cert_fingerprint, &existing_id);
    if (rc < 0) return -1;

    sqlite3_stmt *stmt = NULL;

    if (rc == 0) {
        static const char *SQL =
            "UPDATE devices SET last_seen = ?, claimed_device_id = ? WHERE id = ?;";
        if (sqlite3_prepare_v2(reg->db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "registry: prepare(touch) failed: %s\n", sqlite3_errmsg(reg->db));
            return -1;
        }
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
        sqlite3_bind_text(stmt, 2, claimed_device_id, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, existing_id);
        int step_rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (step_rc != SQLITE_DONE) {
            fprintf(stderr, "registry: step(touch) failed: %s\n", sqlite3_errmsg(reg->db));
            return -1;
        }
        return existing_id;
    }

    int64_t legacy_id = find_promotable_legacy_row(reg, claimed_device_id);
    if (legacy_id >= 0) {
        static const char *SQL =
            "UPDATE devices SET cert_fingerprint = ?, status = 'enrolled', last_seen = ? "
            "WHERE id = ?;";
        if (sqlite3_prepare_v2(reg->db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "registry: prepare(promote) failed: %s\n", sqlite3_errmsg(reg->db));
            return -1;
        }
        sqlite3_bind_text(stmt, 1, cert_fingerprint, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
        sqlite3_bind_int64(stmt, 3, legacy_id);
        int step_rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (step_rc != SQLITE_DONE) {
            fprintf(stderr, "registry: step(promote) failed: %s\n", sqlite3_errmsg(reg->db));
            return -1;
        }
        printf("registry: promoted legacy row id=%lld to enrolled (fingerprint=%s)\n",
               (long long)legacy_id, cert_fingerprint);
        return legacy_id;
    }

    static const char *INSERT_SQL =
        "INSERT INTO devices (cert_fingerprint, claimed_device_id, first_seen, last_seen, status) "
        "VALUES (?, ?, ?, ?, 'enrolled');";
    if (sqlite3_prepare_v2(reg->db, INSERT_SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(insert) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, cert_fingerprint, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, claimed_device_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    int step_rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (step_rc != SQLITE_DONE) {
        fprintf(stderr, "registry: step(insert) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }

    return sqlite3_last_insert_rowid(reg->db);
}

int mdm_registry_store_inventory(mdm_registry_t *reg, int64_t device_row_id,
                                  const char *inventory_json, int64_t now) {
    static const char *SQL =
        "UPDATE devices SET inventory_json = ?, inventory_updated_at = ? WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(store_inventory) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, inventory_json, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 3, device_row_id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "registry: step(store_inventory) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    return 0;
}

int mdm_registry_get_latest_inventory(mdm_registry_t *reg, const char *cert_fingerprint,
                                       char **out_json) {
    *out_json = NULL;

    static const char *SQL = "SELECT inventory_json FROM devices WHERE cert_fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(get_inventory) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, cert_fingerprint, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 1;
    }
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "registry: step(get_inventory) failed: %s\n", sqlite3_errmsg(reg->db));
        sqlite3_finalize(stmt);
        return -1;
    }

    const unsigned char *text = sqlite3_column_text(stmt, 0);
    if (text == NULL) {
        sqlite3_finalize(stmt);
        return 1;
    }
    *out_json = strdup((const char *)text);
    sqlite3_finalize(stmt);
    return (*out_json != NULL) ? 0 : -1;
}

int mdm_registry_next_sequence(mdm_registry_t *reg, int64_t device_row_id, int64_t *out_seq) {
    static const char *SQL =
        "UPDATE devices SET last_command_seq = last_command_seq + 1 WHERE id = ? "
        "RETURNING last_command_seq;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(next_sequence) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, device_row_id);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "registry: step(next_sequence) failed: %s\n", sqlite3_errmsg(reg->db));
        sqlite3_finalize(stmt);
        return -1;
    }
    *out_seq = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return 0;
}

int mdm_registry_queue_command(mdm_registry_t *reg, int64_t device_row_id,
                                const char *signed_envelope_json, int64_t now) {
    static const char *SQL =
        "INSERT INTO pending_commands (device_id, signed_envelope_json, created_at) "
        "VALUES (?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(queue_command) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, device_row_id);
    sqlite3_bind_text(stmt, 2, signed_envelope_json, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "registry: step(queue_command) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    return 0;
}

int mdm_registry_pop_pending_command(mdm_registry_t *reg, int64_t device_row_id, char **out_json) {
    *out_json = NULL;

    static const char *SELECT_SQL =
        "SELECT id, signed_envelope_json FROM pending_commands "
        "WHERE device_id = ? AND delivered = 0 ORDER BY id ASC LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, SELECT_SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(pop_pending) failed: %s\n", sqlite3_errmsg(reg->db));
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, device_row_id);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 1;
    }
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "registry: step(pop_pending select) failed: %s\n", sqlite3_errmsg(reg->db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_int64 pending_id = sqlite3_column_int64(stmt, 0);
    const unsigned char *text = sqlite3_column_text(stmt, 1);
    char *json = (text != NULL) ? strdup((const char *)text) : NULL;
    sqlite3_finalize(stmt);

    if (json == NULL) return -1;

    static const char *UPDATE_SQL = "UPDATE pending_commands SET delivered = 1 WHERE id = ?;";
    if (sqlite3_prepare_v2(reg->db, UPDATE_SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(pop_pending update) failed: %s\n", sqlite3_errmsg(reg->db));
        free(json);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, pending_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "registry: step(pop_pending update) failed: %s\n", sqlite3_errmsg(reg->db));
        free(json);
        return -1;
    }

    *out_json = json;
    return 0;
}

void mdm_registry_list_devices(mdm_registry_t *reg) {
    static const char *SQL =
        "SELECT id, cert_fingerprint, claimed_device_id, status, last_seen, last_command_seq "
        "FROM devices ORDER BY last_seen DESC;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(reg->db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "registry: prepare(list_devices) failed: %s\n", sqlite3_errmsg(reg->db));
        return;
    }

    /* Prints the full fingerprint, not a truncated preview — it's the
     * exact string --queue-command and --print-inventory need, and a
     * shortened one would force the operator to go query sqlite directly
     * to use either. */
    printf("%-4s %-66s %-24s %-10s %-12s %s\n", "id", "fingerprint", "claimed_device_id", "status",
           "last_seen", "seq");
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_int64 id = sqlite3_column_int64(stmt, 0);
        const unsigned char *fp = sqlite3_column_text(stmt, 1);
        const unsigned char *claimed = sqlite3_column_text(stmt, 2);
        const unsigned char *status = sqlite3_column_text(stmt, 3);
        sqlite3_int64 last_seen = sqlite3_column_int64(stmt, 4);
        sqlite3_int64 seq = sqlite3_column_int64(stmt, 5);

        printf("%-4lld %-66s %-24s %-10s %-12lld %lld\n", (long long)id,
               fp != NULL ? (const char *)fp : "-", claimed != NULL ? (const char *)claimed : "-",
               status != NULL ? (const char *)status : "-", (long long)last_seen, (long long)seq);
    }
    sqlite3_finalize(stmt);
}
