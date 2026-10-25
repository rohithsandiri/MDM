#include "inventory.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utmpx.h>

#include "messages.h"

static void collect_hostname_kernel(mdm_inventory_t *inv) {
    struct utsname u;
    if (uname(&u) != 0) {
        fprintf(stderr, "inventory: uname() failed: %s\n", strerror(errno));
        return;
    }
    snprintf(inv->hostname, sizeof(inv->hostname), "%s", u.nodename);
    snprintf(inv->kernel_release, sizeof(inv->kernel_release), "%s", u.release);
    snprintf(inv->kernel_version, sizeof(inv->kernel_version), "%s", u.version);
}

static void collect_cpu(mdm_inventory_t *inv) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f == NULL) {
        fprintf(stderr, "inventory: /proc/cpuinfo unavailable: %s\n", strerror(errno));
        return;
    }

    char line[512];
    int got_model = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "processor", 9) == 0) {
            inv->cpu_count++;
        } else if (!got_model && strncmp(line, "model name", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon != NULL) {
                colon++;
                while (*colon == ' ' || *colon == '\t') colon++;
                size_t len = strlen(colon);
                while (len > 0 && (colon[len - 1] == '\n' || colon[len - 1] == '\r')) {
                    colon[--len] = '\0';
                }
                snprintf(inv->cpu_model, sizeof(inv->cpu_model), "%s", colon);
                got_model = 1;
            }
        }
    }
    fclose(f);
}

static void collect_memory(mdm_inventory_t *inv) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (f == NULL) {
        fprintf(stderr, "inventory: /proc/meminfo unavailable: %s\n", strerror(errno));
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f) != NULL) {
        uint64_t kb;
        if (sscanf(line, "MemTotal: %" SCNu64 " kB", &kb) == 1) {
            inv->mem_total_kb = kb;
        } else if (sscanf(line, "MemAvailable: %" SCNu64 " kB", &kb) == 1) {
            inv->mem_available_kb = kb;
        }
    }
    fclose(f);
}

static void collect_disk(mdm_inventory_t *inv) {
    struct statvfs sv;
    if (statvfs("/", &sv) != 0) {
        fprintf(stderr, "inventory: statvfs(\"/\") failed: %s\n", strerror(errno));
        return;
    }
    inv->disk_total_bytes = (uint64_t)sv.f_blocks * (uint64_t)sv.f_frsize;
    inv->disk_free_bytes = (uint64_t)sv.f_bavail * (uint64_t)sv.f_frsize;
}

static void collect_network(mdm_inventory_t *inv) {
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) != 0) {
        fprintf(stderr, "inventory: getifaddrs() failed: %s\n", strerror(errno));
        return;
    }

    size_t cap = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) continue;

        if (inv->iface_count == cap) {
            size_t new_cap = (cap == 0) ? 8 : cap * 2;
            mdm_net_iface_t *tmp = realloc(inv->ifaces, new_cap * sizeof(*tmp));
            if (tmp == NULL) break;
            inv->ifaces = tmp;
            cap = new_cap;
        }

        mdm_net_iface_t *slot = &inv->ifaces[inv->iface_count];
        snprintf(slot->name, sizeof(slot->name), "%s", ifa->ifa_name);
        const struct sockaddr_in *sin = (const struct sockaddr_in *)(const void *)ifa->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, slot->ipv4, sizeof(slot->ipv4)) == NULL) {
            slot->ipv4[0] = '\0';
        }
        inv->iface_count++;
    }
    freeifaddrs(ifaddr);
}

static void collect_uptime_load(mdm_inventory_t *inv) {
    FILE *f = fopen("/proc/uptime", "r");
    if (f != NULL) {
        double up = 0, idle = 0;
        if (fscanf(f, "%lf %lf", &up, &idle) == 2) {
            inv->uptime_seconds = up;
        }
        fclose(f);
    } else {
        fprintf(stderr, "inventory: /proc/uptime unavailable: %s\n", strerror(errno));
    }

    f = fopen("/proc/loadavg", "r");
    if (f != NULL) {
        if (fscanf(f, "%lf %lf %lf", &inv->load1, &inv->load5, &inv->load15) != 3) {
            fprintf(stderr, "inventory: failed to parse /proc/loadavg\n");
        }
        fclose(f);
    } else {
        fprintf(stderr, "inventory: /proc/loadavg unavailable: %s\n", strerror(errno));
    }
}

static void collect_logged_in_users(mdm_inventory_t *inv) {
    size_t cap = 0;
    struct utmpx *entry;

    setutxent();
    while ((entry = getutxent()) != NULL) {
        if (entry->ut_type != USER_PROCESS || entry->ut_user[0] == '\0') continue;

        char name[sizeof(entry->ut_user) + 1];
        memcpy(name, entry->ut_user, sizeof(entry->ut_user));
        name[sizeof(entry->ut_user)] = '\0';

        if (inv->logged_in_user_count == cap) {
            size_t new_cap = (cap == 0) ? 8 : cap * 2;
            char **tmp = realloc(inv->logged_in_users, new_cap * sizeof(char *));
            if (tmp == NULL) break;
            inv->logged_in_users = tmp;
            cap = new_cap;
        }

        char *dup = strdup(name);
        if (dup != NULL) {
            inv->logged_in_users[inv->logged_in_user_count++] = dup;
        }
    }
    endutxent();
}

/* Fixed argv, no shell — execv() of a known binary path, never a string
 * built from input and handed to system(). Returns 0 and a malloc'd,
 * NUL-terminated buffer in *out (caller frees) on success, -1 on error. */
static int run_capture(const char *path, char *const argv[], char **out, size_t *out_len) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        fprintf(stderr, "inventory: pipe() failed: %s\n", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "inventory: fork() failed: %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(path, argv);
        _exit(127); /* execv failed */
    }

    close(pipefd[1]);

    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (buf == NULL) {
        close(pipefd[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }

    ssize_t n;
    while ((n = read(pipefd[0], buf + len, cap - len - 1)) > 0) {
        len += (size_t)n;
        if (len + 1 >= cap) {
            size_t new_cap = cap * 2;
            if (new_cap > (size_t)MDM_MAX_PAYLOAD_LEN * 4) {
                fprintf(stderr, "inventory: subprocess output exceeded safety cap, truncating\n");
                break;
            }
            char *tmp = realloc(buf, new_cap);
            if (tmp == NULL) break;
            buf = tmp;
            cap = new_cap;
        }
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    if (n < 0) {
        fprintf(stderr, "inventory: read() from subprocess failed: %s\n", strerror(errno));
        free(buf);
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) == 127) {
        fprintf(stderr, "inventory: subprocess '%s' failed to run\n", path);
        free(buf);
        return -1;
    }

    buf[len] = '\0';
    *out = buf;
    *out_len = len;
    return 0;
}

static int binary_exists(const char *path) {
    return access(path, X_OK) == 0;
}

static void append_package(mdm_inventory_t *inv, size_t *cap, const char *entry) {
    if (inv->package_count == *cap) {
        size_t new_cap = (*cap == 0) ? 256 : (*cap * 2);
        char **tmp = realloc(inv->packages, new_cap * sizeof(char *));
        if (tmp == NULL) return;
        inv->packages = tmp;
        *cap = new_cap;
    }
    char *dup = strdup(entry);
    if (dup != NULL) {
        inv->packages[inv->package_count++] = dup;
    }
}

/* dpkg -l output is a fixed banner (ending in a "+++-====" rule line)
 * followed by "<status> <name> <version> <arch> <description...>" rows. */
static void parse_dpkg_lines(mdm_inventory_t *inv, size_t *cap, char *buf) {
    int skipped_header = 0;
    char *line = strtok(buf, "\n");
    while (line != NULL) {
        if (!skipped_header) {
            if (line[0] == '+') skipped_header = 1;
            line = strtok(NULL, "\n");
            continue;
        }

        char status[8] = {0}, name[128] = {0}, version[128] = {0};
        if (sscanf(line, "%7s %127s %127s", status, name, version) == 3) {
            char entry[260];
            snprintf(entry, sizeof(entry), "%s %s", name, version);
            append_package(inv, cap, entry);
        }
        line = strtok(NULL, "\n");
    }
}

/* rpm -qa output is one "name-version-release.arch" string per line. */
static void parse_rpm_lines(mdm_inventory_t *inv, size_t *cap, char *buf) {
    char *line = strtok(buf, "\n");
    while (line != NULL) {
        if (line[0] != '\0') {
            append_package(inv, cap, line);
        }
        line = strtok(NULL, "\n");
    }
}

static void collect_packages(mdm_inventory_t *inv) {
    size_t cap = 0;
    char *buf = NULL;
    size_t len = 0;

    if (binary_exists("/usr/bin/dpkg")) {
        char *argv[] = {"/usr/bin/dpkg", "-l", NULL};
        if (run_capture("/usr/bin/dpkg", argv, &buf, &len) == 0) {
            parse_dpkg_lines(inv, &cap, buf);
        }
    } else if (binary_exists("/usr/bin/rpm") || binary_exists("/bin/rpm")) {
        const char *rpm_path = binary_exists("/usr/bin/rpm") ? "/usr/bin/rpm" : "/bin/rpm";
        char *argv[] = {(char *)rpm_path, "-qa", NULL};
        if (run_capture(rpm_path, argv, &buf, &len) == 0) {
            parse_rpm_lines(inv, &cap, buf);
        }
    } else {
        fprintf(stderr, "inventory: no supported package manager found (dpkg/rpm)\n");
    }

    free(buf);
}

void mdm_inventory_collect(mdm_inventory_t *inv) {
    memset(inv, 0, sizeof(*inv));
    collect_hostname_kernel(inv);
    collect_cpu(inv);
    collect_memory(inv);
    collect_disk(inv);
    collect_network(inv);
    collect_uptime_load(inv);
    collect_logged_in_users(inv);
    collect_packages(inv);
}

void mdm_inventory_free(mdm_inventory_t *inv) {
    free(inv->ifaces);
    for (size_t i = 0; i < inv->logged_in_user_count; i++) {
        free(inv->logged_in_users[i]);
    }
    free(inv->logged_in_users);
    for (size_t i = 0; i < inv->package_count; i++) {
        free(inv->packages[i]);
    }
    free(inv->packages);
    memset(inv, 0, sizeof(*inv));
}

cJSON *mdm_inventory_to_json(const mdm_inventory_t *inv) {
    cJSON *root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "hostname", inv->hostname);
    cJSON_AddStringToObject(root, "kernel_release", inv->kernel_release);
    cJSON_AddStringToObject(root, "kernel_version", inv->kernel_version);

    cJSON_AddStringToObject(root, "cpu_model", inv->cpu_model);
    cJSON_AddNumberToObject(root, "cpu_count", inv->cpu_count);

    cJSON_AddNumberToObject(root, "mem_total_kb", (double)inv->mem_total_kb);
    cJSON_AddNumberToObject(root, "mem_available_kb", (double)inv->mem_available_kb);

    cJSON_AddNumberToObject(root, "disk_total_bytes", (double)inv->disk_total_bytes);
    cJSON_AddNumberToObject(root, "disk_free_bytes", (double)inv->disk_free_bytes);

    cJSON *ifaces = cJSON_CreateArray();
    for (size_t i = 0; i < inv->iface_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "name", inv->ifaces[i].name);
        cJSON_AddStringToObject(item, "ipv4", inv->ifaces[i].ipv4);
        cJSON_AddItemToArray(ifaces, item);
    }
    cJSON_AddItemToObject(root, "network_interfaces", ifaces);

    cJSON_AddNumberToObject(root, "uptime_seconds", inv->uptime_seconds);
    cJSON_AddNumberToObject(root, "load1", inv->load1);
    cJSON_AddNumberToObject(root, "load5", inv->load5);
    cJSON_AddNumberToObject(root, "load15", inv->load15);

    cJSON *users = cJSON_CreateArray();
    for (size_t i = 0; i < inv->logged_in_user_count; i++) {
        cJSON_AddItemToArray(users, cJSON_CreateString(inv->logged_in_users[i]));
    }
    cJSON_AddItemToObject(root, "logged_in_users", users);

    cJSON *packages = cJSON_CreateArray();
    for (size_t i = 0; i < inv->package_count; i++) {
        cJSON_AddItemToArray(packages, cJSON_CreateString(inv->packages[i]));
    }
    cJSON_AddItemToObject(root, "packages", packages);

    return root;
}
