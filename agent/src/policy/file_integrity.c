#include "file_integrity.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "events.h"
#include "messages.h"

#define MDM_MAX_WATCHES 32

typedef struct {
    int  wd;
    char path[512];
} mdm_watch_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static mdm_watch_t g_watches[MDM_MAX_WATCHES];
static size_t g_watch_count = 0;
static int g_inotify_fd = -1;
static pthread_t g_thread;
static int g_thread_started = 0;

static const char *find_path_for_wd_locked(int wd) {
    for (size_t i = 0; i < g_watch_count; i++) {
        if (g_watches[i].wd == wd) return g_watches[i].path;
    }
    return NULL;
}

static void *watch_thread_main(void *arg) {
    (void)arg;
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    for (;;) {
        ssize_t len = read(g_inotify_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "policy_file_integrity: read() failed: %s\n", strerror(errno));
            break;
        }
        if (len == 0) break;

        for (char *p = buf; p < buf + len;) {
            struct inotify_event *ev = (struct inotify_event *)(void *)p;

            pthread_mutex_lock(&g_lock);
            const char *path = find_path_for_wd_locked(ev->wd);
            char message[600];
            if (path != NULL) {
                snprintf(message, sizeof(message), "modified: %s (inotify mask=0x%x)", path,
                          ev->mask);
            } else {
                snprintf(message, sizeof(message), "event for unknown watch descriptor %d", ev->wd);
            }
            pthread_mutex_unlock(&g_lock);

            fprintf(stderr, "policy_file_integrity: %s\n", message);
            mdm_policy_events_push("file_integrity", message);

            p += sizeof(struct inotify_event) + ev->len;
        }
    }
    return NULL;
}

void mdm_policy_file_integrity_start(void) {
    if (g_thread_started) return;

    g_inotify_fd = inotify_init1(0);
    if (g_inotify_fd < 0) {
        fprintf(stderr, "policy_file_integrity: inotify_init1() failed: %s\n", strerror(errno));
        return;
    }

    if (pthread_create(&g_thread, NULL, watch_thread_main, NULL) != 0) {
        fprintf(stderr, "policy_file_integrity: failed to start watch thread\n");
        close(g_inotify_fd);
        g_inotify_fd = -1;
        return;
    }
    pthread_detach(g_thread);
    g_thread_started = 1;
    printf("policy_file_integrity: watch thread started\n");
}

static int add_watch(const char *path) {
    int wd = inotify_add_watch(g_inotify_fd, path,
                                IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF |
                                    IN_MOVE_SELF);
    if (wd < 0) {
        fprintf(stderr, "policy_file_integrity: inotify_add_watch('%s') failed: %s\n", path,
                strerror(errno));
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    int rc = -1;
    if (g_watch_count < MDM_MAX_WATCHES) {
        g_watches[g_watch_count].wd = wd;
        snprintf(g_watches[g_watch_count].path, sizeof(g_watches[g_watch_count].path), "%s", path);
        g_watch_count++;
        rc = 0;
    } else {
        fprintf(stderr, "policy_file_integrity: max watches (%d) reached, rejecting '%s'\n",
                MDM_MAX_WATCHES, path);
        inotify_rm_watch(g_inotify_fd, wd);
    }
    pthread_mutex_unlock(&g_lock);
    return rc;
}

static int remove_watch(const char *path) {
    pthread_mutex_lock(&g_lock);
    int rc = -1;
    for (size_t i = 0; i < g_watch_count; i++) {
        if (strcmp(g_watches[i].path, path) == 0) {
            inotify_rm_watch(g_inotify_fd, g_watches[i].wd);
            g_watches[i] = g_watches[g_watch_count - 1];
            g_watch_count--;
            rc = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    if (rc != 0) {
        fprintf(stderr, "policy_file_integrity: '%s' was not being watched\n", path);
    }
    return rc;
}

int mdm_policy_file_integrity_apply(const cJSON *params) {
    const cJSON *action = cJSON_GetObjectItemCaseSensitive(params, MDM_PARAM_ACTION);
    const cJSON *path = cJSON_GetObjectItemCaseSensitive(params, MDM_PARAM_PATH);
    if (!cJSON_IsString(action) || !cJSON_IsString(path)) {
        fprintf(stderr, "policy_file_integrity: missing/invalid 'action'/'path' params\n");
        return -1;
    }

    mdm_policy_file_integrity_start();
    if (g_inotify_fd < 0) {
        fprintf(stderr, "policy_file_integrity: watch thread unavailable, cannot apply\n");
        return -1;
    }

    if (strcmp(action->valuestring, "watch") == 0) {
        printf("policy_file_integrity: watching '%s'\n", path->valuestring);
        return add_watch(path->valuestring);
    }
    if (strcmp(action->valuestring, "unwatch") == 0) {
        printf("policy_file_integrity: unwatching '%s'\n", path->valuestring);
        return remove_watch(path->valuestring);
    }

    fprintf(stderr, "policy_file_integrity: unknown action '%s'\n", action->valuestring);
    return -1;
}
