#include "usb_lockdown.h"

#include <errno.h>
#include <libudev.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/select.h>

#include "events.h"
#include "messages.h"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_enabled = 0;
static pthread_t g_thread;
static int g_thread_started = 0;

/* Finds every current mount of `devnode` in /proc/mounts and force-
 * unmounts it. This *is* the block action for this phase: it denies use
 * of whatever filesystem the device was presenting. Returns the number
 * of mounts removed (0 if none were mounted — still a legitimate
 * outcome, not an error). */
static int unmount_device(const char *devnode) {
    FILE *f = fopen("/proc/mounts", "r");
    if (f == NULL) {
        fprintf(stderr, "policy_usb_lockdown: failed to open /proc/mounts: %s\n", strerror(errno));
        return 0;
    }

    int blocked = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        char dev[256], mnt[256];
        if (sscanf(line, "%255s %255s", dev, mnt) != 2) continue;
        if (strcmp(dev, devnode) != 0) continue;

        if (umount2(mnt, MNT_FORCE) == 0) {
            blocked++;
            char msg[600];
            snprintf(msg, sizeof(msg), "blocked USB mass storage: unmounted %s from %s", devnode,
                      mnt);
            printf("policy_usb_lockdown: %s\n", msg);
            mdm_policy_events_push("usb_lockdown", msg);
        } else {
            fprintf(stderr, "policy_usb_lockdown: umount2('%s') failed: %s\n", mnt,
                    strerror(errno));
        }
    }
    fclose(f);
    return blocked;
}

static void handle_device(struct udev_device *dev) {
    const char *action = udev_device_get_action(dev);
    if (action == NULL || strcmp(action, "add") != 0) return;

    const char *devtype = udev_device_get_devtype(dev);
    if (devtype == NULL || (strcmp(devtype, "disk") != 0 && strcmp(devtype, "partition") != 0)) {
        return;
    }

    const char *bus = udev_device_get_property_value(dev, "ID_BUS");
    if (bus == NULL || strcmp(bus, "usb") != 0) return;

    const char *devnode = udev_device_get_devnode(dev);
    if (devnode == NULL) return;

    pthread_mutex_lock(&g_lock);
    int enabled = g_enabled;
    pthread_mutex_unlock(&g_lock);

    if (!enabled) {
        printf("policy_usb_lockdown: USB mass-storage device %s added (lockdown disabled, "
               "allowing)\n", devnode);
        return;
    }

    printf("policy_usb_lockdown: USB mass-storage device %s added, lockdown enabled -- blocking\n",
           devnode);
    if (unmount_device(devnode) == 0) {
        /* Not mounted (yet) — still log/report that we saw and are
         * denying it, so the event trail doesn't look empty. */
        char msg[600];
        snprintf(msg, sizeof(msg), "blocked USB mass storage: %s added while lockdown enabled "
                                     "(no active mount found to remove)", devnode);
        mdm_policy_events_push("usb_lockdown", msg);
    }
}

static void *monitor_thread_main(void *arg) {
    (void)arg;

    struct udev *udev = udev_new();
    if (udev == NULL) {
        fprintf(stderr, "policy_usb_lockdown: udev_new() failed\n");
        return NULL;
    }

    struct udev_monitor *mon = udev_monitor_new_from_netlink(udev, "udev");
    if (mon == NULL) {
        fprintf(stderr, "policy_usb_lockdown: udev_monitor_new_from_netlink() failed\n");
        udev_unref(udev);
        return NULL;
    }

    udev_monitor_filter_add_match_subsystem_devtype(mon, "block", NULL);
    udev_monitor_enable_receiving(mon);
    int fd = udev_monitor_get_fd(mon);

    printf("policy_usb_lockdown: udev monitor thread started\n");

    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        int rc = select(fd + 1, &fds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "policy_usb_lockdown: select() failed: %s\n", strerror(errno));
            break;
        }
        if (!FD_ISSET(fd, &fds)) continue;

        struct udev_device *dev = udev_monitor_receive_device(mon);
        if (dev != NULL) {
            handle_device(dev);
            udev_device_unref(dev);
        }
    }

    udev_monitor_unref(mon);
    udev_unref(udev);
    return NULL;
}

void mdm_policy_usb_lockdown_start(void) {
    if (g_thread_started) return;

    if (pthread_create(&g_thread, NULL, monitor_thread_main, NULL) != 0) {
        fprintf(stderr, "policy_usb_lockdown: failed to start monitor thread\n");
        return;
    }
    pthread_detach(g_thread);
    g_thread_started = 1;
}

int mdm_policy_usb_lockdown_apply(const cJSON *params) {
    const cJSON *enabled = cJSON_GetObjectItemCaseSensitive(params, MDM_PARAM_ENABLED);
    if (!cJSON_IsBool(enabled)) {
        fprintf(stderr, "policy_usb_lockdown: missing/invalid 'enabled' param\n");
        return -1;
    }

    mdm_policy_usb_lockdown_start();

    pthread_mutex_lock(&g_lock);
    g_enabled = cJSON_IsTrue(enabled) ? 1 : 0;
    pthread_mutex_unlock(&g_lock);

    printf("policy_usb_lockdown: lockdown %s\n", g_enabled ? "ENABLED" : "disabled");
    return 0;
}
