/* Wire framing shared by mdm-agent and mdm-server: a 4-byte big-endian
 * length prefix followed by exactly that many bytes of UTF-8 JSON. Kept
 * here, not duplicated per-program, so both sides can never drift on the
 * wire format. Header-only (static inline) so no extra build-system entry
 * is needed in either Makefile. */
#ifndef MDM_PROTO_FRAMING_H
#define MDM_PROTO_FRAMING_H

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "messages.h"

#define MDM_FRAME_MAX_LEN MDM_MAX_PAYLOAD_LEN

static inline int mdm_frame_write_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static inline int mdm_frame_read_all(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1; /* peer closed before sending full frame */
        got += (size_t)n;
    }
    return 0;
}

/* Sends `len` bytes of `json` as one length-prefixed frame. Returns 0 on
 * success, -1 on error (including len exceeding MDM_FRAME_MAX_LEN). */
static inline int mdm_frame_send(int fd, const char *json, size_t len) {
    if (len > MDM_FRAME_MAX_LEN) return -1;

    uint32_t len_be = htonl((uint32_t)len);
    if (mdm_frame_write_all(fd, (const uint8_t *)&len_be, sizeof(len_be)) != 0) {
        return -1;
    }
    return mdm_frame_write_all(fd, (const uint8_t *)json, len);
}

/* Reads one length-prefixed frame and returns it as a malloc'd,
 * NUL-terminated string (caller frees). Returns NULL on error, EOF, or a
 * declared length exceeding MDM_FRAME_MAX_LEN. */
static inline char *mdm_frame_recv(int fd) {
    uint32_t len_be = 0;
    if (mdm_frame_read_all(fd, (uint8_t *)&len_be, sizeof(len_be)) != 0) {
        return NULL;
    }

    uint32_t len = ntohl(len_be);
    if (len == 0 || len > MDM_FRAME_MAX_LEN) {
        return NULL;
    }

    char *buf = malloc((size_t)len + 1);
    if (buf == NULL) return NULL;

    if (mdm_frame_read_all(fd, (uint8_t *)buf, len) != 0) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

#endif /* MDM_PROTO_FRAMING_H */
