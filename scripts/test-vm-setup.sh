#!/usr/bin/env bash
# Provision a disposable container for testing mdm-agent. Never run the
# agent on the host — it locks screens, blocks USB, and wipes directories.
#
# This uses a privileged, systemd-enabled Ubuntu container as the disposable
# target. That's sufficient through Phase 3 (networking, inventory, mTLS)
# and for exercising loginctl/dbus (Phase 5 lock/reboot stubs). Real USB
# hotplug testing (Phase 4 udev policy) needs actual hardware/a real VM
# (e.g. multipass or UTM) since Docker containers don't see real USB events
# — revisit the tooling then if this becomes a blocker.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="mdm-test-vm"
CONTAINER_NAME="mdm-test-vm"

usage() {
    cat <<EOF >&2
usage: $0 [build|start|shell|stop|destroy]

  build    Build the test container image (default)
  start    Start (or reuse) a detached disposable container
  shell    Exec an interactive shell into the running container
  stop     Stop the container
  destroy  Stop and remove the container and image
EOF
    exit 1
}

ACTION="${1:-build}"

require_docker() {
    command -v docker >/dev/null 2>&1 || {
        echo "docker is required but not found in PATH." >&2
        exit 1
    }
}

build_image() {
    require_docker
    local dockerfile="${SCRIPT_DIR}/Dockerfile.test-vm"
    cat > "${dockerfile}" <<'EOF'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config \
    openssl libssl-dev libcurl4-openssl-dev libsqlite3-dev sqlite3 libudev-dev \
    nftables dbus systemd systemd-sysv \
    iproute2 procps util-linux netcat-openbsd \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Standard trick for running systemd as PID 1 inside a container.
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
    docker build -t "${IMAGE_NAME}" -f "${dockerfile}" "${SCRIPT_DIR}"
}

start_container() {
    require_docker
    if docker ps --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
        echo "Container '${CONTAINER_NAME}' already running."
        return
    fi
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    docker run -d --name "${CONTAINER_NAME}" \
        --privileged \
        --tmpfs /run --tmpfs /run/lock \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        -v "${PROJECT_ROOT}:/mdm:rw" \
        "${IMAGE_NAME}"
    echo "Started disposable test container '${CONTAINER_NAME}'. Project mounted at /mdm."
}

shell_container() {
    require_docker
    docker exec -it "${CONTAINER_NAME}" bash
}

stop_container() {
    require_docker
    docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    echo "Stopped '${CONTAINER_NAME}'."
}

destroy_all() {
    require_docker
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    docker rmi -f "${IMAGE_NAME}" >/dev/null 2>&1 || true
    echo "Removed container and image."
}

case "${ACTION}" in
    build)   build_image ;;
    start)   start_container ;;
    shell)   shell_container ;;
    stop)    stop_container ;;
    destroy) destroy_all ;;
    *)       usage ;;
esac
