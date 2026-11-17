#!/usr/bin/env bash
# Build the detonation cell images on the box that runs the sandbox. Idempotent; pulls once, with network, HERE.
# Samples later run with no egress at all. Foreign-arch runners need qemu binfmt on the host (one-time):
#   docker run --privileged --rm tonistiigi/binfmt --install all
set -euo pipefail
cd "$(dirname "$0")"
build() { # tag platform base
  printf 'FROM %s\nRUN apk add --no-cache strace coreutils iproute2\n' "$3" | docker build -q --platform "$2" -t "$1" - >/dev/null && echo "built $1"
}
build ninja-sandbox-cell:amd64 linux/amd64 alpine:3.20
if [ "${CELL_ALL_ARCHES:-1}" = "1" ] && ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -q qemu; then
  build ninja-sandbox-cell:386   linux/386    i386/alpine:3.20   || echo "skip 386"
  build ninja-sandbox-cell:armv7 linux/arm/v7 arm32v7/alpine:3.20 || echo "skip armv7"
  build ninja-sandbox-cell:arm64 linux/arm64  arm64v8/alpine:3.20 || echo "skip arm64"
else
  echo "no qemu binfmt on this host: only x86-64 samples will run (install: docker run --privileged --rm tonistiigi/binfmt --install all)"
fi
docker build -q -t ninja-sandbox-cell:sinkhole -f Dockerfile.sinkhole . >/dev/null && echo "built ninja-sandbox-cell:sinkhole"
docker network inspect "${SANDBOX_CELL_NET:-sandbox-cell}" >/dev/null 2>&1 || docker network create --internal --subnet "${SANDBOX_CELL_SUBNET:-10.66.0.0/24}" "${SANDBOX_CELL_NET:-sandbox-cell}"
docker pull -q curlimages/curl:8.10.1 >/dev/null 2>&1 && echo "pulled curlimages/curl (dropper fetcher)" || echo "curl image pull failed: dropper fetching will not work until it is pulled"
echo "cell ready: $(docker images --format '{{.Repository}}:{{.Tag}}' | grep -c '^ninja-sandbox-cell:') images, network ${SANDBOX_CELL_NET:-sandbox-cell} (internal)"
