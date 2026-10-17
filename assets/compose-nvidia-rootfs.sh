#!/bin/bash
set -euo pipefail

error() { printf '%s\n' "$*" >&2; }
# shellcheck source=assets/image-builder-loop.sh
source /loop.sh

ensure_loop_node /sys/class/misc/loop-control /dev/loop-control c
loop_device=""
for _ in {1..8}; do
    candidate=$(losetup --find)
    ensure_loop_node "/sys/class/block/${candidate##*/}" "$candidate" b
    if losetup --read-only --partscan "$candidate" /upstream.image; then
        loop_device="$candidate"
        break
    fi
    [[ -s "/sys/class/block/${candidate##*/}/loop/backing_file" ]] || exit 1
done
[[ -n "$loop_device" ]] || { error "Could not allocate a loop device"; exit 1; }

mkdir -p /mnt/upstream
cleanup() {
    umount /mnt/upstream 2>/dev/null || true
    losetup -d "$loop_device" || true
}
trap cleanup EXIT

partition="${loop_device}p1"
for _ in {1..10}; do
    # The runner's Docker daemon shares sysfs but can miss udev-created nodes.
    sleep 1
    sysfs="/sys/class/block/${partition##*/}"
    if [[ -r "${sysfs}/dev" ]]; then
        ensure_loop_node "$sysfs" "$partition" b
        if blockdev --getsize64 "$partition" >/dev/null 2>&1; then
            break
        fi
    fi
done
blockdev --getsize64 "$partition" >/dev/null 2>&1 || {
    error "Loop partition is unavailable: $partition"
    exit 1
}

mount -t erofs -o ro "$partition" /mnt/upstream
cp -a /mnt/upstream/. /output/
# Keep upstream NVIDIA libraries and components when a dependency has the same name.
cp -a --update=none /overlay/. /output/
# NVRC invokes the launcher, which installs CDI before executing the real agent.
for path in usr/bin/kata-agent usr/local/bin/kata-agent usr/local/bin/podvm-install-cdi usr/share/podvm/cdi/metadata.yaml; do
    cp -a --remove-destination "/overlay/$path" "/output/$path"
done
# The release identity is embedded in the measured guest image.
cp -a --remove-destination /overlay/etc/os-release /output/etc/os-release
cp -a --remove-destination /overlay/etc/kata-opa/default-policy.rego /output/etc/kata-opa/default-policy.rego
