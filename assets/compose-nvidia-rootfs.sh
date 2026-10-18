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
# Merge the daemon account without replacing upstream account databases or
# silently assigning its privileges to an existing UID/GID.
for database in passwd group; do
    touch "/output/etc/$database"
    entry=$(cat "/overlay/etc/$database")
    name=${entry%%:*}
    id=$(printf '%s\n' "$entry" | cut -d: -f3)
    existing=$(awk -F: -v name="$name" '$1 == name { print }' "/output/etc/$database")
    if [[ -n "$existing" ]]; then
        [[ "$existing" == "$entry" ]] || { error "Conflicting $name $database entry"; exit 1; }
    else
        if ! awk -F: -v id="$id" '$3 == id { exit 1 }' "/output/etc/$database"; then
            error "Conflicting chrony $database ID: $id"
            exit 1
        fi
        printf '%s\n' "$entry" >> "/output/etc/$database"
    fi
done
# Keep upstream NVIDIA libraries and components when a dependency has the same name.
cp -a --update=none /overlay/. /output/
# NVRC's launcher preserves the exec handoff to the real agent as PID 1.
for path in usr/bin/kata-agent usr/libexec/podvm/kata-agent bin/sh \
    usr/sbin/chronyd usr/bin/chronyc usr/bin/install usr/bin/sleep \
    usr/local/bin/podvm-time-sync etc/chrony/chrony.conf \
    etc/chrony/nts-bootstrap-ubuntu.crt etc/chrony/bootstrap-source.json \
    etc/ssl/certs/ca-certificates.crt \
    etc/cdi/podvm-metadata.yaml; do
    cp -a --remove-destination "/overlay/$path" "/output/$path"
done
# The release identity is embedded in the measured guest image.
cp -a --remove-destination /overlay/etc/os-release /output/etc/os-release
cp -a --remove-destination /overlay/etc/kata-opa/default-policy.rego /output/etc/kata-opa/default-policy.rego
