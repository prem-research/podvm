#!/bin/bash
set -euo pipefail

loop_device=$(losetup --find --show --read-only --partscan /upstream.image)
mkdir -p /mnt/upstream
cleanup() {
    umount /mnt/upstream 2>/dev/null || true
    losetup -d "$loop_device"
}
trap cleanup EXIT
mount -t erofs -o ro "${loop_device}p1" /mnt/upstream
cp -a /mnt/upstream/. /output/
# Keep upstream NVIDIA libraries and components when a dependency has the same name.
cp -a --update=none /overlay/. /output/
# The PodVM agent is the one intentional replacement of an upstream component.
cp -a --remove-destination /overlay/usr/bin/kata-agent /output/usr/bin/kata-agent
# The release identity is embedded in the measured guest image.
cp -a --remove-destination /overlay/etc/os-release /output/etc/os-release
cp -a --remove-destination /overlay/etc/kata-opa/default-policy.rego /output/etc/kata-opa/default-policy.rego
