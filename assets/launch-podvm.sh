#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 {tdx|sev-snp} [extra qemu arguments ...]" >&2
    exit 2
}

[[ $# -ge 1 ]] || usage
tee_type=$1
shift
base_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cmdline=$(<"${base_dir}/cmdline")
common=(
    -enable-kvm -nographic -no-reboot -nodefaults
    -smp 2 -m 8G
    -kernel "${base_dir}/vmlinuz"
    -initrd "${base_dir}/initrd.img"
    -append "${cmdline}"
    -drive "file=${base_dir}/podvm.qcow2,if=none,id=root,format=qcow2,readonly=on"
    -netdev user,id=network0
    -device virtio-scsi-pci,id=scsi0,disable-modern=false
    -device scsi-hd,drive=root,bus=scsi0.0
    -device virtio-net-pci,netdev=network0,disable-modern=false
    -device virtio-serial-pci,disable-modern=false
)

case "${tee_type}" in
tdx)
    exec qemu-system-x86_64 \
        -object tdx-guest,id=tdx \
        -machine q35,kernel-irqchip=split,hpet=off,smm=off,pic=off,confidential-guest-support=tdx \
        -cpu host,pmu=off \
        -bios "${base_dir}/firmware/OVMF.inteltdx.fd" \
        "${common[@]}" "$@"
    ;;
sev-snp)
    exec qemu-system-x86_64 \
        -object memory-backend-memfd,id=ram1,size=8G,share=true,prealloc=false \
        -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on \
        -machine q35,vmport=off,confidential-guest-support=sev0,memory-backend=ram1 \
        -cpu EPYC-v4 \
        -bios "${base_dir}/firmware/AMDSEV.fd" \
        "${common[@]}" "$@"
    ;;
*) usage ;;
esac
