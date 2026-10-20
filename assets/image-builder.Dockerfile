ARG BUILDER
FROM ${BUILDER}
RUN apt-get update && apt-get install --yes --no-install-recommends \
    bash ca-certificates coreutils cryptsetup-bin e2fsprogs file gawk \
    grep mount parted qemu-utils udev util-linux && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["bash", "/kata/tools/osbuilder/image-builder/image_builder.sh"]
