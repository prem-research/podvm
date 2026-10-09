ARG BUILDER
FROM ${BUILDER}
ARG DEBIAN_SNAPSHOT
ARG GO_VERSION
ARG GO_SHA256
# The agent is built for GNU libc on bookworm, whose ABI also runs on the
# Ubuntu 24.04 guest. Runtime dependencies are checked before image creation.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources \
    && printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s bookworm main\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install --yes --no-install-recommends libseccomp-dev protobuf-compiler pkg-config cryptsetup-bin erofs-utils \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --retry 3 "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
    && printf '%s  /tmp/go.tar.gz\n' "${GO_SHA256}" | sha256sum --check --strict \
    && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}" RUSTUP_TOOLCHAIN=1.95.0 GOTOOLCHAIN=local
