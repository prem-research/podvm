ARG BUILDER
FROM ${BUILDER}
ARG DEBIAN_SNAPSHOT
ARG GO_VERSION
ARG GO_SHA256
# The agent is built for GNU libc on bookworm, whose ABI also runs on the
# Ubuntu 24.04 guest. Runtime dependencies are checked before image creation.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources \
    && printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s bookworm main\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list \
    && for attempt in 1 2 3 4 5; do \
         apt-get -o Acquire::Retries=5 -o Acquire::http::Pipeline-Depth=0 -o Acquire::Queue-Mode=access -o APT::Update::Error-Mode=any update \
         && apt-get -o Acquire::Retries=5 -o Acquire::http::Pipeline-Depth=0 -o Acquire::Queue-Mode=access install --yes --no-install-recommends libseccomp-dev protobuf-compiler pkg-config cryptsetup-bin erofs-utils \
         && break; \
         [ "$attempt" -lt 5 ] || exit 1; \
         sleep $((attempt * 10)); \
       done \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --retry 3 "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
    && printf '%s  /tmp/go.tar.gz\n' "${GO_SHA256}" | sha256sum --check --strict \
    && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}" RUSTUP_TOOLCHAIN=1.95.0 GOTOOLCHAIN=local
