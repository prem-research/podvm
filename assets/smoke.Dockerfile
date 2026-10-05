ARG BUILDER
FROM ${BUILDER}
# Run the pinned Kata shim through a private containerd inside this container.
RUN apt-get update && apt-get install --yes --no-install-recommends busybox containerd \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/kata/bin:${PATH}"
COPY smoke-entrypoint.sh /usr/local/bin/podvm-smoke
ENTRYPOINT ["sh", "/usr/local/bin/podvm-smoke"]
